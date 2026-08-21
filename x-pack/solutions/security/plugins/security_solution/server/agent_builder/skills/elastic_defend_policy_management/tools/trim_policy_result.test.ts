/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from 'crypto';
import { estimateTokens } from '@kbn/agent-builder-genai-utils/tools/utils/token_count';
import { createOtherResult } from '@kbn/agent-builder-server';
import { policyFactory } from '../../../../../common/endpoint/models/policy_config';
import { hashPolicyConfig } from '../domain/hash_policy_config';
import { normalize } from '../domain/normalize';
import {
  GUARDED_ENVELOPE_HEADROOM_TOKENS,
  estimateGuardedEnvelopeTokens,
  fitsGuardedEnvelope,
  omitTrailingToFit,
  parentTrimMetadata,
  presentBoundedIdentityStrings,
  presentWithinGuardedBudget,
  sidedTrimMetadata,
  toPresentationHash,
  trimPolicyResult,
  trimPolicyResultWithMeta,
  tryOmitTrailingToFit,
} from './trim_policy_result';

const nest = (depth: number, leaf: unknown): unknown =>
  depth === 0 ? leaf : { next: nest(depth - 1, leaf) };

const countPresentedNodes = (value: unknown): number => {
  if (Array.isArray(value)) {
    return value.reduce((total, item) => total + countPresentedNodes(item), 1);
  }
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value as Record<string, unknown>).reduce((total, [key, item]) => {
      if (
        key === 'string_truncated' ||
        key === 'value_truncated' ||
        key === 'value_total' ||
        key === 'depth_truncated' ||
        key === 'output_truncated' ||
        key === 'output_total_nodes'
      ) {
        return total;
      }
      return total + countPresentedNodes(item);
    }, 1);
  }
  return 1;
};

describe('trimPolicyResult', () => {
  it('passes through primitives and objects that fit every cap', () => {
    expect(trimPolicyResult('short')).toBe('short');
    expect(trimPolicyResult(7)).toBe(7);
    expect(trimPolicyResult(true)).toBe(true);
    expect(trimPolicyResult(null)).toBe(null);
    expect(trimPolicyResult({ name: 'policy', enabled: true })).toEqual({
      enabled: true,
      name: 'policy',
    });
  });

  it('caps strings at 512 and annotates only the parent object when cut', () => {
    const exact = 'E'.repeat(512);
    const over = 'Y'.repeat(600);

    expect(trimPolicyResult({ label: exact })).toEqual({ label: exact });
    expect(trimPolicyResult({ label: over })).toEqual({
      label: 'Y'.repeat(512),
      string_truncated: true,
    });
    expect(trimPolicyResult(over)).toBe('Y'.repeat(512));
    expect(JSON.stringify(trimPolicyResult({ label: over }))).not.toContain('Y'.repeat(513));
  });

  it('caps arrays at 50 and annotates the parent with totals', () => {
    const exact = Array.from({ length: 50 }, (_, index) => `item-${index}`);
    const over = Array.from({ length: 80 }, (_, index) => `item-${index}`);

    expect(trimPolicyResult({ values: exact })).toEqual({ values: exact });
    expect(trimPolicyResult({ values: over })).toEqual({
      values: over.slice(0, 50),
      value_truncated: true,
      value_total: 80,
    });
    expect(JSON.stringify(trimPolicyResult({ values: over }))).not.toContain('item-50');
    expect(trimPolicyResult(over)).toEqual(over.slice(0, 50));
  });

  it('caps object entries at 50 in deterministic key order and reports totals', () => {
    const exact: Record<string, string> = {};
    for (let index = 0; index < 50; index += 1) {
      exact[`k${String(index).padStart(2, '0')}`] = `keep-${index}`;
    }
    const over: Record<string, string> = {
      alpha: 'first',
      mu: 'middle',
    };
    for (let index = 0; index < 48; index += 1) {
      over[`n${String(index).padStart(2, '0')}`] = `keep-${index}`;
    }
    over.zzz_secret = 'RAW_DROPPED_VALUE';

    const trimmedExact = trimPolicyResult(exact) as Record<string, unknown>;
    expect(Object.keys(trimmedExact)).toEqual(
      Object.keys(exact).sort((a, b) => a.localeCompare(b))
    );
    expect(trimmedExact).not.toHaveProperty('value_truncated');

    const trimmedOver = trimPolicyResult(over) as Record<string, unknown>;
    const dataKeys = Object.keys(trimmedOver).filter(
      (key) => key !== 'value_truncated' && key !== 'value_total'
    );
    expect(dataKeys).toHaveLength(50);
    expect(dataKeys).toEqual([...dataKeys].sort((a, b) => a.localeCompare(b)));
    expect(dataKeys[0]).toBe('alpha');
    expect(trimmedOver).toEqual(
      expect.objectContaining({
        alpha: 'first',
        mu: 'middle',
        value_truncated: true,
        value_total: 51,
      })
    );
    expect(trimmedOver).not.toHaveProperty('zzz_secret');
    expect(JSON.stringify(trimmedOver)).not.toContain('RAW_DROPPED_VALUE');
  });

  it('stops expanding below depth 10 and does not keep raw deep values', () => {
    const hidden = { secret: 'HIDDEN_DEEP_VALUE' };
    const deep = nest(10, hidden) as Record<string, unknown>;
    const trimmed = trimPolicyResult(deep) as Record<string, unknown>;

    const walk = (value: unknown): unknown => {
      if (typeof value === 'object' && value !== null && 'next' in (value as object)) {
        return walk((value as { next: unknown }).next);
      }
      return value;
    };

    expect(walk(trimmed)).toEqual({ depth_truncated: true });
    expect(JSON.stringify(trimmed)).not.toContain('HIDDEN_DEEP_VALUE');
    expect(JSON.stringify(trimmed)).not.toContain('secret');
  });

  it('applies the 500-node presentation budget and reports the original total', () => {
    const input: Record<string, unknown> = {};
    for (let index = 0; index < 50; index += 1) {
      input[`k${String(index).padStart(2, '0')}`] = Array.from({ length: 50 }, (_, item) => item);
    }

    const trimmed = trimPolicyResult(input) as Record<string, unknown>;
    const presented = countPresentedNodes(trimmed);

    expect(trimmed.output_truncated).toBe(true);
    expect(trimmed.output_total_nodes).toBe(1 + 50 + 50 * 50);
    expect(presented).toBeLessThanOrEqual(500);
    expect(Object.keys(trimmed).some((key) => /^k\d{2}$/.test(key) && key > 'k09')).toBe(false);
  });

  it('applies string, array, object, depth, and node caps together without retaining dropped data', () => {
    const input: Record<string, unknown> = {
      k00: 'Y'.repeat(600),
      k01: { items: Array.from({ length: 80 }, (_, index) => `item-${index}`) },
      k02: nest(10, { secret: 'HIDDEN_DEEP_VALUE' }),
    };
    for (let index = 3; index < 60; index += 1) {
      input[`k${String(index).padStart(2, '0')}`] =
        index < 50 ? Array.from({ length: 50 }, (_, item) => item) : 'RAW_DROPPED_VALUE';
    }

    const trimmed = trimPolicyResult(input) as Record<string, unknown>;
    const k01 = trimmed.k01 as Record<string, unknown>;
    const dataKeys = Object.keys(trimmed).filter(
      (key) =>
        key !== 'string_truncated' &&
        key !== 'value_truncated' &&
        key !== 'value_total' &&
        key !== 'output_truncated' &&
        key !== 'output_total_nodes'
    );

    expect(dataKeys.length).toBeGreaterThanOrEqual(3);
    expect(dataKeys.length).toBeLessThan(50);
    expect(dataKeys).toEqual([...dataKeys].sort((a, b) => a.localeCompare(b)));
    expect(trimmed.k00).toBe('Y'.repeat(512));
    expect(trimmed.string_truncated).toBe(true);
    expect(trimmed.value_truncated).toBe(true);
    expect(trimmed.value_total).toBe(60);
    expect(k01.items).toHaveLength(50);
    expect(k01.value_truncated).toBe(true);
    expect(k01.value_total).toBe(80);
    expect(trimmed.output_truncated).toBe(true);
    expect(trimmed.output_total_nodes).toBeGreaterThan(500);
    expect(countPresentedNodes(trimmed)).toBeLessThanOrEqual(500);

    const serialized = JSON.stringify(trimmed);
    expect(serialized).not.toContain('Y'.repeat(513));
    expect(serialized).not.toContain('item-50');
    expect(serialized).not.toContain('RAW_DROPPED_VALUE');
    expect(serialized).not.toContain('HIDDEN_DEEP_VALUE');
    expect(trimmed).not.toHaveProperty('k50');
    expect(trimmed).not.toHaveProperty('k59');
  });

  it('exposes primitive and array root truncation on parent metadata', () => {
    const overString = trimPolicyResultWithMeta('Y'.repeat(600));
    expect(overString.value).toBe('Y'.repeat(512));
    expect(overString.metadata).toEqual({ string_truncated: true });
    expect(parentTrimMetadata(overString.value, overString.metadata)).toEqual({
      string_truncated: true,
    });
    expect(JSON.stringify(overString.value)).not.toContain('Y'.repeat(513));

    const overArray = Array.from({ length: 80 }, (_, index) => `item-${index}`);
    const arrayTrim = trimPolicyResultWithMeta(overArray);
    expect(arrayTrim.value).toEqual(overArray.slice(0, 50));
    expect(arrayTrim.metadata).toEqual({ value_truncated: true, value_total: 80 });
    expect(parentTrimMetadata(arrayTrim.value, arrayTrim.metadata)).toEqual({
      value_truncated: true,
      value_total: 80,
    });
    expect(JSON.stringify(arrayTrim.value)).not.toContain('item-50');

    const objectTrim = trimPolicyResultWithMeta({ label: 'Y'.repeat(600) });
    expect(parentTrimMetadata(objectTrim.value, objectTrim.metadata)).toEqual({});
  });

  it('annotates node-budget cuts on array roots without wrapping the array', () => {
    const huge = Array.from({ length: 50 }, () => Array.from({ length: 20 }, (_, item) => item));
    const trimmed = trimPolicyResultWithMeta(huge);
    expect(Array.isArray(trimmed.value)).toBe(true);
    expect(trimmed.metadata.output_truncated).toBe(true);
    expect(trimmed.metadata.output_total_nodes).toBe(1 + 50 + 50 * 20);
    expect(sidedTrimMetadata('from', trimmed.metadata).from_output_truncated).toBe(true);
    expect(sidedTrimMetadata('from', trimmed.metadata).from_output_total_nodes).toBe(
      trimmed.metadata.output_total_nodes
    );
  });

  it('digests the complete stableStringify service hash as a compact SHA-256', () => {
    const serviceHash = hashPolicyConfig(normalize(policyFactory()));
    const digest = toPresentationHash(serviceHash);
    expect(digest).toBe(createHash('sha256').update(serviceHash).digest('hex'));
    expect(digest).toHaveLength(64);
    expect(digest).not.toBe(serviceHash);
    expect(toPresentationHash(serviceHash)).toBe(digest);
    expect(toPresentationHash(`${serviceHash}x`)).not.toBe(digest);
  });

  it('estimates the exact guarded envelope and omits trailing items with totals', () => {
    const dto = omitTrailingToFit(
      (keep) => ({
        items: Array.from({ length: keep }, (_, index) => ({
          id: `row-${index}`,
          pad: 'N'.repeat(200),
        })),
        items_total: 8,
        items_truncated: keep < 8,
      }),
      8,
      200
    );
    const envelope = JSON.stringify({ results: [createOtherResult(dto)] });
    expect(estimateGuardedEnvelopeTokens(dto)).toBe(estimateTokens(envelope));
    expect(estimateGuardedEnvelopeTokens(dto)).toBeLessThanOrEqual(
      200 - GUARDED_ENVELOPE_HEADROOM_TOKENS
    );
    expect(dto.items_total).toBe(8);
    expect(dto.items_truncated).toBe(true);
    expect(dto.items.length).toBeGreaterThan(0);
    expect(dto.items.length).toBeLessThan(8);
  });

  it('caps every constructible identity string and sets adjacent truncation flags', () => {
    const presented = presentBoundedIdentityStrings({
      id: 'I'.repeat(600),
      name: 'N'.repeat(600),
      description: 'D'.repeat(600),
      revision: 9,
      version: 'V'.repeat(600),
      updatedAt: 'A'.repeat(600),
      updatedBy: 'B'.repeat(600),
      packageVersion: 'P'.repeat(600),
    });

    expect(presented).toEqual(
      expect.objectContaining({
        id: 'I'.repeat(512),
        id_string_truncated: true,
        name: 'N'.repeat(512),
        name_string_truncated: true,
        description: 'D'.repeat(512),
        description_string_truncated: true,
        revision: 9,
        version: 'V'.repeat(512),
        version_string_truncated: true,
        updatedAt: 'A'.repeat(512),
        updatedBy: 'B'.repeat(512),
        packageVersion: 'P'.repeat(512),
      })
    );
    expect(presented).toHaveProperty('updatedAt_string_truncated', true);
    expect(presented).toHaveProperty('updatedBy_string_truncated', true);
    expect(presented).toHaveProperty('packageVersion_string_truncated', true);
  });

  it('leaves short identity strings unflagged and omits absent optional fields', () => {
    const identity = {
      id: 'policy-1',
      name: 'Endpoint Policy',
      description: 'visible description',
      revision: 3,
      version: 'WzEsMV0=',
    };

    expect(presentBoundedIdentityStrings(identity)).toEqual(identity);
    expect(presentBoundedIdentityStrings(identity)).not.toHaveProperty('id_string_truncated');
    expect(presentBoundedIdentityStrings(identity)).not.toHaveProperty('updatedAt');
    expect(presentBoundedIdentityStrings(identity)).not.toHaveProperty(
      'updatedBy_string_truncated'
    );
  });

  it('returns undefined from tryOmitTrailingToFit when even keep=0 overflows', () => {
    const oversized = { pad: 'X'.repeat(4_000) };
    expect(tryOmitTrailingToFit(() => oversized, 3, 200)).toBeUndefined();
  });

  it('does not return an over-budget last attempt from omitTrailingToFit', () => {
    const oversized = { pad: 'X'.repeat(4_000) };
    const skeleton = { ok: true, value_total: 8, value_truncated: true };
    const dto = omitTrailingToFit(
      () => oversized,
      3,
      200,
      () => skeleton
    );

    expect(dto).toEqual(skeleton);
    expect(fitsGuardedEnvelope(dto, 200)).toBe(true);
    expect(() => omitTrailingToFit(() => oversized, 0, 200)).toThrow(
      'Policy tool result exceeded the guarded token envelope'
    );
  });

  it('does not return an over-budget last attempt from presentWithinGuardedBudget', () => {
    const oversized = { pad: 'X'.repeat(4_000) };
    const skeleton = { ok: true };
    const dto = presentWithinGuardedBudget(
      () => oversized,
      200,
      () => skeleton
    );

    expect(dto).toEqual(skeleton);
    expect(fitsGuardedEnvelope(dto, 200)).toBe(true);
    expect(
      presentWithinGuardedBudget(
        () => ({ ok: true }),
        200,
        () => skeleton
      )
    ).toEqual({
      ok: true,
    });
    expect(() =>
      presentWithinGuardedBudget(
        () => oversized,
        200,
        () => oversized
      )
    ).toThrow('Policy tool result exceeded the guarded token envelope');
  });
});
