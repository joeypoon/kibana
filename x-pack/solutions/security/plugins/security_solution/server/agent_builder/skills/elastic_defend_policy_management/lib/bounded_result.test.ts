/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  RESULT_TOKEN_BUDGET,
  TOOL_RESULT_TOKEN_BUDGET,
  TOOL_RESULT_TOKEN_SAFETY_FACTOR,
  boundList,
  buildResultBudgetNotice,
  estimateResultTokens,
  estimateWrappedHandlerTokens,
  isWithinPlatformBudget,
  isWithinResultBudget,
  truncateBoundedString,
  truncateBoundedValue,
} from './bounded_result';

describe('estimateResultTokens', () => {
  it('grows with the serialized size, which is what the platform measures', () => {
    expect(estimateResultTokens({ a: 'x'.repeat(400) })).toBeGreaterThan(
      estimateResultTokens({ a: 'x' })
    );
  });

  it('counts a value that serializes to nothing as zero rather than crashing', () => {
    expect(estimateResultTokens(undefined)).toBe(0);
    expect(estimateResultTokens(() => undefined)).toBe(0);
  });
});

describe('boundList', () => {
  const options = {
    itemLabel: 'policies',
    continuation: 'Narrow the request to see the rest.',
  };

  it('returns everything, with no notice, when the whole list fits', () => {
    const bounded = boundList({ items: [1, 2, 3], maxItems: 10, ...options });

    expect(bounded.items).toEqual([1, 2, 3]);
    expect(bounded.returned).toBe(3);
    expect(bounded.total).toBe(3);
    expect(bounded.truncated).toBe(false);
    expect(bounded.truncationNotice).toBeUndefined();
  });

  it('trims to the item ceiling and discloses the real total', () => {
    const bounded = boundList({
      items: Array.from({ length: 50 }, (_, index) => index),
      maxItems: 10,
      ...options,
    });

    expect(bounded.returned).toBe(10);
    expect(bounded.total).toBe(50);
    expect(bounded.truncated).toBe(true);
    expect(bounded.truncationNotice).toContain('Showing 10 of 50 policies');
    expect(bounded.truncationNotice).toContain('40 were left out');
    expect(bounded.truncationNotice).toContain(options.continuation);
  });

  it('trims on the token budget when items are individually large', () => {
    const bounded = boundList({
      items: Array.from({ length: 100 }, () => ({ blob: 'x'.repeat(4000) })),
      maxItems: 1000,
      tokenBudget: 5000,
      ...options,
    });

    expect(bounded.returned).toBeLessThan(100);
    expect(bounded.truncated).toBe(true);
    expect(estimateResultTokens(bounded.items)).toBeLessThanOrEqual(6000);
  });

  it('charges the result envelope against the budget so items are measured against what is left', () => {
    const items = Array.from({ length: 10 }, () => ({ blob: 'x'.repeat(400) }));
    const shared = { items, maxItems: 1000, tokenBudget: 1200, ...options };

    const withoutEnvelope = boundList(shared);
    const withEnvelope = boundList({ ...shared, envelopeTokens: 800 });

    expect(withoutEnvelope.truncated).toBe(false);
    expect(withoutEnvelope.returned).toBe(10);

    expect(withEnvelope.truncated).toBe(true);
    expect(withEnvelope.returned).toBeLessThan(10);
    expect(estimateResultTokens(withEnvelope.items) + 800).toBeLessThanOrEqual(1200);
    expect(withEnvelope.truncationNotice).toContain(`of 10 ${options.itemLabel}`);
  });

  it('still discloses the trim when the envelope alone exceeds the budget, without a false empty estate', () => {
    const bounded = boundList({
      items: [{ blob: 'x'.repeat(400) }, { blob: 'y'.repeat(400) }],
      maxItems: 1000,
      tokenBudget: 100,
      envelopeTokens: 5000,
      ...options,
    });

    expect(bounded.returned).toBe(0);
    expect(bounded.truncated).toBe(true);
    expect(bounded.total).toBe(2);
    expect(bounded.truncationNotice).toContain('not an empty estate');
    expect(bounded.truncationNotice).toContain('of 2');
  });

  it('trims a large input and discloses its full total', () => {
    const bounded = boundList({
      items: Array.from({ length: 900 }, (_, index) => index),
      maxItems: 2,
      ...options,
    });

    expect(bounded.returned).toBe(2);
    expect(bounded.total).toBe(900);
    expect(bounded.truncated).toBe(true);
    expect(bounded.truncationNotice).toContain('Showing 2 of 900');
  });

  it('uses the input length as the total when nothing is trimmed', () => {
    const bounded = boundList({ items: [1, 2], maxItems: 10, ...options });

    expect(bounded.total).toBe(2);
    expect(bounded.truncated).toBe(false);
  });

  it('omits a first item that still exceeds the budget and states that the item exists', () => {
    const bounded = boundList({
      items: [{ blob: 'x'.repeat(100_000) }, { blob: 'y' }],
      maxItems: 10,
      tokenBudget: 10,
      ...options,
    });

    expect(bounded.returned).toBe(0);
    expect(bounded.items).toEqual([]);
    expect(bounded.total).toBe(2);
    expect(bounded.truncated).toBe(true);
    expect(bounded.truncationNotice).toContain('not an empty estate');
    expect(bounded.truncationNotice).toContain('2 exist');
  });

  it('handles an empty list without claiming a truncation', () => {
    const bounded = boundList({ items: [], maxItems: 10, ...options });

    expect(bounded.items).toEqual([]);
    expect(bounded.total).toBe(0);
    expect(bounded.truncated).toBe(false);
    expect(bounded.truncationNotice).toBeUndefined();
  });

  it('states that omitted items are not absent from the deployment', () => {
    const bounded = boundList({
      items: Array.from({ length: 99 }, (_, index) => index),
      maxItems: 2,
      ...options,
    });

    expect(bounded.truncationNotice).toContain('not absent from your deployment');
  });
});

describe('result budget', () => {
  it('leaves headroom under the platform limit rather than spending all of it', () => {
    expect(TOOL_RESULT_TOKEN_BUDGET).toBe(20_000);
    expect(TOOL_RESULT_TOKEN_SAFETY_FACTOR).toBeLessThan(1);
    expect(RESULT_TOKEN_BUDGET).toBeLessThan(TOOL_RESULT_TOKEN_BUDGET);
    expect(RESULT_TOKEN_BUDGET).toBeGreaterThan(12_000);
  });

  it('reports whether an assembled payload fits', () => {
    expect(isWithinResultBudget({ small: true })).toBe(true);
    expect(isWithinResultBudget({ big: 'x'.repeat(200_000) })).toBe(false);
  });

  it('states the wrapped estimate and the platform bound, and steers the reader to the totals', () => {
    const notice = buildResultBudgetNotice({ estimatedTokens: 134_943 });

    expect(notice).toContain('134943');
    expect(notice).toContain(String(TOOL_RESULT_TOKEN_BUDGET));
    expect(notice).toContain('wrapped tokens');
    expect(notice).toContain('states its own total');
    expect(notice).toContain('Nothing was removed');
  });
});

describe('wrapped handler estimate', () => {
  it('counts the createOtherResult envelope, not only the inner data', () => {
    const data = { applied: false, message: 'ok' };

    expect(estimateWrappedHandlerTokens(data)).toBeGreaterThan(estimateResultTokens(data));
  });

  it('treats the platform 20k budget as the wrap limit', () => {
    expect(isWithinPlatformBudget({ small: true })).toBe(true);
    expect(isWithinPlatformBudget({ big: 'x'.repeat(200_000) })).toBe(false);
  });
});

describe('truncateBoundedString', () => {
  it('leaves a short string unchanged', () => {
    expect(truncateBoundedString('hello', 128)).toBe('hello');
  });

  it('marks the original length when it truncates', () => {
    const truncated = truncateBoundedString('y'.repeat(80_000), 64);

    expect(truncated.length).toBeLessThanOrEqual(64);
    expect(truncated).toContain('truncated');
    expect(truncated).toContain('80000');
  });

  it('leaves non-string values untouched', () => {
    expect(truncateBoundedValue(true, 8)).toBe(true);
    expect(truncateBoundedValue(12, 8)).toBe(12);
    expect(truncateBoundedValue(null, 8)).toBeNull();
  });
});
