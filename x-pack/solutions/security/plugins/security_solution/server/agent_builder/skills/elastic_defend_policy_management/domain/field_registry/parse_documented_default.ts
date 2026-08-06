/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { EN_LOCALE, i18n } from '@kbn/i18n';

import type { PolicyFieldValueType } from './types';
import type { AdvancedPolicySchemaType } from '../../../../../../common/endpoint/service/policy/field_registry/advanced_policy_schema';

export type UnparseableDefaultReason =
  | 'no_default_statement'
  | 'prose_default_only'
  | 'value_absent'
  | 'value_not_scalar'
  | 'version_conditional_unresolved'
  | 'documentation_not_english_source';

export interface VersionConditionalBranch {
  readonly boundary: string;
  readonly direction: 'earlier' | 'later';
  readonly value: boolean | number | string;
  readonly type: Extract<PolicyFieldValueType, 'boolean' | 'number' | 'string'>;
}

export type ParsedDocumentedDefault =
  | {
      readonly status: 'parsed';
      readonly value: boolean | number | string;
      readonly type: Extract<PolicyFieldValueType, 'boolean' | 'number' | 'string'>;
    }
  | {
      readonly status: 'version_conditional';
      readonly branches: readonly VersionConditionalBranch[];
    }
  | { readonly status: 'unparseable'; readonly reason: UnparseableDefaultReason };

const VERSION_CONDITIONAL_CLAUSE =
  /\bfor\s+(\d+(?:\.\d+)*)\s+and\s+(earlier|later)\s*,\s*default\s*:?\s*([^.]+?)\s*\./gi;

const EXPLICIT_DEFAULT_STATEMENT = /\bDefault\s*:?\s+(.+)$/;

const PROSE_DEFAULT_PHRASE = /\bby\s+default\b/i;

const NUMBER_WITH_GLOSS = /^(-?\d+(?:\.\d+)?)\s*\([^)]*\)$/;

const INTEGER_OR_DECIMAL = /^-?\d+(?:\.\d+)?$/;

const CONTAINS_WHITESPACE = /\s/;

const LEADING_QUOTES = /^[`'"]+/;
const TRAILING_QUOTES = /[`'"]+$/;

const stripValueDecoration = (raw: string): string => {
  let value = raw.trim();

  if (value.endsWith('.')) {
    value = value.slice(0, -1).trim();
  }

  return value.replace(LEADING_QUOTES, '').replace(TRAILING_QUOTES, '').trim();
};

type ScalarOutcome =
  | {
      readonly status: 'scalar';
      readonly value: boolean | number | string;
      readonly type: Extract<PolicyFieldValueType, 'boolean' | 'number' | 'string'>;
    }
  | { readonly status: 'rejected'; readonly reason: 'value_absent' | 'value_not_scalar' };

const toScalar = (raw: string): ScalarOutcome => {
  const value = stripValueDecoration(raw);

  if (value.length === 0) {
    return { status: 'rejected', reason: 'value_not_scalar' };
  }

  const lowercased = value.toLowerCase();

  if (lowercased === 'true') {
    return { status: 'scalar', value: true, type: 'boolean' };
  }

  if (lowercased === 'false') {
    return { status: 'scalar', value: false, type: 'boolean' };
  }

  if (INTEGER_OR_DECIMAL.test(value)) {
    return { status: 'scalar', value: Number(value), type: 'number' };
  }

  const glossed = value.match(NUMBER_WITH_GLOSS);

  if (glossed !== null) {
    return { status: 'scalar', value: Number(glossed[1]), type: 'number' };
  }

  if (lowercased === 'none') {
    return { status: 'rejected', reason: 'value_absent' };
  }

  if (CONTAINS_WHITESPACE.test(value)) {
    return { status: 'rejected', reason: 'value_not_scalar' };
  }

  return { status: 'scalar', value, type: 'string' };
};

export const parseDocumentedDefault = (
  entry: Pick<AdvancedPolicySchemaType, 'documentation'>
): ParsedDocumentedDefault => {
  const { documentation } = entry;

  VERSION_CONDITIONAL_CLAUSE.lastIndex = 0;
  const conditionalClauses = [...documentation.matchAll(VERSION_CONDITIONAL_CLAUSE)];

  if (conditionalClauses.length > 0) {
    const branches: VersionConditionalBranch[] = [];

    for (const [, boundary, direction, rawValue] of conditionalClauses) {
      const scalar = toScalar(rawValue);

      if (scalar.status !== 'scalar') {
        return { status: 'unparseable', reason: 'version_conditional_unresolved' };
      }

      branches.push({
        boundary,
        direction: direction.toLowerCase() === 'earlier' ? 'earlier' : 'later',
        value: scalar.value,
        type: scalar.type,
      });
    }

    const isExhaustivePair =
      branches.length === 2 &&
      branches[0].direction === 'earlier' &&
      branches[1].direction === 'later';

    if (!isExhaustivePair) {
      return { status: 'unparseable', reason: 'version_conditional_unresolved' };
    }

    return { status: 'version_conditional', branches };
  }

  const statement = documentation.match(EXPLICIT_DEFAULT_STATEMENT);

  if (statement === null) {
    if (i18n.getLocale().toLowerCase().split('-')[0] !== EN_LOCALE) {
      return { status: 'unparseable', reason: 'documentation_not_english_source' };
    }

    return {
      status: 'unparseable',
      reason: PROSE_DEFAULT_PHRASE.test(documentation)
        ? 'prose_default_only'
        : 'no_default_statement',
    };
  }

  const scalar = toScalar(statement[1]);

  if (scalar.status !== 'scalar') {
    return { status: 'unparseable', reason: scalar.reason };
  }

  return { status: 'parsed', value: scalar.value, type: scalar.type };
};
