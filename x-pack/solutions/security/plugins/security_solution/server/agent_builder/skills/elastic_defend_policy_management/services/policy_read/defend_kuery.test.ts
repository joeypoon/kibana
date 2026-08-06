/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { escapeRegExp } from 'lodash';
import { fromKueryExpression, toElasticsearchQuery } from '@kbn/es-query';
import { PACKAGE_POLICY_SAVED_OBJECT_TYPE } from '@kbn/fleet-plugin/common';
import { buildDefendKuery, normalizePolicySearch, POLICY_SEARCH_MAX_LENGTH } from './defend_kuery';

const PACKAGE_CLAUSE = `${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.package.name: "endpoint"`;

const collectQueryStringPatterns = (query: unknown): string[] => {
  if (Array.isArray(query)) {
    return query.flatMap(collectQueryStringPatterns);
  }

  if (typeof query !== 'object' || query === null) {
    return [];
  }

  return Object.entries(query as Record<string, unknown>).flatMap(([key, value]) => {
    if (key === 'query_string') {
      return [String((value as { query?: unknown }).query)];
    }

    return collectQueryStringPatterns(value);
  });
};

const compile = (search?: string): unknown =>
  toElasticsearchQuery(fromKueryExpression(buildDefendKuery(search)));

const matchesCompiled = (query: unknown, document: Record<string, unknown>): boolean => {
  if (typeof query !== 'object' || query === null) {
    return true;
  }

  const [clause, body] = Object.entries(query)[0] as [string, unknown];

  if (clause === 'bool') {
    const fields = body as Record<string, unknown>;
    const branch = (name: string): unknown[] => {
      const value = fields[name];
      if (value === undefined) {
        return [];
      }
      return Array.isArray(value) ? value : [value];
    };

    return (
      branch('filter').every((sub) => matchesCompiled(sub, document)) &&
      branch('must').every((sub) => matchesCompiled(sub, document)) &&
      !branch('must_not').some((sub) => matchesCompiled(sub, document)) &&
      (branch('should').length === 0 ||
        branch('should').some((sub) => matchesCompiled(sub, document)))
    );
  }

  if (clause === 'match' || clause === 'match_phrase' || clause === 'term') {
    const [field, expected] = Object.entries(body as Record<string, unknown>)[0];
    const wanted =
      typeof expected === 'object' && expected !== null && 'value' in expected
        ? (expected as { value: unknown }).value
        : expected;

    return document[field] !== undefined && document[field] === wanted;
  }

  if (clause === 'query_string') {
    const { fields, query: pattern } = body as { fields?: string[]; query?: unknown };
    const matcher = new RegExp(
      `^${String(pattern ?? '')
        .split('*')
        .map(escapeRegExp)
        .join('.*')}$`,
      'i'
    );

    return (fields ?? []).some((field) => {
      const actual = document[field];
      return typeof actual === 'string' && matcher.test(actual);
    });
  }

  throw new Error(`matchesCompiled(): unsupported clause [${clause}]`);
};

const policyDocument = (name: string): Record<string, unknown> => ({
  [`${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.package.name`]: 'endpoint',
  [`${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name`]: name,
});

describe('buildDefendKuery', () => {
  it('filters to the Elastic Defend package only when no search is supplied', () => {
    expect(buildDefendKuery()).toBe(PACKAGE_CLAUSE);
  });

  it('joins the package clause and every name token with AND', () => {
    const kuery = buildDefendKuery('Prod Windows');

    expect(kuery).toBe(
      `${PACKAGE_CLAUSE} AND ${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name: *Prod* AND ${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name: *Windows*`
    );
  });

  it('escapes KQL metacharacters in the caller input so they stay literal', () => {
    const patterns = collectQueryStringPatterns(compile('prod: "eu"'));

    expect(patterns[0]).toContain('*prod');
    expect(patterns.join(' ')).toContain('\\:');
    expect(patterns.join(' ')).toContain('\\"');
  });

  it('ANDs one wildcard clause per whitespace-separated token so a multi-word name still matches', () => {
    const compiled = compile('Prod Windows Servers');

    expect(collectQueryStringPatterns(compiled)).toEqual(['*Prod*', '*Windows*', '*Servers*']);
    expect(collectQueryStringPatterns(compiled)).not.toContain('*Prod Windows Servers*');

    expect(matchesCompiled(compiled, policyDocument('Prod Windows Servers'))).toBe(true);
    expect(matchesCompiled(compiled, policyDocument('Prod Linux Servers'))).toBe(false);
    expect(matchesCompiled(compiled, policyDocument('Servers for Windows - Prod'))).toBe(true);
  });

  it('collapses runs of whitespace instead of emitting an empty wildcard clause', () => {
    expect(collectQueryStringPatterns(compile('  spaced   out  '))).toEqual(['*spaced*', '*out*']);
  });

  it('treats a whitespace-only search as no search at all', () => {
    expect(buildDefendKuery('   ')).toBe(PACKAGE_CLAUSE);
  });

  it('normalizes whitespace-only and empty-after-trim search to absent', () => {
    expect(normalizePolicySearch(undefined)).toBeUndefined();
    expect(normalizePolicySearch('   ')).toBeUndefined();
    expect(normalizePolicySearch('\n\t')).toBeUndefined();
    expect(normalizePolicySearch('  Prod  ')).toBe('Prod');
  });

  it('bounds the search before tokenizing so a long term cannot smuggle extra clauses', () => {
    const kuery = buildDefendKuery(`${'a'.repeat(300)} tail`);

    expect(kuery).toContain(`*${'a'.repeat(POLICY_SEARCH_MAX_LENGTH)}*`);
    expect(kuery).not.toContain('tail');
  });

  it('matches only Defend package policies', () => {
    const compiled = compile();

    expect(matchesCompiled(compiled, policyDocument('anything'))).toBe(true);
    expect(
      matchesCompiled(compiled, {
        [`${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.package.name`]: 'nginx',
        [`${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name`]: 'anything',
      })
    ).toBe(false);
  });
});
