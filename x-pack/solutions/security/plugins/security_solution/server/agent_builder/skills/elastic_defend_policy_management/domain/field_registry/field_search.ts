/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  POLICY_EVENT_COLLECTION_LABELS,
  POLICY_PROTECTION_UPDATES_LABEL,
} from '../../../../../../common/endpoint/models/policy_settings_ui_labels';
import { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import { getFieldRegistry, getFieldRegistryEntry } from './derive_field_registry';
import {
  describePathWritability,
  type PathNotWritableReason,
  type PathWritability,
} from './path_writability';

const RESULT_LIMIT = 10;

const STOPWORDS = new Set([
  'a',
  'an',
  'and',
  'the',
  'of',
  'on',
  'in',
  'to',
  'for',
  'setting',
  'settings',
  'policy',
  'enable',
  'disable',
  'turn',
]);

const OS_QUERY_WORDS: Readonly<Record<string, PolicyOperatingSystem>> = {
  windows: PolicyOperatingSystem.windows,
  mac: PolicyOperatingSystem.mac,
  macos: PolicyOperatingSystem.mac,
  linux: PolicyOperatingSystem.linux,
};

const POLICY_OPERATING_SYSTEMS: ReadonlySet<string> = new Set(Object.values(PolicyOperatingSystem));

const EVENT_COLLECTION_OSES = ['windows', 'mac', 'linux'] as const;

export type PolicyFieldSearchHit = {
  readonly path: string;
  readonly os: readonly PolicyOperatingSystem[];
  readonly label?: string;
  readonly matchedTerms: readonly string[];
  readonly score: number;
} & (
  | { readonly writable: true }
  | { readonly writable: false; readonly not_writable_reason: PathNotWritableReason }
);

export interface PolicyFieldSearchResult {
  readonly found: boolean;
  readonly match: 'search';
  readonly query: string;
  readonly osFilter?: readonly PolicyOperatingSystem[];
  readonly results: readonly PolicyFieldSearchHit[];
  readonly results_total: number;
  readonly results_truncated: boolean;
  readonly candidates_truncated: boolean;
}

interface IndexedPolicyField {
  readonly path: string;
  readonly os: readonly PolicyOperatingSystem[];
  readonly order: number;
  readonly label?: string;
  readonly tokens: ReadonlySet<string>;
  readonly labelTokens: ReadonlySet<string>;
}

interface ScoredField {
  readonly path: string;
  readonly os: readonly PolicyOperatingSystem[];
  readonly order: number;
  readonly label?: string;
  readonly matchedTerms: readonly string[];
  readonly score: number;
  readonly writability: PathWritability;
  readonly labelMatch: boolean;
}

interface TokenizedQuery {
  readonly osFilter: readonly PolicyOperatingSystem[];
  readonly tokens: readonly string[];
}

const isPolicyOperatingSystem = (value: string): value is PolicyOperatingSystem =>
  POLICY_OPERATING_SYSTEMS.has(value);

const splitTokens = (value: string): readonly string[] =>
  value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 0);

const stemToken = (token: string): string =>
  token.length > 3 && token.endsWith('s') ? token.slice(0, -1) : token;

const tokenize = (value: string): readonly string[] => {
  const tokens: string[] = [];
  const seen = new Set<string>();
  for (const raw of splitTokens(value)) {
    const token = stemToken(raw);
    if (!STOPWORDS.has(raw) && !STOPWORDS.has(token) && !seen.has(token)) {
      seen.add(token);
      tokens.push(token);
    }
  }
  return tokens;
};

const tokenizeQuery = (query: string): TokenizedQuery => {
  const osFilter: PolicyOperatingSystem[] = [];
  const seenOs = new Set<PolicyOperatingSystem>();
  const scoringWords: string[] = [];
  for (const raw of splitTokens(query)) {
    const os = OS_QUERY_WORDS[raw];
    if (os !== undefined) {
      if (!seenOs.has(os)) {
        seenOs.add(os);
        osFilter.push(os);
      }
    } else {
      scoringWords.push(raw);
    }
  }
  return { osFilter, tokens: tokenize(scoringWords.join(' ')) };
};

const scoringTextForPath = (path: string): string => {
  const [first, ...rest] = path.split('.');
  if (first !== undefined && rest.length > 0 && isPolicyOperatingSystem(first)) {
    return rest.join('.');
  }
  return path;
};

const requireLabelRegistryEntry = (path: string): void => {
  if (getFieldRegistryEntry(path) === undefined) {
    throw new Error(`Policy settings UI label has no registry entry: ${path}`);
  }
};

const sharedLabelsByPath = (): ReadonlyMap<string, string> => {
  const labels = new Map<string, string>();
  for (const os of EVENT_COLLECTION_OSES) {
    for (const { field, label } of POLICY_EVENT_COLLECTION_LABELS[os]) {
      const path = `${os}.events.${field}`;
      requireLabelRegistryEntry(path);
      labels.set(path, label);
    }
  }
  requireLabelRegistryEntry(POLICY_PROTECTION_UPDATES_LABEL.path);
  labels.set(POLICY_PROTECTION_UPDATES_LABEL.path, POLICY_PROTECTION_UPDATES_LABEL.label);
  return labels;
};

const buildSearchIndex = (): readonly IndexedPolicyField[] => {
  const labels = sharedLabelsByPath();
  return getFieldRegistry().map((entry, order) => {
    const label = labels.get(entry.path);
    const labelTokens = new Set(label === undefined ? [] : tokenize(label));
    return {
      path: entry.path,
      os: [...entry.os],
      order,
      ...(label !== undefined ? { label } : {}),
      tokens: new Set([...tokenize(scoringTextForPath(entry.path)), ...labelTokens]),
      labelTokens,
    };
  });
};

const SEARCH_INDEX = buildSearchIndex();

const entryMatchesOsFilter = (
  os: readonly PolicyOperatingSystem[],
  osFilter: readonly PolicyOperatingSystem[]
): boolean =>
  osFilter.length === 0 || os.length === 0 || os.some((entryOs) => osFilter.includes(entryOs));

const compareScoredFields = (left: ScoredField, right: ScoredField): number => {
  if (left.score !== right.score) {
    return right.score - left.score;
  }
  if (left.writability.writable !== right.writability.writable) {
    return left.writability.writable ? -1 : 1;
  }
  if (left.labelMatch !== right.labelMatch) {
    return left.labelMatch ? -1 : 1;
  }
  return left.order - right.order;
};

const toSearchHit = (scored: ScoredField): PolicyFieldSearchHit => {
  const described = {
    path: scored.path,
    os: scored.os,
    ...(scored.label !== undefined ? { label: scored.label } : {}),
    matchedTerms: scored.matchedTerms,
    score: scored.score,
  };
  if (scored.writability.writable) {
    return { ...described, writable: true };
  }
  return {
    ...described,
    writable: false,
    not_writable_reason: scored.writability.reason,
  };
};

const scoreIndexedField = (
  indexed: IndexedPolicyField,
  tokens: readonly string[]
): ScoredField | undefined => {
  const matchedTerms = tokens.filter((token) => indexed.tokens.has(token));
  if (matchedTerms.length === 0) {
    return undefined;
  }
  return {
    path: indexed.path,
    os: indexed.os,
    order: indexed.order,
    ...(indexed.label !== undefined ? { label: indexed.label } : {}),
    matchedTerms,
    score: matchedTerms.length,
    writability: describePathWritability(indexed.path),
    labelMatch: matchedTerms.some((term) => indexed.labelTokens.has(term)),
  };
};

export const searchPolicyFields = (query: string): PolicyFieldSearchResult => {
  const { osFilter, tokens } = tokenizeQuery(query);
  const matches: ScoredField[] = [];
  for (const indexed of SEARCH_INDEX) {
    if (entryMatchesOsFilter(indexed.os, osFilter)) {
      const scored = scoreIndexedField(indexed, tokens);
      if (scored !== undefined) {
        matches.push(scored);
      }
    }
  }
  matches.sort(compareScoredFields);

  let topWritableScore: number | undefined;
  for (const match of matches) {
    if (
      match.writability.writable &&
      (topWritableScore === undefined || match.score > topWritableScore)
    ) {
      topWritableScore = match.score;
    }
  }

  const returned = matches.slice(0, RESULT_LIMIT);
  const returnedPaths = new Set(returned.map((match) => match.path));
  const candidatesTruncated = matches.some(
    (match) =>
      match.writability.writable &&
      match.score === topWritableScore &&
      !returnedPaths.has(match.path)
  );

  return {
    found: matches.length > 0,
    match: 'search',
    query,
    ...(osFilter.length > 0 ? { osFilter } : {}),
    results: returned.map(toSearchHit),
    results_total: matches.length,
    results_truncated: matches.length > returned.length,
    candidates_truncated: candidatesTruncated,
  };
};
