/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  PartialResultDisclosure,
  PolicyReadPrivilegeBasis,
  ScopeDisclosure,
} from '../../domain/read/types';

export interface BuildScopeDisclosureOptions {
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
  readonly returned: number;
  readonly total: number;
  readonly enforcedSpaceId?: string;
  readonly partial?: PartialResultDisclosure;
}

export const buildScopeDisclosure = ({
  privilegeBasis,
  returned,
  total,
  enforcedSpaceId,
  partial,
}: BuildScopeDisclosureOptions): ScopeDisclosure => ({
  privilegeBasis,
  returned,
  total,
  ...(enforcedSpaceId ? { spaceId: enforcedSpaceId } : {}),
  ...(partial ? { partial } : {}),
});

export interface DescribeScopeOptions {
  readonly searchActive?: boolean;
}

export const describeScope = (
  { returned, total, partial }: ScopeDisclosure,
  { searchActive = false }: DescribeScopeOptions = {}
): string => {
  const countSentence = searchActive
    ? `Showing ${returned} of ${total} Elastic Defend policies you can access that match the name filter. Omit \`search\` to cover every accessible policy.`
    : `Showing ${returned} of ${total} Elastic Defend policies you can access.`;

  return partial ? `${countSentence} ${partial.detail} ${partial.continuation}` : countSentence;
};

export const createFleetAgentsPrivilegeDisclosure = (): PartialResultDisclosure => ({
  reason: 'missing_privilege',
  detail:
    'Agent assignment counts were not included because you do not have permission to read Fleet agents.',
  continuation:
    'Ask an administrator for Fleet agent read access, then run this again to include agent counts.',
});

export const createResultLimitDisclosure = ({
  returned,
  total,
}: Pick<ScopeDisclosure, 'returned' | 'total'>): PartialResultDisclosure => ({
  reason: 'result_limit_reached',
  detail:
    `The read stopped at this feature's interactive work limit after examining ${total} Elastic ` +
    `Defend policies; ${returned} of them are in this result, and more policies may match your ` +
    `request.`,
  continuation: 'Narrow the request with `search` and run again so the rest are covered.',
});

export const createUpstreamFailureDisclosure = (
  operation: string,
  returned: number
): PartialResultDisclosure => ({
  reason: 'upstream_failure',
  detail: `Retrieving Elastic Defend policies failed part-way through (${operation}) after ${returned} policies.`,
  continuation: 'Run this again; if it keeps failing, an administrator should check Fleet.',
});

export const createRegistryCoverageDisclosure = (
  registryGapVersions: readonly string[],
  excluded: number
): PartialResultDisclosure => ({
  reason: 'upstream_failure',
  detail: `${excluded} Elastic Defend ${
    excluded === 1 ? 'policy was' : 'policies were'
  } left out because this feature has no policy field definitions for package ${
    registryGapVersions.length === 1 ? 'version' : 'versions'
  } ${registryGapVersions.join(', ')}.`,
  continuation:
    'The remaining policies are unaffected. Report the package version above so support for it can be added.',
});
