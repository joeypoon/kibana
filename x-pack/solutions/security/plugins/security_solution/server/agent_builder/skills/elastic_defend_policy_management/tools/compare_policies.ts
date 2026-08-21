/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import { z } from '@kbn/zod/v4';
import type { StartServicesAccessor } from '@kbn/core/server';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import { diffPolicyConfig } from '../domain/diff';
import type { NormalizedPolicyConfig } from '../domain/normalized_policy_config';
import type { HasAtLeast } from '../services/access_context';
import { getEndpointPolicy } from '../services/read_policy';
import { createPolicyTool } from './create_policy_tool';
import type { PresentedPolicyIdentity, TrimLimits } from './trim_policy_result';
import {
  DEFAULT_TRIM_LIMITS,
  omitTrailingToFit,
  parentTrimMetadata,
  presentBoundedIdentityStrings,
  presentWithinGuardedBudget,
  sidedTrimMetadata,
  toPresentationHash,
  trimPolicyResultWithMeta,
} from './trim_policy_result';

export const COMPARE_POLICIES_TOOL_ID = 'security.policy_management.compare_policies';

const IDENTIFIER_MAX_LENGTH = 256;
const COMPARE_DIFF_DISPLAY_CAP = 50;
const COMPARE_POLICIES_MAX_RESULT_TOKENS = 12_000;

export type PolicyComparisonRef = Readonly<{ type: 'policy'; idOrName: string }>;

export const policyComparisonRefSchema = z.object({
  type: z.literal('policy'),
  idOrName: z
    .string()
    .trim()
    .min(1)
    .max(IDENTIFIER_MAX_LENGTH)
    .describe('Saved-object id or exact endpoint policy name in the current space.'),
});

export const comparePoliciesSchema = z.object({
  left: policyComparisonRefSchema.describe('Left comparison side: a live policy.'),
  right: policyComparisonRefSchema.describe('Right comparison side: a live policy.'),
});

type PresentedComparisonSide = Readonly<{
  type: 'policy';
  policy: PresentedPolicyIdentity;
  normalizedHash: string;
}>;

type ResolvedComparisonSide = Readonly<{
  presented: PresentedComparisonSide;
  normalizedConfig: NormalizedPolicyConfig;
}>;

const resolveComparisonSide = async (
  ref: PolicyComparisonRef,
  access: HasAtLeast<'policy_read'>
): Promise<ResolvedComparisonSide> => {
  const { policy, normalizedConfig, normalizedHash } = await getEndpointPolicy(access, {
    idOrName: ref.idOrName,
  });

  return {
    presented: { type: 'policy', policy, normalizedHash },
    normalizedConfig,
  };
};

const presentComparisonSide = (presented: PresentedComparisonSide): PresentedComparisonSide => ({
  ...presented,
  policy: presentBoundedIdentityStrings(presented.policy),
  normalizedHash: toPresentationHash(presented.normalizedHash),
});

const presentDiffEntry = (
  entry: Readonly<{ path: string; from: unknown; to: unknown }>,
  limits: TrimLimits
): Record<string, unknown> => {
  const fromTrim = trimPolicyResultWithMeta(entry.from, limits);
  const toTrim = trimPolicyResultWithMeta(entry.to, limits);
  return {
    path: entry.path,
    from: fromTrim.value,
    to: toTrim.value,
    ...sidedTrimMetadata('from', parentTrimMetadata(fromTrim.value, fromTrim.metadata)),
    ...sidedTrimMetadata('to', parentTrimMetadata(toTrim.value, toTrim.metadata)),
  };
};

const presentComparePolicies = (
  left: PresentedComparisonSide,
  right: PresentedComparisonSide,
  fullDiff: readonly Readonly<{ path: string; from: unknown; to: unknown }>[]
): Record<string, unknown> => {
  const presentedLeft = presentComparisonSide(left);
  const presentedRight = presentComparisonSide(right);
  const capped = fullDiff.slice(0, COMPARE_DIFF_DISPLAY_CAP);

  const buildSkeleton = (): Record<string, unknown> => ({
    left: presentedLeft,
    right: presentedRight,
    equal: fullDiff.length === 0,
    diffs: [],
    value_total: fullDiff.length,
    value_truncated: fullDiff.length > 0,
  });

  const build = (keep: number, limits: TrimLimits): Record<string, unknown> => ({
    left: presentedLeft,
    right: presentedRight,
    equal: fullDiff.length === 0,
    diffs: capped.slice(0, keep).map((entry) => presentDiffEntry(entry, limits)),
    value_total: fullDiff.length,
    value_truncated: keep < fullDiff.length,
  });

  const defaultFit = omitTrailingToFit(
    (keep) => build(keep, DEFAULT_TRIM_LIMITS),
    capped.length,
    COMPARE_POLICIES_MAX_RESULT_TOKENS,
    buildSkeleton
  );
  const keptDiffs = defaultFit.diffs as unknown[];
  if (keptDiffs.length > 0 || fullDiff.length === 0) {
    return defaultFit;
  }

  return presentWithinGuardedBudget(
    (limits) => build(1, limits),
    COMPARE_POLICIES_MAX_RESULT_TOKENS,
    () => defaultFit
  );
};

export const createComparePoliciesTool = ({
  endpointAppContextService,
  getStartServices,
}: {
  endpointAppContextService: EndpointAppContextService;
  getStartServices: StartServicesAccessor;
}): BuiltinSkillBoundedTool<typeof comparePoliciesSchema> =>
  createPolicyTool({
    endpointAppContextService,
    getStartServices,
    id: COMPARE_POLICIES_TOOL_ID,
    description:
      'Compare two Elastic Defend policies in the current space. ' +
      'Accepts live policy references on either side. Returns identities, hashes, equality, ' +
      'and a bounded deterministic diff. Does not count endpoints or write policies.',
    schema: comparePoliciesSchema,
    level: 'policy_read',
    maxResultTokens: COMPARE_POLICIES_MAX_RESULT_TOKENS,
    run: async (
      { left, right }: z.infer<typeof comparePoliciesSchema>,
      access: HasAtLeast<'policy_read'>
    ) => {
      const [leftSide, rightSide] = await Promise.all([
        resolveComparisonSide(left, access),
        resolveComparisonSide(right, access),
      ]);
      const fullDiff = diffPolicyConfig(leftSide.normalizedConfig, rightSide.normalizedConfig);
      return presentComparePolicies(leftSide.presented, rightSide.presented, fullDiff);
    },
  });
