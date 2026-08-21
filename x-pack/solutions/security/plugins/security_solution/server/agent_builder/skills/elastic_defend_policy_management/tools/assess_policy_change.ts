/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import type { StartServicesAccessor } from '@kbn/core/server';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import type { PolicyDiffEntry } from '../domain/diff';
import {
  assessPolicyChangeParamsSchema,
  type AssessPolicyChangeParams,
  type PolicyChangeFact,
  type PolicyChangeOperation,
  type PolicyChangeSideEffect,
} from '../domain/impact';
import type { HasAtLeast } from '../services/access_context';
import type { AssessPolicyChangeDto } from '../services/assess_change';
import { assessChange } from '../services/assess_change';
import { createPolicyTool } from './create_policy_tool';
import type { TrimLimits } from './trim_policy_result';
import {
  DEFAULT_TRIM_LIMITS,
  TIGHTEST_TRIM_LIMITS,
  omitTrailingToFit,
  parentTrimMetadata,
  presentBoundedIdentityStrings,
  presentWithinGuardedBudget,
  sidedTrimMetadata,
  trimPolicyResultWithMeta,
  tryOmitTrailingToFit,
} from './trim_policy_result';

export const ASSESS_POLICY_CHANGE_TOOL_ID = 'security.policy_management.assess_policy_change';

export const assessPolicyChangeSchema = assessPolicyChangeParamsSchema;

const ASSESS_DISPLAY_CAP = 50;
const ASSESS_POLICY_CHANGE_MAX_RESULT_TOKENS = 12_000;

const ARRAY_TRIM_PREFIX = {
  requestedOperations: 'requested_operations',
  requestedImpact: 'requested_impact',
  expandedChanges: 'expanded_changes',
  normalizedDiff: 'normalized_diff',
  sideEffects: 'side_effects',
} as const;

const arrayTrimMeta = (
  name: keyof typeof ARRAY_TRIM_PREFIX,
  kept: number,
  total: number
): Record<string, true | number> =>
  kept < total
    ? {
        [`${ARRAY_TRIM_PREFIX[name]}_value_truncated`]: true,
        [`${ARRAY_TRIM_PREFIX[name]}_value_total`]: total,
      }
    : {};

const presentFromTo = (
  entry: Readonly<{ from: unknown; to: unknown }>,
  limits: TrimLimits
): Record<string, unknown> => {
  const fromTrim = trimPolicyResultWithMeta(entry.from, limits);
  const toTrim = trimPolicyResultWithMeta(entry.to, limits);
  return {
    from: fromTrim.value,
    to: toTrim.value,
    ...sidedTrimMetadata('from', parentTrimMetadata(fromTrim.value, fromTrim.metadata)),
    ...sidedTrimMetadata('to', parentTrimMetadata(toTrim.value, toTrim.metadata)),
  };
};

const presentRequestedOperation = (
  operation: PolicyChangeOperation,
  limits: TrimLimits
): Record<string, unknown> => {
  if (operation.op !== 'set_field') {
    return { ...operation };
  }

  const valueTrim = trimPolicyResultWithMeta(operation.value, limits);
  return {
    op: operation.op,
    path: operation.path,
    value: valueTrim.value,
    ...parentTrimMetadata(valueTrim.value, valueTrim.metadata),
  };
};

const presentRequestedOperationIdentity = (
  operation: PolicyChangeOperation
): Record<string, unknown> => {
  if (operation.op !== 'set_field') {
    return { ...operation };
  }

  return {
    op: operation.op,
    path: operation.path,
    value_truncated: true,
  };
};

const presentPolicyChangeFact = (
  entry: PolicyChangeFact,
  limits: TrimLimits
): Record<string, unknown> => {
  const { kind: originKind, ...origin } = entry.origin;
  const { kind: registryKind, ...registry } = entry.registry;

  return {
    path: entry.path,
    originKind,
    registryKind,
    origin,
    registry,
    eligibility: entry.eligibility,
    ...presentFromTo(entry, limits),
  };
};

const presentNormalizedDiff = (
  entry: PolicyDiffEntry,
  limits: TrimLimits
): Record<string, unknown> => ({
  path: entry.path,
  ...presentFromTo(entry, limits),
});

const presentSideEffect = (
  entry: PolicyChangeSideEffect,
  limits: TrimLimits
): Record<string, unknown> => ({
  path: entry.path,
  reason: entry.reason,
  registry: entry.registry,
  ...presentFromTo(entry, limits),
});

const presentAssessmentPolicy = (
  policy: AssessPolicyChangeDto['policy']
): Record<string, unknown> => {
  const presented = presentBoundedIdentityStrings({
    id: policy.id,
    name: policy.name,
    description: '',
    revision: policy.revision,
    version: policy.version,
  });

  return {
    id: presented.id,
    name: presented.name,
    revision: presented.revision,
    version: presented.version,
    ...(presented.id_string_truncated === true ? { id_string_truncated: true as const } : {}),
    ...(presented.name_string_truncated === true ? { name_string_truncated: true as const } : {}),
    ...(presented.version_string_truncated === true
      ? { version_string_truncated: true as const }
      : {}),
  };
};

const presentBlastRadius = (
  blastRadius: AssessPolicyChangeDto['blastRadius']
): Record<string, unknown> => {
  const { population, source, status } = blastRadius;

  return {
    population,
    source,
    status,
    ...(Object.hasOwn(status, 'all')
      ? { headline: status.all }
      : { headlineUnavailable: true as const }),
  };
};

const presentAssessPolicyChange = (dto: AssessPolicyChangeDto): Record<string, unknown> => {
  const policy = presentAssessmentPolicy(dto.policy);
  const blastRadius = presentBlastRadius(dto.blastRadius);

  const requestedTotal = dto.requestedOperations.length;

  const build = (
    keep: number,
    limits: TrimLimits,
    requestedKeep: number = requestedTotal
  ): Record<string, unknown> => {
    const requested = dto.requestedOperations.slice(0, requestedKeep);
    const requestedImpact = dto.requestedImpact.slice(0, keep);
    const expanded = dto.expandedChanges.slice(0, keep);
    const diffs = dto.normalizedDiff.slice(0, keep);
    const sides = dto.sideEffects.slice(0, keep);

    return {
      policy,
      spaceId: dto.spaceId,
      requestedOperations: requested.map((operation) =>
        presentRequestedOperation(operation, limits)
      ),
      ...arrayTrimMeta('requestedOperations', requested.length, requestedTotal),
      requestedImpact: requestedImpact.map((entry) => presentPolicyChangeFact(entry, limits)),
      ...arrayTrimMeta('requestedImpact', requestedImpact.length, dto.requestedImpact.length),
      expandedChanges: expanded.map((entry) => presentPolicyChangeFact(entry, limits)),
      ...arrayTrimMeta('expandedChanges', expanded.length, dto.expandedChanges.length),
      normalizedDiff: diffs.map((entry) => presentNormalizedDiff(entry, limits)),
      ...arrayTrimMeta('normalizedDiff', diffs.length, dto.normalizedDiff.length),
      sideEffects: sides.map((entry) => presentSideEffect(entry, limits)),
      ...arrayTrimMeta('sideEffects', sides.length, dto.sideEffects.length),
      blastRadius,
    };
  };

  const buildIdentityRequested = (requestedKeep: number): Record<string, unknown> => {
    const requested = dto.requestedOperations.slice(0, requestedKeep);

    return {
      policy,
      spaceId: dto.spaceId,
      requestedOperations: requested.map(presentRequestedOperationIdentity),
      ...arrayTrimMeta('requestedOperations', requested.length, requestedTotal),
      requestedImpact: [],
      ...arrayTrimMeta('requestedImpact', 0, dto.requestedImpact.length),
      expandedChanges: [],
      ...arrayTrimMeta('expandedChanges', 0, dto.expandedChanges.length),
      normalizedDiff: [],
      ...arrayTrimMeta('normalizedDiff', 0, dto.normalizedDiff.length),
      sideEffects: [],
      ...arrayTrimMeta('sideEffects', 0, dto.sideEffects.length),
      blastRadius,
    };
  };

  const skeleton = (): Record<string, unknown> => ({
    policy,
    spaceId: dto.spaceId,
    requestedOperations: [],
    ...arrayTrimMeta('requestedOperations', 0, requestedTotal),
    requestedImpact: [],
    ...arrayTrimMeta('requestedImpact', 0, dto.requestedImpact.length),
    expandedChanges: [],
    ...arrayTrimMeta('expandedChanges', 0, dto.expandedChanges.length),
    normalizedDiff: [],
    ...arrayTrimMeta('normalizedDiff', 0, dto.normalizedDiff.length),
    sideEffects: [],
    ...arrayTrimMeta('sideEffects', 0, dto.sideEffects.length),
    blastRadius,
  });

  const defaultFit = tryOmitTrailingToFit(
    (keep) => build(keep, DEFAULT_TRIM_LIMITS),
    ASSESS_DISPLAY_CAP,
    ASSESS_POLICY_CHANGE_MAX_RESULT_TOKENS
  );

  if (defaultFit !== undefined) {
    const keptRequestedImpact = defaultFit.requestedImpact as unknown[];
    const keptExpanded = defaultFit.expandedChanges as unknown[];
    const keptDiffs = defaultFit.normalizedDiff as unknown[];
    const keptSides = defaultFit.sideEffects as unknown[];
    if (
      keptRequestedImpact.length > 0 ||
      keptExpanded.length > 0 ||
      keptDiffs.length > 0 ||
      keptSides.length > 0 ||
      (dto.requestedImpact.length === 0 &&
        dto.expandedChanges.length === 0 &&
        dto.normalizedDiff.length === 0 &&
        dto.sideEffects.length === 0)
    ) {
      return defaultFit;
    }
  }

  return presentWithinGuardedBudget(
    (limits) => build(1, limits),
    ASSESS_POLICY_CHANGE_MAX_RESULT_TOKENS,
    () =>
      omitTrailingToFit(
        (requestedKeep) => build(0, TIGHTEST_TRIM_LIMITS, requestedKeep),
        requestedTotal,
        ASSESS_POLICY_CHANGE_MAX_RESULT_TOKENS,
        () =>
          omitTrailingToFit(
            buildIdentityRequested,
            requestedTotal,
            ASSESS_POLICY_CHANGE_MAX_RESULT_TOKENS,
            skeleton
          )
      )
  );
};

export const createAssessPolicyChangeTool = ({
  endpointAppContextService,
  getStartServices,
}: {
  endpointAppContextService: EndpointAppContextService;
  getStartServices: StartServicesAccessor;
}): BuiltinSkillBoundedTool<typeof assessPolicyChangeSchema> =>
  createPolicyTool({
    endpointAppContextService,
    getStartServices,
    id: ASSESS_POLICY_CHANGE_TOOL_ID,
    description:
      'Assess a bounded proposed change to one Elastic Defend endpoint policy in the current space. ' +
      'Returns requested operations, requested direct impact, expanded intent, normalized diff, and derived side effects as separate facts, ' +
      'plus policy identity and version, enrolled-agent blast-radius source, population, and complete status map, ' +
      'and per-path eligibility computed from registry license, current license, product features, and environment. ' +
      'Uses status.all as the enrolled-agent headline only when that key is present. ' +
      'Does not write policies.',
    schema: assessPolicyChangeSchema,
    level: 'estate_read',
    maxResultTokens: ASSESS_POLICY_CHANGE_MAX_RESULT_TOKENS,
    run: async (params: AssessPolicyChangeParams, access: HasAtLeast<'estate_read'>) => {
      const dto = await assessChange(access, endpointAppContextService, params);
      return presentAssessPolicyChange(dto);
    },
  });
