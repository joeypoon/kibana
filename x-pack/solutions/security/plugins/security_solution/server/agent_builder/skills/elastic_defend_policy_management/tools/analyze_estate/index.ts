/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType } from '@kbn/agent-builder-common/tools';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import type {
  AssignmentEvidence,
  EstateAccounting,
  PolicySnapshot,
  PolicyReadPrivilegeBasis,
  PolicyUseClassification,
} from '../../domain/read/types';
import type { DuplicateCandidate, DuplicateGroup, PolicyComparison } from '../../domain/compare';
import { comparePolicies, groupDuplicatePolicies } from '../../domain/compare';
import { classifyPolicyUse } from '../../domain/unused';
import {
  buildDefendKuery,
  normalizePolicySearch,
  buildScopeDisclosure,
  createFleetAgentsPrivilegeDisclosure,
  createRegistryCoverageDisclosure,
  createUpstreamFailureDisclosure,
  isDefendPackagePolicy,
  readDefendPolicy,
  toPolicySnapshot,
  PolicyRegistryVersionUnknownError,
} from '../../services/policy_read';
import { createResultLimitDisclosure } from '../../services/policy_read/scope_disclosure';
import { collectAssignmentEvidence } from '../../services/policy_read/assignment_evidence';
import { traverseEstate } from '../../services/policy_read/estate_accounting';
import {
  boundList,
  MAX_EXEMPLAR_STRING_CHARS,
  RESULT_TOKEN_BUDGET,
  truncateBoundedString,
} from '../../lib/bounded_result';
import {
  createPolicyConfigDerivations,
  resolvePolicyFieldRegistry,
} from '../../lib/policy_registry_cache';
import type { DefendPolicyManagementSkillDeps, ResolvedPolicyServices } from '../../deps';
import { resolvePolicyServices } from '../../deps';
import { INTERACTIVE_ESTATE_WORK_LIMIT } from '../work_limit';
import { policySearchInput, POLICY_SEARCH_CONTRACT } from '../schemas';
import {
  CONFIGURED_NOT_APPLIED_STATEMENT,
  DEFEND_POLICY_MANAGEMENT_ERROR,
  UNTRUSTED_FIELD_DATA_STATEMENT,
  toScopeDisclosurePayload,
  toolDenial,
  toolError,
  toolException,
  toolSuccess,
} from '../../lib/tool_results';

export const ANALYZE_DEFEND_POLICY_ESTATE_TOOL_ID = 'security.analyze_defend_policy_estate';

const MAX_POLICY_ID_LENGTH = 256;

export const MAX_DUPLICATE_GROUPS = 20;
export const MAX_UNUSED_EXEMPLARS = 50;

export const ESTATE_ENVELOPE_TOKENS = 1_400;

const ESTATE_EXEMPLAR_TOKEN_BUDGET = RESULT_TOKEN_BUDGET - ESTATE_ENVELOPE_TOKENS;
export const DUPLICATE_GROUPS_TOKEN_BUDGET = Math.floor(ESTATE_EXEMPLAR_TOKEN_BUDGET * 0.6);
export const USE_CLASSIFICATIONS_TOKEN_BUDGET =
  ESTATE_EXEMPLAR_TOKEN_BUDGET - DUPLICATE_GROUPS_TOKEN_BUDGET;

export const DUPLICATE_GROUP_ENVELOPE_TOKENS = 300;

export const MAX_DUPLICATE_GROUP_MEMBERS = 25;

export const MAX_AGENT_POLICY_ID_EXEMPLARS = 5;

const AGENT_POLICY_ASSIGNMENT_ENVELOPE_TOKENS = 120;

export const COMPARE_ENVELOPE_TOKENS = 1_000 + AGENT_POLICY_ASSIGNMENT_ENVELOPE_TOKENS * 2;

const toAgentPolicyAssignmentEnvelope = (
  policyIds: readonly string[]
): {
  readonly agent_policy_id_count: number;
  readonly agent_policy_id_exemplars: readonly string[];
} => ({
  agent_policy_id_count: policyIds.length,
  agent_policy_id_exemplars: policyIds
    .slice(0, MAX_AGENT_POLICY_ID_EXEMPLARS)
    .map((id) => truncateBoundedString(id, MAX_EXEMPLAR_STRING_CHARS)),
});

const COMPARE_LIST_TOKEN_BUDGET = RESULT_TOKEN_BUDGET - COMPARE_ENVELOPE_TOKENS;
export const COMPARE_DIFFERENCES_TOKEN_BUDGET = Math.floor(COMPARE_LIST_TOKEN_BUDGET * 0.6);
export const COMPARE_NOT_COMPARABLE_TOKEN_BUDGET =
  COMPARE_LIST_TOKEN_BUDGET - COMPARE_DIFFERENCES_TOKEN_BUDGET;

const MAX_COMPARED_DIFFERENCES = 200;
const MAX_NOT_COMPARABLE_FIELDS = 200;

export const analyzeDefendPolicyEstateSchema = z
  .object({
    mode: z
      .enum(['estate', 'compare_two'])
      .describe(
        'What to compute. "estate" analyses the Elastic Defend policies the user can access in ' +
          'ONE server-side pass — disclosing when the traversal stops short of the full accessible ' +
          'set — covering duplicate grouping, likely-unused classification, and counts. ' +
          '"compare_two" compares exactly two named policies field by field. Never call this tool ' +
          'repeatedly to compare policies pairwise — use "estate" for anything estate-wide.'
      ),
    leftPolicyId: z
      .string()
      .min(1)
      .max(MAX_POLICY_ID_LENGTH)
      .optional()
      .describe('First policy id. REQUIRED when `mode` is "compare_two"; ignored otherwise.'),
    rightPolicyId: z
      .string()
      .min(1)
      .max(MAX_POLICY_ID_LENGTH)
      .optional()
      .describe('Second policy id. REQUIRED when `mode` is "compare_two"; ignored otherwise.'),
    search: policySearchInput
      .optional()
      .describe(
        `Optional filter narrowing which policies the "estate" pass covers. ${POLICY_SEARCH_CONTRACT} Ignored when \`mode\` is "compare_two".`
      ),
    includeUnusedAnalysis: z
      .boolean()
      .default(true)
      .describe(
        'Whether the "estate" pass classifies which policies are likely unused. Requires Fleet ' +
          'agent-read access to reach a determinate answer; without it every assigned policy is ' +
          'reported as undetermined. Ignored when `mode` is "compare_two".'
      ),
  })
  .strict();

const FILTERED_ESTATE_NOTE =
  'This analysis is scoped to policies whose names match the filter. Omit `search` to analyse ' +
  'every policy the user can access.';

const FILTERED_ZERO_NOTE =
  '`search` is a literal, case-sensitive substring filter — not a regular expression and not a ' +
  'glob — so a wildcard-shaped filter matches (almost) nothing. If you expected policies here, ' +
  'omit `search` to analyse every accessible policy.';

export const createAnalyzeDefendPolicyEstateTool = (
  deps: DefendPolicyManagementSkillDeps
): BuiltinSkillBoundedTool<typeof analyzeDefendPolicyEstateSchema> => ({
  id: ANALYZE_DEFEND_POLICY_ESTATE_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Analyse Elastic Defend policies in relation to each other. `mode: "estate"` does ONE ' +
    'server-side pass over the Elastic Defend policies the user can access — bounded by a work ' +
    'limit that, if reached, is disclosed so a partial answer is never presented as estate-wide — ' +
    'and returns exact-duplicate groups, likely-unused classification, counts, bounded exemplars, ' +
    'and a traversal accounting record proving coverage. Use it for "do I have redundant policies", ' +
    '"which are unused", and estate-wide questions. The optional `search` is a LITERAL, ' +
    'CASE-SENSITIVE name substring filter — not regex, not glob — and omitting it covers the whole ' +
    'accessible estate. `mode: "compare_two"` compares exactly two ' +
    'policies field by field with per-OS attribution. Never loop this tool to compare policies ' +
    'pairwise. Read-only. Returns CONFIGURED policy and cannot confirm what endpoints are running. ' +
    'Never recommends deletion.',
  schema: analyzeDefendPolicyEstateSchema,
  handler: async (input, { request }) => {
    const { mode, leftPolicyId, rightPolicyId, search, includeUnusedAnalysis } = input;

    try {
      const resolved = await resolvePolicyServices({ deps, request });
      if (!resolved.ok) {
        return toolDenial(resolved.denial);
      }

      const services = resolved.value;

      if (mode === 'compare_two') {
        if (leftPolicyId === undefined || rightPolicyId === undefined) {
          return toolError({
            message:
              '`mode: "compare_two"` requires both `leftPolicyId` and `rightPolicyId`. Nothing was compared.',
            error: DEFEND_POLICY_MANAGEMENT_ERROR.invalidRequest,
          });
        }

        return await compareTwoPolicies({
          deps,
          services,
          leftPolicyId,
          rightPolicyId,
        });
      }

      return await analyzeEstate({
        deps,
        services,
        search: normalizePolicySearch(search),
        includeUnusedAnalysis,
      });
    } catch (error) {
      return toolException(error, {
        logger: deps.logger,
        toolId: ANALYZE_DEFEND_POLICY_ESTATE_TOOL_ID,
        operation:
          mode === 'compare_two'
            ? 'comparing two Elastic Defend policies'
            : 'analysing the Elastic Defend policy estate',
      });
    }
  },
});

interface CompareTwoOptions {
  readonly deps: DefendPolicyManagementSkillDeps;
  readonly services: ResolvedPolicyServices;
  readonly leftPolicyId: string;
  readonly rightPolicyId: string;
}

const compareTwoPolicies = async ({
  deps,
  services,
  leftPolicyId,
  rightPolicyId,
}: CompareTwoOptions) => {
  const derivations = createPolicyConfigDerivations({ referenceVersion: deps.kibanaVersion });
  const { privilegeBasis } = services;

  const readOne = async (policyId: string) =>
    readDefendPolicy({
      packagePolicyService: services.packagePolicyService,
      privilegeBasis,
      derivations,
      spaceId: services.spaceId,
      getSoClient: services.getSoClient,
      policyId,
    });

  const [leftOutcome, rightOutcome] = await Promise.all([
    readOne(leftPolicyId),
    readOne(rightPolicyId),
  ]);

  const missing = [
    ...(!leftOutcome.ok ? [leftPolicyId] : []),
    ...(!rightOutcome.ok ? [rightPolicyId] : []),
  ];

  if (!leftOutcome.ok || !rightOutcome.ok) {
    return toolError({
      message: `No Elastic Defend policy was found for ${
        missing.length === 1 ? 'id' : 'ids'
      } [${missing.join(', ')}] among the policies you can access. Nothing was compared.`,
      error: DEFEND_POLICY_MANAGEMENT_ERROR.notFound,
      metadata: { not_found_policy_ids: missing },
    });
  }

  const left = leftOutcome.value.snapshot;
  const right = rightOutcome.value.snapshot;

  const registry = resolvePolicyFieldRegistry(left.packageVersion, {
    referenceVersion: deps.kibanaVersion,
  });

  if ('status' in registry) {
    return toolError({
      message:
        `The comparison could not run: policy [${left.identity.id}] is on Elastic Defend package ` +
        `version ${registry.requestedVersion}, which this feature has no field definitions for.${
          registry.nearestKnownVersion === undefined
            ? ''
            : ` The nearest known version is ${registry.nearestKnownVersion}.`
        }`,
      error: DEFEND_POLICY_MANAGEMENT_ERROR.unknownError,
      metadata: {
        registry_version_unknown: true,
        requested_version: registry.requestedVersion,
      },
    });
  }

  const comparison = comparePolicies({
    left: {
      id: left.identity.id,
      packageVersion: left.packageVersion,
      configNormalized: left.configNormalized,
    },
    right: {
      id: right.identity.id,
      packageVersion: right.packageVersion,
      configNormalized: right.configNormalized,
    },
    registry,
  });

  const boundedDifferences = boundList({
    items: comparison.differences,
    maxItems: MAX_COMPARED_DIFFERENCES,
    tokenBudget: COMPARE_DIFFERENCES_TOKEN_BUDGET,
    itemLabel: 'differing settings',
    continuation:
      'Read each policy individually with `security.get_defend_policy` to see the remaining differences.',
  });

  const boundedNotComparable = boundList({
    items: comparison.notComparable,
    maxItems: MAX_NOT_COMPARABLE_FIELDS,
    tokenBudget: COMPARE_NOT_COMPARABLE_TOKEN_BUDGET,
    itemLabel: 'settings that could not be compared because they are stored on only one policy',
    continuation:
      'Use `not_comparable_total` for how many settings are stored on only one of the two policies; ' +
      'read each policy individually with `security.get_defend_policy` to see the rest.',
  });

  const accounting: EstateAccounting = {
    policiesTraversed: 2,
    pagesFetched: 0,
    complete: true,
  };

  return toolSuccess(
    {
      message: buildComparisonMessage(comparison, left, right, [
        boundedDifferences.truncationNotice,
        boundedNotComparable.truncationNotice,
      ]),
      mode: 'compare_two',
      comparison: {
        leftId: comparison.leftId,
        rightId: comparison.rightId,
        configIdentical: comparison.configIdentical,
        differences: boundedDifferences.items,
        differences_total: comparison.differences.length,
        differences_truncated: boundedDifferences.truncated,
        ...(boundedDifferences.truncationNotice === undefined
          ? {}
          : { differences_truncation_notice: boundedDifferences.truncationNotice }),
        notComparable: boundedNotComparable.items,
        not_comparable_total: comparison.notComparable.length,
        not_comparable_truncated: boundedNotComparable.truncated,
        ...(boundedNotComparable.truncationNotice === undefined
          ? {}
          : { not_comparable_truncation_notice: boundedNotComparable.truncationNotice }),
        protectionUpdatesPinDiffers: comparison.protectionUpdatesPinDiffers,
        leftGlobalManifestVersion: comparison.leftGlobalManifestVersion,
        rightGlobalManifestVersion: comparison.rightGlobalManifestVersion,
      },
      policies: [left, right].map((snapshot) => ({
        identity: {
          id: snapshot.identity.id,
          revision: snapshot.identity.revision,
          ...(snapshot.identity.version === undefined
            ? {}
            : { version: snapshot.identity.version }),
          updatedAt: snapshot.identity.updatedAt,
        },
        name: truncateBoundedString(snapshot.name, MAX_EXEMPLAR_STRING_CHARS),
        package_version: snapshot.packageVersion,
        ...toAgentPolicyAssignmentEnvelope(snapshot.policyIds),
      })),
      estate_accounting: accounting,
      comparison_registry_version: registry.packageVersion,
      protection_updates_pin_note:
        '`global_manifest_version` is the protection-updates pin and is reported as its OWN dimension ' +
        'via `protectionUpdatesPinDiffers`. It is never a configuration difference: two policies ' +
        'differing only in this pin have IDENTICAL protection configuration.',
      scope_disclosure: toScopeDisclosurePayload(
        buildScopeDisclosure({ privilegeBasis, returned: 2, total: 2 })
      ),
      configured_not_applied: CONFIGURED_NOT_APPLIED_STATEMENT,
      untrusted_field_data: UNTRUSTED_FIELD_DATA_STATEMENT,
    },
    { logger: deps.logger, toolId: ANALYZE_DEFEND_POLICY_ESTATE_TOOL_ID }
  );
};

const buildComparisonMessage = (
  comparison: PolicyComparison,
  left: PolicySnapshot,
  right: PolicySnapshot,
  truncationNotices: ReadonlyArray<string | undefined>
): string => {
  const cited =
    `Compared ${JSON.stringify(left.name)} (id ${left.identity.id}, revision ` +
    `${left.identity.revision}) with ${JSON.stringify(right.name)} (id ${right.identity.id}, ` +
    `revision ${right.identity.revision}).`;

  const config = comparison.configIdentical
    ? 'Their protection configurations are IDENTICAL.'
    : `Their configurations differ in ${comparison.differences.length} ${
        comparison.differences.length === 1 ? 'setting' : 'settings'
      }.`;

  const pin = comparison.protectionUpdatesPinDiffers
    ? `Their protection-updates pins differ (${comparison.leftGlobalManifestVersion} vs ${comparison.rightGlobalManifestVersion}); that is a separate dimension from protection configuration, not a configuration difference.`
    : undefined;

  const notComparable =
    comparison.notComparable.length === 0
      ? undefined
      : `${comparison.notComparable.length} settings could not be compared because they are stored on only one of the two policies.`;

  return [cited, config, pin, notComparable, ...truncationNotices]
    .filter((part): part is string => part !== undefined)
    .join(' ');
};

interface AnalyzeEstateOptions {
  readonly deps: DefendPolicyManagementSkillDeps;
  readonly services: ResolvedPolicyServices;
  readonly search?: string;
  readonly includeUnusedAnalysis: boolean;
}

interface EstateAggregate {
  readonly candidates: DuplicateCandidate[];
  readonly assignmentInputs: Array<Pick<PackagePolicy, 'id' | 'policy_ids'>>;
  readonly nameById: Map<string, string>;
  readonly registryGapVersions: Set<string>;
  readonly packageVersions: Map<string, number>;
  skipped: number;
  unassigned: number;
}

const analyzeEstate = async ({
  deps,
  services,
  search,
  includeUnusedAnalysis,
}: AnalyzeEstateOptions) => {
  const derivations = createPolicyConfigDerivations({ referenceVersion: deps.kibanaVersion });
  const { privilegeBasis } = services;
  const aggregate: EstateAggregate = {
    candidates: [],
    assignmentInputs: [],
    nameById: new Map(),
    registryGapVersions: new Set(),
    packageVersions: new Map(),
    skipped: 0,
    unassigned: 0,
  };

  const { aggregate: folded, accounting } = await traverseEstate<EstateAggregate>({
    packagePolicyService: services.packagePolicyService,
    soClient: services.getSoClient(),
    spaceId: services.spaceId,
    kuery: buildDefendKuery(search),
    logger: deps.logger,
    maxPoliciesTraversed: INTERACTIVE_ESTATE_WORK_LIMIT,
    visit: (policy) => {
      if (!isDefendPackagePolicy(policy)) {
        return;
      }

      try {
        const snapshot = toPolicySnapshot(policy, derivations);
        const { identity, name, packageVersion, configNormalized, policyIds } = snapshot;

        aggregate.candidates.push({
          id: identity.id,
          name,
          revision: identity.revision,
          packageVersion,
          policyIds,
          configNormalized,
        });
        aggregate.assignmentInputs.push({ id: policy.id, policy_ids: policy.policy_ids });
        aggregate.nameById.set(identity.id, name);
        aggregate.packageVersions.set(
          packageVersion,
          (aggregate.packageVersions.get(packageVersion) ?? 0) + 1
        );

        if (policyIds.length === 0) {
          aggregate.unassigned += 1;
        }
      } catch (error) {
        if (error instanceof PolicyRegistryVersionUnknownError) {
          aggregate.registryGapVersions.add(error.detail.requestedVersion);
        }

        aggregate.skipped += 1;
        deps.logger.warn(
          `Estate analysis skipped Elastic Defend policy [${policy.id}]: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    },
    finalize: () => aggregate,
  });

  const analysedCount = folded.candidates.length;

  if (analysedCount === 0) {
    return toolSuccess(
      {
        message: buildEmptyEstateMessage({ accounting, folded, search }),
        mode: 'estate',
        policies_analysed: 0,
        duplicate_groups: [],
        estate_accounting: accounting,
        estate_work_limit: INTERACTIVE_ESTATE_WORK_LIMIT,
        scope_disclosure: toScopeDisclosurePayload(
          buildScopeDisclosure({
            privilegeBasis,
            returned: 0,
            total: 0,
            ...(resolveEstatePartial({ folded, accounting }) ?? {}),
          })
        ),
        configured_not_applied: CONFIGURED_NOT_APPLIED_STATEMENT,
        untrusted_field_data: UNTRUSTED_FIELD_DATA_STATEMENT,
      },
      { logger: deps.logger, toolId: ANALYZE_DEFEND_POLICY_ESTATE_TOOL_ID }
    );
  }

  const dominantVersion = [...folded.packageVersions.entries()].sort(
    (left, right) => right[1] - left[1]
  )[0][0];
  const registry = resolvePolicyFieldRegistry(dominantVersion, {
    referenceVersion: deps.kibanaVersion,
  });

  if ('status' in registry) {
    return toolError({
      message:
        `The estate analysis could not run: the most common Elastic Defend package version in your ` +
        `estate (${registry.requestedVersion}) has no policy field definitions in this feature.`,
      error: DEFEND_POLICY_MANAGEMENT_ERROR.unknownError,
      metadata: { registry_version_unknown: true, requested_version: registry.requestedVersion },
    });
  }

  const { groups, accounting: duplicateAccounting } = groupDuplicatePolicies({
    policies: folded.candidates,
  });

  const unusedOutcome = includeUnusedAnalysis
    ? await classifyEstateUse({
        deps,
        services,
        privilegeBasis,
        assignmentInputs: folded.assignmentInputs,
      })
    : undefined;

  const boundedGroups = boundList({
    items: groups.map(toDuplicateGroupPayload),
    maxItems: MAX_DUPLICATE_GROUPS,
    tokenBudget: DUPLICATE_GROUPS_TOKEN_BUDGET,
    itemLabel: 'duplicate groups',
    continuation:
      'The group counts above cover every group found; narrow the estate with `search` to see the ' +
      'members of the remaining groups.',
  });

  const unusedExemplars = unusedOutcome?.classifications.filter(({ state }) => state !== 'in_use');
  const boundedUnused = boundList({
    items: (unusedExemplars ?? []).map(toUseClassificationPayload),
    maxItems: MAX_UNUSED_EXEMPLARS,
    tokenBudget: USE_CLASSIFICATIONS_TOKEN_BUDGET,
    itemLabel: 'policies that are not confirmed in use',
    continuation:
      'The counts above cover every policy analysed; narrow the estate with `search` to enumerate ' +
      'the rest individually.',
  });

  return toolSuccess(
    {
      message: buildEstateMessage({
        analysedCount,
        accounting,
        exactCount: groups.length,
        unusedSummary: unusedOutcome?.summary,
        folded,
        search,
        truncationNotices: [boundedGroups.truncationNotice, boundedUnused.truncationNotice],
      }),
      mode: 'estate',
      policies_analysed: analysedCount,
      package_version_counts: Object.fromEntries(folded.packageVersions),
      unassigned_policy_count: folded.unassigned,
      exact_duplicate_group_count: groups.length,
      policies_in_exact_duplicate_groups: groups.reduce(
        (total, group) => total + group.members.length,
        0
      ),
      duplicate_groups: boundedGroups.items,
      duplicate_groups_total: groups.length,
      duplicate_groups_truncated: boundedGroups.truncated,
      ...(boundedGroups.truncationNotice === undefined
        ? {}
        : { duplicate_groups_truncation_notice: boundedGroups.truncationNotice }),
      duplicate_analysis_accounting: duplicateAccounting,
      ...(unusedOutcome === undefined
        ? {
            unused_analysis_included: false,
            unused_analysis_note:
              'Likely-unused classification was not requested. Call again with ' +
              '`includeUnusedAnalysis: true` to include it.',
          }
        : {
            unused_analysis_included: true,
            use_state_counts: unusedOutcome.summary,
            use_classifications: boundedUnused.items,
            use_classifications_total: unusedExemplars?.length ?? 0,
            use_classifications_truncated: boundedUnused.truncated,
            ...(boundedUnused.truncationNotice === undefined
              ? {}
              : { use_classifications_truncation_notice: boundedUnused.truncationNotice }),
            undetermined_note:
              'An `undetermined` state is a PRIVILEGE LIMITATION, never a finding that a policy has no ' +
              'agents. Fleet reports zero agents to callers without agent-read access with no signal ' +
              'that the number was withheld, so no count is reported at all. Report it as undetermined ' +
              'and state the continuation.',
          }),
      estate_accounting: accounting,
      estate_work_limit: INTERACTIVE_ESTATE_WORK_LIMIT,
      scope_disclosure: toScopeDisclosurePayload(
        buildScopeDisclosure({
          privilegeBasis,
          returned: analysedCount,
          total: analysedCount + folded.skipped,
          ...(resolveEstatePartial({ folded, accounting, unusedOutcome }) ?? {}),
        })
      ),
      no_deletion_note:
        'A duplicate or likely-unused finding is NEVER a recommendation to delete a policy. Describe ' +
        'the configuration finding and leave any decision to the user.',
      configured_not_applied: CONFIGURED_NOT_APPLIED_STATEMENT,
      untrusted_field_data: UNTRUSTED_FIELD_DATA_STATEMENT,
    },
    { logger: deps.logger, toolId: ANALYZE_DEFEND_POLICY_ESTATE_TOOL_ID }
  );
};

const resolveEstatePartial = ({
  folded,
  accounting,
  unusedOutcome,
}: {
  folded: EstateAggregate;
  accounting: EstateAccounting;
  unusedOutcome?: EstateUseOutcome;
}) => {
  if (folded.registryGapVersions.size > 0) {
    return {
      partial: createRegistryCoverageDisclosure([...folded.registryGapVersions], folded.skipped),
    };
  }

  if (!accounting.complete) {
    if (accounting.incompleteReason === 'result_limit_reached') {
      return {
        partial: createResultLimitDisclosure({
          returned: accounting.policiesTraversed,
          total: accounting.policiesTraversed,
        }),
      };
    }

    return {
      partial: createUpstreamFailureDisclosure(
        accounting.incompleteReason ?? 'traversing Elastic Defend policies',
        accounting.policiesTraversed
      ),
    };
  }

  if (unusedOutcome?.agentPrivilegeAbsent === true) {
    return { partial: createFleetAgentsPrivilegeDisclosure() };
  }

  return undefined;
};

interface EstateUseOutcome {
  readonly classifications: readonly PolicyUseClassification[];
  readonly summary: Record<string, number>;
  readonly agentPrivilegeAbsent: boolean;
}

const classifyEstateUse = async ({
  deps,
  services,
  privilegeBasis,
  assignmentInputs,
}: {
  deps: DefendPolicyManagementSkillDeps;
  services: ResolvedPolicyServices;
  privilegeBasis: PolicyReadPrivilegeBasis;
  assignmentInputs: ReadonlyArray<Pick<PackagePolicy, 'id' | 'policy_ids'>>;
}): Promise<EstateUseOutcome> => {
  const evidence = await collectAssignmentEvidence({
    policies: assignmentInputs,
    privilegeBasis,
    getAgentClient: services.getAgentClient,
    logger: deps.logger,
  });

  const evidenceById = new Map<string, AssignmentEvidence>(
    evidence.map((record) => [record.policyId, record])
  );
  const classifications: PolicyUseClassification[] = [];
  const summary: Record<string, number> = {};

  for (const policy of assignmentInputs) {
    const record = evidenceById.get(policy.id);

    if (record !== undefined) {
      const classification = classifyPolicyUse(record, policy.policy_ids ?? []);

      classifications.push(classification);
      summary[classification.state] = (summary[classification.state] ?? 0) + 1;
    }
  }

  return {
    classifications,
    summary,
    agentPrivilegeAbsent: !privilegeBasis.fleetAgentsRead,
  };
};

const toDuplicateGroupPayload = ({
  configHash,
  members,
  differsOnlyByProtectionUpdatesPin,
}: DuplicateGroup) => {
  const boundedMembers = boundList({
    items: members.map((member) => ({
      ...member,
      name: truncateBoundedString(member.name, MAX_EXEMPLAR_STRING_CHARS),
    })),
    maxItems: MAX_DUPLICATE_GROUP_MEMBERS,
    tokenBudget: DUPLICATE_GROUPS_TOKEN_BUDGET,
    envelopeTokens: DUPLICATE_GROUP_ENVELOPE_TOKENS,
    itemLabel: 'members of this duplicate group',
    continuation:
      'Use `members_total` for the size of this group; narrow the estate with `search` to enumerate ' +
      'the remaining members.',
  });

  return {
    configHash,
    members: boundedMembers.items,
    members_total: boundedMembers.total,
    members_truncated: boundedMembers.truncated,
    ...(boundedMembers.truncationNotice === undefined
      ? {}
      : { members_truncation_notice: boundedMembers.truncationNotice }),
    differsOnlyByProtectionUpdatesPin,
  };
};

const toUseClassificationPayload = ({
  policyId,
  state,
  evidence,
  assignmentEvidence,
}: PolicyUseClassification) => ({
  policyId,
  state,
  evidence,
  assignmentEvidence,
});

const describeTraversal = (accounting: EstateAccounting, filtered: boolean): string =>
  accounting.complete
    ? filtered
      ? `The traversal covered all ${accounting.policiesTraversed} policies MATCHING the name filter across ${accounting.pagesFetched} page(s); policies not matching it were not examined.`
      : `The traversal covered all ${accounting.policiesTraversed} policies across ${accounting.pagesFetched} page(s).`
    : `WARNING: the traversal did NOT complete (${
        accounting.incompleteReason ?? 'unknown reason'
      }) after ${
        accounting.policiesTraversed
      } policies. These findings are NOT estate-wide and must not be presented as covering every policy.`;

const buildEmptyEstateMessage = ({
  accounting,
  folded,
  search,
}: {
  accounting: EstateAccounting;
  folded: EstateAggregate;
  search?: string;
}): string => {
  const filter = search === undefined ? '' : ` matching the name filter ${JSON.stringify(search)}`;
  const gap =
    folded.registryGapVersions.size === 0
      ? undefined
      : `${
          folded.skipped
        } policies were left out because this feature has no field definitions for package version(s) ${[
          ...folded.registryGapVersions,
        ].join(', ')}.`;
  const filteredZeroNote =
    accounting.complete && search !== undefined ? FILTERED_ZERO_NOTE : undefined;

  const lead = accounting.complete
    ? `No Elastic Defend policies you can access${filter} could be analysed.`
    : `The analysis stopped before covering the accessible set and examined no Elastic Defend policies${filter}.`;

  return [lead, filteredZeroNote, gap, describeTraversal(accounting, search !== undefined)]
    .filter((part): part is string => part !== undefined)
    .join(' ');
};

const buildEstateMessage = ({
  analysedCount,
  accounting,
  exactCount,
  unusedSummary,
  folded,
  search,
  truncationNotices,
}: {
  analysedCount: number;
  accounting: EstateAccounting;
  exactCount: number;
  unusedSummary?: Record<string, number>;
  folded: EstateAggregate;
  search?: string;
  truncationNotices: ReadonlyArray<string | undefined>;
}): string => {
  const filter = search === undefined ? '' : ` matching the name filter ${JSON.stringify(search)}`;
  const filteredScopeNote = search === undefined ? undefined : FILTERED_ESTATE_NOTE;

  const duplicates =
    exactCount === 0
      ? 'No configuration-identical policies were found.'
      : `Found ${exactCount} exact-duplicate ${exactCount === 1 ? 'group' : 'groups'}.`;

  const unused =
    unusedSummary === undefined
      ? undefined
      : `Use classification: ${
          Object.entries(unusedSummary)
            .map(([state, count]) => `${count} ${state}`)
            .join(', ') || 'none'
        }.`;

  const gap =
    folded.registryGapVersions.size === 0
      ? undefined
      : `${
          folded.skipped
        } policies were excluded because this feature has no field definitions for package version(s) ${[
          ...folded.registryGapVersions,
        ].join(', ')}.`;

  return [
    accounting.complete
      ? `Analysed ${analysedCount} Elastic Defend ${
          analysedCount === 1 ? 'policy' : 'policies'
        } you can access${filter} in one pass.`
      : `The analysis examined ${analysedCount} Elastic Defend ${
          analysedCount === 1 ? 'policy' : 'policies'
        }${filter} before stopping; this is NOT the full accessible set.`,
    filteredScopeNote,
    duplicates,
    unused,
    gap,
    describeTraversal(accounting, search !== undefined),
    ...truncationNotices,
  ]
    .filter((part): part is string => part !== undefined)
    .join(' ');
};
