/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import type { ToolHandlerStandardReturn } from '@kbn/agent-builder-server/tools';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import {
  COMPARE_DIFFERENCES_TOKEN_BUDGET,
  COMPARE_NOT_COMPARABLE_TOKEN_BUDGET,
  createAnalyzeDefendPolicyEstateTool,
  MAX_AGENT_POLICY_ID_EXEMPLARS,
  DUPLICATE_GROUPS_TOKEN_BUDGET,
  ESTATE_ENVELOPE_TOKENS,
  MAX_DUPLICATE_GROUPS,
  MAX_DUPLICATE_GROUP_MEMBERS,
  MAX_UNUSED_EXEMPLARS,
  USE_CLASSIFICATIONS_TOKEN_BUDGET,
} from '.';
import {
  boundList,
  estimateResultTokens,
  isWithinResultBudget,
  RESULT_TOKEN_BUDGET,
  TOOL_RESULT_TOKEN_BUDGET,
} from '../../lib/bounded_result';
import { INTERACTIVE_ESTATE_WORK_LIMIT } from '../work_limit';
import type { DefendPolicyManagementToolMocks } from '../../lib/test_helpers';
import {
  createDefendPolicyMock,
  createDefendPolicyManagementToolMocks,
  expectConfiguredNotAppliedIsResultScoped,
  expectReadOnlyAndNoForbiddenReads,
  expectWrappedHandlerWithinPlatformBudget,
} from '../../lib/test_helpers';

const PINNED_PACKAGE_VERSION = '9.4.0';

const DUPLICATE_GROUP_COUNT = 10;
const CLONES_PER_GROUP = 26;

interface DifferenceRef {
  keyPath: string;
  os?: string;
}

interface EstatePayload {
  message: string;
  mode: string;
  policies_analysed: number;
  unassigned_policy_count: number;
  exact_duplicate_group_count: number;
  policies_in_exact_duplicate_groups: number;
  duplicate_groups: Array<{
    configHash: string;
    members: Array<{ id: string; name: string; policyIds: string[] }>;
    members_total: number;
    members_truncated: boolean;
    members_truncation_notice?: string;
    differsOnlyByProtectionUpdatesPin: boolean;
  }>;
  duplicate_groups_total: number;
  duplicate_groups_truncated: boolean;
  duplicate_groups_truncation_notice?: string;
  result_budget_notice?: string;
  duplicate_analysis_accounting: {
    policiesConsidered: number;
    duplicateGroupCount: number;
    policiesInDuplicateGroups: number;
  };
  unused_analysis_included: boolean;
  use_state_counts?: Record<string, number>;
  use_classifications?: Array<{
    policyId: string;
    state: string;
    evidence: string;
    assignmentEvidence: { status: string; agentCount?: number; agentPolicyIds: string[] };
  }>;
  use_classifications_total?: number;
  use_classifications_truncated?: boolean;
  use_classifications_truncation_notice?: string;
  estate_accounting: {
    policiesTraversed: number;
    pagesFetched: number;
    complete: boolean;
    incompleteReason?: string;
  };
  estate_work_limit: number;
  configured_not_applied?: string;
  scope_disclosure: {
    privilege_basis: Record<string, boolean>;
    returned: number;
    total: number;
    partial?: { reason: string; detail: string; continuation: string };
  };
}

interface ComparisonPayload {
  message: string;
  mode: string;
  policies: Array<{
    identity: { id: string; revision: number; version?: string; updatedAt: string };
    name: string;
    package_version: string;
    agent_policy_id_count: number;
    agent_policy_id_exemplars: string[];
  }>;
  comparison: {
    leftId: string;
    rightId: string;
    configIdentical: boolean;
    differences: DifferenceRef[];
    differences_total: number;
    differences_truncated: boolean;
    differences_truncation_notice?: string;
    notComparable: DifferenceRef[];
    not_comparable_total: number;
    not_comparable_truncated: boolean;
    not_comparable_truncation_notice?: string;
    protectionUpdatesPinDiffers: boolean;
    leftGlobalManifestVersion: string;
    rightGlobalManifestVersion: string;
  };
  estate_accounting: { policiesTraversed: number; complete: boolean };
  result_budget_notice?: string;
  configured_not_applied?: string;
  scope_disclosure: {
    privilege_basis: Record<string, boolean>;
    returned: number;
    total: number;
  };
}

const FLEET_MAX_ASSIGNMENT_IDS = 1000;

const createUuidAssignmentIds = (count = FLEET_MAX_ASSIGNMENT_IDS): string[] =>
  Array.from({ length: count }, (_, index) => {
    const serial = index.toString(16).padStart(12, '0');
    return `aaaaaaaa-bbbb-4ccc-8ddd-${serial}`;
  });

interface ErrorPayload {
  message: string;
  metadata?: Record<string, unknown>;
}

const defendPolicy = ({
  id,
  name,
  policyIds = ['agent-policy-1'],
  globalManifestVersion,
  packageVersion = PINNED_PACKAGE_VERSION,
  mutate,
}: {
  id: string;
  name: string;
  policyIds?: string[];
  globalManifestVersion?: string;
  packageVersion?: string;
  mutate?: (config: PackagePolicy['inputs'][0]['config']) => void;
}): PackagePolicy => {
  const policy = createDefendPolicyMock({
    id,
    name,
    policy_ids: policyIds,
    package: { name: 'endpoint', title: 'Elastic Defend', version: packageVersion },
  });

  const config = policy.inputs[0].config!.policy.value;

  if (globalManifestVersion !== undefined) {
    config.global_manifest_version = globalManifestVersion;
  }

  mutate?.(policy.inputs[0].config);

  return policy;
};

describe('security.analyze_defend_policy_estate', () => {
  let mocks: DefendPolicyManagementToolMocks;
  let tool: ReturnType<typeof createAnalyzeDefendPolicyEstateTool>;

  const runTool = async (input: Parameters<typeof tool.handler>[0]) =>
    (await tool.handler(input, mocks.context)) as ToolHandlerStandardReturn;

  const givenEstate = (...pages: PackagePolicy[][]) => {
    mocks.packagePolicyService.fetchAllItems.mockResolvedValue({
      async *[Symbol.asyncIterator]() {
        for (const page of pages) {
          yield page;
        }
      },
    } as ReturnType<typeof mocks.packagePolicyService.fetchAllItems> extends Promise<infer T> ? T : never);
  };

  beforeEach(() => {
    mocks = createDefendPolicyManagementToolMocks();
    tool = createAnalyzeDefendPolicyEstateTool(mocks.deps);
  });

  describe('mode: estate', () => {
    it('groups byte-identical configs as exact duplicates and excludes a differing one', async () => {
      givenEstate([
        defendPolicy({ id: 'p1', name: 'Prod A', policyIds: ['ap-1'] }),
        defendPolicy({ id: 'p2', name: 'Prod B', policyIds: ['ap-2'] }),
        defendPolicy({
          id: 'p3',
          name: 'Prod C',
          mutate: (config) => {
            config!.policy.value.windows.malware.blocklist = false;
            config!.policy.value.windows.malware.mode = ProtectionModes.detect;
          },
        }),
      ]);

      const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: false })).results[0]
        .data as EstatePayload;

      const exact = payload.duplicate_groups[0];
      const memberIds = exact?.members.map(({ id }) => id) ?? [];

      expect(memberIds).toEqual(expect.arrayContaining(['p1', 'p2']));
      expect(memberIds).not.toContain('p3');
      expect(exact?.configHash).toBeDefined();
      expect(new Set(exact?.members.map(({ policyIds }) => policyIds.join(','))).size).toBe(2);
      expectConfiguredNotAppliedIsResultScoped(payload);
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('always surfaces the estate accounting record proving coverage', async () => {
      givenEstate([defendPolicy({ id: 'p1', name: 'A' })], [defendPolicy({ id: 'p2', name: 'B' })]);

      const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: false })).results[0]
        .data as EstatePayload;

      expect(payload.estate_accounting).toEqual({
        policiesTraversed: 2,
        pagesFetched: 2,
        complete: true,
      });
      expect(payload.policies_analysed).toBe(2);
      expect(payload.message).toContain('covered all 2 policies');
    });

    it('searches with the shared tokenized kuery, so a multi-word name filter cannot silently match nothing', async () => {
      givenEstate([]);

      await runTool({
        mode: 'estate',
        search: 'Prod Windows Servers',
        includeUnusedAnalysis: false,
      });

      expect(mocks.packagePolicyService.fetchAllItems).toHaveBeenCalledTimes(1);
      const [, options] = mocks.packagePolicyService.fetchAllItems.mock.calls[0];
      expect(options?.kuery).toContain('package.name: "endpoint"');
      expect(options?.kuery).toContain('name: *Prod*');
      expect(options?.kuery).toContain('name: *Windows*');
      expect(options?.kuery).toContain('name: *Servers*');
      expect(options?.kuery?.split(' AND ')).toHaveLength(4);
    });

    it('stops at the interactive work limit and accounts for the partial estate honestly', async () => {
      const pages: PackagePolicy[][] = [];
      for (let page = 0; page * 100 < INTERACTIVE_ESTATE_WORK_LIMIT + 100; page += 1) {
        pages.push(
          Array.from({ length: 100 }, (_, index) =>
            defendPolicy({ id: `p-${page * 100 + index}`, name: `P ${page * 100 + index}` })
          )
        );
      }
      givenEstate(...pages);

      const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: false })).results[0]
        .data as EstatePayload;

      expect(payload.estate_work_limit).toBe(INTERACTIVE_ESTATE_WORK_LIMIT);
      expect(payload.estate_accounting.complete).toBe(false);
      expect(payload.estate_accounting.incompleteReason).toBe('result_limit_reached');
      expect(payload.estate_accounting.policiesTraversed).toBe(INTERACTIVE_ESTATE_WORK_LIMIT);
      expect(payload.policies_analysed).toBe(INTERACTIVE_ESTATE_WORK_LIMIT);
      expect(payload.scope_disclosure.partial?.reason).toBe('result_limit_reached');
      expect(payload.scope_disclosure.partial?.detail).toContain('work limit');
      expect(payload.scope_disclosure.partial?.detail).not.toContain(
        'policies matching your request'
      );
      expect(payload.scope_disclosure.partial?.continuation).toContain('search');
      expect(payload.message).toContain('did NOT complete');
      expect(payload.message).toContain('before stopping');
      expect(payload.message).not.toMatch(/\b\d+ Elastic Defend policies? you can access/);
      expect(payload.message).not.toMatch(/you can access/);
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('marks the answer NOT estate-wide when the traversal was interrupted', async () => {
      mocks.packagePolicyService.fetchAllItems.mockRejectedValue(new Error('Fleet went away'));

      const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: false })).results[0]
        .data as EstatePayload;

      expect(payload.estate_accounting.complete).toBe(false);
      expect(payload.estate_accounting.incompleteReason).toBe('upstream_failure');
      expect(payload.message).toContain('did NOT complete');
      expect(payload.message).toContain('examined no');
      expect(payload.message).not.toMatch(/No Elastic Defend policies you can access/);
      expect(payload.message).not.toMatch(/you can access/);
    });

    it('surfaces the duplicate-analysis accounting so coverage is proven, not assumed', async () => {
      givenEstate([defendPolicy({ id: 'p1', name: 'A' }), defendPolicy({ id: 'p2', name: 'B' })]);

      const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: false })).results[0]
        .data as EstatePayload;

      expect(payload.duplicate_analysis_accounting).toEqual({
        policiesConsidered: 2,
        duplicateGroupCount: 1,
        policiesInDuplicateGroups: 2,
      });
    });

    describe('use classification', () => {
      it('degrades every assigned policy to undetermined without the agent privilege, emitting no count', async () => {
        mocks.setPrivileges({
          securityPolicyManagementRead: true,
          fleetAgentsRead: false,
        });
        givenEstate([
          defendPolicy({ id: 'p5', name: 'Assigned A', policyIds: ['ap-5'] }),
          defendPolicy({ id: 'p6', name: 'Assigned B', policyIds: ['ap-6'] }),
        ]);

        const result = await runTool({ mode: 'estate', includeUnusedAnalysis: true });
        const payload = result.results[0].data as EstatePayload;

        for (const classification of payload.use_classifications ?? []) {
          expect(classification.state).toBe('undetermined');
          expect(classification.assignmentEvidence.agentCount).toBeUndefined();
          expect(classification.assignmentEvidence.status).toBe('privilege_absent');
        }

        expect(JSON.stringify(payload)).not.toMatch(/"agentCount"/);
        expect(payload.scope_disclosure.partial).toMatchObject({
          reason: 'missing_privilege',
          detail: expect.stringContaining('permission'),
          continuation: expect.stringContaining('administrator'),
        });
        expect(mocks.agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
        expectReadOnlyAndNoForbiddenReads(mocks);
      });

      it('never presents undetermined as "no agents"', async () => {
        mocks.setPrivileges({
          securityPolicyManagementRead: true,
          fleetAgentsRead: false,
        });
        givenEstate([defendPolicy({ id: 'p5', name: 'Assigned', policyIds: ['ap-5'] })]);

        const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: true })).results[0]
          .data as EstatePayload;

        expect(JSON.stringify(payload)).toContain('PRIVILEGE LIMITATION');
      });

      it('omits the classification entirely when it was not requested', async () => {
        givenEstate([defendPolicy({ id: 'p1', name: 'A' })]);

        const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: false })).results[0]
          .data as EstatePayload;

        expect(payload.unused_analysis_included).toBe(false);
        expect(payload.use_classifications).toBeUndefined();
      });
    });

    describe('empty estate', () => {
      it('reports zero analysed with a complete traversal, not an error', async () => {
        givenEstate([]);

        const result = await runTool({ mode: 'estate', includeUnusedAnalysis: true });
        const payload = result.results[0].data as EstatePayload;

        expect(result.results[0].type).toBe(ToolResultType.other);
        expect(payload.policies_analysed).toBe(0);
        expect(payload.duplicate_groups).toEqual([]);
        expect(payload.estate_accounting.complete).toBe(true);
        expect(payload.message).toContain('No Elastic Defend policies');
      });
    });

    describe('truncation', () => {
      it('bounds exemplars while keeping aggregates and totals complete', async () => {
        const policies: PackagePolicy[] = [];
        for (let index = 0; index < 60; index += 1) {
          const tweak = (config: PackagePolicy['inputs'][0]['config']) => {
            config!.policy.value.windows.advanced = {
              artifacts: { global: { interval: `${index + 1}m` } },
            };
          };
          policies.push(
            defendPolicy({ id: `a-${index}`, name: `A ${index}`, mutate: tweak }),
            defendPolicy({ id: `b-${index}`, name: `B ${index}`, mutate: tweak })
          );
        }
        givenEstate(policies);

        const result = await runTool({ mode: 'estate', includeUnusedAnalysis: false });
        const payload = result.results[0].data as EstatePayload;

        expect(payload.policies_analysed).toBe(120);
        expect(payload.estate_accounting).toMatchObject({
          policiesTraversed: 120,
          complete: true,
        });
        expect(payload.exact_duplicate_group_count).toBe(60);
        expect(payload.message).toContain('60 exact-duplicate groups');
        expect(payload.duplicate_groups_total).toBe(60);
        expect(payload.duplicate_groups.length).toBeLessThan(payload.duplicate_groups_total);
        expect(payload.duplicate_groups_truncated).toBe(true);
        expect(payload.duplicate_groups_truncation_notice).toContain('of 60');
        expect(estimateResultTokens(result)).toBeLessThan(TOOL_RESULT_TOKEN_BUDGET);
      });

      it('bounds the MEMBERS of one huge exact-duplicate group and discloses the real size', async () => {
        const cloneCount = 3_000;
        const clones: PackagePolicy[] = [];
        for (let index = 0; index < cloneCount; index += 1) {
          clones.push(defendPolicy({ id: `clone-${index}`, name: `Clone ${index}` }));
        }
        givenEstate(clones);

        const result = await runTool({ mode: 'estate', includeUnusedAnalysis: false });
        const payload = result.results[0].data as EstatePayload;

        expect(payload.policies_analysed).toBe(cloneCount);
        expect(payload.exact_duplicate_group_count).toBe(1);
        expect(payload.policies_in_exact_duplicate_groups).toBe(cloneCount);
        expect(payload.duplicate_groups).toHaveLength(1);

        const [group] = payload.duplicate_groups;

        expect(group.members.length).toBeLessThan(cloneCount);
        expect(group.members_total).toBe(cloneCount);
        expect(group.members_truncated).toBe(true);
        expect(group.members_truncation_notice).toContain(`of ${cloneCount}`);
        expect(group.members_truncation_notice).toContain('not absent from your deployment');

        expect(estimateResultTokens(result)).toBeLessThan(TOOL_RESULT_TOKEN_BUDGET);
        expect(payload.result_budget_notice).toBeUndefined();
      });

      it('keeps oversized policy names under the wrapped 20k budget without dropping counts', async () => {
        const hugeName = `A ${'n'.repeat(80_000)}`;
        const policies: PackagePolicy[] = [];
        for (let index = 0; index < 20; index += 1) {
          const tweak = (config: PackagePolicy['inputs'][0]['config']) => {
            config!.policy.value.windows.advanced = {
              artifacts: { global: { interval: `${index + 1}m` } },
            };
          };
          policies.push(
            defendPolicy({ id: `a-${index}`, name: hugeName, mutate: tweak }),
            defendPolicy({ id: `b-${index}`, name: hugeName, mutate: tweak })
          );
        }
        givenEstate(policies);

        const result = await runTool({ mode: 'estate', includeUnusedAnalysis: false });
        const payload = result.results[0].data as EstatePayload;

        expectWrappedHandlerWithinPlatformBudget(result);
        expect(payload.result_budget_notice).toBeUndefined();
        expect(payload.policies_analysed).toBe(40);
        expect(payload.estate_accounting.complete).toBe(true);
        expect(payload.exact_duplicate_group_count).toBe(20);
        expect(payload.duplicate_groups_total).toBe(20);
        expect(payload.scope_disclosure.total).toBe(40);
        expectConfiguredNotAppliedIsResultScoped(payload);
        for (const group of payload.duplicate_groups) {
          for (const member of group.members) {
            expect(member.name.length).toBeLessThan(80_000);
            expect(member.name).toContain('truncated');
          }
        }
        expect(mocks.logger.warn).not.toHaveBeenCalled();
      });
    });

    describe('one shared budget across concurrent lists', () => {
      const givenClonedEstateWithoutAgentPrivilege = () => {
        mocks.setPrivileges({
          securityPolicyManagementRead: true,
          fleetAgentsRead: false,
        });

        const policies: PackagePolicy[] = [];

        for (let group = 0; group < DUPLICATE_GROUP_COUNT; group += 1) {
          const tweak = (config: PackagePolicy['inputs'][0]['config']) => {
            config!.policy.value.windows.advanced = {
              artifacts: {
                global: {
                  interval: `${group + 1}m`,
                  base_url: `https://artifacts-${group}.example.internal/downloads`,
                  manifest_relative_url: `/v1/manifests/group-${group}`,
                  public_key: `group-${group}-global-artifact-public-key`,
                },
                user: { public_key: `group-${group}-user-artifact-public-key` },
              },
              elasticsearch: { delay: `${group + 1}s` },
            };
          };

          for (let clone = 0; clone < CLONES_PER_GROUP; clone += 1) {
            policies.push(
              defendPolicy({
                id: `eu-west-prod-group-${group}-clone-${clone}`,
                name: `Prod EU-West Windows workstations (group ${group}, clone ${clone})`,
                policyIds: [
                  `agent-policy-eu-west-prod-${group}-${clone}`,
                  `agent-policy-eu-west-dr-${group}-${clone}`,
                ],
                mutate: tweak,
              })
            );
          }
        }

        givenEstate(policies);
      };

      it('keeps the ASSEMBLED payload inside the budget when both exemplar lists are full', async () => {
        givenClonedEstateWithoutAgentPrivilege();

        const result = await runTool({ mode: 'estate', includeUnusedAnalysis: true });
        const payload = result.results[0].data as EstatePayload;

        expect(payload.policies_analysed).toBe(DUPLICATE_GROUP_COUNT * CLONES_PER_GROUP);
        expect(payload.duplicate_groups_total).toBe(DUPLICATE_GROUP_COUNT);
        expect(payload.use_classifications_total).toBe(DUPLICATE_GROUP_COUNT * CLONES_PER_GROUP);

        expect(isWithinResultBudget(payload)).toBe(true);
        expect(estimateResultTokens(result)).toBeLessThan(TOOL_RESULT_TOKEN_BUDGET);
        expect(payload.result_budget_notice).toBeUndefined();

        expect(estimateResultTokens(payload.duplicate_groups)).toBeLessThanOrEqual(
          DUPLICATE_GROUPS_TOKEN_BUDGET
        );
        expect(estimateResultTokens(payload.use_classifications)).toBeLessThanOrEqual(
          USE_CLASSIFICATIONS_TOKEN_BUDGET
        );

        expect(payload.duplicate_groups_truncated).toBe(true);
        expect(payload.duplicate_groups_truncation_notice).toContain(
          `of ${DUPLICATE_GROUP_COUNT} duplicate groups`
        );
        expect(payload.duplicate_groups_truncation_notice).toContain('narrow the estate');
        expect(payload.use_classifications_truncated).toBe(true);
        expect(payload.use_classifications_truncation_notice).toContain(
          `of ${DUPLICATE_GROUP_COUNT * CLONES_PER_GROUP} policies`
        );
        expect(payload.use_classifications_truncation_notice).toContain('narrow the estate');
        expect(payload.exact_duplicate_group_count).toBe(DUPLICATE_GROUP_COUNT);
        expect(payload.policies_in_exact_duplicate_groups).toBe(
          DUPLICATE_GROUP_COUNT * CLONES_PER_GROUP
        );
        expect(payload.use_state_counts).toEqual({
          undetermined: DUPLICATE_GROUP_COUNT * CLONES_PER_GROUP,
        });
      });

      it('would overrun the PLATFORM limit on the same input if each list got the whole budget', async () => {
        givenClonedEstateWithoutAgentPrivilege();

        const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: true })).results[0]
          .data as EstatePayload;

        const [oneGroup] = payload.duplicate_groups;
        const [oneClassification] = payload.use_classifications ?? [];
        const unsplit = { continuation: 'narrow the estate', itemLabel: 'items' };

        const unsplitGroups = boundList({
          items: Array.from({ length: payload.duplicate_groups_total }, () => oneGroup),
          maxItems: MAX_DUPLICATE_GROUPS,
          ...unsplit,
        });
        const unsplitUnused = boundList({
          items: Array.from(
            { length: payload.use_classifications_total ?? 0 },
            () => oneClassification
          ),
          maxItems: MAX_UNUSED_EXEMPLARS,
          ...unsplit,
        });

        expect(unsplitGroups.truncated).toBe(false);
        expect(unsplitGroups.returned).toBe(payload.duplicate_groups_total);
        expect(unsplitUnused.returned).toBe(MAX_UNUSED_EXEMPLARS);

        const unsplitTokens =
          estimateResultTokens(unsplitGroups.items) +
          estimateResultTokens(unsplitUnused.items) +
          ESTATE_ENVELOPE_TOKENS;

        expect(unsplitTokens).toBeGreaterThan(TOOL_RESULT_TOKEN_BUDGET);
        expect(estimateResultTokens(payload)).toBeLessThanOrEqual(RESULT_TOKEN_BUDGET);
      });

      it('cannot let one group MEMBER list escape the duplicate-groups allocation', async () => {
        const memberCount = 30;
        const clones: PackagePolicy[] = [];
        for (let index = 0; index < memberCount; index += 1) {
          clones.push(
            defendPolicy({
              id: `bulky-${index}`,
              name: `Bulky clone ${index} ${'n'.repeat(2_000)}`,
            })
          );
        }
        givenEstate(clones);

        const result = await runTool({ mode: 'estate', includeUnusedAnalysis: false });
        const payload = result.results[0].data as EstatePayload;

        expect(payload.duplicate_groups).toHaveLength(1);

        const [group] = payload.duplicate_groups;

        expect(group.members.length).toBeLessThanOrEqual(MAX_DUPLICATE_GROUP_MEMBERS);
        expect(estimateResultTokens(group)).toBeLessThanOrEqual(DUPLICATE_GROUPS_TOKEN_BUDGET);
        expect(estimateResultTokens(payload.duplicate_groups)).toBeLessThanOrEqual(
          DUPLICATE_GROUPS_TOKEN_BUDGET
        );
        expect(group.members_total).toBe(memberCount);
        expect(group.members_truncated).toBe(true);
        expect(group.members_truncation_notice).toContain(`of ${memberCount}`);
        expect(isWithinResultBudget(payload)).toBe(true);
      });
    });

    describe('registry coverage gap', () => {
      it('excludes an unanswerable policy and discloses the package version', async () => {
        givenEstate([
          defendPolicy({ id: 'p1', name: 'Good' }),
          createDefendPolicyMock({
            id: 'p-bad',
            name: 'Unknown version',
            package: { name: 'endpoint', title: 'Elastic Defend', version: 'unreleased-build' },
          }),
        ]);

        const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: false })).results[0]
          .data as EstatePayload;

        expect(payload.policies_analysed).toBe(1);
        expect(payload.scope_disclosure.partial).toMatchObject({ reason: 'upstream_failure' });
        expect(payload.scope_disclosure.partial?.detail).toContain('unreleased-build');
        expect(payload.message).toContain('unreleased-build');
      });
    });

    describe('search guidance', () => {
      it('states the literal, case-sensitive, non-regex search contract in the schema and tool text', () => {
        const searchDescription = tool.schema.shape.search.description ?? '';

        expect(searchDescription).toContain('CASE-SENSITIVE');
        expect(searchDescription).toContain('NOT a regular expression');
        expect(searchDescription).toContain('NOT a glob');
        expect(searchDescription).toContain('`*`');
        expect(searchDescription).toContain('`.*`');
        expect(searchDescription).toContain('OMIT this parameter');
        expect(searchDescription).toContain('compare_two');
        expect(tool.description).toContain('not regex');
        expect(tool.description).toContain('not glob');
      });

      it('scopes a filtered estate pass to the filter and instructs omitting it for the whole estate', async () => {
        givenEstate([
          defendPolicy({ id: 'p1', name: 'Prod A' }),
          defendPolicy({ id: 'p2', name: 'Prod B' }),
        ]);

        const payload = (
          await runTool({ mode: 'estate', search: 'Prod', includeUnusedAnalysis: false })
        ).results[0].data as EstatePayload;

        expect(payload.policies_analysed).toBe(2);
        expect(payload.message).toContain('you can access matching the name filter "Prod"');
        expect(payload.message).toContain('MATCHING the name filter');
        expect(payload.message).toContain('policies not matching it were not examined');
        expect(payload.message).toContain('Omit `search`');
        expect(payload.message).toContain('every policy the user can access');
        expect(payload.message).not.toMatch(/policies you can access in one pass/);
      });

      it.each(['.*', '*'])(
        'explains an empty result for a wildcard-shaped %s filter instead of letting it read as an empty estate',
        async (search) => {
          givenEstate([]);

          const payload = (await runTool({ mode: 'estate', search, includeUnusedAnalysis: false }))
            .results[0].data as EstatePayload;

          expect(payload.policies_analysed).toBe(0);
          expect(payload.message).toContain('you can access matching');
          expect(payload.message).not.toMatch(
            /No Elastic Defend policies you can access could be analysed/
          );
          expect(payload.message).toContain('literal, case-sensitive substring filter');
          expect(payload.message).toContain('not a regular expression');
          expect(payload.message).toContain('not a glob');
          expect(payload.message).toContain('omit `search`');
          expect(payload.message).toContain('analyse every accessible policy');
        }
      );

      it('keeps the unfiltered estate wording unchanged', async () => {
        givenEstate([defendPolicy({ id: 'p1', name: 'A' })]);

        const payload = (await runTool({ mode: 'estate', includeUnusedAnalysis: false })).results[0]
          .data as EstatePayload;

        expect(payload.message).toContain('Analysed 1 Elastic Defend policy you can access');
        expect(payload.message).toContain('covered all 1 policies across 1 page(s)');
        expect(payload.message).not.toContain('name filter');
        expect(payload.message).not.toContain('Omit `search`');
      });

      it('treats a whitespace-only search as unfiltered exhaustive estate wording', async () => {
        givenEstate([defendPolicy({ id: 'p1', name: 'A' })]);

        const payload = (
          await runTool({ mode: 'estate', search: '   ', includeUnusedAnalysis: false })
        ).results[0].data as EstatePayload;

        expect(payload.message).toContain('Analysed 1 Elastic Defend policy you can access');
        expect(payload.message).toContain('covered all 1 policies across 1 page(s)');
        expect(payload.message).not.toContain('name filter');
        expect(payload.message).not.toContain('Omit `search`');
        const kuery = mocks.packagePolicyService.fetchAllItems.mock.calls[0][1]?.kuery;
        expect(kuery).toContain('package.name: "endpoint"');
        expect(kuery?.includes(' AND ')).toBe(false);
      });
    });
  });

  describe('mode: compare_two', () => {
    it('reports exactly the differing key paths with per-OS attribution', async () => {
      mocks.packagePolicyService.get.mockImplementation(async (_soClient, id) =>
        id === 'p1'
          ? defendPolicy({ id: 'p1', name: 'Base' })
          : defendPolicy({
              id: 'p3',
              name: 'Tuned',
              mutate: (config) => {
                config!.policy.value.windows.malware.blocklist = false;
                config!.policy.value.linux.malware.mode = ProtectionModes.off;
              },
            })
      );

      const result = await runTool({
        mode: 'compare_two',
        leftPolicyId: 'p1',
        rightPolicyId: 'p3',
        includeUnusedAnalysis: false,
      });
      const payload = result.results[0].data as ComparisonPayload;

      expect(payload.comparison.configIdentical).toBe(false);
      expect(payload.comparison.differences).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            keyPath: 'malware.blocklist',
            os: PolicyOperatingSystem.windows,
          }),
          expect.objectContaining({
            keyPath: 'malware.mode',
            os: PolicyOperatingSystem.linux,
          }),
        ])
      );
      for (const difference of payload.comparison.differences) {
        expect(difference.os).toBeDefined();
      }
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('reports an accounting record naming exactly two policies examined', async () => {
      mocks.packagePolicyService.get.mockImplementation(async (_soClient, id) =>
        defendPolicy({ id, name: id })
      );

      const payload = (
        await runTool({
          mode: 'compare_two',
          leftPolicyId: 'p1',
          rightPolicyId: 'p2',
          includeUnusedAnalysis: false,
        })
      ).results[0].data as ComparisonPayload;

      expect(payload.estate_accounting).toMatchObject({ policiesTraversed: 2, complete: true });
      expect(mocks.packagePolicyService.fetchAllItems).not.toHaveBeenCalled();
    });

    it('refuses without both ids, and compares nothing', async () => {
      const result = await runTool({
        mode: 'compare_two',
        leftPolicyId: 'p1',
        includeUnusedAnalysis: false,
      });
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'invalid_request' });
      expect(payload.message).toContain('Nothing was compared');
      expect(mocks.packagePolicyService.get).not.toHaveBeenCalled();
    });

    it('reports a missing policy as not_found without describing it', async () => {
      mocks.packagePolicyService.get.mockImplementation(async (_soClient, id) =>
        id === 'p1' ? defendPolicy({ id: 'p1', name: 'Base' }) : null
      );

      const result = await runTool({
        mode: 'compare_two',
        leftPolicyId: 'p1',
        rightPolicyId: 'ghost',
        includeUnusedAnalysis: false,
      });
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({
        error: 'not_found',
        not_found_policy_ids: ['ghost'],
      });
      expect(payload.message).toContain('Nothing was compared');
    });

    describe('one shared budget across concurrent lists', () => {
      const givenBothResultListsFilledComparison = () => {
        const pem = `-----BEGIN CERTIFICATE-----\n${'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5'.repeat(
          170
        )}\n-----END CERTIFICATE-----`;

        mocks.packagePolicyService.get.mockImplementation(async (_soClient, id) => {
          const isLeft = id === 'left-8x';

          return defendPolicy({
            id,
            name: isLeft ? 'Policy with extra stored leaves' : 'Baseline without those leaves',
            mutate: (config) => {
              for (const os of ['windows', 'mac', 'linux'] as const) {
                const branch = config!.policy.value[os];
                branch.advanced = {
                  ...branch.advanced,
                  artifacts: {
                    global: {
                      ca_cert: `${pem}\n${os}-${id}-global-ca`,
                      ...(isLeft
                        ? {
                            public_key: `${pem}\n${os}-${id}-global-key`,
                            proxy_url: `https://proxy.example.internal/${os}/${id}?chain=${pem}`,
                          }
                        : {}),
                    },
                    ...(isLeft
                      ? {
                          user: {
                            ca_cert: `${pem}\n${os}-${id}-user-ca`,
                            public_key: `${pem}\n${os}-${id}-user-key`,
                            proxy_url: `https://proxy.example.internal/${os}/${id}/user?chain=${pem}`,
                          },
                        }
                      : {}),
                  },
                };
              }
            },
          });
        });
      };

      it('keeps the ASSEMBLED comparison inside the budget with both lists full', async () => {
        givenBothResultListsFilledComparison();

        const result = await runTool({
          mode: 'compare_two',
          leftPolicyId: 'left-8x',
          rightPolicyId: 'right-94',
          includeUnusedAnalysis: false,
        });
        const payload = result.results[0].data as ComparisonPayload;
        const differencesTokens = estimateResultTokens(payload.comparison.differences);

        expect(payload.comparison.not_comparable_total).toBeGreaterThan(0);
        expect(payload.comparison.not_comparable_truncated).toBe(true);
        expect(payload.comparison.differences_total).toBeGreaterThan(0);
        expect(
          payload.comparison.differences_truncated ||
            differencesTokens > COMPARE_DIFFERENCES_TOKEN_BUDGET / 2
        ).toBe(true);

        expect(isWithinResultBudget(payload)).toBe(true);
        expect(estimateResultTokens(result)).toBeLessThan(TOOL_RESULT_TOKEN_BUDGET);

        expect(differencesTokens).toBeLessThanOrEqual(COMPARE_DIFFERENCES_TOKEN_BUDGET);
        expect(estimateResultTokens(payload.comparison.notComparable)).toBeLessThanOrEqual(
          COMPARE_NOT_COMPARABLE_TOKEN_BUDGET
        );

        expect(payload.comparison.not_comparable_truncation_notice).toContain(
          `of ${payload.comparison.not_comparable_total}`
        );
        expect(payload.comparison.not_comparable_truncation_notice).toContain(
          'security.get_defend_policy'
        );
        expect(payload.message).toContain(payload.comparison.not_comparable_truncation_notice);
        expect(payload.message).toContain(
          `${payload.comparison.not_comparable_total} settings could not be compared`
        );
        expect(payload.comparison.notComparable.length).toBeLessThan(
          payload.comparison.not_comparable_total
        );
        if (payload.comparison.differences_truncated) {
          expect(payload.comparison.differences.length).toBeLessThan(
            payload.comparison.differences_total
          );
        }
      });

      it('would overrun the PLATFORM limit on the same comparison if each list got the whole budget', async () => {
        givenBothResultListsFilledComparison();

        const payload = (
          await runTool({
            mode: 'compare_two',
            leftPolicyId: 'left-8x',
            rightPolicyId: 'right-94',
            includeUnusedAnalysis: false,
          })
        ).results[0].data as ComparisonPayload;

        const [oneNotComparable] = payload.comparison.notComparable;
        const unboundedNotComparable = Array.from(
          { length: payload.comparison.not_comparable_total },
          () => oneNotComparable
        );

        expect(estimateResultTokens(unboundedNotComparable)).toBeGreaterThan(
          TOOL_RESULT_TOKEN_BUDGET
        );
        expect(estimateResultTokens(payload)).toBeLessThanOrEqual(RESULT_TOKEN_BUDGET);
      });
    });

    it('keeps a 1000 UUID assignment compare under the wrapped 20k budget with exact counts', async () => {
      const assignmentIds = createUuidAssignmentIds();

      mocks.packagePolicyService.get.mockImplementation(async (_soClient, id) =>
        defendPolicy({
          id,
          name: id,
          policyIds: assignmentIds,
          mutate:
            id === 'p3'
              ? (config) => {
                  config!.policy.value.windows.malware.blocklist = false;
                }
              : undefined,
        })
      );

      const result = await runTool({
        mode: 'compare_two',
        leftPolicyId: 'p1',
        rightPolicyId: 'p3',
        includeUnusedAnalysis: false,
      });
      const payload = result.results[0].data as ComparisonPayload;

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(payload.mode).toBe('compare_two');
      expect(payload.policies).toHaveLength(2);
      for (const policy of payload.policies) {
        expect(policy.agent_policy_id_count).toBe(FLEET_MAX_ASSIGNMENT_IDS);
        expect(policy.agent_policy_id_exemplars).toEqual(
          assignmentIds.slice(0, MAX_AGENT_POLICY_ID_EXEMPLARS)
        );
        expect('agent_policy_ids' in policy).toBe(false);
      }
      expect(payload.comparison.configIdentical).toBe(false);
      expect(payload.comparison.differences_total).toBeGreaterThan(0);
      expect(payload.comparison.differences).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            keyPath: 'malware.blocklist',
            os: PolicyOperatingSystem.windows,
          }),
        ])
      );
      expect(payload.comparison.differences.length).toBeLessThanOrEqual(
        payload.comparison.differences_total
      );
      expect(payload.scope_disclosure.returned).toBe(2);
      expect(payload.scope_disclosure.total).toBe(2);
      expectConfiguredNotAppliedIsResultScoped(payload);
      expect(payload.result_budget_notice).toBeUndefined();
      expectWrappedHandlerWithinPlatformBudget(result);
    });
  });

  describe('authorization denied', () => {
    it('returns an error result before any Fleet read, in either mode', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });

      for (const input of [
        { mode: 'estate' as const, includeUnusedAnalysis: true },
        {
          mode: 'compare_two' as const,
          leftPolicyId: 'p1',
          rightPolicyId: 'p2',
          includeUnusedAnalysis: false,
        },
      ]) {
        const result = await runTool(input);
        const payload = result.results[0].data as ErrorPayload;

        expect(result.results[0].type).toBe(ToolResultType.error);
        expect(payload.metadata).toMatchObject({ error: 'not_authorized' });
        expect(payload.metadata?.need_any).toEqual([
          'Security > Elastic Defend Policy Management: Read',
          'Fleet > Agent policies: Read and Fleet > Integrations: Read',
        ]);
        expect(Object.keys(payload.metadata ?? {}).sort()).toEqual(['error', 'need_any']);
      }

      expect(mocks.packagePolicyService.fetchAllItems).not.toHaveBeenCalled();
      expect(mocks.packagePolicyService.get).not.toHaveBeenCalled();
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('never even constructs the security-extension-excluded saved-objects client, in either mode', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });
      givenEstate([defendPolicy({ id: 'p1', name: 'Prod A' })]);

      for (const input of [
        { mode: 'estate' as const, includeUnusedAnalysis: true },
        {
          mode: 'compare_two' as const,
          leftPolicyId: 'p1',
          rightPolicyId: 'p2',
          includeUnusedAnalysis: false,
        },
      ]) {
        await runTool(input);
      }

      expect(mocks.savedObjects.getScopedClient).not.toHaveBeenCalled();

      mocks.setPrivileges({ securityPolicyManagementRead: true });
      await runTool({ mode: 'estate', includeUnusedAnalysis: false });

      expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
        excludedExtensions: [SECURITY_EXTENSION_ID],
      });
    });
  });

  describe('exception', () => {
    it('becomes an error result rather than a thrown exception', async () => {
      mocks.packagePolicyService.get.mockRejectedValue(new Error('saved objects exploded'));

      const result = await runTool({
        mode: 'compare_two',
        leftPolicyId: 'p1',
        rightPolicyId: 'p2',
        includeUnusedAnalysis: false,
      });
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'unknown_error' });
      expect(payload.message).toContain('saved objects exploded');
      expect(mocks.logger.error).toHaveBeenCalled();
    });

    it('reports Fleet being unavailable without throwing', async () => {
      mocks.withoutFleet();

      const result = await runTool({ mode: 'estate', includeUnusedAnalysis: true });

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect((result.results[0].data as ErrorPayload).message).toContain('Fleet');
    });
  });

  describe('schema', () => {
    it('requires a mode and bounds every string input', () => {
      expect(tool.schema.safeParse({}).success).toBe(false);
      expect(tool.schema.safeParse({ mode: 'pairwise_loop' }).success).toBe(false);
      expect(tool.schema.safeParse({ mode: 'estate', search: 'x'.repeat(257) }).success).toBe(
        false
      );
      expect(
        tool.schema.safeParse({ mode: 'compare_two', leftPolicyId: 'x'.repeat(257) }).success
      ).toBe(false);
      expect(tool.schema.safeParse({ mode: 'estate', unexpected: true }).success).toBe(false);
      expect(tool.schema.safeParse({ mode: 'estate' }).success).toBe(true);
      expect(tool.schema.safeParse({ mode: 'estate', search: '   ' }).success).toBe(true);
      expect(tool.schema.safeParse({ mode: 'estate', search: '   ' }).data?.search).toBeUndefined();
    });

    it('includes the unused analysis by default', () => {
      expect(tool.schema.parse({ mode: 'estate' }).includeUnusedAnalysis).toBe(true);
    });
  });
});
