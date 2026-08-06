/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AgentBuilderPluginSetup } from '@kbn/agent-builder-server';
import type { BuiltinSkillBoundedTool, SkillDefinition } from '@kbn/agent-builder-server/skills';
import type { ToolHandlerStandardReturn } from '@kbn/agent-builder-server/tools';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { allowedExperimentalValues } from '../../../../common/experimental_features';
import type { ExperimentalFeatures } from '../../../../common/experimental_features';
import { registerSkills } from '../register_skills';
import {
  ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID,
  createElasticDefendPolicyManagementSkill,
} from './skill';
import { PolicyOperatingSystem } from '../../../../common/endpoint/types';
import {
  createAgentPolicy,
  createEndpointPackagePolicy,
  createUnitedMetadataHit,
  createUnitedMetadataSearchResponse,
  setupAgentPolicies,
  setupEndpointPackagePolicies,
} from './services/policy_apply_state/mocks';
import type { DefendPolicyManagementToolMocks } from './lib/test_helpers';
import {
  ANTI_LEAK_RAW_DATA_MARKERS,
  PROHIBITED_PACKAGE_POLICY_METHODS,
  createAntiLeakSourceFixtures,
  createDefendPolicyMock,
  createDefendPolicyManagementToolMocks,
  expectApplyStateReadsWithinException,
} from './lib/test_helpers';

describe('elastic-defend-policy-management registration', () => {
  const registeredIds = (register: jest.Mock): string[] =>
    register.mock.calls.map(([skill]) => (skill as SkillDefinition).id);

  const runRegistration = async (elasticDefendPolicyManagementSkill: boolean) => {
    const register = jest.fn();
    const mocks = createDefendPolicyManagementToolMocks();

    await registerSkills({
      agentBuilder: {
        skills: { register },
      } as unknown as AgentBuilderPluginSetup,
      experimentalFeatures: {
        ...allowedExperimentalValues,
        elasticDefendPolicyManagementSkill,
      } as ExperimentalFeatures,
      getStartServices: mocks.deps.getStartServices,
      kibanaVersion: '9.4.0',
      logger: mocks.logger,
      ml: undefined,
      options: {
        endpointAppContextService: mocks.deps.endpointAppContextService,
        productFeaturesService: mocks.deps.productFeaturesService,
      },
    });

    return register;
  };

  it('registers the skill when the flag is ON', async () => {
    const register = await runRegistration(true);

    expect(registeredIds(register)).toContain(ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID);
  });

  it('does NOT register the skill when the flag is OFF', async () => {
    const register = await runRegistration(false);

    expect(registeredIds(register)).not.toContain(ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID);
  });

  it('leaves every other skill unaffected by the flag', async () => {
    const withFlag = registeredIds(await runRegistration(true));
    const withoutFlag = registeredIds(await runRegistration(false));

    expect(withFlag.filter((id) => id !== ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID)).toEqual(
      withoutFlag
    );
  });

  it('ships with the flag defaulted to off', () => {
    expect(allowedExperimentalValues.elasticDefendPolicyManagementSkill).toBe(false);
  });
});

describe('elastic-defend-policy-management read-only guarantee', () => {
  let mocks: DefendPolicyManagementToolMocks;

  const exerciseEveryTool = async (): Promise<{
    resultsByToolId: Record<string, string>;
    sourceFixturesSerialized: string;
  }> => {
    const skill = createElasticDefendPolicyManagementSkill(mocks.deps);
    const tools = (await skill.getInlineTools!()) as BuiltinSkillBoundedTool[];

    const policy: PackagePolicy = createDefendPolicyMock({
      id: 'defend-1',
      revision: 2,
      version: 'WzEyMyw0XQ==',
      package: { name: 'endpoint', title: 'Elastic Defend', version: '9.4.0' },
    });
    const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
    const sourceFixtures = createAntiLeakSourceFixtures(policy, endpointPolicy.id);

    mocks.packagePolicyService.get.mockResolvedValue(policy);
    mocks.packagePolicyService.fetchAllItems.mockResolvedValue({
      async *[Symbol.asyncIterator]() {
        yield [policy];
      },
    } as Awaited<ReturnType<typeof mocks.packagePolicyService.fetchAllItems>>);

    setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
    setupAgentPolicies(mocks.agentPolicyService, [createAgentPolicy({ revision: 3 })]);

    const unitedHit = {
      ...createUnitedMetadataHit(sourceFixtures.hostDetailsWrapped as never, {
        policy_id: 'agent-policy-1',
        policy_revision: 3,
      }),
      policy_info: sourceFixtures.hostInfo.policy_info,
      policy_response: sourceFixtures.policyResponseApi.policy_response,
    };
    mocks.applyStateEsClient.search.mockResponse(
      createUnitedMetadataSearchResponse([unitedHit as never])
    );

    const inputsByToolId: Record<string, Record<string, unknown>> = {
      'security.get_defend_policy_inventory': {},
      'security.get_defend_policy': { policyId: 'defend-1', settingsFilter: 'all' },
      'security.analyze_defend_policy_estate': { mode: 'estate', includeUnusedAnalysis: true },
      'security.assess_defend_policy_change': {
        policyId: 'defend-1',
        revision: 2,
        version: 'WzEyMyw0XQ==',
        operations: [
          {
            keyPath: 'malware.blocklist',
            os: PolicyOperatingSystem.windows,
            proposedValue: false,
          },
        ],
      },
      'security.summarize_defend_policy_apply_state': {},
    };

    const resultsByToolId: Record<string, string> = {};

    for (const tool of tools) {
      const input = inputsByToolId[tool.id];

      expect(input).toBeDefined();
      const result = (await tool.handler(input, mocks.context)) as ToolHandlerStandardReturn;

      expect(result.results.length).toBeGreaterThan(0);
      resultsByToolId[tool.id] = JSON.stringify(result);
    }

    const analyzeToolId = 'security.analyze_defend_policy_estate';
    const estateTool = tools.find(({ id }) => id === analyzeToolId)!;
    const compareResult = (await estateTool.handler(
      {
        mode: 'compare_two',
        leftPolicyId: 'defend-1',
        rightPolicyId: 'defend-1',
        includeUnusedAnalysis: false,
      },
      mocks.context
    )) as ToolHandlerStandardReturn;

    expect(compareResult.results.length).toBeGreaterThan(0);
    resultsByToolId[`${analyzeToolId}:compare_two`] = JSON.stringify(compareResult);

    return {
      resultsByToolId,
      sourceFixturesSerialized: sourceFixtures.serialized,
    };
  };

  beforeEach(() => {
    mocks = createDefendPolicyManagementToolMocks();
  });

  it('calls no mutating Fleet package-policy method from any tool', async () => {
    await exerciseEveryTool();

    const called = mocks.calledPackagePolicyMethods();

    expect(called).toEqual(expect.arrayContaining(['get']));
    expect(PROHIBITED_PACKAGE_POLICY_METHODS.filter((method) => called.includes(method))).toEqual(
      []
    );
  });

  it('names every prohibited method explicitly, so a new Fleet write method is a decision', () => {
    expect(PROHIBITED_PACKAGE_POLICY_METHODS).toEqual(
      expect.arrayContaining([
        'create',
        'update',
        'bulkUpdate',
        'delete',
        'upgrade',
        'bulkUpgrade',
        'rollback',
        'restoreRollback',
        'runExternalCallbacks',
        'inspect',
      ])
    );
  });

  it('queries no ES index from the configured-policy tools, and only the apply-state exception index from the apply-state tool', async () => {
    await exerciseEveryTool();

    expect(mocks.searchedIndices()).toEqual([]);
    expectApplyStateReadsWithinException(mocks);
  });

  it('never reaches for the agent client without the Fleet agent-read privilege', async () => {
    mocks.setPrivileges({ fleetAgentsRead: false });

    await exerciseEveryTool();

    expect(mocks.agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
  });

  it('serializes no raw Fleet, artifact, endpoint-metadata, or policy-response shape from any of the five tools', async () => {
    const { resultsByToolId, sourceFixturesSerialized } = await exerciseEveryTool();

    expect(Object.keys(resultsByToolId).sort()).toEqual(
      [
        'security.analyze_defend_policy_estate',
        'security.analyze_defend_policy_estate:compare_two',
        'security.assess_defend_policy_change',
        'security.get_defend_policy',
        'security.get_defend_policy_inventory',
        'security.summarize_defend_policy_apply_state',
      ].sort()
    );

    for (const marker of ANTI_LEAK_RAW_DATA_MARKERS) {
      expect({ marker, presentInFixtures: sourceFixturesSerialized.includes(marker) }).toEqual({
        marker,
        presentInFixtures: true,
      });
    }

    for (const [toolId, serialized] of Object.entries(resultsByToolId)) {
      for (const marker of ANTI_LEAK_RAW_DATA_MARKERS) {
        expect({ toolId, marker, leaked: serialized.includes(marker) }).toEqual({
          toolId,
          marker,
          leaked: false,
        });
      }
    }
  });
});
