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
import { buildPolicyFieldRegistry } from '../../domain/field_registry/generate_field_registry';
import {
  COMPARABLE_APPLICABILITY,
  evaluateFieldApplicability,
} from '../../domain/field_registry/applicability';
import { MAX_CHANGE_OPERATIONS } from '../../domain/impact';
import { allowedExperimentalValues } from '../../../../../../common';
import { createAssessDefendPolicyChangeTool } from '.';
import type { DefendPolicyManagementToolMocks } from '../../lib/test_helpers';
import {
  createDefendPolicyMock,
  createDefendPolicyManagementToolMocks,
  expectConfiguredNotAppliedIsResultScoped,
  expectReadOnlyAndNoForbiddenReads,
  expectWrappedHandlerWithinPlatformBudget,
} from '../../lib/test_helpers';

const PINNED_PACKAGE_VERSION = '9.4.0';
const CURRENT_REVISION = 2;
const CURRENT_VERSION = 'WzEyMyw0XQ==';
const FLEET_MAX_PACKAGE_POLICY_ASSIGNMENTS = 1000;
const MAX_PROPOSED_STRING_LENGTH = 4096;

const FLEET_MAX_ASSIGNMENT_IDS = Array.from(
  { length: FLEET_MAX_PACKAGE_POLICY_ASSIGNMENTS },
  (_, index) => `aaaaaaaa-bbbb-4ccc-8ddd-${index.toString().padStart(12, '0')}`
);

const buildMaxStringOperations = (): Array<{
  keyPath: string;
  os: PolicyOperatingSystem;
  proposedValue: string;
}> => {
  const registry = buildPolicyFieldRegistry({ packageVersion: PINNED_PACKAGE_VERSION });
  const operations = registry.fields.flatMap((field) => {
    if (!field.configurable || field.os.length === 0) {
      return [];
    }

    const applicability = evaluateFieldApplicability(field, PINNED_PACKAGE_VERSION);
    if (COMPARABLE_APPLICABILITY[applicability] !== true) {
      return [];
    }

    return [
      {
        keyPath: field.keyPath,
        os: field.os[0],
        proposedValue: 'm'.repeat(MAX_PROPOSED_STRING_LENGTH),
      },
    ];
  });

  const selected = operations.slice(0, MAX_CHANGE_OPERATIONS);
  if (selected.length !== MAX_CHANGE_OPERATIONS) {
    throw new Error(`expected ${MAX_CHANGE_OPERATIONS} operations, got ${selected.length}`);
  }

  return selected;
};

interface AssessmentPayload {
  message: string;
  assessed: true;
  proposal: {
    policyId: string;
    identity: { revision: number; version?: string };
    operations: Array<{
      keyPath: string;
      os?: string;
      expectedCurrentValue?: unknown;
      proposedValue: unknown;
    }>;
  };
  assessedIdentity: { id: string; revision: number; version?: string };
  diffs: Array<{
    keyPath: string;
    os?: string;
    before: unknown;
    after: unknown;
    defaultValue?: unknown;
    type?: string;
    enumValues?: string[];
    documentation?: string;
  }>;
  validatorOutcomes: Array<{ validator: string; passed: boolean; message?: string }>;
  verifiedConfigurationEffects: string[];
  likelyPopulationEffects: string[];
  unknowns: string[];
  applied: false;
  advisory_statement: string;
  configured_not_applied?: string;
  how_to_actually_apply: string;
  result_budget_notice?: string;
  scope_disclosure: { privilege_basis: Record<string, boolean>; returned: number; total: number };
}

interface RejectionPayload {
  message: string;
  assessed: false;
  rejection: {
    reason: string;
    message: string;
    keyPath?: string;
    os?: string;
    currentIdentity?: { id: string; revision: number };
  };
  proposal_submitted: { operations: unknown[] };
  applied: false;
}

interface ErrorPayload {
  message: string;
  metadata?: Record<string, unknown>;
}

describe('security.assess_defend_policy_change', () => {
  let mocks: DefendPolicyManagementToolMocks;
  let tool: ReturnType<typeof createAssessDefendPolicyChangeTool>;

  const runTool = async (input: Parameters<typeof tool.handler>[0]) =>
    (await tool.handler(input, mocks.context)) as ToolHandlerStandardReturn;

  const givenPolicy = (
    mutate?: (config: PackagePolicy['inputs'][0]['config']) => void
  ): PackagePolicy => {
    const policy = createDefendPolicyMock({
      id: 'defend-1',
      revision: CURRENT_REVISION,
      version: CURRENT_VERSION,
      package: { name: 'endpoint', title: 'Elastic Defend', version: PINNED_PACKAGE_VERSION },
    });

    mutate?.(policy.inputs[0].config);
    mocks.packagePolicyService.get.mockResolvedValue(policy);

    return policy;
  };

  const blocklistOff = {
    policyId: 'defend-1',
    revision: CURRENT_REVISION,
    version: CURRENT_VERSION,
    operations: [
      {
        keyPath: 'malware.blocklist',
        os: PolicyOperatingSystem.windows,
        proposedValue: false,
      },
    ],
  };

  beforeEach(() => {
    mocks = createDefendPolicyManagementToolMocks();
    tool = createAssessDefendPolicyChangeTool(mocks.deps);
  });

  describe('success', () => {
    it('echoes back the canonical proposal it actually assessed, verbatim', async () => {
      givenPolicy();

      const result = await runTool(blocklistOff);
      const payload = result.results[0].data as AssessmentPayload;

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(payload.proposal.policyId).toBe('defend-1');
      expect(payload.proposal.identity).toEqual({
        revision: CURRENT_REVISION,
        version: CURRENT_VERSION,
      });
      expect(payload.proposal.operations).toEqual([
        {
          keyPath: 'malware.blocklist',
          os: PolicyOperatingSystem.windows,
          proposedValue: false,
        },
      ]);
      expect(payload.assessedIdentity).toMatchObject({
        id: 'defend-1',
        revision: CURRENT_REVISION,
      });
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('threads trustedDevices experimental state into persist preview', async () => {
      givenPolicy();
      Object.assign(mocks.endpointAppContextService, {
        experimentalFeatures: { ...allowedExperimentalValues, trustedDevices: false },
      });

      const payload = (await runTool(blocklistOff)).results[0].data as AssessmentPayload;

      expect(payload.diffs).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            keyPath: 'malware.blocklist',
            os: PolicyOperatingSystem.windows,
            after: false,
          }),
          expect.objectContaining({
            keyPath: 'device_control.enabled',
            after: undefined,
          }),
        ])
      );
      expect(payload.diffs.length).toBeGreaterThan(1);
    });

    it('passes the enriched diff metadata through: type, enum values, and documentation', async () => {
      givenPolicy();

      const payload = (
        await runTool({
          ...blocklistOff,
          operations: [
            {
              keyPath: 'malware.mode',
              os: PolicyOperatingSystem.windows,
              proposedValue: ProtectionModes.detect,
            },
            {
              keyPath: 'advanced.artifacts.global.interval',
              os: PolicyOperatingSystem.windows,
              proposedValue: '30m',
            },
          ],
        })
      ).results[0].data as AssessmentPayload;

      const modeDiff = payload.diffs.find(({ keyPath }) => keyPath === 'malware.mode');
      expect(modeDiff).toMatchObject({
        type: 'enum',
        enumValues: expect.arrayContaining([ProtectionModes.prevent]),
      });

      const intervalDiff = payload.diffs.find(
        ({ keyPath }) => keyPath === 'advanced.artifacts.global.interval'
      );
      expect(intervalDiff?.type).toBeDefined();
      expect(intervalDiff?.documentation).toBeDefined();
    });

    it('reports applied:false and the advisory statement, never a claim of change', async () => {
      givenPolicy();

      const payload = (await runTool(blocklistOff)).results[0].data as AssessmentPayload;

      expect(payload.applied).toBe(false);
      expect(payload.advisory_statement).toBe('advisory_not_applied');
      expect(payload.message).toContain('advisory only');
      expect(payload.message).not.toContain('advisory_not_applied');
      expect(payload.how_to_actually_apply).toMatch(/Policies/);
      expectConfiguredNotAppliedIsResultScoped(payload);
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('reports the assigned population from Fleet records without claiming execution', async () => {
      givenPolicy();
      mocks.setPrivileges({
        securityPolicyManagementRead: true,
        fleetAgentsRead: true,
      });
      mocks.agentClient.getAgentStatusForAgentPolicy.mockResolvedValue({
        all: 5,
        active: 4,
        inactive: 1,
        unenrolled: 0,
        online: 4,
        error: 0,
        offline: 0,
        updating: 0,
        other: 0,
        events: 0,
      } as Awaited<ReturnType<typeof mocks.agentClient.getAgentStatusForAgentPolicy>>);

      const payload = (await runTool(blocklistOff)).results[0].data as AssessmentPayload;

      expect(payload.likelyPopulationEffects.join(' ')).toContain('population:active_agents:4');
      const getStartServices = jest.mocked(mocks.deps.getStartServices);
      const fleetStart = (await getStartServices.mock.results[0].value)[1].fleet;
      expect(fleetStart?.agentService?.asScoped).toHaveBeenCalledWith(mocks.request);
      expect(payload.unknowns).toContain('runtime:policy_execution_unknown');
    });

    it('emits no agent count at all without the Fleet agent-read privilege', async () => {
      givenPolicy();
      mocks.setPrivileges({
        securityPolicyManagementRead: true,
        fleetAgentsRead: false,
      });

      const payload = (await runTool(blocklistOff)).results[0].data as AssessmentPayload;

      expect(payload.likelyPopulationEffects.join(' ')).toMatch(/could not be determined/i);
      expect(payload.likelyPopulationEffects.join(' ')).not.toMatch(/\b0 enrolled\b/);
      expect(mocks.agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
      const getStartServices = jest.mocked(mocks.deps.getStartServices);
      const fleetStart = (await getStartServices.mock.results[0].value)[1].fleet;
      expect(fleetStart?.agentService?.asScoped).not.toHaveBeenCalled();
    });

    it('fits a maximum-size proposal inside the result budget', async () => {
      givenPolicy();

      const result = await runTool({
        ...blocklistOff,
        operations: Array.from({ length: MAX_CHANGE_OPERATIONS }, (_, index) => ({
          keyPath: 'advanced.artifacts.global.interval',
          os:
            index % 3 === 0
              ? PolicyOperatingSystem.windows
              : index % 3 === 1
              ? PolicyOperatingSystem.mac
              : PolicyOperatingSystem.linux,
          proposedValue: `${index + 1}m`,
        })),
      });

      expectWrappedHandlerWithinPlatformBudget(result);
    });

    it('keeps 10×4096 string operations under the wrapped 20k budget without dropping contract fields', async () => {
      givenPolicy();

      const result = await runTool({
        ...blocklistOff,
        operations: Array.from({ length: 10 }, (_, index) => ({
          keyPath: 'advanced.artifacts.global.interval',
          os:
            index % 3 === 0
              ? PolicyOperatingSystem.windows
              : index % 3 === 1
              ? PolicyOperatingSystem.mac
              : PolicyOperatingSystem.linux,
          proposedValue: 'm'.repeat(4096),
        })),
      });
      const payload = result.results[0].data as AssessmentPayload;
      const keys = Object.keys(payload);

      expectWrappedHandlerWithinPlatformBudget(result);
      expect(payload.result_budget_notice).toBeUndefined();
      expect(payload.applied).toBe(false);
      expect(payload.validatorOutcomes.length).toBeGreaterThan(0);
      expectConfiguredNotAppliedIsResultScoped(payload);
      expect(payload.scope_disclosure.total).toBe(1);
      expect(payload.proposal.operations).toHaveLength(10);
      expect(payload.diffs.length).toBeGreaterThan(0);
      for (const operation of payload.proposal.operations) {
        expect(String(operation.proposedValue).length).toBeLessThan(4096);
        expect(String(operation.proposedValue)).toContain('truncated');
      }
      expect(keys.indexOf('applied')).toBeLessThan(keys.indexOf('proposal'));
      expect(keys.indexOf('validatorOutcomes')).toBeLessThan(keys.indexOf('proposal'));
      expect(keys.indexOf('configured_not_applied')).toBeLessThan(keys.indexOf('proposal'));
      expect(keys.indexOf('scope_disclosure')).toBeLessThan(keys.indexOf('proposal'));
    });

    it('fits 50 max-string operations, 1000 UUID assignments, and silent persist diffs in the wrapped budget', async () => {
      mocks.packagePolicyService.get.mockResolvedValue(
        createDefendPolicyMock({
          id: 'defend-1',
          revision: CURRENT_REVISION,
          version: CURRENT_VERSION,
          package: { name: 'endpoint', title: 'Elastic Defend', version: PINNED_PACKAGE_VERSION },
          policy_ids: [...FLEET_MAX_ASSIGNMENT_IDS],
        })
      );
      Object.assign(mocks.endpointAppContextService, {
        experimentalFeatures: { ...allowedExperimentalValues, trustedDevices: false },
      });

      const operations = buildMaxStringOperations();
      const result = await runTool({
        policyId: 'defend-1',
        revision: CURRENT_REVISION,
        version: CURRENT_VERSION,
        operations,
      });
      const payload = result.results[0].data as AssessmentPayload;
      const serializedPopulation = JSON.stringify(payload.likelyPopulationEffects);
      const serializedResult = JSON.stringify(payload);
      const operationIdentities = operations.map(({ keyPath, os }) => `${os}:${keyPath}`);
      const echoedIdentities = payload.proposal.operations.map(
        ({ keyPath, os }) => `${os ?? ''}:${keyPath}`
      );
      const diffIdentities = new Set(
        payload.diffs.map(({ keyPath, os }) => `${os ?? ''}:${keyPath}`)
      );

      expect(payload.assessed).toBe(true);
      expectWrappedHandlerWithinPlatformBudget(result);
      expect(payload.result_budget_notice).toBeUndefined();
      expect(payload.applied).toBe(false);
      expect(payload.validatorOutcomes).toHaveLength(3);
      expectConfiguredNotAppliedIsResultScoped(payload);
      expect(payload.scope_disclosure.total).toBe(1);
      expect(payload.proposal.operations).toHaveLength(MAX_CHANGE_OPERATIONS);
      expect(payload.diffs.length).toBeGreaterThanOrEqual(MAX_CHANGE_OPERATIONS);
      expect(payload.verifiedConfigurationEffects).toEqual(
        expect.arrayContaining([
          'advisory_not_applied',
          `configuration:changed:${payload.diffs.length}`,
        ])
      );
      expect(payload.likelyPopulationEffects).toEqual(
        expect.arrayContaining(['population:assigned:1000', 'population:lookup_incomplete'])
      );
      expect(FLEET_MAX_ASSIGNMENT_IDS.some((id) => serializedPopulation.includes(id))).toBe(false);
      expect(FLEET_MAX_ASSIGNMENT_IDS.some((id) => serializedResult.includes(id))).toBe(false);
      expect(echoedIdentities).toEqual(operationIdentities);
      for (const identity of operationIdentities) {
        expect(diffIdentities.has(identity)).toBe(true);
      }
      expect(payload.diffs.some(({ keyPath }) => keyPath.includes('device_control'))).toBe(true);
    });
  });

  describe('empty / no-change path', () => {
    it('states plainly that nothing would change when the value already matches', async () => {
      givenPolicy((config) => {
        config!.policy.value.windows.malware.blocklist = false;
      });

      const payload = (await runTool(blocklistOff)).results[0].data as AssessmentPayload;

      expect(payload.diffs).toEqual([]);
      expect(payload.message).toContain('would change no stored configuration value');
      expect(payload.applied).toBe(false);
    });
  });

  describe('rejection', () => {
    it('refuses a stale revision, reports the current identity, and assesses nothing', async () => {
      givenPolicy();

      const result = await runTool({ ...blocklistOff, revision: CURRENT_REVISION - 1 });
      const payload = result.results[0].data as RejectionPayload;

      expect(payload.assessed).toBe(false);
      expect(payload.rejection.reason).toBe('stale_snapshot');
      expect(payload.rejection.currentIdentity).toMatchObject({
        id: 'defend-1',
        revision: CURRENT_REVISION,
      });
      expect(payload).not.toHaveProperty('diffs');
      expect(payload.message).toContain('REFUSED');
      expect(payload.message).not.toContain('advisory_not_applied');
      expect(payload.proposal_submitted.operations).toHaveLength(1);
      expectReadOnlyAndNoForbiddenReads(mocks);
    });
  });

  describe('authorization denied', () => {
    it('returns an error result with no policy metadata, before any Fleet read', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });
      givenPolicy();

      const result = await runTool(blocklistOff);
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'not_authorized' });
      expect(payload.metadata?.need_any).toEqual([
        'Security > Elastic Defend Policy Management: Read',
        'Fleet > Agent policies: Read and Fleet > Integrations: Read',
      ]);
      expect(Object.keys(payload.metadata ?? {}).sort()).toEqual(['error', 'need_any']);
      expect(mocks.packagePolicyService.get).not.toHaveBeenCalled();
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('never even constructs the security-extension-excluded saved-objects client', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });
      givenPolicy();

      await runTool(blocklistOff);

      expect(mocks.savedObjects.getScopedClient).not.toHaveBeenCalled();

      mocks.setPrivileges({ securityPolicyManagementRead: true });
      await runTool(blocklistOff);

      expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
        excludedExtensions: [SECURITY_EXTENSION_ID],
      });
    });

    it('returns not_found for an unknown policy without describing it', async () => {
      mocks.packagePolicyService.get.mockResolvedValue(null);

      const result = await runTool(blocklistOff);
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toEqual({ error: 'not_found' });
    });

    it('returns not_found for a Defend policy with no endpoint input without leaking input details', async () => {
      const policy = createDefendPolicyMock({
        id: 'defend-1',
        package: { name: 'endpoint', title: 'Elastic Defend', version: PINNED_PACKAGE_VERSION },
      });
      mocks.packagePolicyService.get.mockResolvedValue({ ...policy, inputs: [] });

      const result = await runTool(blocklistOff);
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toEqual({ error: 'not_found' });
      expect(payload.message).not.toMatch(/input/i);
      expect(JSON.stringify(payload)).not.toContain(policy.name);
    });
  });

  describe('exception', () => {
    it('becomes an error result rather than a thrown exception', async () => {
      mocks.packagePolicyService.get.mockRejectedValue(new Error('Fleet read failed'));

      const result = await runTool(blocklistOff);
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'unknown_error' });
      expect(payload.message).toContain('Fleet read failed');
      expect(mocks.logger.error).toHaveBeenCalled();
    });

    it('turns an agent-lookup failure into a result rather than a throw', async () => {
      givenPolicy();
      mocks.setPrivileges({
        securityPolicyManagementRead: true,
        fleetAgentsRead: true,
      });
      mocks.agentClient.getAgentStatusForAgentPolicy.mockRejectedValue(new Error('agents down'));

      const result = await runTool(blocklistOff);

      expect(result.results[0].type).toBe(ToolResultType.other);
      const payload = result.results[0].data as AssessmentPayload;
      expect(payload.likelyPopulationEffects.join(' ')).toMatch(/incomplete/i);
    });

    it('reports Fleet being unavailable without throwing', async () => {
      mocks.withoutFleet();

      const result = await runTool(blocklistOff);

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect((result.results[0].data as ErrorPayload).message).toContain('Fleet');
    });
  });

  describe('schema', () => {
    it('caps operations at MAX_CHANGE_OPERATIONS and requires at least one', () => {
      const operation = { keyPath: 'malware.blocklist', proposedValue: false };

      expect(tool.schema.safeParse({ policyId: 'p', revision: 1, operations: [] }).success).toBe(
        false
      );
      expect(
        tool.schema.safeParse({
          policyId: 'p',
          revision: 1,
          operations: Array.from({ length: MAX_CHANGE_OPERATIONS + 1 }, () => operation),
        }).success
      ).toBe(false);
      expect(
        tool.schema.safeParse({
          policyId: 'p',
          revision: 1,
          operations: Array.from({ length: MAX_CHANGE_OPERATIONS }, () => operation),
        }).success
      ).toBe(true);
    });

    it('bounds every string and rejects a non-scalar proposed value', () => {
      const base = { policyId: 'p', revision: 1 };

      expect(
        tool.schema.safeParse({
          ...base,
          operations: [{ keyPath: 'x'.repeat(257), proposedValue: 1 }],
        }).success
      ).toBe(false);
      expect(
        tool.schema.safeParse({
          ...base,
          operations: [{ keyPath: 'k', proposedValue: 'x'.repeat(4097) }],
        }).success
      ).toBe(false);
      expect(
        tool.schema.safeParse({
          ...base,
          operations: [{ keyPath: 'k', proposedValue: { nested: true } }],
        }).success
      ).toBe(false);
      expect(
        tool.schema.safeParse({ ...base, operations: [{ keyPath: 'k', proposedValue: [1, 2] }] })
          .success
      ).toBe(false);
      expect(tool.schema.safeParse({ ...base, revision: -1, operations: [] }).success).toBe(false);
      expect(
        tool.schema.safeParse({
          ...base,
          operations: [{ keyPath: 'k', proposedValue: 1, unexpected: true }],
        }).success
      ).toBe(false);
      expect(
        tool.schema.safeParse({ ...base, operations: [{ keyPath: 'k', proposedValue: 1 }] }).success
      ).toBe(true);
    });

    it('accepts a null proposed value and a null expectation as real values', () => {
      const parsed = tool.schema.parse({
        policyId: 'p',
        revision: 1,
        operations: [{ keyPath: 'k', expectedCurrentValue: null, proposedValue: null }],
      });

      expect(parsed.operations[0].proposedValue).toBeNull();
      expect(parsed.operations[0].expectedCurrentValue).toBeNull();
    });

    it('requires a revision, so a proposal always carries what makes staleness detectable', () => {
      expect(
        tool.schema.safeParse({
          policyId: 'p',
          operations: [{ keyPath: 'k', proposedValue: 1 }],
        }).success
      ).toBe(false);
    });
  });
});
