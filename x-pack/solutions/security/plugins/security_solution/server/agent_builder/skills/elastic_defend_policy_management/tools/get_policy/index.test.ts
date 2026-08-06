/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import type { ToolHandlerStandardReturn } from '@kbn/agent-builder-server/tools';
import { SavedObjectsErrorHelpers, SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';
import { buildPolicyFieldRegistry } from '../../domain/field_registry/generate_field_registry';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import { createGetDefendPolicyTool, MAX_AGENT_POLICY_ID_EXEMPLARS } from '.';
import {
  estimateResultTokens,
  RESULT_TOKEN_BUDGET,
  TOOL_RESULT_TOKEN_BUDGET,
} from '../../lib/bounded_result';
import type { DefendPolicyManagementToolMocks } from '../../lib/test_helpers';
import {
  createDefendPolicyMock,
  createDefendPolicyManagementToolMocks,
  expectConfiguredNotAppliedIsResultScoped,
  expectReadOnlyAndNoForbiddenReads,
  expectWrappedHandlerWithinPlatformBudget,
} from '../../lib/test_helpers';

const PINNED_PACKAGE_VERSION = '9.4.0';

interface SettingPayload {
  keyPath: string;
  os?: string;
  value: unknown;
  defaultValue?: unknown;
  state: 'explicit' | 'default' | 'indeterminate';
  applicability?: string;
  category?: string;
  stored?: false;
  unrecognized?: true;
  indeterminateReasonCode?: string;
  indeterminateReason?: string;
  type?: string;
  enumValues?: string[];
  enum_values_unavailable?: true;
  documentation?: string;
  documentation_unavailable?: true;
}

interface ReadPayload {
  message: string;
  policy: {
    identity: { id: string; revision: number; version?: string; updatedAt: string };
    name: string;
    description?: string;
    package_version: string;
    agent_policy_id_count: number;
    agent_policy_id_exemplars: string[];
    provenance: {
      createdAt: string;
      createdBy: string;
      updatedAt: string;
      updatedBy: string;
    };
    config_hash: string;
    global_manifest_version: string;
  };
  settings: SettingPayload[];
  settings_summary: {
    total: number;
    explicit: number;
    default: number;
    indeterminate: number;
    applicable: number;
    versionUnavailable: number;
    unsupported: number;
    unknown: number;
    unrecognized: number;
    notStored: number;
  };
  settings_legend: Record<string, string>;
  indeterminate_reason_legend: Record<string, string | undefined>;
  settings_returned: number;
  settings_matching_filter: number;
  settings_filter: 'stored' | 'all' | 'explicit_only';
  settings_selection?: { keyPaths?: string[]; category?: string };
  key_paths_not_found?: string[];
  settings_truncated: boolean;
  settings_truncation_notice?: string;
  result_budget_notice?: string;
  configured_not_applied?: string;
  scope_disclosure: { privilege_basis: Record<string, boolean>; returned: number; total: number };
}

interface ErrorPayload {
  message: string;
  metadata?: Record<string, unknown>;
}

const FLEET_MAX_ASSIGNMENT_IDS = 1000;

const createUuidAssignmentIds = (count = FLEET_MAX_ASSIGNMENT_IDS): string[] =>
  Array.from({ length: count }, (_, index) => {
    const serial = index.toString(16).padStart(12, '0');
    return `aaaaaaaa-bbbb-4ccc-8ddd-${serial}`;
  });

const expectCompactAssignmentEnvelope = ({
  count,
  exemplars,
  assignmentIds,
}: {
  count: number;
  exemplars: readonly string[];
  assignmentIds: readonly string[];
}): void => {
  expect(count).toBe(assignmentIds.length);
  expect(exemplars).toEqual(assignmentIds.slice(0, MAX_AGENT_POLICY_ID_EXEMPLARS));
  expect(exemplars.every((id) => id.length === 36)).toBe(true);
};

const findSetting = (
  settings: readonly SettingPayload[],
  keyPath: string,
  os?: string
): SettingPayload | undefined =>
  settings.find((setting) => setting.keyPath === keyPath && setting.os === os);

describe('security.get_defend_policy', () => {
  let mocks: DefendPolicyManagementToolMocks;
  let tool: ReturnType<typeof createGetDefendPolicyTool>;

  const runTool = async (
    policyId: string,
    settingsFilter: 'stored' | 'all' | 'explicit_only' = 'stored'
  ) =>
    (await tool.handler({ policyId, settingsFilter }, mocks.context)) as ToolHandlerStandardReturn;

  const runToolInput = async (input: Record<string, unknown>) =>
    (await tool.handler(
      input as Parameters<typeof tool.handler>[0],
      mocks.context
    )) as ToolHandlerStandardReturn;

  const givenPolicy = (overrides: Parameters<typeof createDefendPolicyMock>[0] = {}) => {
    const policy = createDefendPolicyMock({
      package: { name: 'endpoint', title: 'Elastic Defend', version: PINNED_PACKAGE_VERSION },
      ...overrides,
    });

    mocks.packagePolicyService.get.mockResolvedValue(policy);

    return policy;
  };

  beforeEach(() => {
    mocks = createDefendPolicyManagementToolMocks();
    tool = createGetDefendPolicyTool(mocks.deps);
  });

  describe('success', () => {
    it('reports identity, provenance, and stored configured settings', async () => {
      givenPolicy({ id: 'defend-7', name: 'Prod Servers', revision: 4 });

      const result = await runTool('defend-7');
      const payload = result.results[0].data as ReadPayload;

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(payload.settings_filter).toBe('stored');
      expect(payload.settings.every(({ stored }) => stored === undefined)).toBe(true);
      expect(payload.policy.identity).toMatchObject({ id: 'defend-7', revision: 4 });
      expect(payload.policy.identity.version).toBeDefined();
      expect(payload.policy.agent_policy_id_count).toBe(1);
      expect(payload.policy.agent_policy_id_exemplars).toEqual(['agent-policy-1']);
      expect('agent_policy_ids' in payload.policy).toBe(false);
      expect(payload.policy.provenance).toEqual({
        createdAt: '2026-01-01T00:00:00.000Z',
        createdBy: 'creator',
        updatedAt: '2026-02-02T00:00:00.000Z',
        updatedBy: 'updater',
      });
      expect(payload.message).toContain('Prod Servers');
      expect(payload.message).toContain('revision 4');
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('covers every configurable field the registry advertises for this package version', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1', 'all')).results[0].data as ReadPayload;
      const registry = buildPolicyFieldRegistry({ packageVersion: PINNED_PACKAGE_VERSION });

      const advertised = new Set<string>();
      for (const field of registry.fields) {
        if (field.configurable) {
          if (field.os.length === 0) {
            advertised.add(`root|${field.keyPath}`);
          } else {
            for (const os of field.os) advertised.add(`${os}|${field.keyPath}`);
          }
        }
      }

      const reported = new Set(
        payload.settings.map(({ keyPath, os }) => `${os ?? 'root'}|${keyPath}`)
      );

      expect([...advertised].filter((key) => !reported.has(key))).toEqual([]);
      expect(payload.settings_truncated).toBe(false);
    });

    it('reports applicability so an unsupported setting is not presented as active configuration', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1')).results[0].data as ReadPayload;

      expect(payload.settings.some(({ applicability }) => applicability === undefined)).toBe(true);
      expect(JSON.stringify(payload.settings_legend)).toContain('applicable');
      expect(payload.settings_legend.applicability_unknown).toContain(
        'registry has no support window'
      );
      expect(payload.settings_legend.applicability_unknown).toContain('NOT evidence');
      expect(
        payload.settings_summary.applicable +
          payload.settings_summary.versionUnavailable +
          payload.settings_summary.unsupported +
          payload.settings_summary.unknown
      ).toBe(payload.settings_summary.total);

      const advertised = (await runTool('defend-1', 'all')).results[0].data as ReadPayload;
      expect(
        advertised.settings.some(({ applicability }) => applicability === 'version_unavailable')
      ).toBe(true);
      expect(advertised.settings.some(({ applicability }) => applicability === 'unknown')).toBe(
        true
      );
    });

    it('omits inferred stored:false rows from an unselected stored read', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1')).results[0].data as ReadPayload;

      expect(payload.settings_filter).toBe('stored');
      expect(payload.settings.some(({ stored }) => stored === false)).toBe(false);
      expect(
        findSetting(
          payload.settings,
          'advanced.agent.connection_delay',
          PolicyOperatingSystem.windows
        )
      ).toBeUndefined();
      expect(payload.settings_summary.notStored).toBeGreaterThan(0);
      expect(payload.settings_matching_filter).toBe(payload.settings.length);
      expect(payload.settings_matching_filter).toBeLessThan(payload.settings_summary.total);
      expect(payload.message).toContain('omitted from this result');
      expect(payload.message).not.toContain('marked `stored: false`');
      expect(JSON.stringify(payload.settings_legend)).toContain('INFERRED');
    });

    it('marks an inferred value stored:false so it cannot pass as an observation', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1', 'all')).results[0].data as ReadPayload;
      const inferred = payload.settings.filter(({ stored }) => stored === false);
      const observed = payload.settings.filter(({ stored }) => stored === undefined);

      expect(inferred.length).toBeGreaterThan(0);
      expect(observed.length).toBeGreaterThan(0);
      expect(inferred.length + observed.length).toBe(payload.settings.length);
      expect(JSON.stringify(payload.settings_legend)).toContain('INFERRED');
      expect(payload.settings_summary.total).toBeGreaterThanOrEqual(payload.settings.length);
      expect(payload.message).toContain('marked `stored: false`');
    });

    it('reports the protection-updates pin as its own dimension, not as a protection setting', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1')).results[0].data as ReadPayload;

      expect(payload.policy.global_manifest_version).toBeDefined();
      expect(payload.policy.config_hash).toBeDefined();
      expect(JSON.stringify(payload)).toContain('protection-updates pin');
    });

    it('fits stored and advertised-all results inside the platform token budget', async () => {
      givenPolicy();

      const stored = await runTool('defend-1');
      const advertised = await runTool('defend-1', 'all');

      expect(estimateResultTokens(stored)).toBeLessThan(TOOL_RESULT_TOKEN_BUDGET);
      expect(estimateResultTokens(advertised)).toBeLessThan(TOOL_RESULT_TOKEN_BUDGET);
    });

    it('keeps a 40k description under the wrapped 20k platform budget', async () => {
      givenPolicy({ description: 'y'.repeat(40_000) });

      const result = await runTool('defend-1');
      const payload = result.results[0].data as ReadPayload;

      expectWrappedHandlerWithinPlatformBudget(result);
      expect(payload.result_budget_notice).toBeUndefined();
      expect(payload.policy.description?.length).toBeLessThan(40_000);
      expect(payload.policy.description).toContain('truncated');
      expect(payload.settings.length).toBeGreaterThan(0);
      expect(payload.settings_summary.total).toBeGreaterThan(0);
      expectConfiguredNotAppliedIsResultScoped(payload);
      expect(mocks.logger.warn).not.toHaveBeenCalled();
    });

    it('truncates an oversized setting string value without dropping filter identity', async () => {
      const policy = givenPolicy();
      policy.inputs[0].config!.policy.value.windows.popup.malware.message = 'y'.repeat(40_000);
      mocks.packagePolicyService.get.mockResolvedValue(policy);

      const result = await runTool('defend-1', 'all');
      const payload = result.results[0].data as ReadPayload;
      const popup = findSetting(
        payload.settings,
        'popup.malware.message',
        PolicyOperatingSystem.windows
      );

      expect(payload.settings_filter).toBe('all');
      expect(payload.settings_returned).toBe(payload.settings.length);
      expect(typeof popup?.value).toBe('string');
      expect(String(popup?.value).length).toBeLessThan(40_000);
      expect(String(popup?.value)).toContain('truncated');
      expectWrappedHandlerWithinPlatformBudget(result);
    });

    it('echoes the requested explicit-only filter and reports its matching denominator', async () => {
      const policy = givenPolicy();
      policy.inputs[0].config!.policy.value.windows.malware.blocklist = false;
      mocks.packagePolicyService.get.mockResolvedValue(policy);

      const payload = (await runTool('defend-1', 'explicit_only')).results[0].data as ReadPayload;

      expect(payload.settings_filter).toBe('explicit_only');
      expect(payload.settings_returned).toBe(payload.settings.length);
      expect(payload.settings_matching_filter).toBe(payload.settings.length);
    });

    it('narrows to deliberately changed settings on request', async () => {
      const policy = givenPolicy();
      policy.inputs[0].config!.policy.value.windows.malware.blocklist = false;
      mocks.packagePolicyService.get.mockResolvedValue(policy);

      const payload = (await runTool('defend-1', 'explicit_only')).results[0].data as ReadPayload;

      expect(payload.settings.length).toBeGreaterThan(0);
      expect(payload.settings.every(({ state }) => state === 'explicit')).toBe(true);
      expect(payload.settings_summary.total).toBeGreaterThan(payload.settings.length);
    });

    it('leaves NO indeterminate setting without a reason the model can state', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1', 'all')).results[0].data as ReadPayload;
      const indeterminate = payload.settings.filter(({ state }) => state === 'indeterminate');

      expect(indeterminate.length).toBeGreaterThan(0);
      expect(indeterminate.length).toBe(payload.settings_summary.indeterminate);

      expect(
        indeterminate
          .filter(
            ({ indeterminateReasonCode, indeterminateReason }) =>
              indeterminateReasonCode === undefined && indeterminateReason === undefined
          )
          .map(({ os, keyPath }) => `${os ?? 'root'}|${keyPath}`)
      ).toEqual([]);

      expect(indeterminate.some(({ stored }) => stored === false)).toBe(true);
      expect(indeterminate.some(({ stored }) => stored === undefined)).toBe(true);
    });

    it('still gives every stored indeterminate setting a reason', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1')).results[0].data as ReadPayload;
      const indeterminate = payload.settings.filter(({ state }) => state === 'indeterminate');

      expect(indeterminate.length).toBeGreaterThan(0);
      expect(indeterminate.every(({ stored }) => stored === undefined)).toBe(true);
      expect(
        indeterminate
          .filter(
            ({ indeterminateReasonCode, indeterminateReason }) =>
              indeterminateReasonCode === undefined && indeterminateReason === undefined
          )
          .map(({ os, keyPath }) => `${os ?? 'root'}|${keyPath}`)
      ).toEqual([]);
    });

    it('explains every emitted reason code in `indeterminate_reason_legend`', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1', 'all')).results[0].data as ReadPayload;
      const emitted = new Set(
        payload.settings
          .map(({ indeterminateReasonCode }) => indeterminateReasonCode)
          .filter((code): code is string => code !== undefined)
      );

      expect(emitted.size).toBeGreaterThan(0);
      expect(
        [...emitted].filter((code) => payload.indeterminate_reason_legend[code] === undefined)
      ).toEqual([]);
    });

    describe('settings the registry has no definition for', () => {
      const givenPolicyWithUnknownKeys = (perOsCount: number, valueLength = 40) => {
        const policy = givenPolicy();
        const config = policy.inputs[0].config!.policy.value;

        for (const os of ['windows', 'mac', 'linux'] as const) {
          const advanced: Record<string, unknown> = { ...config[os].advanced };

          for (let index = 0; index < perOsCount; index += 1) {
            advanced[`smoke_infl_key_${index}`] = 'v'.repeat(valueLength);
          }

          config[os].advanced = advanced;
        }

        mocks.packagePolicyService.get.mockResolvedValue(policy);

        return policy;
      };

      it('counts them in settings_returned, settings_matching_filter, and the summary', async () => {
        givenPolicy();
        const baseline = (await runTool('defend-1')).results[0].data as ReadPayload;

        givenPolicyWithUnknownKeys(3);
        const payload = (await runTool('defend-1')).results[0].data as ReadPayload;
        expect(payload.settings_summary.unrecognized).toBe(9);
        expect(payload.settings_summary.total).toBe(baseline.settings_summary.total + 9);
        expect(payload.settings_matching_filter).toBe(baseline.settings_matching_filter + 9);
        expect(payload.settings_returned).toBe(payload.settings.length);
        expect(payload.settings_truncated).toBe(
          payload.settings_returned < payload.settings_matching_filter
        );
        expect(payload.settings.filter(({ unrecognized }) => unrecognized === true)).toHaveLength(
          9
        );
        expect(payload.message).toContain('9 settings are stored on the policy but have no field');
      });

      it('reports zero unrecognized on a policy carrying only shipped keys', async () => {
        givenPolicy();

        const payload = (await runTool('defend-1')).results[0].data as ReadPayload;

        expect(payload.settings_summary.unrecognized).toBe(0);
        expect(payload.settings.some(({ unrecognized }) => unrecognized === true)).toBe(false);
        expect(payload.message).not.toContain('have no field definition');
      });

      it('trims and discloses truncation once the grown advertised surface exceeds the envelope reserve', async () => {
        givenPolicyWithUnknownKeys(40);

        const payload = (await runTool('defend-1', 'all')).results[0].data as ReadPayload;

        expect(payload.settings_filter).toBe('all');
        expect(payload.settings_summary.unrecognized).toBe(120);
        expect(payload.settings_truncated).toBe(true);
        expect(payload.settings_returned).toBeLessThan(payload.settings_matching_filter);
        expect(payload.settings_truncation_notice).toContain(
          `of ${payload.settings_matching_filter} settings`
        );

        expect(estimateResultTokens(payload)).toBeLessThanOrEqual(RESULT_TOKEN_BUDGET);
        expect(payload.result_budget_notice).toBeUndefined();
        expect(mocks.logger.warn).not.toHaveBeenCalled();
        expect(payload.settings_truncation_notice).toContain('settingsFilter: "explicit_only"');
      });

      it('trims an unselected stored read once unknown stored leaves exceed the envelope', async () => {
        givenPolicyWithUnknownKeys(150);

        const payload = (await runTool('defend-1')).results[0].data as ReadPayload;

        expect(payload.settings_filter).toBe('stored');
        expect(payload.settings_summary.unrecognized).toBe(450);
        expect(payload.settings_truncated).toBe(true);
        expect(payload.settings_returned).toBeLessThan(payload.settings_matching_filter);
        expect(payload.settings.some(({ stored }) => stored === false)).toBe(false);
        expect(payload.settings_truncation_notice).toContain('settingsFilter: "explicit_only"');
      });

      it('does not tell an already-explicit truncated read to retry explicit_only alone', async () => {
        givenPolicyWithUnknownKeys(80, 800);

        const payload = (await runTool('defend-1', 'explicit_only')).results[0].data as ReadPayload;

        expect(payload.settings_filter).toBe('explicit_only');
        expect(payload.settings_truncated).toBe(true);
        expect(payload.settings_truncation_notice).toBeDefined();
        expect(payload.settings_truncation_notice).not.toMatch(
          /Call this tool again with `settingsFilter: "explicit_only"`/
        );
        expect(payload.settings_truncation_notice).toMatch(/keyPaths|category/);
      });

      it('still returns the complete advertised surface untrimmed when nothing is unrecognized', async () => {
        givenPolicy();

        const payload = (await runTool('defend-1', 'all')).results[0].data as ReadPayload;

        expect(payload.settings_filter).toBe('all');
        expect(payload.settings_truncated).toBe(false);
        expect(payload.settings_returned).toBe(payload.settings_summary.total);
      });

      it('returns every stored row untrimmed while keeping the full-surface summary', async () => {
        givenPolicy();

        const payload = (await runTool('defend-1')).results[0].data as ReadPayload;

        expect(payload.settings_filter).toBe('stored');
        expect(payload.settings_truncated).toBe(false);
        expect(payload.settings_returned).toBe(payload.settings_matching_filter);
        expect(payload.settings_matching_filter).toBe(payload.settings.length);
        expect(payload.settings_matching_filter).toBeLessThan(payload.settings_summary.total);
        expect(payload.settings_summary.notStored).toBeGreaterThan(0);
      });

      it('drops shipped defaults before an unrecognized key when it has to trim', async () => {
        givenPolicyWithUnknownKeys(40);

        const payload = (await runTool('defend-1', 'all')).results[0].data as ReadPayload;

        expect(payload.settings.filter(({ unrecognized }) => unrecognized === true)).toHaveLength(
          120
        );
        expect(payload.settings.filter(({ state }) => state === 'default').length).toBeLessThan(
          payload.settings_summary.default
        );
      });
    });
  });

  describe('detail selection', () => {
    it('emits NO documentation, type, or enum metadata on an unselected read', async () => {
      givenPolicy();

      const payload = (await runTool('defend-1')).results[0].data as ReadPayload;

      expect(payload.settings.length).toBeGreaterThan(0);
      for (const setting of payload.settings) {
        expect(setting.documentation).toBeUndefined();
        expect(setting.documentation_unavailable).toBeUndefined();
        expect(setting.type).toBeUndefined();
        expect(setting.enumValues).toBeUndefined();
        expect(setting.enum_values_unavailable).toBeUndefined();
      }
      expect(payload.settings_selection).toBeUndefined();
      expect(payload.settings_legend.selection_enrichment).toContain('ONLY');
    });

    it('enriches selected key paths with type, enum values, and documentation where known', async () => {
      givenPolicy();

      const payload = (await runToolInput({ policyId: 'defend-1', keyPaths: ['malware.mode'] }))
        .results[0].data as ReadPayload;

      expect(payload.settings.length).toBeGreaterThan(0);
      expect(payload.settings.every(({ keyPath }) => keyPath === 'malware.mode')).toBe(true);
      expect(payload.settings_selection).toEqual({ keyPaths: ['malware.mode'] });

      for (const setting of payload.settings) {
        expect(setting.type).toBe('enum');
        expect(setting.enumValues).toEqual(expect.arrayContaining([ProtectionModes.prevent]));
        expect(setting.documentation).toBeUndefined();
        expect(setting.documentation_unavailable).toBe(true);
      }
      expect(payload.key_paths_not_found).toBeUndefined();
    });

    it('does not claim a stored keyPaths selection is the document stored count', async () => {
      givenPolicy();

      const payload = (await runToolInput({ policyId: 'defend-1', keyPaths: ['malware.mode'] }))
        .results[0].data as ReadPayload;

      expect(payload.settings_filter).toBe('stored');
      expect(payload.settings_selection).toEqual({ keyPaths: ['malware.mode'] });
      expect(payload.settings.every(({ stored }) => stored === undefined)).toBe(true);
      expect(payload.settings_matching_filter).toBeGreaterThan(0);
      expect(payload.settings_matching_filter).toBeLessThan(payload.settings_summary.total);
      expect(payload.message).not.toContain(
        `${payload.settings_matching_filter} of ${payload.settings_summary.total} settings are stored on the document`
      );
      expect(payload.message).toContain('explicitly set');
    });

    it('carries the shipped documentation for a documented advanced setting', async () => {
      givenPolicy();

      const payload = (
        await runToolInput({ policyId: 'defend-1', keyPaths: ['advanced.agent.connection_delay'] })
      ).results[0].data as ReadPayload;

      expect(payload.settings.length).toBeGreaterThan(0);
      expect(payload.settings_filter).toBe('stored');
      expect(payload.settings.some(({ stored }) => stored === false)).toBe(true);
      expect(payload.message).toContain('marked `stored: false`');
      for (const setting of payload.settings) {
        expect(setting.documentation).toBeDefined();
        expect(setting.documentation_unavailable).toBeUndefined();
        expect(setting.type).toBeDefined();
      }
    });

    it('reports a selected path that names nothing instead of dropping it silently', async () => {
      givenPolicy();

      const payload = (
        await runToolInput({
          policyId: 'defend-1',
          keyPaths: ['advanced.no_such_setting'],
        })
      ).results[0].data as ReadPayload;

      expect(payload.settings).toEqual([]);
      expect(payload.key_paths_not_found).toEqual(['advanced.no_such_setting']);
    });

    it('marks a selected unrecognized setting as explicitly unknown, inventing no metadata', async () => {
      const policy = givenPolicy();
      const config = policy.inputs[0].config!.policy.value;
      config.windows.advanced = { ...config.windows.advanced, smoke_infl_key_0: 'v' };
      mocks.packagePolicyService.get.mockResolvedValue(policy);

      const payload = (
        await runToolInput({ policyId: 'defend-1', keyPaths: ['advanced.smoke_infl_key_0'] })
      ).results[0].data as ReadPayload;

      expect(payload.settings).toEqual([
        expect.objectContaining({
          keyPath: 'advanced.smoke_infl_key_0',
          os: PolicyOperatingSystem.windows,
          unrecognized: true,
          type: 'unknown',
          documentation_unavailable: true,
        }),
      ]);
      const [setting] = payload.settings;
      expect(setting.documentation).toBeUndefined();
      expect(setting.enumValues).toBeUndefined();
      expect(setting.enum_values_unavailable).toBeUndefined();
      expect(payload.key_paths_not_found).toBeUndefined();
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('selects by category and echoes the selection', async () => {
      givenPolicy();

      const payload = (await runToolInput({ policyId: 'defend-1', category: 'popup' })).results[0]
        .data as ReadPayload;

      expect(payload.settings.length).toBeGreaterThan(0);
      expect(payload.settings.every(({ category }) => category === 'popup')).toBe(true);
      expect(payload.settings_selection).toEqual({ category: 'popup' });
      expect(payload.settings.every(({ type }) => type !== undefined)).toBe(true);
    });

    it('includes advertised unstored advanced rows when selecting that category on the stored default', async () => {
      givenPolicy();

      const payload = (await runToolInput({ policyId: 'defend-1', category: 'advanced' }))
        .results[0].data as ReadPayload;

      expect(payload.settings_filter).toBe('stored');
      expect(payload.settings.length).toBeGreaterThan(0);
      expect(payload.settings.every(({ category }) => category === 'advanced')).toBe(true);
      expect(payload.settings.some(({ stored }) => stored === false)).toBe(true);
      expect(payload.settings.every(({ type }) => type !== undefined)).toBe(true);
      expect(payload.message).toContain('marked `stored: false`');
    });

    it('composes selection with the explicit_only filter', async () => {
      const policy = givenPolicy();
      policy.inputs[0].config!.policy.value.windows.malware.blocklist = false;
      mocks.packagePolicyService.get.mockResolvedValue(policy);

      const payload = (
        await runToolInput({
          policyId: 'defend-1',
          settingsFilter: 'explicit_only',
          keyPaths: ['malware.blocklist', 'malware.mode'],
        })
      ).results[0].data as ReadPayload;

      expect(payload.settings.length).toBeGreaterThan(0);
      expect(payload.settings.every(({ keyPath }) => keyPath === 'malware.blocklist')).toBe(true);
      expect(payload.settings.every(({ state }) => state === 'explicit')).toBe(true);
    });

    it('tells a truncated keyPaths selection to keep that selection', async () => {
      const policy = givenPolicy();
      const config = policy.inputs[0].config!.policy.value;
      const keyPaths = Array.from({ length: 25 }, (_, index) => `advanced.smoke_infl_key_${index}`);

      for (const os of ['windows', 'mac', 'linux'] as const) {
        const advanced: Record<string, unknown> = { ...config[os].advanced };
        for (let index = 0; index < 25; index += 1) {
          advanced[`smoke_infl_key_${index}`] = 'v'.repeat(2_000);
        }
        config[os].advanced = advanced;
      }
      mocks.packagePolicyService.get.mockResolvedValue(policy);

      const payload = (
        await runToolInput({
          policyId: 'defend-1',
          settingsFilter: 'explicit_only',
          keyPaths,
        })
      ).results[0].data as ReadPayload;

      expect(payload.settings_filter).toBe('explicit_only');
      expect(payload.settings_selection).toEqual({ keyPaths });
      expect(payload.settings_truncated).toBe(true);
      expect(payload.settings_truncation_notice).toContain('keyPaths');
      expect(payload.settings_truncation_notice).toContain('explicit_only');
      expect(payload.settings_truncation_notice).toContain('Do not omit');
      expect(payload.settings_truncation_notice).not.toMatch(
        /Call this tool again with `settingsFilter: "explicit_only"` to see just the settings/
      );
    });
  });

  describe('legal Fleet assignment cardinality', () => {
    const assertLegalAssignmentGet = (
      result: ToolHandlerStandardReturn,
      payload: ReadPayload,
      assignmentIds: readonly string[]
    ) => {
      expectCompactAssignmentEnvelope({
        count: payload.policy.agent_policy_id_count,
        exemplars: payload.policy.agent_policy_id_exemplars,
        assignmentIds,
      });
      expect(payload.policy.agent_policy_id_exemplars).toHaveLength(MAX_AGENT_POLICY_ID_EXEMPLARS);
      expect('agent_policy_ids' in payload.policy).toBe(false);
      expect(payload.settings.length).toBeGreaterThan(0);
      expect(payload.settings_summary.total).toBeGreaterThan(0);
      expect(payload.settings_returned).toBe(payload.settings.length);
      expect(payload.scope_disclosure.returned).toBe(1);
      expect(payload.scope_disclosure.total).toBe(1);
      expectConfiguredNotAppliedIsResultScoped(payload);
      expect(payload.result_budget_notice).toBeUndefined();
      expectWrappedHandlerWithinPlatformBudget(result);
    };

    it('keeps a default stored read with 1000 UUID assignments under the wrapped 20k budget', async () => {
      const assignmentIds = createUuidAssignmentIds();
      givenPolicy({ policy_ids: assignmentIds });

      const result = await runTool('defend-1');
      const payload = result.results[0].data as ReadPayload;

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(payload.settings_filter).toBe('stored');
      expect(payload.settings.some(({ stored }) => stored === false)).toBe(false);
      assertLegalAssignmentGet(result, payload, assignmentIds);
    });

    it('keeps an advertised-all read with 1000 UUID assignments under the wrapped 20k budget', async () => {
      const assignmentIds = createUuidAssignmentIds();
      givenPolicy({ policy_ids: assignmentIds });

      const result = await runTool('defend-1', 'all');
      const payload = result.results[0].data as ReadPayload;

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(payload.settings_filter).toBe('all');
      assertLegalAssignmentGet(result, payload, assignmentIds);
    });

    it('keeps a selected advanced read with 1000 UUID assignments under the wrapped 20k budget', async () => {
      const assignmentIds = createUuidAssignmentIds();
      givenPolicy({ policy_ids: assignmentIds });

      const result = await runToolInput({ policyId: 'defend-1', category: 'advanced' });
      const payload = result.results[0].data as ReadPayload;

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(payload.settings_selection).toEqual({ category: 'advanced' });
      expect(payload.settings.every(({ category }) => category === 'advanced')).toBe(true);
      expect(payload.settings.every(({ type }) => type !== undefined)).toBe(true);
      assertLegalAssignmentGet(result, payload, assignmentIds);
    });
  });

  describe('empty / no-result path', () => {
    it('reports the 404 `get` THROWS for a missing id as not_found, leaking no saved-object type', async () => {
      mocks.packagePolicyService.get.mockRejectedValue(
        SavedObjectsErrorHelpers.createGenericNotFoundError(
          'ingest-agent-policies',
          'missing-policy'
        )
      );

      const result = await runTool('missing-policy');
      const payload = result.results[0].data as ErrorPayload;

      expect(payload.metadata).toEqual({ error: 'not_found' });
      expect(payload.message).not.toMatch(/ingest-agent-policies|ingest-package-policies/);
      expect(payload.message).not.toMatch(/saved object/i);
      expect(payload.message).toContain('missing-policy');
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('reports a Defend policy with no endpoint input as not_found without leaking input details', async () => {
      const policy = createDefendPolicyMock({
        package: { name: 'endpoint', title: 'Elastic Defend', version: PINNED_PACKAGE_VERSION },
      });
      mocks.packagePolicyService.get.mockResolvedValue({ ...policy, inputs: [] });

      const result = await runTool('defend-1');
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toEqual({ error: 'not_found' });
      expect(payload.message).toContain('defend-1');
      expect(payload.message).not.toMatch(/input/i);
      expect(JSON.stringify(payload)).not.toContain(policy.name);
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('still reports a genuine upstream failure as unknown_error, not as not_found', async () => {
      mocks.packagePolicyService.get.mockRejectedValue(new Error('elasticsearch unavailable'));

      const payload = (await runTool('defend-1')).results[0].data as ErrorPayload;

      expect(payload.metadata).toMatchObject({ error: 'unknown_error' });
    });
  });

  describe('registry coverage', () => {
    it('reports registry_version_unknown with the nearest known version, and applies no other schema', async () => {
      givenPolicy({
        package: { name: 'endpoint', title: 'Elastic Defend', version: 'unreleased-build' },
      });

      const result = await runTool('defend-1');
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({
        registry_version_unknown: true,
        requested_version: 'unreleased-build',
      });
      expect(payload.metadata?.nearest_known_version).toBeDefined();
      expect(payload.message).toMatch(/NOT read from a different version/i);
    });
  });

  describe('authorization denied', () => {
    it('returns an error result naming the privileges, with no policy metadata', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });
      givenPolicy();

      const result = await runTool('defend-1');
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'not_authorized' });
      expect(payload.metadata?.need_any).toEqual([
        'Security > Elastic Defend Policy Management: Read',
        'Fleet > Agent policies: Read and Fleet > Integrations: Read',
      ]);
      expect(Object.keys(payload.metadata ?? {}).sort()).toEqual(['error', 'need_any']);
      expect(mocks.packagePolicyService.get).not.toHaveBeenCalled();
      expect(JSON.stringify(payload)).not.toMatch(/Defend policy 1/);
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('never even constructs the security-extension-excluded saved-objects client', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });
      givenPolicy();

      await runTool('defend-1');

      expect(mocks.savedObjects.getScopedClient).not.toHaveBeenCalled();

      mocks.setPrivileges({ securityPolicyManagementRead: true });
      await runTool('defend-1');

      expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
        excludedExtensions: [SECURITY_EXTENSION_ID],
      });
    });

    it('succeeds on Fleet integration-policy read alone, without the Security privilege', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: true,
      });
      givenPolicy();

      const result = await runTool('defend-1');
      const payload = result.results[0].data as ReadPayload;

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(payload.scope_disclosure.privilege_basis).toMatchObject({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: true,
      });
    });
  });

  describe('exception', () => {
    it('becomes an error result rather than a thrown exception', async () => {
      mocks.packagePolicyService.get.mockRejectedValue(new Error('saved objects unavailable'));

      const result = await runTool('defend-1');
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'unknown_error' });
      expect(payload.message).toContain('saved objects unavailable');
      expect(mocks.logger.error).toHaveBeenCalled();
    });
  });

  describe('schema', () => {
    it('bounds the policy id and rejects unexpected keys', () => {
      expect(tool.schema.safeParse({ policyId: 'x'.repeat(257) }).success).toBe(false);
      expect(tool.schema.safeParse({ policyId: '' }).success).toBe(false);
      expect(tool.schema.safeParse({}).success).toBe(false);
      expect(tool.schema.safeParse({ policyId: 'p', unexpected: 1 }).success).toBe(false);
      expect(tool.schema.safeParse({ policyId: 'p' }).success).toBe(true);
    });

    it('defaults to stored document fields and still accepts all and explicit_only', () => {
      expect(tool.schema.parse({ policyId: 'p' }).settingsFilter).toBe('stored');
      expect(tool.schema.parse({ policyId: 'p', settingsFilter: 'all' }).settingsFilter).toBe(
        'all'
      );
      expect(
        tool.schema.parse({ policyId: 'p', settingsFilter: 'explicit_only' }).settingsFilter
      ).toBe('explicit_only');
      expect(tool.schema.safeParse({ policyId: 'p', settingsFilter: 'bogus' }).success).toBe(false);
    });

    it('bounds the detail selection and rejects unknown categories', () => {
      expect(tool.schema.safeParse({ policyId: 'p', keyPaths: [] }).success).toBe(false);
      expect(
        tool.schema.safeParse({ policyId: 'p', keyPaths: Array.from({ length: 26 }, () => 'k') })
          .success
      ).toBe(false);
      expect(tool.schema.safeParse({ policyId: 'p', keyPaths: ['x'.repeat(257)] }).success).toBe(
        false
      );
      expect(tool.schema.safeParse({ policyId: 'p', category: 'bogus' }).success).toBe(false);
      expect(
        tool.schema.safeParse({ policyId: 'p', keyPaths: ['malware.mode'], category: 'protection' })
          .success
      ).toBe(true);
    });
  });
});
