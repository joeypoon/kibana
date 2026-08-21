/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType, ToolType } from '@kbn/agent-builder-common';
import type { ToolHandlerContext } from '@kbn/agent-builder-server/tools';
import type { StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock, loggingSystemMock } from '@kbn/core/server/mocks';
import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import { createToolHandlerContext } from '../../../__mocks__/test_helpers';
import * as fieldRegistry from '../domain/field_registry';
import { POLICY_TOOL_ERROR_MESSAGES } from './create_policy_tool';
import {
  GET_POLICY_FIELD_REFERENCE_TOOL_ID,
  createGetPolicyFieldReferenceTool,
  getPolicyFieldReferenceSchema,
} from './get_policy_field_reference';
import type { ExactFieldReferenceResult } from './get_policy_field_reference';

jest.mock('../domain/field_registry', () => {
  const actual = jest.requireActual('../domain/field_registry');
  return {
    ...actual,
    getFieldRegistryEntry: jest.fn((path: string) => actual.getFieldRegistryEntry(path)),
  };
});

const SPACE_ID = 'space-marketing';

const createGetStartServices = (): StartServicesAccessor =>
  jest.fn(async () => [
    { savedObjects: { getScopedClient: jest.fn().mockReturnValue({}) } },
  ]) as unknown as StartServicesAccessor;

const createService = (canReadPolicyManagement: boolean) => {
  const endpointAppContextService = createMockEndpointAppContextService();
  const getStartServices = createGetStartServices();
  const scopedFleet = endpointAppContextService.getInternalFleetServices();

  endpointAppContextService.getInternalFleetServices.mockReset();
  endpointAppContextService.getInternalFleetServices.mockReturnValue(scopedFleet);
  endpointAppContextService.getEndpointAuthz.mockResolvedValue(
    getEndpointAuthzInitialStateMock({
      canReadPolicyManagement,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    })
  );

  return { endpointAppContextService, getStartServices };
};

const createContext = (): ToolHandlerContext => {
  const request = httpServerMock.createKibanaRequest();
  return createToolHandlerContext(
    request,
    elasticsearchClientMock.createScopedClusterClient(),
    loggingSystemMock.createLogger(),
    { spaceId: SPACE_ID }
  );
};

const createTool = (canReadPolicyManagement = true) =>
  createGetPolicyFieldReferenceTool(createService(canReadPolicyManagement));

const getResult = async (path: string, canReadPolicyManagement = true) => {
  const tool = createTool(canReadPolicyManagement);
  const result = await tool.handler({ path }, createContext());
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }
  return result.results[0];
};

describe('createGetPolicyFieldReferenceTool', () => {
  it('defines a builtin field-reference tool routed at policy_read', () => {
    const tool = createTool();

    expect(tool.id).toBe(GET_POLICY_FIELD_REFERENCE_TOOL_ID);
    expect(tool.type).toBe(ToolType.builtin);
  });

  it('describes machine-readable registry documentation versus long-form guidance not retrieved by this tool', () => {
    const tool = createTool();

    expect(tool.description).toContain(
      'Look up a single Elastic Defend policy setting by exact path, OS-less protection key, or OS-less remainder.'
    );
    expect(tool.description).toContain(
      'Lookup order is exact path, then protection key, then OS-less remainder.'
    );
    expect(tool.description).toContain(
      'OS-less remainder matching strips exactly one leading supported-OS segment and compares the complete remainder.'
    );
    expect(tool.description).toContain(
      'Found results set `documentationAvailability` to present or absent and `longFormGuidance` to not_retrieved_by_this_tool'
    );
    expect(tool.description).toContain(
      '`longFormGuidance` means this tool did not retrieve long-form guidance; it is not unavailable after Integration Knowledge retrieval'
    );
    expect(tool.description).toContain(
      'Restate `entry.documentation` only when `documentationAvailability` is present'
    );
    expect(tool.description).not.toContain('`longFormGuidance` to unavailable');
    expect(tool.description).not.toContain('`found` and metadata do not document behavior');
    expect(tool.description).not.toContain(
      'When present, `entry.documentation` is short registry documentation and may be restated as such'
    );
  });

  it('returns the existing safe not_authorized result without looking up fields', async () => {
    const lookupSpy = jest.mocked(fieldRegistry.getFieldRegistryEntry);
    lookupSpy.mockClear();

    const result = await getResult('linux.events.dns', false);

    expect(lookupSpy).not.toHaveBeenCalled();
    expect(result.type).toBe(ToolResultType.error);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.not_authorized,
      metadata: { error: 'not_authorized' },
    });
    expect(result.data).not.toHaveProperty('stack');
  });

  it('returns the exact registry entry for a typed event path', async () => {
    const result = await getResult('linux.events.dns');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: true,
      match: 'exact',
      path: 'linux.events.dns',
      documentationAvailability: 'absent',
      longFormGuidance: 'not_retrieved_by_this_tool',
      entry: expect.objectContaining({
        path: 'linux.events.dns',
        kind: 'event',
        tier: 1,
        defaultValue: true,
        source: 'factory',
      }),
    });
    const exact = result.data as ExactFieldReferenceResult;
    expect(exact.entry).not.toHaveProperty('documentation');
    expect(exact.entry).not.toHaveProperty('productFeatureGate');
    expect(exact).not.toHaveProperty('content');
    expect(JSON.stringify(exact)).not.toContain('"longFormGuidance":"unavailable"');
  });

  it('expands an OS-less protection key to the maintained OS set', async () => {
    const result = await getResult('malware.mode');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: true,
      match: 'protection_key_path',
      path: 'malware.mode',
      longFormGuidance: 'not_retrieved_by_this_tool',
      entries: expect.any(Array),
    });
    expect(result.data).not.toHaveProperty('content');

    const { entries } = result.data as {
      entries: Array<{
        documentationAvailability: 'absent' | 'present';
        entry: { path: string; kind: string };
      }>;
    };
    expect(entries).toHaveLength(3);
    expect(entries.map((row) => row.entry.path).sort()).toEqual([
      'linux.malware.mode',
      'mac.malware.mode',
      'windows.malware.mode',
    ]);
    expect(entries.every((row) => row.entry.kind === 'protection')).toBe(true);
    expect(entries.every((row) => row.documentationAvailability === 'absent')).toBe(true);
  });

  it('returns a successful unknown miss for an invented path', async () => {
    const result = await getResult('windows.turbo_mode');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: false,
      match: 'none',
      path: 'windows.turbo_mode',
      reason: 'unknown_path',
    });
  });

  it('expands a valid OS-less non-protection remainder to exact per-OS facts', async () => {
    const result = await getResult('behavior_protection.reputation_service');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: true,
      match: 'os_less_remainder',
      path: 'behavior_protection.reputation_service',
      longFormGuidance: 'not_retrieved_by_this_tool',
      entries: expect.any(Array),
    });

    const { entries } = result.data as {
      entries: Array<{
        documentationAvailability: 'absent' | 'present';
        entry: { path: string; documentation?: string };
      }>;
    };
    expect(entries.map((row) => row.entry.path).sort()).toEqual([
      'linux.behavior_protection.reputation_service',
      'mac.behavior_protection.reputation_service',
      'windows.behavior_protection.reputation_service',
    ]);
    expect(entries.every((row) => row.documentationAvailability === 'absent')).toBe(true);
    expect(entries.every((row) => row.entry.documentation === undefined)).toBe(true);
  });

  it('does not match logging.file to advanced.logging.file remainders', async () => {
    const result = await getResult('logging.file');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: true,
      match: 'os_less_remainder',
      path: 'logging.file',
      longFormGuidance: 'not_retrieved_by_this_tool',
      entries: expect.any(Array),
    });

    const { entries } = result.data as {
      entries: Array<{ entry: { path: string } }>;
    };
    expect(entries.map((row) => row.entry.path).sort()).toEqual([
      'linux.logging.file',
      'mac.logging.file',
      'windows.logging.file',
    ]);
    expect(entries.some((row) => row.entry.path.includes('.advanced.'))).toBe(false);
  });

  it('keeps a wrong-OS exact path unknown instead of falling through to the remainder', async () => {
    const result = await getResult('linux.ransomware.mode');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: false,
      match: 'none',
      path: 'linux.ransomware.mode',
      reason: 'unknown_path',
    });
  });

  it('returns the dual-source exact entry for a schema-and-factory protection', async () => {
    const result = await getResult('mac.ransomware.mode');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: true,
      match: 'exact',
      path: 'mac.ransomware.mode',
      documentationAvailability: 'present',
      longFormGuidance: 'not_retrieved_by_this_tool',
      entry: expect.objectContaining({
        path: 'mac.ransomware.mode',
        kind: 'protection',
        tier: 1,
        source: 'both',
        documentation: expect.stringContaining('Enable ransomware protection for macOS'),
      }),
    });
    expect(result.data).not.toHaveProperty('content');
  });

  it('keeps mixed protection-key documentation availability on each expanded entry', async () => {
    const result = await getResult('ransomware.mode');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: true,
      match: 'protection_key_path',
      path: 'ransomware.mode',
      longFormGuidance: 'not_retrieved_by_this_tool',
      entries: expect.any(Array),
    });

    const { entries } = result.data as {
      entries: Array<{
        documentationAvailability: 'absent' | 'present';
        entry: { path: string; documentation?: string };
      }>;
    };
    expect(entries.map((row) => row.entry.path)).toEqual([
      'windows.ransomware.mode',
      'mac.ransomware.mode',
    ]);
    expect(entries[0]).toEqual({
      documentationAvailability: 'absent',
      entry: expect.objectContaining({ path: 'windows.ransomware.mode' }),
    });
    expect(entries[0]?.entry).not.toHaveProperty('documentation');
    expect(entries[1]).toEqual({
      documentationAvailability: 'present',
      entry: expect.objectContaining({
        path: 'mac.ransomware.mode',
        documentation: expect.stringContaining('Enable ransomware protection for macOS'),
      }),
    });
  });

  it('returns the Protection Updates product-feature gate on global_manifest_version', async () => {
    const result = await getResult('global_manifest_version');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      found: true,
      match: 'exact',
      path: 'global_manifest_version',
      documentationAvailability: 'absent',
      longFormGuidance: 'not_retrieved_by_this_tool',
      entry: expect.objectContaining({
        path: 'global_manifest_version',
        productFeatureGate: 'endpointProtectionUpdates',
        userEditable: true,
      }),
    });
  });

  it('rejects an overlength path at the schema boundary', () => {
    expect(getPolicyFieldReferenceSchema.safeParse({ path: 'a'.repeat(256) }).success).toBe(true);
    expect(getPolicyFieldReferenceSchema.safeParse({ path: 'a'.repeat(257) }).success).toBe(false);
    expect(getPolicyFieldReferenceSchema.safeParse({ path: '' }).success).toBe(false);
  });

  it('rejects extra keys instead of silently ignoring them', () => {
    expect(
      getPolicyFieldReferenceSchema.safeParse({ path: 'linux.events.dns', os: 'linux' }).success
    ).toBe(false);
    expect(getPolicyFieldReferenceSchema.safeParse({ path: 'linux.events.dns' }).success).toBe(
      true
    );
  });

  it('returns a stable unknown_error when lookup throws', async () => {
    const lookupSpy = jest.mocked(fieldRegistry.getFieldRegistryEntry);
    lookupSpy.mockImplementation(() => {
      throw new Error('registry fault');
    });

    try {
      const result = await getResult('linux.events.dns');

      expect(result.type).toBe(ToolResultType.error);
      expect(result.data).toEqual({
        message: POLICY_TOOL_ERROR_MESSAGES.unknown_error,
        metadata: { error: 'unknown_error' },
      });
      expect(result.data).not.toHaveProperty('stack');
      expect(JSON.stringify(result.data)).not.toContain('registry fault');
    } finally {
      lookupSpy.mockImplementation((path: string) =>
        jest.requireActual('../domain/field_registry').getFieldRegistryEntry(path)
      );
    }
  });
});
