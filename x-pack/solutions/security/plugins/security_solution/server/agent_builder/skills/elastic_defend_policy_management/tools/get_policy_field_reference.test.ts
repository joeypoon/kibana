/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType } from '@kbn/agent-builder-common';
import type { ToolHandlerContext } from '@kbn/agent-builder-server/tools';
import { httpServerMock, loggingSystemMock } from '@kbn/core/server/mocks';
import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import { z } from '@kbn/zod/v4';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import { createToolHandlerContext } from '../../../__mocks__/test_helpers';
import { createPolicyTool } from './create_policy_tool';
import {
  GET_POLICY_FIELD_REFERENCE_TOOL_ID,
  createGetPolicyFieldReferenceTool,
  getPolicyFieldReferenceSchema,
} from './get_policy_field_reference';
import type {
  ExactFieldReferenceResult,
  SearchFieldReferenceResult,
} from './get_policy_field_reference';

jest.mock('./create_policy_tool', () => {
  const actual = jest.requireActual('./create_policy_tool');
  return {
    ...actual,
    createPolicyTool: jest.fn((options) => actual.createPolicyTool(options)),
  };
});

const mockedCreatePolicyTool = jest.mocked(createPolicyTool);

const SPACE_ID = 'space-marketing';

const createService = (canReadPolicyManagement: boolean) => {
  const endpointAppContextService = createMockEndpointAppContextService();
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

  return { endpointAppContextService };
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
  const result = await tool.handler({ selector: { path } }, createContext());
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }
  return result.results[0];
};

const getQueryResult = async (query: string, canReadPolicyManagement = true) => {
  const tool = createTool(canReadPolicyManagement);
  const result = await tool.handler({ selector: { query } }, createContext());
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }
  return result.results[0];
};

describe('createGetPolicyFieldReferenceTool', () => {
  it('defines a builtin field-reference tool with the approved id and schema', () => {
    const deps = createService(true);
    createGetPolicyFieldReferenceTool(deps);

    expect(mockedCreatePolicyTool).toHaveBeenCalledWith(
      expect.objectContaining({
        endpointAppContextService: deps.endpointAppContextService,
        id: GET_POLICY_FIELD_REFERENCE_TOOL_ID,
        schema: getPolicyFieldReferenceSchema,
      })
    );
  });

  it('returns the exact registry entry with writability facts and accepted values', async () => {
    const result = await getResult('linux.events.dns');

    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual(
      expect.objectContaining({
        found: true,
        match: 'exact',
        path: 'linux.events.dns',
        documentationAvailability: 'absent',
        longFormGuidance: 'not_retrieved_by_this_tool',
        entry: expect.objectContaining({
          path: 'linux.events.dns',
        }),
      })
    );
    const exact = result.data as ExactFieldReferenceResult;
    expect(exact).not.toHaveProperty('content');
    expect(JSON.stringify(exact)).not.toContain('"longFormGuidance":"unavailable"');

    const usb = await getResult('windows.device_control.usb_storage');

    expect(usb.type).toBe(ToolResultType.other);
    expect(usb.data).toEqual({
      found: true,
      match: 'exact',
      path: 'windows.device_control.usb_storage',
      documentationAvailability: 'absent',
      longFormGuidance: 'not_retrieved_by_this_tool',
      writable: true,
      acceptedValues: { type: 'enum', values: ['audit', 'read_only', 'no_execute', 'deny_all'] },
      entry: expect.objectContaining({
        path: 'windows.device_control.usb_storage',
      }),
    });
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
        writable: boolean;
        not_writable_reason?: string;
        acceptedValues?: { type: string };
        entry: { path: string; documentation?: string };
      }>;
    };
    expect(entries.map((row) => row.entry.path).sort()).toEqual([
      'linux.behavior_protection.reputation_service',
      'mac.behavior_protection.reputation_service',
      'windows.behavior_protection.reputation_service',
    ]);
    expect(entries.every((row) => row.documentationAvailability === 'absent')).toBe(true);
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
        writable: boolean;
        not_writable_reason?: string;
        acceptedValues?: { type: string };
        entry: { path: string; documentation?: string };
      }>;
    };
    expect(entries.map((row) => row.entry.path)).toEqual([
      'windows.ransomware.mode',
      'mac.ransomware.mode',
    ]);
    expect(entries[0]).toEqual(
      expect.objectContaining({
        documentationAvailability: 'absent',
        entry: expect.objectContaining({ path: 'windows.ransomware.mode' }),
      })
    );
    expect(entries[0]?.entry).not.toHaveProperty('documentation');
    expect(entries[1]).toEqual(
      expect.objectContaining({
        documentationAvailability: 'present',
        entry: expect.objectContaining({
          path: 'mac.ransomware.mode',
          documentation: expect.stringContaining('Enable ransomware protection for macOS'),
        }),
      })
    );
  });

  it('returns ranked device control search results with both settings and accepted values', async () => {
    const result = await getQueryResult('device control');

    expect(result.type).toBe(ToolResultType.other);
    const data = result.data as SearchFieldReferenceResult;
    expect(data.found).toBe(true);
    expect(data.match).toBe('search');
    expect(data.query).toBe('device control');
    expect(data).not.toHaveProperty('osFilter');
    expect(data.results_truncated).toBe(false);
    expect(data.candidates_truncated).toBe(false);
    expect(data.results_total).toBe(data.results.length);

    const byPath = new Map(data.results.map((hit) => [hit.path, hit]));
    expect(byPath.get('windows.device_control.enabled')).toEqual({
      path: 'windows.device_control.enabled',
      os: ['windows'],
      writable: true,
      acceptedValues: { type: 'boolean' },
      matchedTerms: ['device', 'control'],
      score: 2,
    });
    expect(byPath.get('windows.device_control.usb_storage')).toEqual({
      path: 'windows.device_control.usb_storage',
      os: ['windows'],
      writable: true,
      acceptedValues: {
        type: 'enum',
        values: ['audit', 'read_only', 'no_execute', 'deny_all'],
      },
      matchedTerms: ['device', 'control'],
      score: 2,
    });

    const usbDomain = byPath.get('windows.device_control.usb_storage')?.acceptedValues;
    if (usbDomain?.type !== 'enum') {
      throw new Error('expected an enum domain for usb_storage');
    }
    expect(usbDomain.values).not.toContain('full_access');

    const coupledPopup = byPath.get('windows.popup.device_control.enabled');
    expect(coupledPopup).toEqual({
      path: 'windows.popup.device_control.enabled',
      os: ['windows'],
      writable: false,
      not_writable_reason: 'coupled_only',
      matchedTerms: ['device', 'control'],
      score: 2,
    });
    expect(coupledPopup).not.toHaveProperty('acceptedValues');
  });

  it('emits native Zod v4 JSON Schema with a required root selector and strict exclusive branches', () => {
    const jsonSchema = z.toJSONSchema(getPolicyFieldReferenceSchema, { io: 'input' });

    expect(jsonSchema.type).toBe('object');
    expect(jsonSchema.required).toEqual(['selector']);

    const selectorSchema = jsonSchema.properties?.selector;
    expect(selectorSchema).toBeDefined();
    if (typeof selectorSchema !== 'object') {
      throw new Error('expected a selector object schema');
    }
    const branches = selectorSchema.anyOf ?? [];
    expect(branches).toHaveLength(2);
    for (const field of ['path', 'query'] as const) {
      const branch = branches.find((b) => field in (b.properties ?? {}));
      expect(branch).toBeDefined();
      expect(branch?.type).toBe('object');
      expect(branch?.required).toEqual([field]);
      expect(branch?.additionalProperties).toBe(false);
    }
  });
});
