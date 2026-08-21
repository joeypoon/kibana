/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType, ToolType } from '@kbn/agent-builder-common';
import { estimateTokens } from '@kbn/agent-builder-genai-utils/tools/utils/token_count';
import { createOtherResult } from '@kbn/agent-builder-server';
import type { StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock, loggingSystemMock } from '@kbn/core/server/mocks';
import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import { policyFactory } from '../../../../../common/endpoint/models/policy_config';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import { createToolHandlerContext } from '../../../__mocks__/test_helpers';
import { hashPolicyConfig } from '../domain/hash_policy_config';
import { normalize } from '../domain/normalize';
import type { PolicyAccessContext } from '../services/access_context';
import { InvalidEndpointPolicyError } from '../services/policy_errors';
import type { EndpointPolicyRead } from '../services/read_policy';
import { getEndpointPolicy } from '../services/read_policy';
import { createPolicyTool } from './create_policy_tool';
import { GET_POLICY_TOOL_ID, createGetPolicyTool, getPolicySchema } from './get_policy';
import {
  GUARDED_ENVELOPE_HEADROOM_TOKENS,
  estimateGuardedEnvelopeTokens,
  fitsGuardedEnvelope,
  toPresentationHash,
  trimPolicyResultWithMeta,
} from './trim_policy_result';

jest.mock('../services/read_policy', () => ({
  getEndpointPolicy: jest.fn(),
}));

jest.mock('./create_policy_tool', () => ({
  createPolicyTool: jest.fn(),
}));

jest.mock('./trim_policy_result', () => {
  const actual = jest.requireActual('./trim_policy_result');
  return {
    ...actual,
    trimPolicyResultWithMeta: jest.fn((value: unknown, limits?: unknown) =>
      actual.trimPolicyResultWithMeta(value, limits)
    ),
  };
});

const SPACE_ID = 'space-marketing';
const getStartServices = jest.fn() as unknown as StartServicesAccessor;
const mockedGetEndpointPolicy = jest.mocked(getEndpointPolicy);
const mockedCreatePolicyTool = jest.mocked(createPolicyTool);
const mockedTrimPolicyResultWithMeta = jest.mocked(trimPolicyResultWithMeta);
const mockAccess = {
  spaceId: SPACE_ID,
  level: 'policy_read',
} as PolicyAccessContext<'policy_read'>;

const createPolicyRead = (overrides: Partial<EndpointPolicyRead> = {}): EndpointPolicyRead => {
  const storedConfig = policyFactory();
  const normalizedConfig = normalize(storedConfig);
  return {
    policy: {
      id: 'policy-1',
      name: 'Endpoint Policy',
      description: 'visible description',
      revision: 3,
      version: 'WzEsMV0=',
      updatedAt: '2024-01-01T00:00:00.000Z',
      updatedBy: 'analyst',
      packageVersion: '8.16.0',
    },
    storedConfig,
    normalizedConfig,
    normalizedHash: hashPolicyConfig(normalizedConfig),
    ...overrides,
  };
};

const createContext = () =>
  createToolHandlerContext(
    httpServerMock.createKibanaRequest(),
    elasticsearchClientMock.createScopedClusterClient(),
    loggingSystemMock.createLogger(),
    { spaceId: SPACE_ID }
  );

const getResult = async (idOrName: string) => {
  const tool = createGetPolicyTool({
    endpointAppContextService: createMockEndpointAppContextService(),
    getStartServices,
  });
  const result = await tool.handler({ idOrName }, createContext());
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }
  return result.results[0];
};

describe('createGetPolicyTool', () => {
  beforeEach(() => {
    mockedCreatePolicyTool.mockImplementation((options) => ({
      id: options.id,
      type: ToolType.builtin,
      description: options.description,
      schema: options.schema,
      maxResultTokens: options.maxResultTokens,
      handler: async (params, ctx) => ({
        results: [
          createOtherResult(await options.run(params, mockAccess, { request: ctx.request })),
        ],
      }),
    }));
    mockedGetEndpointPolicy.mockReset();
    mockedTrimPolicyResultWithMeta.mockReset();
    mockedTrimPolicyResultWithMeta.mockImplementation((value: unknown, limits?: unknown) =>
      jest.requireActual('./trim_policy_result').trimPolicyResultWithMeta(value, limits)
    );
  });

  it('registers the approved id, policy_read access, and 12000-token budget', () => {
    const endpointAppContextService = createMockEndpointAppContextService();
    const tool = createGetPolicyTool({ endpointAppContextService, getStartServices });

    expect(mockedCreatePolicyTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
      id: GET_POLICY_TOOL_ID,
      description: expect.any(String),
      schema: getPolicySchema,
      level: 'policy_read',
      maxResultTokens: 12_000,
      run: expect.any(Function),
    });
    expect(tool.id).toBe(GET_POLICY_TOOL_ID);
    expect(tool.type).toBe(ToolType.builtin);
    expect(tool.maxResultTokens).toBe(12_000);
  });

  it('bounds and trims idOrName at the schema boundary', () => {
    expect(getPolicySchema.parse({ idOrName: '  policy-1  ' })).toEqual({ idOrName: 'policy-1' });
    expect(getPolicySchema.safeParse({ idOrName: 'a'.repeat(256) }).success).toBe(true);
    expect(getPolicySchema.safeParse({ idOrName: 'a'.repeat(257) }).success).toBe(false);
    expect(getPolicySchema.safeParse({ idOrName: '' }).success).toBe(false);
    expect(getPolicySchema.safeParse({ idOrName: '   ' }).success).toBe(false);
  });

  it('calls getEndpointPolicy with factory access before trimming presentation', async () => {
    const read = createPolicyRead();
    const order: string[] = [];
    mockedGetEndpointPolicy.mockImplementation(async () => {
      order.push('service');
      return read;
    });
    mockedTrimPolicyResultWithMeta.mockImplementation((value: unknown, limits?: unknown) => {
      order.push('trim');
      return jest.requireActual('./trim_policy_result').trimPolicyResultWithMeta(value, limits);
    });

    const result = await getResult('policy-1');
    const dto = result.data as {
      policy: { id: string };
      normalizedHash: string;
      config: unknown;
    };

    expect(mockedGetEndpointPolicy).toHaveBeenCalledWith(mockAccess, { idOrName: 'policy-1' });
    expect(mockedTrimPolicyResultWithMeta).toHaveBeenCalledWith(
      read.normalizedConfig,
      expect.anything()
    );
    expect(order[0]).toBe('service');
    expect(order.slice(1).every((step) => step === 'trim')).toBe(true);
    expect(order).toContain('trim');
    expect(result.type).toBe(ToolResultType.other);
    expect(dto.policy).toEqual(read.policy);
    expect(dto.normalizedHash).toBe(toPresentationHash(read.normalizedHash));
    expect(dto.config).toEqual(read.normalizedConfig);
  });

  it('keeps identity and a compact digest for one enormous policy under 12000 tokens', async () => {
    const hugeConfig = normalize(policyFactory());
    const windows = hugeConfig.windows as { advanced?: Record<string, unknown> };
    const advanced: Record<string, unknown> = {
      ...(windows.advanced ?? {}),
      long_string: 'Y'.repeat(10_000),
      huge_array: Array.from({ length: 80 }, (_, index) => `item-${index}`),
    };
    for (let index = 0; index < 50; index += 1) {
      advanced[`k${String(index).padStart(2, '0')}`] = 'N'.repeat(512);
    }
    windows.advanced = advanced;
    const serviceHash = hashPolicyConfig(hugeConfig);
    mockedGetEndpointPolicy.mockResolvedValue(
      createPolicyRead({
        normalizedConfig: hugeConfig,
        normalizedHash: serviceHash,
      })
    );

    const result = await getResult('policy-1');
    const dto = result.data as {
      policy: { id: string; name: string; version: string };
      normalizedHash: string;
      config: Record<string, unknown>;
    };
    const envelope = JSON.stringify({ results: [createOtherResult(dto)] });
    const serialized = JSON.stringify(result);

    expect(mockedTrimPolicyResultWithMeta).toHaveBeenCalledWith(hugeConfig, expect.anything());
    expect(result.type).toBe(ToolResultType.other);
    expect(dto.policy).toEqual(
      expect.objectContaining({
        id: 'policy-1',
        name: 'Endpoint Policy',
        version: 'WzEsMV0=',
      })
    );
    expect(dto.normalizedHash).toBe(toPresentationHash(serviceHash));
    expect(dto.normalizedHash).toHaveLength(64);
    expect(result.data).not.toHaveProperty('normalizedConfig');
    expect(serialized).toContain('policy-1');
    expect(serialized).not.toContain(serviceHash);
    expect(serialized).not.toContain('Y'.repeat(10_000));
    expect(serialized).not.toContain('item-50');
    expect(estimateGuardedEnvelopeTokens(dto)).toBeLessThanOrEqual(12_000);
    expect(estimateTokens(envelope)).toBeLessThanOrEqual(12_000);
  });

  it('caps a long presented description and flags only when cut', async () => {
    mockedGetEndpointPolicy.mockResolvedValue(
      createPolicyRead({
        policy: {
          id: 'policy-1',
          name: 'N'.repeat(600),
          description: 'D'.repeat(600),
          revision: 3,
          version: 'WzEsMV0=',
        },
      })
    );

    const longResult = await getResult('policy-1');
    expect(longResult.data).toEqual(
      expect.objectContaining({
        policy: expect.objectContaining({
          id: 'policy-1',
          name: 'N'.repeat(512),
          name_string_truncated: true,
          description: 'D'.repeat(512),
          description_string_truncated: true,
          version: 'WzEsMV0=',
          revision: 3,
        }),
      })
    );

    mockedGetEndpointPolicy.mockResolvedValue(createPolicyRead());
    const shortResult = await getResult('policy-1');
    expect((shortResult.data as { policy: { description: string } }).policy.description).toBe(
      'visible description'
    );
    expect((shortResult.data as { policy: Record<string, unknown> }).policy).not.toHaveProperty(
      'description_string_truncated'
    );
  });

  it('fits a 48k updatedBy identity under the guarded envelope and retains digest identity', async () => {
    const read = createPolicyRead({
      policy: {
        id: 'policy-1',
        name: 'Endpoint Policy',
        description: 'visible description',
        revision: 3,
        version: 'WzEsMV0=',
        updatedAt: '2024-01-01T00:00:00.000Z',
        updatedBy: 'B'.repeat(48_000),
        packageVersion: '8.16.0',
      },
    });
    mockedGetEndpointPolicy.mockResolvedValue(read);

    const result = await getResult('policy-1');
    const dto = result.data as {
      policy: Record<string, unknown>;
      normalizedHash: string;
    };
    const serialized = JSON.stringify(result);

    expect(result.type).toBe(ToolResultType.other);
    expect(dto.policy.id).toBe('policy-1');
    expect(dto.policy.updatedBy).toBe('B'.repeat(512));
    expect(dto.policy).toHaveProperty('updatedBy_string_truncated', true);
    expect(dto.normalizedHash).toBe(toPresentationHash(read.normalizedHash));
    expect(dto.normalizedHash).toHaveLength(64);
    expect(dto.normalizedHash).not.toBe(read.normalizedHash);
    expect(serialized).not.toContain('B'.repeat(513));
    expect(fitsGuardedEnvelope(dto, 12_000)).toBe(true);
    expect(
      estimateGuardedEnvelopeTokens(dto) + GUARDED_ENVELOPE_HEADROOM_TOKENS
    ).toBeLessThanOrEqual(12_000);
  });

  it('caps every oversized get identity string and keeps the digest under budget', async () => {
    const read = createPolicyRead({
      policy: {
        id: 'I'.repeat(80_000),
        name: 'N'.repeat(80_000),
        description: 'D'.repeat(80_000),
        revision: 3,
        version: 'V'.repeat(80_000),
        updatedAt: 'A'.repeat(80_000),
        updatedBy: 'B'.repeat(80_000),
        packageVersion: 'P'.repeat(80_000),
      },
    });
    mockedGetEndpointPolicy.mockResolvedValue(read);

    const result = await getResult('I'.repeat(80_000));
    const dto = result.data as {
      policy: Record<string, unknown>;
      normalizedHash: string;
    };

    expect(dto.policy).toEqual(
      expect.objectContaining({
        id: 'I'.repeat(512),
        id_string_truncated: true,
        name: 'N'.repeat(512),
        name_string_truncated: true,
        description: 'D'.repeat(512),
        description_string_truncated: true,
        revision: 3,
        version: 'V'.repeat(512),
        version_string_truncated: true,
        updatedAt: 'A'.repeat(512),
        updatedBy: 'B'.repeat(512),
        packageVersion: 'P'.repeat(512),
      })
    );
    expect(dto.policy).toHaveProperty('updatedAt_string_truncated', true);
    expect(dto.policy).toHaveProperty('updatedBy_string_truncated', true);
    expect(dto.policy).toHaveProperty('packageVersion_string_truncated', true);
    expect(dto.normalizedHash).toBe(toPresentationHash(read.normalizedHash));
    expect(fitsGuardedEnvelope(dto, 12_000)).toBe(true);
    expect(JSON.stringify(result)).not.toContain('I'.repeat(513));
  });

  it('propagates invalid_policy from the service for a malformed selected policy', async () => {
    mockedGetEndpointPolicy.mockRejectedValue(new InvalidEndpointPolicyError('broken-id'));

    await expect(getResult('broken-id')).rejects.toMatchObject({
      name: 'InvalidEndpointPolicyError',
      policyId: 'broken-id',
    });
    expect(mockedGetEndpointPolicy).toHaveBeenCalledWith(mockAccess, { idOrName: 'broken-id' });
    expect(mockedTrimPolicyResultWithMeta).not.toHaveBeenCalled();
  });
});
