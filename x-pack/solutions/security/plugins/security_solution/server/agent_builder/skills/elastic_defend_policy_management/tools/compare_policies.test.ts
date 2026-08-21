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
import { ProtectionModes } from '../../../../../common/endpoint/types';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import { createToolHandlerContext } from '../../../__mocks__/test_helpers';
import { diffPolicyConfig } from '../domain/diff';
import { hashPolicyConfig } from '../domain/hash_policy_config';
import { normalize } from '../domain/normalize';
import type { PolicyAccessContext } from '../services/access_context';
import { InvalidEndpointPolicyError } from '../services/policy_errors';
import type { EndpointPolicyRead } from '../services/read_policy';
import { getEndpointPolicy } from '../services/read_policy';
import {
  COMPARE_POLICIES_TOOL_ID,
  comparePoliciesSchema,
  createComparePoliciesTool,
  type PolicyComparisonRef,
} from './compare_policies';
import { createPolicyTool } from './create_policy_tool';
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

jest.mock('../domain/diff', () => {
  const actual = jest.requireActual('../domain/diff');
  return {
    ...actual,
    diffPolicyConfig: jest.fn((...args: unknown[]) => actual.diffPolicyConfig(...args)),
  };
});

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
const mockedDiffPolicyConfig = jest.mocked(diffPolicyConfig);
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

const getResult = async (left: PolicyComparisonRef, right: PolicyComparisonRef) => {
  const tool = createComparePoliciesTool({
    endpointAppContextService: createMockEndpointAppContextService(),
    getStartServices,
  });
  const result = await tool.handler({ left, right }, createContext());
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }
  return result.results[0];
};

const maxObject = (): Record<string, string> => {
  const value: Record<string, string> = {};
  for (let index = 0; index < 50; index += 1) {
    value[`k${String(index).padStart(2, '0')}`] = 'T'.repeat(512);
  }
  return value;
};

describe('createComparePoliciesTool', () => {
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
    mockedDiffPolicyConfig.mockReset();
    mockedDiffPolicyConfig.mockImplementation((...args) =>
      jest.requireActual('../domain/diff').diffPolicyConfig(...args)
    );
    mockedTrimPolicyResultWithMeta.mockReset();
    mockedTrimPolicyResultWithMeta.mockImplementation((value: unknown, limits?: unknown) =>
      jest.requireActual('./trim_policy_result').trimPolicyResultWithMeta(value, limits)
    );
  });

  it('registers the approved id, policy_read access, and 12000-token budget', () => {
    const endpointAppContextService = createMockEndpointAppContextService();
    const tool = createComparePoliciesTool({ endpointAppContextService, getStartServices });

    expect(mockedCreatePolicyTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
      id: COMPARE_POLICIES_TOOL_ID,
      description: expect.any(String),
      schema: comparePoliciesSchema,
      level: 'policy_read',
      maxResultTokens: 12_000,
      run: expect.any(Function),
    });
    expect(tool.id).toBe(COMPARE_POLICIES_TOOL_ID);
    expect(tool.type).toBe(ToolType.builtin);
    expect(tool.maxResultTokens).toBe(12_000);
  });

  it('accepts two live policy refs and rejects invalid refs', () => {
    expect(
      comparePoliciesSchema.parse({
        left: { type: 'policy', idOrName: '  policy-1  ' },
        right: { type: 'policy', idOrName: 'policy-2' },
      })
    ).toEqual({
      left: { type: 'policy', idOrName: 'policy-1' },
      right: { type: 'policy', idOrName: 'policy-2' },
    });
    expect(
      comparePoliciesSchema.safeParse({
        left: { type: 'policy', idOrName: '' },
        right: { type: 'policy', idOrName: 'policy-2' },
      }).success
    ).toBe(false);
    expect(
      comparePoliciesSchema.safeParse({
        left: { type: 'policy', idOrName: 'a'.repeat(257) },
        right: { type: 'policy', idOrName: 'policy-2' },
      }).success
    ).toBe(false);
    expect(
      comparePoliciesSchema.safeParse({
        left: { type: 'policy' },
        right: { type: 'policy', idOrName: 'policy-2' },
      }).success
    ).toBe(false);
  });

  it('compares two live policies with the same access', async () => {
    const leftRead = createPolicyRead();
    const rightRaw = policyFactory();
    rightRaw.windows.malware.mode = ProtectionModes.detect;
    const rightRead = createPolicyRead({
      policy: { ...leftRead.policy, id: 'policy-2', name: 'Other Policy' },
      normalizedConfig: normalize(rightRaw),
      normalizedHash: hashPolicyConfig(normalize(rightRaw)),
    });
    mockedGetEndpointPolicy.mockResolvedValueOnce(leftRead).mockResolvedValueOnce(rightRead);

    const result = await getResult(
      { type: 'policy', idOrName: 'policy-1' },
      { type: 'policy', idOrName: 'policy-2' }
    );

    expect(mockedGetEndpointPolicy).toHaveBeenCalledTimes(2);
    expect(mockedGetEndpointPolicy).toHaveBeenCalledWith(mockAccess, { idOrName: 'policy-1' });
    expect(mockedGetEndpointPolicy).toHaveBeenCalledWith(mockAccess, { idOrName: 'policy-2' });
    expect(mockedDiffPolicyConfig).toHaveBeenCalledWith(
      leftRead.normalizedConfig,
      rightRead.normalizedConfig
    );
    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual(
      expect.objectContaining({
        left: {
          type: 'policy',
          policy: leftRead.policy,
          normalizedHash: toPresentationHash(leftRead.normalizedHash),
        },
        right: {
          type: 'policy',
          policy: rightRead.policy,
          normalizedHash: toPresentationHash(rightRead.normalizedHash),
        },
        equal: false,
        value_truncated: false,
      })
    );
    expect((result.data as { diffs: unknown[] }).diffs.length).toBeGreaterThan(0);
    expect((result.data as { value_total: number }).value_total).toBe(
      (result.data as { diffs: unknown[] }).diffs.length
    );
  });

  it('returns equal true when the full deterministic diff is empty', async () => {
    const read = createPolicyRead();
    mockedGetEndpointPolicy.mockResolvedValue(read);

    const result = await getResult(
      { type: 'policy', idOrName: 'policy-1' },
      { type: 'policy', idOrName: 'policy-1' }
    );

    expect(result.data).toEqual(
      expect.objectContaining({
        equal: true,
        diffs: [],
        value_total: 0,
        value_truncated: false,
      })
    );
  });

  it('diffs full values first, then presents a budgeted page with truthful totals and parent flags', async () => {
    const leftRead = createPolicyRead();
    const rightRead = createPolicyRead({
      policy: { ...leftRead.policy, id: 'policy-2' },
    });
    const fullDiff = Array.from({ length: 51 }, (_, index) => ({
      path: `windows.advanced.extra_${index}`,
      from: 'x'.repeat(600),
      to: { nested: 'y'.repeat(600) },
    }));
    const order: string[] = [];
    mockedGetEndpointPolicy.mockResolvedValueOnce(leftRead).mockResolvedValueOnce(rightRead);
    mockedDiffPolicyConfig.mockImplementation(() => {
      order.push('diff');
      return fullDiff;
    });
    mockedTrimPolicyResultWithMeta.mockImplementation((value: unknown, limits?: unknown) => {
      order.push('trim');
      return jest.requireActual('./trim_policy_result').trimPolicyResultWithMeta(value, limits);
    });

    const result = await getResult(
      { type: 'policy', idOrName: 'policy-1' },
      { type: 'policy', idOrName: 'policy-2' }
    );
    const dto = result.data as {
      diffs: Array<Record<string, unknown>>;
      value_total: number;
      value_truncated: boolean;
    };

    expect(mockedDiffPolicyConfig).toHaveBeenCalledWith(
      leftRead.normalizedConfig,
      rightRead.normalizedConfig
    );
    expect(order[0]).toBe('diff');
    expect(order.slice(1).every((step) => step === 'trim')).toBe(true);
    expect(mockedTrimPolicyResultWithMeta).toHaveBeenCalledWith(
      fullDiff[0]?.from,
      expect.anything()
    );
    expect(mockedTrimPolicyResultWithMeta).toHaveBeenCalledWith(fullDiff[0]?.to, expect.anything());
    expect(dto.value_total).toBe(51);
    expect(dto.value_truncated).toBe(true);
    expect(dto.diffs.length).toBeGreaterThan(0);
    expect(dto.diffs.length).toBeLessThanOrEqual(50);
    expect(dto.diffs[0]).toEqual(
      expect.objectContaining({
        path: 'windows.advanced.extra_0',
        from: 'x'.repeat(512),
        from_string_truncated: true,
        to: { nested: 'y'.repeat(512), string_truncated: true },
      })
    );
    expect(JSON.stringify(result)).not.toContain('windows.advanced.extra_50');
    expect(JSON.stringify(result)).not.toContain('x'.repeat(513));
    expect(JSON.stringify(result)).not.toContain('y'.repeat(513));
  });

  it('fits 50 large diffs under the 12000-token guarded envelope', async () => {
    const leftRead = createPolicyRead({
      policy: {
        id: 'policy-1',
        name: 'N'.repeat(600),
        description: 'D'.repeat(600),
        revision: 3,
        version: 'WzEsMV0=',
      },
    });
    const rightRead = createPolicyRead({
      policy: {
        id: 'policy-2',
        name: 'M'.repeat(600),
        description: 'E'.repeat(600),
        revision: 4,
        version: 'WzIsMV0=',
      },
    });
    mockedGetEndpointPolicy.mockResolvedValueOnce(leftRead).mockResolvedValueOnce(rightRead);
    mockedDiffPolicyConfig.mockReturnValue(
      Array.from({ length: 50 }, (_, index) => ({
        path: `windows.advanced.extra_${index}`,
        from: 'F'.repeat(512),
        to: maxObject(),
      }))
    );

    const result = await getResult(
      { type: 'policy', idOrName: 'policy-1' },
      { type: 'policy', idOrName: 'policy-2' }
    );
    const dto = result.data as {
      diffs: Array<Record<string, unknown>>;
      left: {
        normalizedHash: string;
        policy: {
          name: string;
          description: string;
          name_string_truncated?: true;
          description_string_truncated?: true;
        };
      };
      value_total: number;
      value_truncated: boolean;
    };
    const envelope = JSON.stringify({ results: [createOtherResult(dto)] });

    expect(result.type).toBe(ToolResultType.other);
    expect(dto.left.normalizedHash).toBe(toPresentationHash(leftRead.normalizedHash));
    expect(dto.left.policy.name).toBe('N'.repeat(512));
    expect(dto.left.policy.description).toBe('D'.repeat(512));
    expect(dto.left.policy.name_string_truncated).toBe(true);
    expect(dto.left.policy.description_string_truncated).toBe(true);
    expect(dto.value_total).toBe(50);
    expect(dto.value_truncated).toBe(true);
    expect(dto.diffs.length).toBeGreaterThan(0);
    expect(dto.diffs.length).toBeLessThan(50);
    expect(dto.diffs[0]?.path).toBe('windows.advanced.extra_0');
    expect(dto.diffs[0]?.from).toBe('F'.repeat(512));
    expect(estimateGuardedEnvelopeTokens(dto)).toBeLessThanOrEqual(12_000);
    expect(estimateTokens(envelope)).toBeLessThanOrEqual(12_000);
    expect(JSON.stringify(result)).not.toContain(leftRead.normalizedHash);
  });

  it('annotates primitive and array from/to truncation on the parent diff entry', async () => {
    const leftRead = createPolicyRead();
    const rightRead = createPolicyRead({
      policy: { ...leftRead.policy, id: 'policy-2' },
    });
    mockedGetEndpointPolicy.mockResolvedValueOnce(leftRead).mockResolvedValueOnce(rightRead);
    mockedDiffPolicyConfig.mockReturnValue([
      {
        path: 'windows.advanced.primitive',
        from: 'Y'.repeat(600),
        to: Array.from({ length: 80 }, (_, index) => `item-${index}`),
      },
    ]);

    const result = await getResult(
      { type: 'policy', idOrName: 'policy-1' },
      { type: 'policy', idOrName: 'policy-2' }
    );
    const [entry] = (result.data as { diffs: Array<Record<string, unknown>> }).diffs;

    expect(entry).toEqual(
      expect.objectContaining({
        path: 'windows.advanced.primitive',
        from: 'Y'.repeat(512),
        from_string_truncated: true,
        to: Array.from({ length: 50 }, (_, index) => `item-${index}`),
        to_value_truncated: true,
        to_value_total: 80,
      })
    );
    expect(JSON.stringify(entry)).not.toContain('Y'.repeat(513));
    expect(JSON.stringify(entry)).not.toContain('item-50');
  });

  it('fits a dual 20k version/updatedBy/updatedAt equal compare under the guarded envelope', async () => {
    const hugeIdentity = {
      id: 'policy-1',
      name: 'Endpoint Policy',
      description: 'visible description',
      revision: 3,
      version: 'V'.repeat(20_000),
      updatedAt: 'A'.repeat(20_000),
      updatedBy: 'B'.repeat(20_000),
    };
    const leftRead = createPolicyRead({ policy: hugeIdentity });
    const rightRead = createPolicyRead({
      policy: { ...hugeIdentity, id: 'policy-2', name: 'Other Policy' },
    });
    mockedGetEndpointPolicy.mockResolvedValueOnce(leftRead).mockResolvedValueOnce(rightRead);

    const result = await getResult(
      { type: 'policy', idOrName: 'policy-1' },
      { type: 'policy', idOrName: 'policy-2' }
    );
    const dto = result.data as {
      left: {
        normalizedHash: string;
        policy: Record<string, unknown>;
      };
      right: { normalizedHash: string; policy: { id: string } };
      equal: boolean;
      diffs: unknown[];
      value_total: number;
      value_truncated: boolean;
    };
    const serialized = JSON.stringify(result);

    expect(result.type).toBe(ToolResultType.other);
    expect(dto.equal).toBe(true);
    expect(dto.diffs).toEqual([]);
    expect(dto.value_total).toBe(0);
    expect(dto.value_truncated).toBe(false);
    expect(dto.left.policy.version).toBe('V'.repeat(512));
    expect(dto.left.policy.updatedAt).toBe('A'.repeat(512));
    expect(dto.left.policy.updatedBy).toBe('B'.repeat(512));
    expect(dto.left.policy).toHaveProperty('version_string_truncated', true);
    expect(dto.left.policy).toHaveProperty('updatedAt_string_truncated', true);
    expect(dto.left.policy).toHaveProperty('updatedBy_string_truncated', true);
    expect(dto.right.policy.id).toBe('policy-2');
    expect(dto.left.normalizedHash).toBe(toPresentationHash(leftRead.normalizedHash));
    expect(dto.right.normalizedHash).toBe(toPresentationHash(rightRead.normalizedHash));
    expect(serialized).not.toContain('V'.repeat(513));
    expect(serialized).not.toContain(leftRead.normalizedHash);
    expect(fitsGuardedEnvelope(dto, 12_000)).toBe(true);
    expect(
      estimateGuardedEnvelopeTokens(dto) + GUARDED_ENVELOPE_HEADROOM_TOKENS
    ).toBeLessThanOrEqual(12_000);
  });

  it('fits even larger dual identity combinations and keep-zero diffs under the guarded envelope', async () => {
    const hugeIdentity = {
      id: 'I'.repeat(80_000),
      name: 'N'.repeat(80_000),
      description: 'D'.repeat(80_000),
      revision: 3,
      version: 'V'.repeat(80_000),
      updatedAt: 'A'.repeat(80_000),
      updatedBy: 'B'.repeat(80_000),
      packageVersion: 'P'.repeat(80_000),
    };
    const leftRead = createPolicyRead({ policy: hugeIdentity });
    const rightRead = createPolicyRead({
      policy: { ...hugeIdentity, id: 'J'.repeat(80_000) },
    });
    mockedGetEndpointPolicy.mockResolvedValueOnce(leftRead).mockResolvedValueOnce(rightRead);
    mockedDiffPolicyConfig.mockReturnValue(
      Array.from({ length: 50 }, (_, index) => ({
        path: `windows.advanced.extra_${index}`,
        from: Array.from({ length: 50 }, () => 'A'.repeat(500)),
        to: Array.from({ length: 50 }, () => 'B'.repeat(500)),
      }))
    );

    const result = await getResult(
      { type: 'policy', idOrName: 'policy-1' },
      { type: 'policy', idOrName: 'policy-2' }
    );
    const dto = result.data as {
      left: { policy: Record<string, unknown>; normalizedHash: string };
      right: { policy: Record<string, unknown> };
      equal: boolean;
      diffs: unknown[];
      value_total: number;
      value_truncated: boolean;
    };

    expect(dto.equal).toBe(false);
    expect(dto.value_total).toBe(50);
    expect(dto.value_truncated).toBe(true);
    expect(dto.diffs.length).toBeLessThan(50);
    expect(dto.left.policy).toEqual(
      expect.objectContaining({
        id: 'I'.repeat(512),
        id_string_truncated: true,
        name: 'N'.repeat(512),
        name_string_truncated: true,
        description: 'D'.repeat(512),
        description_string_truncated: true,
        version: 'V'.repeat(512),
        version_string_truncated: true,
        updatedAt: 'A'.repeat(512),
        updatedBy: 'B'.repeat(512),
        packageVersion: 'P'.repeat(512),
      })
    );
    expect(dto.left.policy).toHaveProperty('updatedAt_string_truncated', true);
    expect(dto.left.policy).toHaveProperty('updatedBy_string_truncated', true);
    expect(dto.left.policy).toHaveProperty('packageVersion_string_truncated', true);
    expect(dto.right.policy.id).toBe('J'.repeat(512));
    expect(dto.left.normalizedHash).toBe(toPresentationHash(leftRead.normalizedHash));
    expect(fitsGuardedEnvelope(dto, 12_000)).toBe(true);
    expect(JSON.stringify(result)).not.toContain('I'.repeat(513));
  });

  it('propagates invalid_policy from a malformed live side', async () => {
    mockedGetEndpointPolicy.mockRejectedValue(new InvalidEndpointPolicyError('broken-id'));

    await expect(
      getResult({ type: 'policy', idOrName: 'broken-id' }, { type: 'policy', idOrName: 'policy-2' })
    ).rejects.toMatchObject({
      name: 'InvalidEndpointPolicyError',
      policyId: 'broken-id',
    });
    expect(mockedTrimPolicyResultWithMeta).not.toHaveBeenCalled();
  });
});
