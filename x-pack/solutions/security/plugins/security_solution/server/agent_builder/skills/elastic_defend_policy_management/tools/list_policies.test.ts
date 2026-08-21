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
import type { z } from '@kbn/zod/v4';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import { createToolHandlerContext } from '../../../__mocks__/test_helpers';
import type { PolicyAccessContext } from '../services/access_context';
import { createPolicyAccessContext } from '../services/access_context';
import { countEndpoints } from '../services/count_endpoints';
import type { EndpointCountResult } from '../services/count_endpoints';
import { PolicyAuthorizationError } from '../services/policy_errors';
import type { ListPoliciesDto, ListPolicyItem } from '../services/read_estate';
import { listEndpointPolicies } from '../services/read_estate';
import { policyFactory } from '../../../../../common/endpoint/models/policy_config';
import { hashPolicyConfig } from '../domain/hash_policy_config';
import { normalize } from '../domain/normalize';
import { createPolicyTool } from './create_policy_tool';
import { LIST_POLICIES_TOOL_ID, createListPoliciesTool, listPoliciesSchema } from './list_policies';
import { estimateGuardedEnvelopeTokens, toPresentationHash } from './trim_policy_result';

jest.mock('../services/read_estate', () => ({
  listEndpointPolicies: jest.fn(),
}));

jest.mock('../services/count_endpoints', () => ({
  countEndpoints: jest.fn(),
}));

jest.mock('../services/access_context', () => {
  const actual = jest.requireActual('../services/access_context');
  return {
    ...actual,
    createPolicyAccessContext: jest.fn(),
  };
});

jest.mock('./create_policy_tool', () => ({
  createPolicyTool: jest.fn(),
}));

const SPACE_ID = 'space-marketing';
const getStartServices = jest.fn() as unknown as StartServicesAccessor;
const mockedListEndpointPolicies = jest.mocked(listEndpointPolicies);
const mockedCreatePolicyTool = jest.mocked(createPolicyTool);
const mockedCreatePolicyAccessContext = jest.mocked(createPolicyAccessContext);
const mockedCountEndpoints = jest.mocked(countEndpoints);
const mockAccess = {
  spaceId: SPACE_ID,
  level: 'policy_read',
} as PolicyAccessContext<'policy_read'>;
const mockEstateAccess = {
  spaceId: SPACE_ID,
  level: 'estate_read',
} as PolicyAccessContext<'estate_read'>;

type ListedItem = ListPolicyItem & {
  usage?: {
    classification: string;
    reason?: string;
    enrolled?: number;
  };
};

const createPosture = () => ({
  windowsProtectionModes: {
    malware: 'prevent',
    ransomware: 'prevent',
    memoryThreat: 'prevent',
    behavior: 'prevent',
  },
  macProtectionModes: {
    malware: 'prevent',
    behavior: 'prevent',
  },
  linuxProtectionModes: {
    malware: 'prevent',
    behavior: 'prevent',
  },
  globalTelemetryEnabled: false,
});

const createListItem = (overrides: Partial<ListPolicyItem> = {}): ListPolicyItem => ({
  id: 'policy-1',
  name: 'Endpoint Policy',
  description: 'visible description',
  revision: 3,
  version: 'WzEsMV0=',
  normalizedHash: 'full-list-hash',
  posture: createPosture(),
  ...overrides,
});

const createListDto = (overrides: Partial<ListPoliciesDto> = {}): ListPoliciesDto => ({
  population: 'endpoint_package_policies',
  page: 1,
  per_page: 20,
  items: [createListItem()],
  value_total: 1,
  has_more: false,
  invalid_policy_count: 0,
  ...overrides,
});

const createContext = () =>
  createToolHandlerContext(
    httpServerMock.createKibanaRequest(),
    elasticsearchClientMock.createScopedClusterClient(),
    loggingSystemMock.createLogger(),
    { spaceId: SPACE_ID }
  );

const getResult = async (params: z.input<typeof listPoliciesSchema> = {}) => {
  const parsed = listPoliciesSchema.parse(params);
  const tool = createListPoliciesTool({
    endpointAppContextService: createMockEndpointAppContextService(),
    getStartServices,
  });
  const result = await tool.handler(parsed, createContext());
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }
  return result.results[0];
};

describe('createListPoliciesTool', () => {
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
    mockedListEndpointPolicies.mockReset();
    mockedCreatePolicyAccessContext.mockReset();
    mockedCountEndpoints.mockReset();
  });

  it('registers the approved id, policy_read access, and 8000-token budget', () => {
    const endpointAppContextService = createMockEndpointAppContextService();
    const tool = createListPoliciesTool({ endpointAppContextService, getStartServices });

    expect(mockedCreatePolicyTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
      id: LIST_POLICIES_TOOL_ID,
      description: expect.any(String),
      schema: listPoliciesSchema,
      level: 'policy_read',
      maxResultTokens: 8_000,
      run: expect.any(Function),
    });
    expect(tool.id).toBe(LIST_POLICIES_TOOL_ID);
    expect(tool.type).toBe(ToolType.builtin);
    expect(tool.maxResultTokens).toBe(8_000);
  });

  it('bounds page and perPage at the schema boundary', () => {
    expect(listPoliciesSchema.parse({})).toEqual({
      page: 1,
      perPage: 20,
      includeUsage: false,
    });
    expect(listPoliciesSchema.parse({ includeUsage: true })).toEqual({
      page: 1,
      perPage: 20,
      includeUsage: true,
    });
    expect(listPoliciesSchema.safeParse({ page: 1, perPage: 1 }).success).toBe(true);
    expect(listPoliciesSchema.safeParse({ page: 10_000, perPage: 50 }).success).toBe(true);
    expect(listPoliciesSchema.safeParse({ page: 0, perPage: 20 }).success).toBe(false);
    expect(listPoliciesSchema.safeParse({ page: 10_001, perPage: 20 }).success).toBe(false);
    expect(listPoliciesSchema.safeParse({ page: 1, perPage: 0 }).success).toBe(false);
    expect(listPoliciesSchema.safeParse({ page: 1, perPage: 51 }).success).toBe(false);
    expect(listPoliciesSchema.safeParse({ page: 1.5, perPage: 20 }).success).toBe(false);
  });

  it('calls listEndpointPolicies with factory access and requested paging', async () => {
    const dto = createListDto({ page: 2, per_page: 10, value_total: 21, has_more: true });
    mockedListEndpointPolicies.mockResolvedValue(dto);

    const result = await getResult({ page: 2, perPage: 10 });

    expect(mockedListEndpointPolicies).toHaveBeenCalledTimes(1);
    expect(mockedListEndpointPolicies).toHaveBeenCalledWith(mockAccess, { page: 2, perPage: 10 });
    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual({
      ...dto,
      items: dto.items.map((item) => ({
        ...item,
        normalizedHash: toPresentationHash(item.normalizedHash),
      })),
    });
  });

  it('returns the service DTO including pagination and invalid-row metadata', async () => {
    const dto = createListDto({
      page: 1,
      per_page: 20,
      value_total: 21,
      has_more: true,
      invalid_policy_count: 2,
      items: [createListItem({ id: 'valid-only' })],
    });
    mockedListEndpointPolicies.mockResolvedValue(dto);

    const result = await getResult({ page: 1, perPage: 20 });

    expect(result.data).toEqual(
      expect.objectContaining({
        population: 'endpoint_package_policies',
        page: 1,
        per_page: 20,
        value_total: 21,
        has_more: true,
        invalid_policy_count: 2,
      })
    );
    expect(result.data).not.toHaveProperty('enrolled_agents');
    expect(result.data).not.toHaveProperty('agents');
    expect(result.data).not.toHaveProperty('usage_unavailable');
    expect(result.data).not.toHaveProperty('usage_truncated');
    expect((result.data as ListPoliciesDto).items[0]).not.toHaveProperty('agents');
    expect((result.data as ListPoliciesDto).items[0]).not.toHaveProperty('usage');
    expect(mockedCreatePolicyAccessContext).not.toHaveBeenCalled();
    expect(mockedCountEndpoints).not.toHaveBeenCalled();
  });

  it('caps long row name and description at 512 and flags only the cut fields', async () => {
    mockedListEndpointPolicies.mockResolvedValue(
      createListDto({
        items: [
          createListItem({
            name: 'N'.repeat(600),
            description: 'D'.repeat(600),
          }),
          createListItem({
            id: 'short',
            name: 'Short',
            description: 'ok',
          }),
        ],
      })
    );

    const result = await getResult();
    const { items } = result.data as ListPoliciesDto;

    expect(items[0]?.name).toBe('N'.repeat(512));
    expect(items[0]?.description).toBe('D'.repeat(512));
    expect(items[0]?.name_string_truncated).toBe(true);
    expect(items[0]?.description_string_truncated).toBe(true);
    expect(items[1]?.name).toBe('Short');
    expect(items[1]?.description).toBe('ok');
    expect(items[1]).not.toHaveProperty('name_string_truncated');
    expect(items[1]).not.toHaveProperty('description_string_truncated');
  });

  it('preserves service-supplied truncation flags when strings are already capped', async () => {
    mockedListEndpointPolicies.mockResolvedValue(
      createListDto({
        items: [
          createListItem({
            name: 'N'.repeat(512),
            description: 'D'.repeat(512),
            name_string_truncated: true,
            description_string_truncated: true,
          }),
        ],
      })
    );

    const result = await getResult();
    const [item] = (result.data as ListPoliciesDto).items;

    expect(item?.name).toHaveLength(512);
    expect(item?.description).toHaveLength(512);
    expect(item?.name_string_truncated).toBe(true);
    expect(item?.description_string_truncated).toBe(true);
    expect(item?.normalizedHash).toBe(toPresentationHash('full-list-hash'));
  });

  it('keeps the structured other result under the 8000-token budget', async () => {
    mockedListEndpointPolicies.mockResolvedValue(
      createListDto({
        items: Array.from({ length: 20 }, (_, index) =>
          createListItem({
            id: `policy-${index}`,
            name: 'N'.repeat(512),
            description: 'D'.repeat(512),
            name_string_truncated: true,
            description_string_truncated: true,
          })
        ),
        value_total: 20,
      })
    );

    const result = await getResult({ page: 1, perPage: 20 });
    const dto = result.data as ListPoliciesDto & {
      items_total?: number;
      items_truncated?: true;
    };
    const envelope = JSON.stringify({ results: [createOtherResult(dto)] });

    expect(result.type).toBe(ToolResultType.other);
    expect(dto.items).toHaveLength(20);
    expect(dto.items[0]?.id).toBe('policy-0');
    expect(dto.items[0]?.normalizedHash).toBe(toPresentationHash('full-list-hash'));
    expect(dto.value_total).toBe(20);
    expect(dto).not.toHaveProperty('items_truncated');
    expect(estimateGuardedEnvelopeTokens(dto)).toBeLessThanOrEqual(8_000);
    expect(estimateTokens(envelope)).toBeLessThanOrEqual(8_000);
    expect(envelope).not.toContain('Output too large');
  });

  it('fits a schema-max real-hash page under 8000 tokens and reports local omissions', async () => {
    const serviceHash = hashPolicyConfig(normalize(policyFactory()));
    expect(listPoliciesSchema.parse({ page: 1, perPage: 50 })).toEqual({
      page: 1,
      perPage: 50,
      includeUsage: false,
    });
    mockedListEndpointPolicies.mockResolvedValue(
      createListDto({
        per_page: 50,
        value_total: 80,
        has_more: true,
        items: Array.from({ length: 50 }, (_, index) =>
          createListItem({
            id: `policy-${index}`,
            name: 'N'.repeat(512),
            description: 'D'.repeat(512),
            name_string_truncated: true,
            description_string_truncated: true,
            normalizedHash: serviceHash,
          })
        ),
      })
    );

    const result = await getResult({ page: 1, perPage: 50 });
    const dto = result.data as ListPoliciesDto & {
      items_total?: number;
      items_truncated?: true;
    };
    const envelope = JSON.stringify({ results: [createOtherResult(dto)] });

    expect(result.type).toBe(ToolResultType.other);
    expect(dto.items.length).toBeGreaterThan(0);
    expect(dto.items.length).toBeLessThan(50);
    expect(dto.items[0]?.id).toBe('policy-0');
    expect(dto.items[0]?.normalizedHash).toBe(toPresentationHash(serviceHash));
    expect(dto.items[0]?.normalizedHash).not.toBe(serviceHash);
    expect(dto.value_total).toBe(80);
    expect(dto.has_more).toBe(true);
    expect(dto.items_total).toBe(50);
    expect(dto.items_truncated).toBe(true);
    expect(estimateGuardedEnvelopeTokens(dto)).toBeLessThanOrEqual(8_000);
    expect(estimateTokens(envelope)).toBeLessThanOrEqual(8_000);
    expect(JSON.stringify(result)).not.toContain('Output too large');
    expect(JSON.stringify(result)).not.toContain(serviceHash);
  });

  it('attaches usage classification after a successful estate_read elevation', async () => {
    const endpointAppContextService = createMockEndpointAppContextService();
    const request = httpServerMock.createKibanaRequest();
    mockedListEndpointPolicies.mockResolvedValue(
      createListDto({
        items: [createListItem({ id: 'used-policy' }), createListItem({ id: 'unused-policy' })],
      })
    );
    mockedCreatePolicyAccessContext.mockResolvedValue(mockEstateAccess);
    mockedCountEndpoints.mockImplementation(
      async (_access, { policyId }): Promise<EndpointCountResult> => {
        if (policyId === 'used-policy') {
          return {
            population: 'enrolled_agents',
            source: 'fleet_status_aggregation',
            status: { all: 4 },
          };
        }
        return {
          population: 'enrolled_agents',
          source: 'no_agent_policy_assignments',
          status: {},
        };
      }
    );

    const tool = createListPoliciesTool({ endpointAppContextService, getStartServices });
    const result = await tool.handler(
      { page: 1, perPage: 20, includeUsage: true },
      createToolHandlerContext(
        request,
        elasticsearchClientMock.createScopedClusterClient(),
        loggingSystemMock.createLogger(),
        { spaceId: SPACE_ID }
      )
    );
    if (!('results' in result)) {
      throw new Error('expected a standard tool result');
    }
    const dto = result.results[0].data as ListPoliciesDto & { items: ListedItem[] };

    expect(mockedCreatePolicyAccessContext).toHaveBeenCalledWith(
      endpointAppContextService,
      { request, spaceId: SPACE_ID },
      'estate_read',
      getStartServices
    );
    expect(mockedCountEndpoints).toHaveBeenCalledTimes(2);
    expect(mockedCountEndpoints).toHaveBeenNthCalledWith(1, mockEstateAccess, {
      policyId: 'used-policy',
    });
    expect(mockedCountEndpoints).toHaveBeenNthCalledWith(2, mockEstateAccess, {
      policyId: 'unused-policy',
    });
    expect(dto.items[0]?.usage).toEqual({ classification: 'used', enrolled: 4 });
    expect(dto.items[1]?.usage).toEqual({
      classification: 'unused',
      reason: 'no_agent_policy_assignments',
    });
    expect(dto).not.toHaveProperty('usage_unavailable');
    expect(dto).not.toHaveProperty('usage_truncated');
  });

  it('classifies every item as undetermined when estate_read elevation is denied', async () => {
    mockedListEndpointPolicies.mockResolvedValue(createListDto());
    mockedCreatePolicyAccessContext.mockRejectedValue(new PolicyAuthorizationError());

    const result = await getResult({ page: 1, perPage: 20, includeUsage: true });
    const dto = result.data as ListPoliciesDto & { items: ListedItem[] };

    expect(result.type).toBe(ToolResultType.other);
    expect(dto.items).toHaveLength(1);
    expect(dto.items[0]?.usage).toEqual({
      classification: 'undetermined',
      reason: 'requires_endpoint_list_read',
    });
    expect(dto).toEqual(
      expect.objectContaining({
        usage_unavailable: 'requires_endpoint_list_read',
        population: 'endpoint_package_policies',
      })
    );
    expect(mockedCountEndpoints).not.toHaveBeenCalled();
  });

  it('classifies a per-policy count throw as undetermined without failing the list', async () => {
    mockedListEndpointPolicies.mockResolvedValue(
      createListDto({
        items: [createListItem({ id: 'broken-count' }), createListItem({ id: 'healthy-count' })],
      })
    );
    mockedCreatePolicyAccessContext.mockResolvedValue(mockEstateAccess);
    mockedCountEndpoints.mockImplementation(
      async (_access, { policyId }): Promise<EndpointCountResult> => {
        if (policyId === 'broken-count') {
          throw new Error('count failed');
        }
        return {
          population: 'enrolled_agents',
          source: 'fleet_status_aggregation',
          status: { all: 1 },
        };
      }
    );

    const result = await getResult({ page: 1, perPage: 20, includeUsage: true });
    const dto = result.data as ListPoliciesDto & { items: ListedItem[] };

    expect(result.type).toBe(ToolResultType.other);
    expect(dto.items[0]?.usage).toEqual({
      classification: 'undetermined',
      reason: 'count_unavailable',
    });
    expect(dto.items[1]?.usage).toEqual({ classification: 'used', enrolled: 1 });
  });

  it('classifies at most 20 policies and sets usage_truncated beyond that', async () => {
    mockedListEndpointPolicies.mockResolvedValue(
      createListDto({
        items: Array.from({ length: 21 }, (_, index) =>
          createListItem({
            id: `policy-${index}`,
            name: `Policy ${index}`,
            description: 'short',
          })
        ),
        value_total: 21,
      })
    );
    mockedCreatePolicyAccessContext.mockResolvedValue(mockEstateAccess);
    mockedCountEndpoints.mockResolvedValue({
      population: 'enrolled_agents',
      source: 'fleet_status_aggregation',
      status: { all: 2 },
    } satisfies EndpointCountResult);

    const result = await getResult({ page: 1, perPage: 50, includeUsage: true });
    const dto = result.data as ListPoliciesDto & {
      usage_truncated?: true;
      items: ListedItem[];
    };

    expect(mockedCountEndpoints).toHaveBeenCalledTimes(20);
    expect(dto.usage_truncated).toBe(true);
    expect(dto.items).toHaveLength(21);
    expect(dto.items[0]?.usage).toEqual({ classification: 'used', enrolled: 2 });
    expect(dto.items[19]?.usage).toEqual({ classification: 'used', enrolled: 2 });
    expect(dto.items[20]?.usage).toEqual({
      classification: 'undetermined',
      reason: 'usage_truncated',
    });
  });
});
