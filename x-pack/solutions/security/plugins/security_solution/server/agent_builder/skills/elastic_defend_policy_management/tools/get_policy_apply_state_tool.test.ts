/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType, ToolType } from '@kbn/agent-builder-common';
import { createOtherResult, isToolResultId } from '@kbn/agent-builder-server';
import type { StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock, loggingSystemMock } from '@kbn/core/server/mocks';
import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import { createToolHandlerContext } from '../../../__mocks__/test_helpers';
import { PolicyNotFoundError } from '../services/policy_errors';
import type { ApplyStateDto } from '../services/read_apply_state';
import { readApplyState } from '../services/read_apply_state';
import { POLICY_TOOL_ERROR_MESSAGES } from './create_policy_tool';
import {
  GET_POLICY_APPLY_STATE_TOOL_ID,
  createGetPolicyApplyStateTool,
  getPolicyApplyStateSchema,
} from './get_policy_apply_state_tool';
import { estimateGuardedEnvelopeTokens, fitsGuardedEnvelope } from './trim_policy_result';

jest.mock('../services/read_apply_state', () => ({
  readApplyState: jest.fn(),
}));

const SPACE_ID = 'space-marketing';
const getStartServices = jest.fn(async () => [
  { savedObjects: { getScopedClient: jest.fn().mockReturnValue({}) } },
]) as unknown as StartServicesAccessor;
const mockedReadApplyState = jest.mocked(readApplyState);

const expectToolResultId = (id: string | undefined): void => {
  if (id === undefined) {
    throw new Error('expected tool_result_id');
  }
  expect(isToolResultId(id)).toBe(true);
};

const createApplyStateDto = (overrides: Partial<ApplyStateDto> = {}): ApplyStateDto => ({
  policy: {
    id: 'policy-1',
    name: 'Endpoint Policy',
    revision: 3,
  },
  spaceId: SPACE_ID,
  out_of_date: {
    value: 5,
    classified_hosts: 805,
    unclassified_overflow_hosts: 20,
    truncated: true,
    source: 'united_metadata_tuple_aggregation',
    population:
      'readable_united_endpoint_hosts_canonical_assignment_matches_target_agent_policy_ids',
  },
  current_policy_response_failures: {
    value: 3,
    classified_hosts: 1500,
    upstream_unclassified_hosts: 20,
    response_unclassified_agents: 0,
    truncated: true,
    source: 'policy_response_latest_per_agent',
    population: 'latest_policy_responses_current_package_revision',
  },
  ...overrides,
});

const createContext = (
  logger: ReturnType<typeof loggingSystemMock.createLogger> = loggingSystemMock.createLogger()
) =>
  createToolHandlerContext(
    httpServerMock.createKibanaRequest(),
    elasticsearchClientMock.createScopedClusterClient(),
    logger,
    { spaceId: SPACE_ID }
  );

const createAuthorizedService = () => {
  const endpointAppContextService = createMockEndpointAppContextService();
  endpointAppContextService.getEndpointAuthz.mockResolvedValue(
    getEndpointAuthzInitialStateMock({
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    })
  );
  return endpointAppContextService;
};

const getResult = async (
  idOrName: string,
  options: {
    endpointAppContextService?: ReturnType<typeof createMockEndpointAppContextService>;
    ctx?: ReturnType<typeof createContext>;
  } = {}
) => {
  const tool = createGetPolicyApplyStateTool({
    endpointAppContextService: options.endpointAppContextService ?? createAuthorizedService(),
    getStartServices,
  });
  const result = await tool.handler({ idOrName }, options.ctx ?? createContext());
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }
  return result.results[0];
};

describe('createGetPolicyApplyStateTool', () => {
  beforeEach(() => {
    mockedReadApplyState.mockReset();
  });

  it('registers the approved id, estate_read access, schema, and 8000-token budget', () => {
    const tool = createGetPolicyApplyStateTool({
      endpointAppContextService: createAuthorizedService(),
      getStartServices,
    });

    expect(tool.id).toBe(GET_POLICY_APPLY_STATE_TOOL_ID);
    expect(tool.type).toBe(ToolType.builtin);
    expect(tool.maxResultTokens).toBe(8_000);
    expect(tool.schema).toBe(getPolicyApplyStateSchema);
  });

  it('bounds and trims idOrName at the schema boundary', () => {
    expect(getPolicyApplyStateSchema.parse({ idOrName: '  policy-1  ' })).toEqual({
      idOrName: 'policy-1',
    });
    expect(getPolicyApplyStateSchema.safeParse({ idOrName: 'a'.repeat(256) }).success).toBe(true);
    expect(getPolicyApplyStateSchema.safeParse({ idOrName: 'a'.repeat(257) }).success).toBe(false);
    expect(getPolicyApplyStateSchema.safeParse({ idOrName: '' }).success).toBe(false);
    expect(getPolicyApplyStateSchema.safeParse({ idOrName: '   ' }).success).toBe(false);
  });

  it('does not describe overflow as out-of-date or failing, or claim origin-only exclusion', () => {
    const tool = createGetPolicyApplyStateTool({
      endpointAppContextService: createAuthorizedService(),
      getStartServices,
    });
    const { description } = tool;

    expect(description).toContain('request-scoped CPS/CCS');
    expect(description).toContain('canonical assignment');
    expect(description).toContain('latest policy responses');
    expect(description).toContain('unclassified truncation');
    expect(description).toContain('must not be added');
    expect(description.toLowerCase()).not.toContain('origin-only');
    expect(description.toLowerCase()).not.toContain('linked-project');
    expect(description.toLowerCase()).not.toContain('remote-cluster');
    expect(description).not.toMatch(/overflow(?:ed)? hosts are (?:out-of-date|failing)/i);
  });

  it('does not treat assignment-matched hosts as enrolled-agent usage or used/unused', () => {
    const tool = createGetPolicyApplyStateTool({
      endpointAppContextService: createAuthorizedService(),
      getStartServices,
    });
    const { description } = tool;

    expect(description).toContain('assigned-versus-applied lag');
    expect(description).toContain(
      'Classified or assignment-matched hosts are not enrolled-agent usage evidence'
    );
    expect(description).toContain('cannot answer used or unused');
    expect(description).not.toMatch(/\benrolled_agents\b/);
  });

  it('preserves apply-state DTO population and source literals', async () => {
    const dto = createApplyStateDto();
    mockedReadApplyState.mockResolvedValue(dto);

    const result = await getResult('policy-1');
    const presented = result.data as ApplyStateDto;

    expect(presented.out_of_date.population).toBe(
      'readable_united_endpoint_hosts_canonical_assignment_matches_target_agent_policy_ids'
    );
    expect(presented.out_of_date.source).toBe('united_metadata_tuple_aggregation');
    expect(presented.current_policy_response_failures.population).toBe(
      'latest_policy_responses_current_package_revision'
    );
    expect(presented.current_policy_response_failures.source).toBe(
      'policy_response_latest_per_agent'
    );
    expect(presented).not.toHaveProperty('enrolled_agents');
    expect(presented.out_of_date).toEqual(dto.out_of_date);
    expect(presented.current_policy_response_failures).toEqual(
      dto.current_policy_response_failures
    );
  });

  it('forwards the handler request and returns presented apply-state counts for an id lookup', async () => {
    const dto = createApplyStateDto();
    const endpointAppContextService = createAuthorizedService();
    const ctx = createContext();
    mockedReadApplyState.mockResolvedValue(dto);

    const tool = createGetPolicyApplyStateTool({ endpointAppContextService, getStartServices });
    const result = await tool.handler({ idOrName: 'policy-1' }, ctx);
    if (!('results' in result)) {
      throw new Error('expected a standard tool result');
    }

    expect(mockedReadApplyState).toHaveBeenCalledTimes(1);
    expect(mockedReadApplyState).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'estate_read',
        spaceId: SPACE_ID,
      }),
      endpointAppContextService,
      { idOrName: 'policy-1' },
      ctx.request
    );
    expect(mockedReadApplyState.mock.calls[0][3]).toBe(ctx.request);
    expect(mockedReadApplyState.mock.calls[0][0]).not.toHaveProperty('request');
    expect(result.results[0].type).toBe(ToolResultType.other);
    expect(result.results[0].data).toEqual(dto);
    expect(result.results[0].data).not.toHaveProperty('value_total');
  });

  it('forwards the handler request and returns presented apply-state counts for a name lookup', async () => {
    const dto = createApplyStateDto({
      policy: { id: 'policy-1', name: 'Named Policy', revision: 7 },
    });
    mockedReadApplyState.mockResolvedValue(dto);

    const result = await getResult('Named Policy');

    expect(mockedReadApplyState).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'estate_read',
        spaceId: SPACE_ID,
      }),
      expect.anything(),
      { idOrName: 'Named Policy' },
      expect.any(Object)
    );
    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toEqual(dto);
    expect((result.data as ApplyStateDto).policy).toEqual({
      id: 'policy-1',
      name: 'Named Policy',
      revision: 7,
    });
  });

  it('caps oversized policy identity and keeps count fields under the 8000-token budget', async () => {
    const dto = createApplyStateDto({
      policy: {
        id: 'I'.repeat(80_000),
        name: 'N'.repeat(80_000),
        revision: 3,
      },
    });
    mockedReadApplyState.mockResolvedValue(dto);

    const result = await getResult('policy-1');
    const presented = result.data as ApplyStateDto & {
      policy: Record<string, unknown>;
    };
    const envelope = JSON.stringify({ results: [createOtherResult(presented)] });

    expect(result.type).toBe(ToolResultType.other);
    expect(presented.policy.id).toBe('I'.repeat(512));
    expect(presented.policy.name).toBe('N'.repeat(512));
    expect(presented.policy.revision).toBe(3);
    expect(presented.policy).toHaveProperty('id_string_truncated', true);
    expect(presented.policy).toHaveProperty('name_string_truncated', true);
    expect(presented.policy).not.toHaveProperty('description');
    expect(presented.policy).not.toHaveProperty('version');
    expect(presented.out_of_date).toEqual(dto.out_of_date);
    expect(presented.current_policy_response_failures).toEqual(
      dto.current_policy_response_failures
    );
    expect(presented).not.toHaveProperty('value_total');
    expect(fitsGuardedEnvelope(presented, 8_000)).toBe(true);
    expect(estimateGuardedEnvelopeTokens(presented)).toBeLessThanOrEqual(8_000);
    expect(envelope).not.toContain('Output too large');
  });

  it('refuses estate_read before run and does not call readApplyState', async () => {
    const endpointAppContextService = createMockEndpointAppContextService();
    endpointAppContextService.getEndpointAuthz.mockResolvedValue(
      getEndpointAuthzInitialStateMock({
        canReadPolicyManagement: true,
        canReadEndpointList: false,
        canWritePolicyManagement: false,
      })
    );

    const result = await getResult('policy-1', { endpointAppContextService });

    expect(mockedReadApplyState).not.toHaveBeenCalled();
    expect(result.type).toBe(ToolResultType.error);
    expectToolResultId(result.tool_result_id);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.not_authorized,
      metadata: { error: 'not_authorized' },
    });
    expect(result.data).not.toHaveProperty('stack');
  });

  it('returns a stable not_found error result without internals', async () => {
    mockedReadApplyState.mockRejectedValue(new PolicyNotFoundError('missing-policy'));

    const result = await getResult('missing-policy');

    expect(mockedReadApplyState).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'estate_read',
        spaceId: SPACE_ID,
      }),
      expect.anything(),
      { idOrName: 'missing-policy' },
      expect.any(Object)
    );
    expect(result.type).toBe(ToolResultType.error);
    expectToolResultId(result.tool_result_id);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.not_found,
      metadata: { error: 'not_found' },
    });
    expect(result.data).not.toHaveProperty('stack');
    expect(JSON.stringify(result.data)).not.toMatch(/ECONNREFUSED|stack|canRead|es\.internal/i);
  });
});
