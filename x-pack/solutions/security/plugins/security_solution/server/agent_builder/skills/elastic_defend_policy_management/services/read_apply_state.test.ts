/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { estypes } from '@elastic/elasticsearch';
import type { ElasticsearchClient, KibanaRequest, StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock } from '@kbn/core/server/mocks';
import { FleetAgentPolicyGenerator } from '../../../../../common/endpoint/data_generators/fleet_agent_policy_generator';
import { FleetPackagePolicyGenerator } from '../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import {
  METADATA_UNITED_INDEX,
  policyIndexPattern,
} from '../../../../../common/endpoint/constants';
import { NotFoundError } from '../../../../endpoint/errors';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import { INITIAL_POLICY_ID } from '../../../../endpoint/routes/policy';
import type { EndpointInternalFleetServicesInterface } from '../../../../endpoint/services/fleet/endpoint_fleet_services_factory';
import type { HasAtLeast, PolicyAccessContext } from './access_context';
import { createPolicyAccessContext } from './access_context';
import {
  APPLY_STATE_AGENT_ID_AGG_NAME,
  APPLY_STATE_MISSING_LONG,
  APPLY_STATE_TUPLE_AGG_NAME,
} from './apply_state/apply_state_united_aggregation';
import { buildUnitedApplyStateFilter } from './apply_state/united_apply_state_filter';
import { PolicyNotFoundError } from './policy_errors';
import type {
  FailureCount,
  FailureSource,
  OutOfDateCount,
  OutOfDateSource,
} from './read_apply_state';
import { readApplyState } from './read_apply_state';

type IsAssignable<A, B> = A extends B ? true : false;

type WriteSatisfiesApplyState = IsAssignable<
  PolicyAccessContext<'policy_write'>,
  Parameters<typeof readApplyState>[0]
> extends true
  ? true
  : never;
type EstateSatisfiesApplyState = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  Parameters<typeof readApplyState>[0]
> extends true
  ? true
  : never;
type PolicyReadDoesNotSatisfyApplyState = IsAssignable<
  PolicyAccessContext<'policy_read'>,
  Parameters<typeof readApplyState>[0]
> extends false
  ? true
  : never;
type PlainObjectDoesNotSatisfyApplyState = IsAssignable<
  {
    spaceId: string;
    fleet: EndpointInternalFleetServicesInterface;
  },
  HasAtLeast<'estate_read'>
> extends false
  ? true
  : never;
type RequestIsRequired = undefined extends Parameters<typeof readApplyState>[3] ? false : true;
type RequestIsKibanaRequest = Parameters<typeof readApplyState>[3] extends KibanaRequest
  ? true
  : never;

const _writeSatisfiesApplyState: WriteSatisfiesApplyState = true;
const _estateSatisfiesApplyState: EstateSatisfiesApplyState = true;
const _policyReadDoesNotSatisfyApplyState: PolicyReadDoesNotSatisfyApplyState = true;
const _plainObjectDoesNotSatisfyApplyState: PlainObjectDoesNotSatisfyApplyState = true;
const _requestIsRequired: RequestIsRequired = true;
const _requestIsKibanaRequest: RequestIsKibanaRequest = true;

void _writeSatisfiesApplyState;
void _estateSatisfiesApplyState;
void _policyReadDoesNotSatisfyApplyState;
void _plainObjectDoesNotSatisfyApplyState;
void _requestIsRequired;
void _requestIsKibanaRequest;

const SPACE_ID = 'space-marketing';
const POLICY_ID = 'policy-a';
const POLICY_NAME = 'Policy A';
const POLICY_REVISION = 3;
const AGENT_POLICY_A = 'agent-policy-a';
const AGENT_POLICY_B = 'agent-policy-b';
const OUT_OF_DATE_POPULATION =
  'readable_united_endpoint_hosts_canonical_assignment_matches_target_agent_policy_ids' as const;
const FAILURE_POPULATION = 'latest_policy_responses_current_package_revision' as const;
const packagePolicyGenerator = new FleetPackagePolicyGenerator();
const agentPolicyGenerator = new FleetAgentPolicyGenerator();

const expectedPolicy = {
  id: POLICY_ID,
  name: POLICY_NAME,
  revision: POLICY_REVISION,
} as const;

const outZero = (source: OutOfDateSource): OutOfDateCount => ({
  value: 0,
  classified_hosts: 0,
  unclassified_overflow_hosts: 0,
  truncated: false,
  source,
  population: OUT_OF_DATE_POPULATION,
});

const failZero = (
  source: FailureSource,
  extras: Partial<Pick<FailureCount, 'upstream_unclassified_hosts' | 'truncated'>> = {}
): FailureCount => ({
  value: 0,
  classified_hosts: 0,
  upstream_unclassified_hosts: 0,
  response_unclassified_agents: 0,
  truncated: false,
  source,
  population: FAILURE_POPULATION,
  ...extras,
});

const createEndpointPolicy = (
  overrides: Parameters<FleetPackagePolicyGenerator['generateEndpointPackagePolicy']>[0] = {}
) =>
  packagePolicyGenerator.generateEndpointPackagePolicy({
    version: 'WzEsMV0=',
    id: POLICY_ID,
    name: POLICY_NAME,
    revision: POLICY_REVISION,
    policy_ids: [AGENT_POLICY_A],
    ...overrides,
  });

const inDateTuple = (agentPolicyId: string, docCount: number, reportedPackageId = POLICY_ID) => ({
  key: [agentPolicyId, reportedPackageId, 5, POLICY_REVISION, 5],
  doc_count: docCount,
});

const unitedSearchResult = ({
  tuples = [inDateTuple(AGENT_POLICY_A, 1)],
  agents = [{ key: 'agent-1', doc_count: 1 }],
  tupleOverflow = 0,
  agentOverflow = 0,
}: {
  tuples?: Array<{ key: unknown[]; doc_count: number }>;
  agents?: Array<{ key: string; doc_count?: number }>;
  tupleOverflow?: number;
  agentOverflow?: number;
} = {}) => ({
  aggregations: {
    [APPLY_STATE_TUPLE_AGG_NAME]: {
      buckets: tuples,
      sum_other_doc_count: tupleOverflow,
    },
    [APPLY_STATE_AGENT_ID_AGG_NAME]: {
      buckets: agents,
      sum_other_doc_count: agentOverflow,
    },
  },
});

const appliedSource = (
  overrides: {
    id?: string;
    version?: number;
    endpoint_policy_version?: number | string | null;
    actions?: unknown;
  } = {}
) => ({
  Endpoint: {
    policy: {
      applied: {
        id: POLICY_ID,
        version: 5,
        endpoint_policy_version: POLICY_REVISION,
        actions: [{ name: 'configure', message: 'failed', status: 'failure' }],
        ...overrides,
      },
    },
  },
});

const responseSearchResult = ({
  hits,
  overflow = 0,
}: {
  hits: Array<{ agentId: string; hit?: { _id?: unknown; _source?: unknown } }>;
  overflow?: number;
}) => ({
  aggregations: {
    latest_actions: {
      buckets: hits.map(({ agentId, hit }) => ({
        key: agentId,
        doc_count: 1,
        latest_event: {
          hits: {
            hits: hit ? [hit] : [],
          },
        },
      })),
      sum_other_doc_count: overflow,
    },
  },
});

const currentFailureHit = (agentId: string, source: Record<string, unknown> = appliedSource()) => ({
  _id: `hit-${agentId}`,
  _source: {
    agent: { id: agentId },
    ...source,
  },
});

const asSearchRequest = (request: unknown): estypes.SearchRequest => {
  if (request == null || typeof request !== 'object') {
    throw new Error('expected Elasticsearch search request');
  }

  return request as estypes.SearchRequest;
};

const indexName = (request: unknown): string => {
  const { index } = asSearchRequest(request);
  return Array.isArray(index) ? index.join(',') : String(index ?? '');
};

const isUnitedSearch = (request: unknown): boolean =>
  indexName(request).includes('metadata_united');

const searchCall = (
  esClient: jest.Mocked<ElasticsearchClient>,
  callIndex: number
): estypes.SearchRequest => asSearchRequest(esClient.search.mock.calls[callIndex]?.[0]);

const createEstateAccess = async () => {
  const endpointAppContextService = createMockEndpointAppContextService();
  const request = httpServerMock.createKibanaRequest();
  const getHostMetadataList = jest.fn();

  endpointAppContextService.getEndpointAuthz.mockResolvedValue(
    getEndpointAuthzInitialStateMock({
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    })
  );
  jest.mocked(endpointAppContextService.getEndpointMetadataService).mockReturnValue({
    getHostMetadataList,
  } as unknown as ReturnType<typeof endpointAppContextService.getEndpointMetadataService>);

  const getStartServices = jest.fn(async () => [
    { savedObjects: { getScopedClient: jest.fn().mockReturnValue({}) } },
  ]) as unknown as StartServicesAccessor;
  const access = await createPolicyAccessContext(
    endpointAppContextService,
    { request, spaceId: SPACE_ID },
    'estate_read',
    getStartServices
  );
  const soClient = access.fleet.getSoClient();
  const getById = jest.mocked(access.fleet.packagePolicy.get);
  const listByName = jest.mocked(access.fleet.packagePolicy.list);
  const ensureInCurrentSpace = jest.mocked(access.fleet.ensureInCurrentSpace);
  const getByIds = jest.mocked(access.fleet.agentPolicy.getByIds);
  const listAgents = jest.mocked(access.fleet.agent.listAgents);
  const fetchAgentList = jest.mocked(access.fleet.fetchAgentList);
  const esClient = endpointAppContextService.getReadEsClient() as jest.Mocked<ElasticsearchClient>;

  endpointAppContextService.getReadEsClient.mockClear();
  endpointAppContextService.getInternalEsClient.mockClear();
  ensureInCurrentSpace.mockResolvedValue(undefined);
  getById.mockResolvedValue(createEndpointPolicy());
  getByIds.mockResolvedValue([agentPolicyGenerator.generate({ id: AGENT_POLICY_A, revision: 5 })]);

  return {
    access,
    request,
    endpointAppContextService,
    soClient,
    getById,
    listByName,
    ensureInCurrentSpace,
    getByIds,
    listAgents,
    fetchAgentList,
    getHostMetadataList,
    esClient,
  };
};

const mockSearches = (
  esClient: jest.Mocked<ElasticsearchClient>,
  {
    united,
    response,
  }: {
    united?: object | (() => Promise<never>);
    response?: object;
  }
) => {
  esClient.search.mockImplementation(async (request) => {
    if (isUnitedSearch(request)) {
      if (typeof united === 'function') {
        return united();
      }
      return united as unknown as estypes.SearchResponse;
    }

    return (response ?? { aggregations: undefined }) as unknown as estypes.SearchResponse;
  });
};

const expectNoForbiddenApis = ({
  listAgents,
  fetchAgentList,
  getHostMetadataList,
  listByName,
  endpointAppContextService,
}: {
  listAgents: jest.Mock;
  fetchAgentList: jest.Mock;
  getHostMetadataList: jest.Mock;
  listByName: jest.Mock;
  endpointAppContextService: ReturnType<typeof createMockEndpointAppContextService>;
}): void => {
  expect(listAgents).not.toHaveBeenCalled();
  expect(fetchAgentList).not.toHaveBeenCalled();
  expect(getHostMetadataList).not.toHaveBeenCalled();
  expect(listByName).not.toHaveBeenCalled();
  expect(endpointAppContextService.getInternalEsClient).not.toHaveBeenCalled();
};

describe('readApplyState', () => {
  it('returns the empty_assignments DTO and issues no ES or agent-policy reads', async () => {
    const harness = await createEstateAccess();
    harness.getById.mockResolvedValue(createEndpointPolicy({ policy_ids: [] }));

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: `  ${POLICY_ID}  ` },
      harness.request
    );

    expect(result).toEqual({
      policy: expectedPolicy,
      spaceId: SPACE_ID,
      out_of_date: outZero('no_agent_policy_assignments'),
      current_policy_response_failures: failZero('no_agent_policy_assignments'),
    });
    expect(harness.ensureInCurrentSpace).toHaveBeenCalledWith({
      integrationPolicyIds: [POLICY_ID],
    });
    expect(harness.getByIds).not.toHaveBeenCalled();
    expect(harness.esClient.search).not.toHaveBeenCalled();
    expect(harness.endpointAppContextService.getReadEsClient).not.toHaveBeenCalled();
    expectNoForbiddenApis(harness);
  });

  it('returns the united_missing DTO and does not search policy responses', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: async () => {
        throw Object.assign(new Error('index missing'), {
          meta: { body: { error: { type: 'index_not_found_exception' } } },
        });
      },
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result).toEqual({
      policy: expectedPolicy,
      spaceId: SPACE_ID,
      out_of_date: outZero('united_index_missing'),
      current_policy_response_failures: failZero('united_index_missing'),
    });
    expect(harness.esClient.search).toHaveBeenCalledTimes(1);
    expect(isUnitedSearch(searchCall(harness.esClient, 0))).toBe(true);
    expect(harness.endpointAppContextService.getReadEsClient).toHaveBeenCalledWith(harness.request);
    expectNoForbiddenApis(harness);
  });

  it('also treats a ResponseError-shaped united index_not_found as united_missing', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: async () => {
        throw Object.assign(new Error('index missing'), {
          body: { error: { type: 'index_not_found_exception' } },
        });
      },
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.out_of_date.source).toBe('united_index_missing');
    expect(result.current_policy_response_failures.source).toBe('united_index_missing');
    expect(harness.esClient.search).toHaveBeenCalledTimes(1);
  });

  it('rethrows non-index_not_found united Elasticsearch faults', async () => {
    const harness = await createEstateAccess();
    const searchFault = new Error('search_phase_execution_exception');
    mockSearches(harness.esClient, {
      united: async () => {
        throw searchFault;
      },
    });

    await expect(
      readApplyState(
        harness.access,
        harness.endpointAppContextService,
        { idOrName: POLICY_ID },
        harness.request
      )
    ).rejects.toBe(searchFault);
    expect(harness.esClient.search).toHaveBeenCalledTimes(1);
  });

  it('does not treat a message-only index_not_found Error as united_missing', async () => {
    const harness = await createEstateAccess();
    const messageOnly = new Error('index_not_found_exception');
    mockSearches(harness.esClient, {
      united: async () => {
        throw messageOnly;
      },
    });

    await expect(
      readApplyState(
        harness.access,
        harness.endpointAppContextService,
        { idOrName: POLICY_ID },
        harness.request
      )
    ).rejects.toBe(messageOnly);
  });

  it('returns united_empty_agent_set with upstream overflow and does not search policy responses', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        tuples: [
          { key: [AGENT_POLICY_A, POLICY_ID, 5, POLICY_REVISION, 5], doc_count: 800 },
          { key: [AGENT_POLICY_A, 'stale-pkg', 5, POLICY_REVISION, 5], doc_count: 5 },
        ],
        agents: [],
        tupleOverflow: 20,
        agentOverflow: 20,
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result).toEqual({
      policy: expectedPolicy,
      spaceId: SPACE_ID,
      out_of_date: {
        value: 5,
        classified_hosts: 805,
        unclassified_overflow_hosts: 20,
        truncated: true,
        source: 'united_metadata_tuple_aggregation',
        population: OUT_OF_DATE_POPULATION,
      },
      current_policy_response_failures: failZero('united_agent_id_set_empty', {
        upstream_unclassified_hosts: 20,
        truncated: true,
      }),
    });
    expect(result).not.toHaveProperty('value_total');
    expect(result.out_of_date).not.toHaveProperty('value_total');
    expect(harness.esClient.search).toHaveBeenCalledTimes(1);
    expectNoForbiddenApis(harness);
  });

  it('returns FAIL_ZERO with united_agent_id_set_empty when the agent set is truly empty', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({ tuples: [], agents: [], tupleOverflow: 0, agentOverflow: 0 }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.out_of_date).toEqual(outZero('united_metadata_tuple_aggregation'));
    expect(result.current_policy_response_failures).toEqual(failZero('united_agent_id_set_empty'));
    expect(harness.esClient.search).toHaveBeenCalledTimes(1);
  });

  it('returns response_404 extras after an issued empty policy-response search', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        agents: [{ key: 'agent-1' }],
        agentOverflow: 20,
      }),
      response: { aggregations: undefined },
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.out_of_date.source).toBe('united_metadata_tuple_aggregation');
    expect(result.current_policy_response_failures).toEqual({
      value: 0,
      classified_hosts: 0,
      upstream_unclassified_hosts: 20,
      response_unclassified_agents: 0,
      truncated: true,
      source: 'policy_response_latest_per_agent',
      population: FAILURE_POPULATION,
    });
    expect(harness.esClient.search).toHaveBeenCalledTimes(2);
    expect(isUnitedSearch(searchCall(harness.esClient, 1))).toBe(false);
  });

  it('returns response_search_ok with united-only overflow kept off the failure value', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        agents: [{ key: 'agent-1' }, { key: 'agent-2' }, { key: 'agent-3' }],
        agentOverflow: 20,
      }),
      response: responseSearchResult({
        hits: ['agent-1', 'agent-2', 'agent-3'].map((agentId) => ({
          agentId,
          hit: currentFailureHit(agentId),
        })),
        overflow: 0,
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.current_policy_response_failures).toEqual({
      value: 3,
      classified_hosts: 3,
      upstream_unclassified_hosts: 20,
      response_unclassified_agents: 0,
      truncated: true,
      source: 'policy_response_latest_per_agent',
      population: FAILURE_POPULATION,
    });
  });

  it('returns response_search_ok with response-only overflow kept distinct', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        agents: [{ key: 'agent-1' }],
        agentOverflow: 0,
      }),
      response: responseSearchResult({
        hits: [{ agentId: 'agent-1', hit: currentFailureHit('agent-1') }],
        overflow: 9,
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.current_policy_response_failures).toEqual({
      value: 1,
      classified_hosts: 1,
      upstream_unclassified_hosts: 0,
      response_unclassified_agents: 9,
      truncated: true,
      source: 'policy_response_latest_per_agent',
      population: FAILURE_POPULATION,
    });
  });

  it('keeps both failure overflow fields independent and never sums them', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        agents: [{ key: 'agent-1' }],
        agentOverflow: 20,
      }),
      response: responseSearchResult({
        hits: [{ agentId: 'agent-1', hit: currentFailureHit('agent-1') }],
        overflow: 7,
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );
    const failures = result.current_policy_response_failures;

    expect(failures).toEqual({
      value: 1,
      classified_hosts: 1,
      upstream_unclassified_hosts: 20,
      response_unclassified_agents: 7,
      truncated: true,
      source: 'policy_response_latest_per_agent',
      population: FAILURE_POPULATION,
    });
    expect(failures.upstream_unclassified_hosts).toBe(20);
    expect(failures.response_unclassified_agents).toBe(7);
    expect(failures.truncated).toBe(true);
  });

  it('counts only out-of-date tuples when the same package spans distinct agent policies', async () => {
    const harness = await createEstateAccess();
    harness.getById.mockResolvedValue(
      createEndpointPolicy({ policy_ids: [AGENT_POLICY_A, AGENT_POLICY_B] })
    );
    harness.getByIds.mockResolvedValue([
      agentPolicyGenerator.generate({ id: AGENT_POLICY_A, revision: 5 }),
      agentPolicyGenerator.generate({ id: AGENT_POLICY_B, revision: 9 }),
    ]);
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        tuples: [inDateTuple(AGENT_POLICY_A, 10), inDateTuple(AGENT_POLICY_B, 4)],
        agents: [{ key: 'agent-1' }],
      }),
      response: responseSearchResult({
        hits: [{ agentId: 'agent-1', hit: currentFailureHit('agent-1', appliedSource()) }],
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.out_of_date.value).toBe(4);
    expect(result.out_of_date.classified_hosts).toBe(14);
    expect(result.out_of_date.unclassified_overflow_hosts).toBe(0);
    expect(harness.getByIds).toHaveBeenCalledWith(
      harness.soClient,
      [AGENT_POLICY_A, AGENT_POLICY_B],
      {
        ignoreMissing: true,
      }
    );
  });

  it('treats reassignment onto this policy as in-filter and out-of-date', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        tuples: [inDateTuple(AGENT_POLICY_A, 6, POLICY_ID.replace('a', 'b'))],
        agents: [{ key: 'agent-1' }],
      }),
      response: { aggregations: undefined },
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );
    const unitedRequest = searchCall(harness.esClient, 0);

    expect(unitedRequest.query).toEqual(buildUnitedApplyStateFilter([AGENT_POLICY_A]));
    expect(result.out_of_date.value).toBe(6);
    expect(result.out_of_date.classified_hosts).toBe(6);
  });

  it('passes only this package policy assignment ids into the united membership filter', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult(),
      response: { aggregations: undefined },
    });

    await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    const unitedRequest = searchCall(harness.esClient, 0);
    const serializedQuery = JSON.stringify(unitedRequest.query);

    expect(unitedRequest.query).toEqual(buildUnitedApplyStateFilter([AGENT_POLICY_A]));
    expect(serializedQuery).toContain(AGENT_POLICY_A);
    expect(serializedQuery).not.toContain(AGENT_POLICY_B);
    expect(serializedQuery).not.toContain('applied.id');
    expect(serializedQuery).not.toContain('united.agent.namespaces');
    expect(serializedQuery).not.toContain('_alias:_origin');
    expect(JSON.stringify(unitedRequest)).not.toContain('.fleet-agents');
  });

  it('passes stored base assignment ids for suffix and source-base membership', async () => {
    const harness = await createEstateAccess();
    harness.getById.mockResolvedValue(createEndpointPolicy({ policy_ids: ['base', 'base', ''] }));
    harness.getByIds.mockResolvedValue([
      agentPolicyGenerator.generate({ id: 'base', revision: 5 }),
    ]);
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        tuples: [inDateTuple('base', 2)],
        agents: [{ key: 'agent-1' }],
      }),
      response: { aggregations: undefined },
    });

    await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    const unitedRequest = searchCall(harness.esClient, 0);
    expect(unitedRequest.query).toEqual(buildUnitedApplyStateFilter(['base']));
    expect(harness.getByIds).toHaveBeenCalledWith(harness.soClient, ['base'], {
      ignoreMissing: true,
    });
    expect(JSON.stringify(unitedRequest.runtime_mappings)).toContain('policy_base_id');
    expect(JSON.stringify(unitedRequest.runtime_mappings)).toContain('replaceAll');
  });

  it('treats a missing configured agent-policy SO as out-of-date', async () => {
    const harness = await createEstateAccess();
    harness.getByIds.mockResolvedValue([]);
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        tuples: [inDateTuple(AGENT_POLICY_A, 3)],
        agents: [{ key: 'agent-1' }],
      }),
      response: { aggregations: undefined },
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(harness.getByIds).toHaveBeenCalledWith(harness.soClient, [AGENT_POLICY_A], {
      ignoreMissing: true,
    });
    expect(result.out_of_date.value).toBe(3);
    expect(result.out_of_date.classified_hosts).toBe(3);
  });

  it('evaluates a missing reported version sentinel once as out-of-date', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        tuples: [
          {
            key: [AGENT_POLICY_A, POLICY_ID, APPLY_STATE_MISSING_LONG, POLICY_REVISION, 5],
            doc_count: 4,
          },
        ],
        agents: [{ key: 'agent-1' }],
      }),
      response: { aggregations: undefined },
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.out_of_date).toEqual({
      value: 4,
      classified_hosts: 4,
      unclassified_overflow_hosts: 0,
      truncated: false,
      source: 'united_metadata_tuple_aggregation',
      population: OUT_OF_DATE_POPULATION,
    });
  });

  it('counts zero current failures when latest is INITIAL after an older current failure', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({ agents: [{ key: 'agent-1' }] }),
      response: responseSearchResult({
        hits: [
          {
            agentId: 'agent-1',
            hit: currentFailureHit(
              'agent-1',
              appliedSource({
                id: INITIAL_POLICY_ID,
                actions: [{ name: 'configure', message: 'failed', status: 'failure' }],
              })
            ),
          },
        ],
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );
    const responseRequest = searchCall(harness.esClient, 1);

    expect(result.current_policy_response_failures.value).toBe(0);
    expect(result.current_policy_response_failures.classified_hosts).toBe(1);
    expect(JSON.stringify(responseRequest.query)).not.toContain(INITIAL_POLICY_ID);
    expect(responseRequest.query?.bool?.must_not).toBeUndefined();
    expect(JSON.stringify(responseRequest.query)).not.toContain('Endpoint.policy.applied.id');
  });

  it('counts zero current failures when the latest current response is success', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({ agents: [{ key: 'agent-1' }] }),
      response: responseSearchResult({
        hits: [
          {
            agentId: 'agent-1',
            hit: currentFailureHit(
              'agent-1',
              appliedSource({
                actions: [{ name: 'configure', message: 'ok', status: 'success' }],
              })
            ),
          },
        ],
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.current_policy_response_failures.value).toBe(0);
    expect(result.current_policy_response_failures.classified_hosts).toBe(1);
  });

  it('rejects latest hits with the wrong package id or revision before counting actions', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        agents: [{ key: 'wrong-id' }, { key: 'wrong-rev' }, { key: 'warning' }],
      }),
      response: responseSearchResult({
        hits: [
          {
            agentId: 'wrong-id',
            hit: currentFailureHit('wrong-id', appliedSource({ id: 'policy-b' })),
          },
          {
            agentId: 'wrong-rev',
            hit: currentFailureHit(
              'wrong-rev',
              appliedSource({ endpoint_policy_version: POLICY_REVISION - 1 })
            ),
          },
          {
            agentId: 'warning',
            hit: currentFailureHit(
              'warning',
              appliedSource({
                actions: [{ name: 'configure', message: 'warn', status: 'warning' }],
              })
            ),
          },
        ],
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.current_policy_response_failures.value).toBe(1);
    expect(result.current_policy_response_failures.classified_hosts).toBe(3);
  });

  it('counts current string revision failures', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({ agents: [{ key: 'agent-1' }] }),
      response: responseSearchResult({
        hits: [
          {
            agentId: 'agent-1',
            hit: currentFailureHit(
              'agent-1',
              appliedSource({ endpoint_policy_version: String(POLICY_REVISION) })
            ),
          },
        ],
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.current_policy_response_failures.value).toBe(1);
    expect(result.current_policy_response_failures.classified_hosts).toBe(1);
    expect(result.current_policy_response_failures.source).toBe('policy_response_latest_per_agent');
  });

  it('keeps different malformed empty null and float-string revisions classified without counting them', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        agents: [
          { key: 'current-string' },
          { key: 'different-string' },
          { key: 'malformed' },
          { key: 'empty' },
          { key: 'null-revision' },
          { key: 'float-string' },
        ],
      }),
      response: responseSearchResult({
        hits: [
          {
            agentId: 'current-string',
            hit: currentFailureHit(
              'current-string',
              appliedSource({ endpoint_policy_version: String(POLICY_REVISION) })
            ),
          },
          {
            agentId: 'different-string',
            hit: currentFailureHit(
              'different-string',
              appliedSource({ endpoint_policy_version: String(POLICY_REVISION - 1) })
            ),
          },
          {
            agentId: 'malformed',
            hit: currentFailureHit(
              'malformed',
              appliedSource({ endpoint_policy_version: 'not-a-revision' })
            ),
          },
          {
            agentId: 'empty',
            hit: currentFailureHit('empty', appliedSource({ endpoint_policy_version: '' })),
          },
          {
            agentId: 'null-revision',
            hit: currentFailureHit(
              'null-revision',
              appliedSource({ endpoint_policy_version: null })
            ),
          },
          {
            agentId: 'float-string',
            hit: currentFailureHit(
              'float-string',
              appliedSource({ endpoint_policy_version: `${POLICY_REVISION}.0` })
            ),
          },
        ],
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.current_policy_response_failures.value).toBe(1);
    expect(result.current_policy_response_failures.classified_hosts).toBe(6);
    expect(result.current_policy_response_failures.source).toBe('policy_response_latest_per_agent');
  });

  it('skips malformed policy-response hits instead of counting them as failures', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({
        agents: [{ key: 'agent-1' }, { key: 'agent-2' }, { key: 'agent-3' }, { key: 'agent-4' }],
      }),
      response: responseSearchResult({
        hits: [
          { agentId: 'agent-1' },
          { agentId: 'agent-2', hit: { _id: 12, _source: appliedSource() } },
          {
            agentId: 'agent-3',
            hit: currentFailureHit('agent-3', appliedSource({ actions: 'not-an-array' })),
          },
          {
            agentId: 'agent-4',
            hit: currentFailureHit('agent-4', {
              Endpoint: { policy: {} },
            }),
          },
        ],
      }),
    });

    const result = await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(result.current_policy_response_failures.value).toBe(0);
    expect(result.current_policy_response_failures.classified_hosts).toBe(2);
    expect(result.current_policy_response_failures.source).toBe('policy_response_latest_per_agent');
  });

  it('propagates request, CCS, and CPS pairing to both Defend reads', async () => {
    const harness = await createEstateAccess();
    harness.endpointAppContextService.isCcsEnabled.mockResolvedValue(true);
    harness.endpointAppContextService.isCpsEnabled.mockReturnValue(false);
    mockSearches(harness.esClient, {
      united: unitedSearchResult({ agents: [{ key: 'agent-1' }] }),
      response: responseSearchResult({
        hits: [{ agentId: 'agent-1', hit: currentFailureHit('agent-1') }],
      }),
    });

    await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    const unitedRequest = searchCall(harness.esClient, 0);
    const responseRequest = searchCall(harness.esClient, 1);

    expect(harness.endpointAppContextService.getReadEsClient).toHaveBeenCalledTimes(1);
    expect(harness.endpointAppContextService.getReadEsClient).toHaveBeenCalledWith(harness.request);
    expect(
      harness.endpointAppContextService.getReadEsClient.mock.calls.every(([value]) => value)
    ).toBe(true);
    expect(harness.endpointAppContextService.isCpsRead).toHaveBeenCalledWith(harness.request);
    expect(unitedRequest.index).toBe(`${METADATA_UNITED_INDEX},*:${METADATA_UNITED_INDEX}`);
    expect(indexName(responseRequest)).toBe(`${policyIndexPattern},*:${policyIndexPattern}`);
    expect(responseRequest.allow_no_indices).toBe(true);
    expect(responseRequest.ignore_unavailable).toBe(true);
    expect(JSON.stringify(responseRequest.aggs)).toContain('event.created');
    expect(JSON.stringify(responseRequest)).toContain(
      'Endpoint.policy.applied.endpoint_policy_version'
    );
  });

  it('keeps CCS off both indexes when CPS can fan out the request', async () => {
    const harness = await createEstateAccess();
    harness.endpointAppContextService.isCcsEnabled.mockResolvedValue(true);
    harness.endpointAppContextService.isCpsEnabled.mockReturnValue(true);
    mockSearches(harness.esClient, {
      united: unitedSearchResult({ agents: [{ key: 'agent-1' }] }),
      response: { aggregations: undefined },
    });

    await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    const unitedRequest = searchCall(harness.esClient, 0);
    const responseRequest = searchCall(harness.esClient, 1);

    expect(harness.endpointAppContextService.isCpsRead).toHaveBeenCalledWith(harness.request);
    expect(unitedRequest.index).toBe(METADATA_UNITED_INDEX);
    expect(indexName(responseRequest)).toBe(policyIndexPattern);
    expect(JSON.stringify(unitedRequest.query)).not.toContain('united.agent.namespaces');
    expect(JSON.stringify(unitedRequest.query)).not.toContain(SPACE_ID);
  });

  it('scopes Fleet reads to the current space and does not use unscoped clients', async () => {
    const harness = await createEstateAccess();
    mockSearches(harness.esClient, {
      united: unitedSearchResult({ agents: [{ key: 'agent-1' }] }),
      response: { aggregations: undefined },
    });

    await readApplyState(
      harness.access,
      harness.endpointAppContextService,
      { idOrName: POLICY_ID },
      harness.request
    );

    expect(harness.getById).toHaveBeenCalledWith(harness.soClient, POLICY_ID, {
      spaceId: SPACE_ID,
    });
    expect(harness.ensureInCurrentSpace).toHaveBeenCalledWith({
      integrationPolicyIds: [POLICY_ID],
    });
    expect(harness.endpointAppContextService.getInternalFleetServices).toHaveBeenCalledWith(
      SPACE_ID
    );
    expectNoForbiddenApis(harness);
  });

  it('maps a foreign-space policy to the same not-found class', async () => {
    const harness = await createEstateAccess();
    harness.ensureInCurrentSpace.mockRejectedValue(new NotFoundError('foreign'));

    await expect(
      readApplyState(
        harness.access,
        harness.endpointAppContextService,
        { idOrName: POLICY_ID },
        harness.request
      )
    ).rejects.toBeInstanceOf(PolicyNotFoundError);
    expect(harness.esClient.search).not.toHaveBeenCalled();
  });

  it('propagates a thrown policy-response search without relabeling it united_missing', async () => {
    const harness = await createEstateAccess();
    const responseFault = Object.assign(new Error('index missing'), {
      meta: { body: { error: { type: 'index_not_found_exception' } } },
    });
    harness.esClient.search.mockImplementation(async (request) => {
      if (isUnitedSearch(request)) {
        return unitedSearchResult({
          agents: [{ key: 'agent-1' }],
        }) as unknown as estypes.SearchResponse;
      }
      throw responseFault;
    });

    await expect(
      readApplyState(
        harness.access,
        harness.endpointAppContextService,
        { idOrName: POLICY_ID },
        harness.request
      )
    ).rejects.toBe(responseFault);
  });
});
