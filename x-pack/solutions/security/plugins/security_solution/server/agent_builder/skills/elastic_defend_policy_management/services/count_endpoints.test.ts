/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SavedObjectsErrorHelpers, type StartServicesAccessor } from '@kbn/core/server';
import { KQLSyntaxError } from '@kbn/es-query';
import { httpServerMock } from '@kbn/core/server/mocks';
import {
  AgentStatusKueryHelper,
  buildPolicyBaseIdsWithFallbackKuery,
} from '@kbn/fleet-plugin/common/services';
import {
  FleetNotFoundError,
  FleetUnauthorizedError,
  PackagePolicyNotFoundError,
} from '@kbn/fleet-plugin/server/errors';
import { FleetPackagePolicyGenerator } from '../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { NotFoundError } from '../../../../endpoint/errors';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import type { EndpointInternalFleetServicesInterface } from '../../../../endpoint/services/fleet/endpoint_fleet_services_factory';
import type { HasAtLeast, PolicyAccessContext } from './access_context';
import { createPolicyAccessContext } from './access_context';
import { countEndpoints } from './count_endpoints';
import { PolicyNotFoundError } from './policy_errors';

type IsAssignable<A, B> = A extends B ? true : false;

type WriteSatisfiesCount = IsAssignable<
  PolicyAccessContext<'policy_write'>,
  Parameters<typeof countEndpoints>[0]
> extends true
  ? true
  : never;
type EstateSatisfiesCount = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  Parameters<typeof countEndpoints>[0]
> extends true
  ? true
  : never;
type PolicyReadDoesNotSatisfyCount = IsAssignable<
  PolicyAccessContext<'policy_read'>,
  Parameters<typeof countEndpoints>[0]
> extends false
  ? true
  : never;
type PlainObjectDoesNotSatisfyCount = IsAssignable<
  {
    spaceId: string;
    fleet: EndpointInternalFleetServicesInterface;
  },
  HasAtLeast<'estate_read'>
> extends false
  ? true
  : never;

const _writeSatisfiesCount: WriteSatisfiesCount = true;
const _estateSatisfiesCount: EstateSatisfiesCount = true;
const _policyReadDoesNotSatisfyCount: PolicyReadDoesNotSatisfyCount = true;
const _plainObjectDoesNotSatisfyCount: PlainObjectDoesNotSatisfyCount = true;

const SPACE_ID = 'space-marketing';
const EXCLUDE_UNENROLLED_AGENTS_KUERY = `not (${AgentStatusKueryHelper.buildKueryForUnenrolledAgents()})`;
const enrolledAgentsFilterKuery = (policyKuery?: string): string =>
  policyKuery === undefined || policyKuery.length === 0
    ? EXCLUDE_UNENROLLED_AGENTS_KUERY
    : `(${policyKuery}) and ${EXCLUDE_UNENROLLED_AGENTS_KUERY}`;
const generator = new FleetPackagePolicyGenerator();

type FleetAgentStatus = Awaited<
  ReturnType<EndpointInternalFleetServicesInterface['agent']['getAgentStatusForAgentPolicy']>
>;

const asFleetAgentStatus = (status: Record<string, unknown>): FleetAgentStatus =>
  status as unknown as FleetAgentStatus;

const createEndpointPolicy = (
  overrides: Parameters<FleetPackagePolicyGenerator['generateEndpointPackagePolicy']>[0] = {}
) =>
  generator.generateEndpointPackagePolicy({
    version: 'WzEsMV0=',
    ...overrides,
  });

const createEstateAccess = async (level: 'estate_read' | 'policy_write' = 'estate_read') => {
  const endpointAppContextService = createMockEndpointAppContextService();
  const request = httpServerMock.createKibanaRequest();
  const getHostMetadataList = jest.fn().mockResolvedValue({
    data: Array.from({ length: 10 }, (_, index) => ({ id: `host-${index}` })),
    total: 11,
  });

  endpointAppContextService.getEndpointAuthz.mockResolvedValue(
    getEndpointAuthzInitialStateMock({
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: level === 'policy_write',
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
    level,
    getStartServices
  );
  const soClient = access.fleet.getSoClient();
  const getById = jest.mocked(access.fleet.packagePolicy.get);
  const listByName = jest.mocked(access.fleet.packagePolicy.list);
  const ensureInCurrentSpace = jest.mocked(access.fleet.ensureInCurrentSpace);
  const getAgentStatusForAgentPolicy = jest.mocked(access.fleet.agent.getAgentStatusForAgentPolicy);
  const listAgents = jest.mocked(access.fleet.agent.listAgents);
  const fetchAgentList = jest.mocked(access.fleet.fetchAgentList);

  ensureInCurrentSpace.mockResolvedValue(undefined);
  listAgents.mockResolvedValue({
    agents: Array.from({ length: 20 }, (_, index) => ({ id: `agent-${index}` })),
    total: 21,
    page: 1,
    perPage: 20,
  } as Awaited<ReturnType<typeof access.fleet.agent.listAgents>>);
  fetchAgentList.mockResolvedValue({
    agents: Array.from({ length: 20 }, (_, index) => ({ id: `agent-${index}` })),
    total: 21,
    page: 1,
    perPage: 20,
  } as Awaited<ReturnType<typeof access.fleet.fetchAgentList>>);

  return {
    access,
    soClient,
    getById,
    listByName,
    ensureInCurrentSpace,
    getAgentStatusForAgentPolicy,
    listAgents,
    fetchAgentList,
    getHostMetadataList,
  };
};

const expectNoForbiddenCountApis = ({
  listAgents,
  fetchAgentList,
  getHostMetadataList,
  listByName,
}: {
  listAgents: jest.Mock;
  fetchAgentList: jest.Mock;
  getHostMetadataList: jest.Mock;
  listByName: jest.Mock;
}): void => {
  expect(listAgents).not.toHaveBeenCalled();
  expect(fetchAgentList).not.toHaveBeenCalled();
  expect(getHostMetadataList).not.toHaveBeenCalled();
  expect(listByName).not.toHaveBeenCalled();
};

describe('countEndpoints', () => {
  it('holds the branded assignability contract without suppression comments', () => {
    expect(_writeSatisfiesCount).toBe(true);
    expect(_estateSatisfiesCount).toBe(true);
    expect(_policyReadDoesNotSatisfyCount).toBe(true);
    expect(_plainObjectDoesNotSatisfyCount).toBe(true);
  });

  it('returns Fleet enrolled-agent totals above the listAgents page size', async () => {
    const {
      access,
      soClient,
      getById,
      listByName,
      ensureInCurrentSpace,
      getAgentStatusForAgentPolicy,
      listAgents,
      fetchAgentList,
      getHostMetadataList,
    } = await createEstateAccess();
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue({
      all: 21,
      active: 18,
      online: 12,
      offline: 4,
      updating: 2,
      error: 1,
      inactive: 2,
      unenrolled: 1,
      events: 0,
      other: 0,
    });

    const result = await countEndpoints(access, { policyId: '  policy-id-1  ' });

    expect(ensureInCurrentSpace).toHaveBeenCalledWith({
      integrationPolicyIds: ['policy-id-1'],
    });
    expect(getById).toHaveBeenCalledWith(soClient, 'policy-id-1', {
      spaceId: SPACE_ID,
    });
    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledWith(
      'agent-policy-a',
      EXCLUDE_UNENROLLED_AGENTS_KUERY
    );
    expect(result).toEqual({
      population: 'enrolled_agents',
      source: 'fleet_status_aggregation',
      status: {
        all: 21,
        active: 18,
        online: 12,
        offline: 4,
        updating: 2,
        error: 1,
        inactive: 2,
        unenrolled: 1,
        events: 0,
        other: 0,
      },
    });
    expect(result.status.all).not.toBe(20);
    expectNoForbiddenCountApis({ listAgents, fetchAgentList, getHostMetadataList, listByName });
  });

  it('passes through inactive and offline enrolled totals after excluding unenrolled agents', async () => {
    const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess();
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'inactive-offline',
        policy_ids: ['agent-policy-a'],
      })
    );
    getAgentStatusForAgentPolicy.mockResolvedValue(
      asFleetAgentStatus({
        all: 5,
        active: 0,
        online: 0,
        offline: 3,
        inactive: 2,
        unenrolled: 0,
      })
    );

    const result = await countEndpoints(access, { policyId: 'inactive-offline' });

    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledWith(
      'agent-policy-a',
      EXCLUDE_UNENROLLED_AGENTS_KUERY
    );
    expect(EXCLUDE_UNENROLLED_AGENTS_KUERY).toBe(
      `not (${AgentStatusKueryHelper.buildKueryForUnenrolledAgents()})`
    );
    expect(result.status).toEqual({
      all: 5,
      active: 0,
      online: 0,
      offline: 3,
      inactive: 2,
      unenrolled: 0,
    });
    expect(result.status.all).not.toBe(result.status.active);
  });

  it('collapses multiple agent-policy ids with version-aware fallback kuery', async () => {
    const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess();
    const policyIds = ['agent-a', 'agent-b', 'agent-c'];
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'multi-policy',
        policy_ids: ['agent-a', 'agent-a', 'agent-b', 'agent-c'],
      })
    );
    getAgentStatusForAgentPolicy.mockResolvedValue(
      asFleetAgentStatus({
        all: 26,
        active: 20,
        orphaned: 1,
        uninstalled: 2,
      })
    );

    const result = await countEndpoints(access, { policyId: 'multi-policy' });
    const expectedPolicyKuery = buildPolicyBaseIdsWithFallbackKuery(policyIds);
    const expectedKuery = enrolledAgentsFilterKuery(expectedPolicyKuery);

    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledWith(undefined, expectedKuery);
    expect(getAgentStatusForAgentPolicy.mock.calls[0][0]).toBeUndefined();
    expect(getAgentStatusForAgentPolicy.mock.calls[0][1]).toBe(expectedKuery);
    expect(expectedKuery).toContain(expectedPolicyKuery);
    expect(expectedKuery).toContain(EXCLUDE_UNENROLLED_AGENTS_KUERY);
    expect(expectedKuery).toContain('policy_base_id:(agent-a or agent-b or agent-c)');
    expect(expectedKuery).toContain(
      'policy_id:(agent-a or agent-b or agent-c) and not policy_base_id:*'
    );
    expect(expectedKuery).not.toBe('policy_id:agent-a OR policy_id:agent-b OR policy_id:agent-c');
    expect(result.status).toEqual({
      all: 26,
      active: 20,
      orphaned: 1,
      uninstalled: 2,
    });
  });

  it('passes through deprecated and future numeric status keys unchanged', async () => {
    const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess();
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'future-keys',
        policy_ids: ['agent-policy-a'],
      })
    );
    getAgentStatusForAgentPolicy.mockResolvedValue(
      asFleetAgentStatus({
        all: 9,
        active: 6,
        events: 0,
        other: 0,
        total: 6,
        orphaned: 1,
        uninstalled: 2,
        quarantined: 3,
        note: 'ignore',
      })
    );

    const result = await countEndpoints(access, { policyId: 'future-keys' });

    expect(result.status).toEqual({
      all: 9,
      active: 6,
      events: 0,
      other: 0,
      total: 6,
      orphaned: 1,
      uninstalled: 2,
      quarantined: 3,
    });
    expect(result.status).not.toHaveProperty('note');
  });

  it('sums numeric own keys only after a rejected multi-id collapse query', async () => {
    const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess();
    const policyIds = ['agent-a', 'agent-b', 'agent-c'];
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'collapse-rejected',
        policy_ids: policyIds,
      })
    );
    getAgentStatusForAgentPolicy
      .mockRejectedValueOnce(SavedObjectsErrorHelpers.createBadRequestError('collapse rejected'))
      .mockResolvedValueOnce(
        asFleetAgentStatus({
          all: 15,
          active: 10,
          orphaned: 1,
          quarantined: 2,
          label: 'skip',
        })
      )
      .mockResolvedValueOnce(
        asFleetAgentStatus({
          all: 8,
          active: 7,
          uninstalled: 1,
        })
      )
      .mockResolvedValueOnce(
        asFleetAgentStatus({
          all: 3,
          active: 3,
          events: 0,
        })
      );

    const result = await countEndpoints(access, { policyId: 'collapse-rejected' });

    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(4);
    expect(getAgentStatusForAgentPolicy).toHaveBeenNthCalledWith(
      1,
      undefined,
      enrolledAgentsFilterKuery(buildPolicyBaseIdsWithFallbackKuery(policyIds))
    );
    expect(getAgentStatusForAgentPolicy).toHaveBeenNthCalledWith(
      2,
      'agent-a',
      EXCLUDE_UNENROLLED_AGENTS_KUERY
    );
    expect(getAgentStatusForAgentPolicy).toHaveBeenNthCalledWith(
      3,
      'agent-b',
      EXCLUDE_UNENROLLED_AGENTS_KUERY
    );
    expect(getAgentStatusForAgentPolicy).toHaveBeenNthCalledWith(
      4,
      'agent-c',
      EXCLUDE_UNENROLLED_AGENTS_KUERY
    );
    expect(result).toEqual({
      population: 'enrolled_agents',
      source: 'fleet_status_aggregation',
      status: {
        all: 26,
        active: 20,
        orphaned: 1,
        quarantined: 2,
        uninstalled: 1,
        events: 0,
      },
    });
  });

  it('falls back to per-id aggregation when the collapse query throws a direct KQLSyntaxError', async () => {
    const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess();
    const policyIds = ['agent-a', 'agent-b'];
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'kql-syntax-error',
        policy_ids: policyIds,
      })
    );
    const kqlSyntaxError = new KQLSyntaxError(
      {
        name: 'KQLSyntaxError',
        message: 'invalid kuery',
        found: '',
        expected: null,
        location: { start: { offset: 0, line: 1, column: 1 } },
      } as never,
      ''
    );
    getAgentStatusForAgentPolicy
      .mockRejectedValueOnce(kqlSyntaxError)
      .mockResolvedValueOnce(asFleetAgentStatus({ all: 4, active: 4 }))
      .mockResolvedValueOnce(asFleetAgentStatus({ all: 6, active: 5, offline: 1 }));

    const result = await countEndpoints(access, { policyId: 'kql-syntax-error' });

    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(3);
    expect(getAgentStatusForAgentPolicy).toHaveBeenNthCalledWith(
      1,
      undefined,
      enrolledAgentsFilterKuery(buildPolicyBaseIdsWithFallbackKuery(policyIds))
    );
    expect(getAgentStatusForAgentPolicy).toHaveBeenNthCalledWith(
      2,
      'agent-a',
      EXCLUDE_UNENROLLED_AGENTS_KUERY
    );
    expect(getAgentStatusForAgentPolicy).toHaveBeenNthCalledWith(
      3,
      'agent-b',
      EXCLUDE_UNENROLLED_AGENTS_KUERY
    );
    expect(result).toEqual({
      population: 'enrolled_agents',
      source: 'fleet_status_aggregation',
      status: { all: 10, active: 9, offline: 1 },
    });
  });

  it('does not fall back to per-id aggregation when collapse fails for a non-query reason', async () => {
    const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess();
    const unavailable = SavedObjectsErrorHelpers.decorateGeneralError(new Error('unavailable'));
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'collapse-5xx',
        policy_ids: ['agent-a', 'agent-b'],
      })
    );
    getAgentStatusForAgentPolicy.mockRejectedValue(unavailable);

    await expect(countEndpoints(access, { policyId: 'collapse-5xx' })).rejects.toBe(unavailable);
    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledWith(
      undefined,
      enrolledAgentsFilterKuery(buildPolicyBaseIdsWithFallbackKuery(['agent-a', 'agent-b']))
    );
  });

  it.each([[[]], [['', '']]])(
    'returns a labelled empty enrolled-agent summary for assignments %j',
    async (policyIds) => {
      const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess();
      getById.mockResolvedValue(
        createEndpointPolicy({
          id: 'empty-assignments',
          policy_ids: policyIds,
        })
      );

      const result = await countEndpoints(access, { policyId: 'empty-assignments' });

      expect(result).toEqual({
        population: 'enrolled_agents',
        source: 'no_agent_policy_assignments',
        status: {},
      });
      expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
      expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalledWith();
      expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalledWith(undefined, undefined);
    }
  );

  it('uses the single-id aggregation after de-duplicating repeated assignments', async () => {
    const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess();
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'deduped',
        policy_ids: ['agent-a', 'agent-a'],
      })
    );
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus({ all: 4, active: 4 }));

    await countEndpoints(access, { policyId: 'deduped' });

    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
    expect(getAgentStatusForAgentPolicy).toHaveBeenCalledWith(
      'agent-a',
      EXCLUDE_UNENROLLED_AGENTS_KUERY
    );
  });

  it.each([
    [
      'saved-object 404',
      SavedObjectsErrorHelpers.createGenericNotFoundError('fleet-package-policies', 'missing'),
    ],
    ['package-policy 404', new PackagePolicyNotFoundError('missing')],
    ['fleet 404', new FleetNotFoundError('missing')],
    ['endpoint 404', new NotFoundError('missing')],
    ['null miss', null],
  ])('returns the same not-found for a missing id after %s', async (_label, miss) => {
    const { access, getById, getAgentStatusForAgentPolicy, listByName } =
      await createEstateAccess();

    if (miss === null) {
      getById.mockResolvedValue(null);
    } else {
      getById.mockRejectedValue(miss);
    }

    await expect(countEndpoints(access, { policyId: 'missing' })).rejects.toMatchObject({
      name: 'PolicyNotFoundError',
      identifier: 'missing',
      message: 'Endpoint policy not found',
    });
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(listByName).not.toHaveBeenCalled();
  });

  it('returns the same non-leaking not-found for a foreign-space membership miss', async () => {
    const { access, getById, ensureInCurrentSpace, getAgentStatusForAgentPolicy, listByName } =
      await createEstateAccess();
    getById.mockResolvedValue(createEndpointPolicy({ id: 'foreign-id', name: 'Foreign' }));
    ensureInCurrentSpace.mockRejectedValue(new NotFoundError('hidden'));

    const foreign = await countEndpoints(access, { policyId: 'foreign-id' }).catch(
      (caught: unknown) => caught
    );
    const missing = new PolicyNotFoundError('foreign-id');

    expect(foreign).toBeInstanceOf(PolicyNotFoundError);
    if (!(foreign instanceof PolicyNotFoundError)) {
      throw new Error('expected PolicyNotFoundError');
    }
    expect(foreign.message).toBe(missing.message);
    expect(foreign.identifier).toBe('foreign-id');
    expect(foreign.message).not.toMatch(/space|hidden|foreign/i);
    expect(getById).not.toHaveBeenCalled();
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(listByName).not.toHaveBeenCalled();
  });

  it('returns the same not-found for a non-endpoint package policy and never aggregates', async () => {
    const { access, getById, getAgentStatusForAgentPolicy, listByName } =
      await createEstateAccess();
    getById.mockResolvedValue(
      generator.generate({
        id: 'system-policy',
        name: 'System',
        version: 'WzEsMV0=',
        package: { name: 'system', title: 'System', version: '1.0.0' },
        policy_ids: ['agent-policy-a'],
      })
    );

    await expect(countEndpoints(access, { policyId: 'system-policy' })).rejects.toMatchObject({
      name: 'PolicyNotFoundError',
      identifier: 'system-policy',
      message: 'Endpoint policy not found',
    });
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(listByName).not.toHaveBeenCalled();
  });

  it.each([
    ['bad request', SavedObjectsErrorHelpers.createBadRequestError('invalid identifier')],
    ['authorization', new FleetUnauthorizedError('forbidden')],
    [
      'conflict',
      SavedObjectsErrorHelpers.createConflictError('fleet-package-policies', 'policy-1'),
    ],
    ['5xx', SavedObjectsErrorHelpers.decorateGeneralError(new Error('unavailable'))],
  ])('rethrows %s from id lookup without aggregating', async (_label, error) => {
    const { access, getById, getAgentStatusForAgentPolicy, listByName } =
      await createEstateAccess();
    getById.mockRejectedValue(error);

    await expect(countEndpoints(access, { policyId: 'policy-1' })).rejects.toBe(error);
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(listByName).not.toHaveBeenCalled();
  });

  it('accepts a write access context at runtime', async () => {
    const { access, getById, getAgentStatusForAgentPolicy } = await createEstateAccess(
      'policy_write'
    );
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'write-ok',
        policy_ids: ['agent-policy-a'],
      })
    );
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus({ all: 2, active: 2 }));

    await expect(countEndpoints(access, { policyId: 'write-ok' })).resolves.toMatchObject({
      population: 'enrolled_agents',
      source: 'fleet_status_aggregation',
      status: { all: 2, active: 2 },
    });
  });
});
