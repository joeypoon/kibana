/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock } from '@kbn/core/server/mocks';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { FleetPackagePolicyGenerator } from '../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import { policyFactory } from '../../../../../common/endpoint/models/policy_config';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { ProtectionModes } from '../../../../../common/endpoint/types';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import type { EndpointInternalFleetServicesInterface } from '../../../../endpoint/services/fleet/endpoint_fleet_services_factory';
import { hashPolicyConfig } from '../domain/hash_policy_config';
import { normalize } from '../domain/normalize';
import type { HasAtLeast, PolicyAccessContext } from './access_context';
import { createPolicyAccessContext } from './access_context';
import { listEndpointPolicies } from './read_estate';

type IsAssignable<A, B> = A extends B ? true : false;

type EstateSatisfiesList = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  Parameters<typeof listEndpointPolicies>[0]
> extends true
  ? true
  : never;
type WriteSatisfiesList = IsAssignable<
  PolicyAccessContext<'policy_write'>,
  Parameters<typeof listEndpointPolicies>[0]
> extends true
  ? true
  : never;
type PlainObjectDoesNotSatisfyList = IsAssignable<
  {
    spaceId: string;
    fleet: EndpointInternalFleetServicesInterface;
  },
  Parameters<typeof listEndpointPolicies>[0]
> extends false
  ? true
  : never;
type PolicyReadSatisfiesList = IsAssignable<
  PolicyAccessContext<'policy_read'>,
  HasAtLeast<'policy_read'>
> extends true
  ? true
  : never;

const _estateSatisfiesList: EstateSatisfiesList = true;
const _writeSatisfiesList: WriteSatisfiesList = true;
const _plainObjectDoesNotSatisfyList: PlainObjectDoesNotSatisfyList = true;
const _policyReadSatisfiesList: PolicyReadSatisfiesList = true;

const SPACE_ID = 'space-marketing';
const generator = new FleetPackagePolicyGenerator();

const createEndpointPolicy = (
  overrides: Parameters<FleetPackagePolicyGenerator['generateEndpointPackagePolicy']>[0] = {}
) =>
  generator.generateEndpointPackagePolicy({
    version: 'WzEsMV0=',
    ...overrides,
  });

const createReadAccess = async () => {
  const endpointAppContextService = createMockEndpointAppContextService();
  const request = httpServerMock.createKibanaRequest();

  endpointAppContextService.getEndpointAuthz.mockResolvedValue(
    getEndpointAuthzInitialStateMock({
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    })
  );

  const getStartServices = jest.fn(async () => [
    { savedObjects: { getScopedClient: jest.fn().mockReturnValue({}) } },
  ]) as unknown as StartServicesAccessor;
  const access = await createPolicyAccessContext(
    endpointAppContextService,
    { request, spaceId: SPACE_ID },
    'policy_read',
    getStartServices
  );
  const soClient = access.fleet.getSoClient();
  const listPolicies = jest.mocked(access.fleet.packagePolicy.list);
  const getById = jest.mocked(access.fleet.packagePolicy.get);
  const getByIds = jest.mocked(access.fleet.packagePolicy.getByIDs);
  const ensureInCurrentSpace = jest.mocked(access.fleet.ensureInCurrentSpace);
  const getAgentStatusForAgentPolicy = jest.mocked(access.fleet.agent.getAgentStatusForAgentPolicy);

  return {
    access,
    soClient,
    listPolicies,
    getById,
    getByIds,
    ensureInCurrentSpace,
    getAgentStatusForAgentPolicy,
  };
};

const accessKuery = (): string => 'fleet-package-policies.package.name: "endpoint"';

const createPage = (items: PackagePolicy[], total: number, page: number, perPage: number) => ({
  items,
  total,
  page,
  perPage,
});

describe('listEndpointPolicies', () => {
  it('holds the branded assignability contract without suppression comments', () => {
    expect(_estateSatisfiesList).toBe(true);
    expect(_writeSatisfiesList).toBe(true);
    expect(_plainObjectDoesNotSatisfyList).toBe(true);
    expect(_policyReadSatisfiesList).toBe(true);
  });

  it('returns has_more false when Fleet total equals the requested page', async () => {
    const { access, soClient, listPolicies } = await createReadAccess();
    const items = Array.from({ length: 20 }, (_, index) =>
      createEndpointPolicy({ id: `policy-${index}`, name: `Policy ${index}` })
    );
    listPolicies.mockResolvedValue(createPage(items, 20, 1, 20));

    const result = await listEndpointPolicies(access, { page: 1, perPage: 20 });

    expect(listPolicies).toHaveBeenCalledTimes(1);
    expect(listPolicies).toHaveBeenCalledWith(soClient, {
      kuery: access.fleet.endpointPolicyKuery,
      page: 1,
      perPage: 20,
      spaceId: SPACE_ID,
    });
    expect(result).toEqual(
      expect.objectContaining({
        population: 'endpoint_package_policies',
        page: 1,
        per_page: 20,
        value_total: 20,
        has_more: false,
        invalid_policy_count: 0,
      })
    );
    expect(result.items).toHaveLength(20);
  });

  it('returns has_more true and 20 rows when Fleet total is 21', async () => {
    const { access, listPolicies } = await createReadAccess();
    const items = Array.from({ length: 20 }, (_, index) =>
      createEndpointPolicy({ id: `policy-${index}`, name: `Policy ${index}` })
    );
    listPolicies.mockResolvedValue(createPage(items, 21, 1, 20));

    const result = await listEndpointPolicies(access, { page: 1, perPage: 20 });

    expect(result.has_more).toBe(true);
    expect(result.value_total).toBe(21);
    expect(result.items).toHaveLength(20);
  });

  it('clamps perPage to 50 and forwards that bound to Fleet', async () => {
    const { access, soClient, listPolicies } = await createReadAccess();
    const items = Array.from({ length: 50 }, (_, index) =>
      createEndpointPolicy({ id: `policy-${index}`, name: `Policy ${index}` })
    );
    listPolicies.mockResolvedValue(createPage(items, 50, 1, 50));

    const result = await listEndpointPolicies(access, { page: 1, perPage: 100 });

    expect(listPolicies).toHaveBeenCalledWith(soClient, {
      kuery: access.fleet.endpointPolicyKuery,
      page: 1,
      perPage: 50,
      spaceId: SPACE_ID,
    });
    expect(result.per_page).toBe(50);
    expect(result.items).toHaveLength(50);
    expect(result.has_more).toBe(false);
  });

  it('skips mixed malformed rows and keeps page-local invalid_policy_count', async () => {
    const { access, listPolicies } = await createReadAccess();
    const valid = createEndpointPolicy({ id: 'valid-id', name: 'Valid Policy' });
    const missingInputs = generator.generate({
      id: 'input-less',
      name: 'Input Less',
      version: 'WzEsMV0=',
      inputs: [],
    });
    const missingVersion = createEndpointPolicy({ id: 'missing-version', name: 'Missing Version' });
    delete missingVersion.version;
    listPolicies.mockResolvedValue(createPage([valid, missingInputs, missingVersion], 3, 1, 20));

    const result = await listEndpointPolicies(access, { page: 1, perPage: 20 });

    expect(result.items.map((item) => item.id)).toEqual(['valid-id']);
    expect(result.invalid_policy_count).toBe(2);
    expect(result.value_total).toBe(3);
    expect(result.has_more).toBe(false);
  });

  it('forwards space scope and endpoint kuery on the single list call', async () => {
    const { access, soClient, listPolicies, getById, getByIds, ensureInCurrentSpace } =
      await createReadAccess();
    listPolicies.mockResolvedValue(createPage([], 0, 2, 10));

    await listEndpointPolicies(access, { page: 2, perPage: 10 });

    expect(listPolicies).toHaveBeenCalledTimes(1);
    expect(listPolicies).toHaveBeenCalledWith(soClient, {
      kuery: access.fleet.endpointPolicyKuery,
      page: 2,
      perPage: 10,
      spaceId: SPACE_ID,
    });
    expect(access.fleet.endpointPolicyKuery).toBe(accessKuery());
    expect(getById).not.toHaveBeenCalled();
    expect(getByIds).not.toHaveBeenCalled();
    expect(ensureInCurrentSpace).not.toHaveBeenCalled();
  });

  it('returns only whitelisted identity, hash, and compact posture', async () => {
    const { access, listPolicies } = await createReadAccess();
    const policy = createEndpointPolicy({
      id: 'policy-id-2',
      name: 'Whitelist Policy',
      description: 'visible description',
      spaceIds: ['other-space'],
      created_by: 'creator',
      created_at: '2020-01-01T00:00:00.000Z',
      agents: 424242,
      policy_ids: ['agent-policy-secret'],
    });
    Object.assign(policy.inputs[0], { compiled_input: { secret: 'compiled-secret' } });
    listPolicies.mockResolvedValue(createPage([policy], 1, 1, 20));

    const result = await listEndpointPolicies(access, { page: 1, perPage: 20 });
    const [item] = result.items;

    expect(item).toBeDefined();
    expect(Object.keys(item ?? {}).sort()).toEqual(
      [
        'description',
        'id',
        'name',
        'normalizedHash',
        'packageVersion',
        'posture',
        'revision',
        'updatedAt',
        'version',
      ].sort()
    );
    expect(item).toEqual({
      id: 'policy-id-2',
      name: 'Whitelist Policy',
      description: 'visible description',
      revision: policy.revision,
      version: 'WzEsMV0=',
      updatedAt: policy.updated_at,
      packageVersion: policy.package?.version,
      normalizedHash: hashPolicyConfig(normalize(policy.inputs[0].config.policy.value)),
      posture: {
        windowsProtectionModes: {
          malware: ProtectionModes.prevent,
          ransomware: ProtectionModes.prevent,
          memoryThreat: ProtectionModes.prevent,
          behavior: ProtectionModes.prevent,
        },
        macProtectionModes: {
          malware: ProtectionModes.prevent,
          behavior: ProtectionModes.prevent,
        },
        linuxProtectionModes: {
          malware: ProtectionModes.prevent,
          behavior: ProtectionModes.prevent,
        },
        globalTelemetryEnabled: false,
      },
    });
    expect(result).not.toHaveProperty('inputs');
    expect(result).not.toHaveProperty('normalizedConfig');
    expect(JSON.stringify(result)).not.toContain('compiled-secret');
    expect(JSON.stringify(result)).not.toContain('other-space');
    expect(JSON.stringify(result)).not.toContain('creator');
    expect(JSON.stringify(result)).not.toContain('agent-policy-secret');
    expect(JSON.stringify(result)).not.toContain('424242');
    expect(JSON.stringify(result)).not.toContain('windows.events');
    expect(item).not.toHaveProperty('inputs');
    expect(item).not.toHaveProperty('config');
    expect(item).not.toHaveProperty('normalizedConfig');
    expect(item).not.toHaveProperty('policy_ids');
    expect(item).not.toHaveProperty('agents');
  });

  it('never derives endpoint or agent counts', async () => {
    const { access, listPolicies, getAgentStatusForAgentPolicy } = await createReadAccess();
    const policy = createEndpointPolicy({ id: 'counted', name: 'Counted', agents: 99 });
    listPolicies.mockResolvedValue(createPage([policy], 7, 1, 20));

    const result = await listEndpointPolicies(access, { page: 1, perPage: 20 });

    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(result).not.toHaveProperty('enrolled_agents');
    expect(result).not.toHaveProperty('agents');
    expect(result.items[0]).not.toHaveProperty('agents');
    expect(result.items[0]).not.toHaveProperty('enrolled_agents');
    expect(result.value_total).toBe(7);
    expect(result.items).toHaveLength(1);
  });

  it('hashes full normalized configs deterministically', async () => {
    const { access, listPolicies } = await createReadAccess();
    const sharedConfig = policyFactory();
    const first = createEndpointPolicy({
      id: 'same-a',
      name: 'Same A',
    });
    first.inputs[0].config.policy.value = sharedConfig;
    const second = createEndpointPolicy({
      id: 'same-b',
      name: 'Same B',
    });
    second.inputs[0].config.policy.value = structuredClone(sharedConfig);
    const driftedConfig = policyFactory();
    driftedConfig.windows.malware.mode = ProtectionModes.detect;
    const drifted = createEndpointPolicy({
      id: 'drifted',
      name: 'Drifted',
    });
    drifted.inputs[0].config.policy.value = driftedConfig;
    listPolicies.mockResolvedValue(createPage([first, second, drifted], 3, 1, 20));

    const result = await listEndpointPolicies(access, { page: 1, perPage: 20 });
    const expectedShared = hashPolicyConfig(normalize(sharedConfig));
    const expectedDrifted = hashPolicyConfig(normalize(driftedConfig));

    expect(result.items[0]?.normalizedHash).toBe(expectedShared);
    expect(result.items[1]?.normalizedHash).toBe(expectedShared);
    expect(result.items[2]?.normalizedHash).toBe(expectedDrifted);
    expect(expectedShared).not.toBe(expectedDrifted);
  });

  it('caps long name and description at 512 and flags only the cut fields', async () => {
    const { access, listPolicies } = await createReadAccess();
    const longName = 'N'.repeat(600);
    const longDescription = 'D'.repeat(600);
    const policy = createEndpointPolicy({
      id: 'long-strings',
      name: longName,
      description: longDescription,
    });
    listPolicies.mockResolvedValue(createPage([policy], 1, 1, 20));

    const result = await listEndpointPolicies(access, { page: 1, perPage: 20 });
    const [item] = result.items;

    expect(item?.name).toBe('N'.repeat(512));
    expect(item?.description).toBe('D'.repeat(512));
    expect(item?.name_string_truncated).toBe(true);
    expect(item?.description_string_truncated).toBe(true);
    expect(item?.name).toHaveLength(512);
    expect(item?.description).toHaveLength(512);
  });
});
