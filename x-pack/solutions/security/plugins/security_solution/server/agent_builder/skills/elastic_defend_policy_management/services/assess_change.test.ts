/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SavedObjectsErrorHelpers, type StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock } from '@kbn/core/server/mocks';
import { licenseMock } from '@kbn/licensing-plugin/common/licensing.mock';
import { ProductFeatureSecurityKey } from '@kbn/security-solution-features/keys';
import { FleetPackagePolicyGenerator } from '../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import type { PolicyConfig } from '../../../../../common/endpoint/types';
import { ProtectionModes } from '../../../../../common/endpoint/types';
import { NotFoundError } from '../../../../endpoint/errors';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import type { EndpointInternalFleetServicesInterface } from '../../../../endpoint/services/fleet/endpoint_fleet_services_factory';
import { getFieldRegistryEntry } from '../domain/field_registry';
import {
  DEVICE_CONTROL_MISSING_POPUP_MESSAGE,
  computePathEligibility,
  prepareChangeSet,
} from '../domain/impact';
import type { HasAtLeast, PolicyAccessContext } from './access_context';
import { createPolicyAccessContext } from './access_context';
import { assessChange, toEligibilityContext } from './assess_change';
import type { EndpointCountResult } from './count_endpoints';
import * as countEndpointsModule from './count_endpoints';
import { PolicyAmbiguousNameError, PolicyNotFoundError } from './policy_errors';
import * as readPolicyModule from './read_policy';

type IsAssignable<A, B> = A extends B ? true : false;

type WriteSatisfiesAssess = IsAssignable<
  PolicyAccessContext<'policy_write'>,
  Parameters<typeof assessChange>[0]
> extends true
  ? true
  : never;
type EstateSatisfiesAssess = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  Parameters<typeof assessChange>[0]
> extends true
  ? true
  : never;
type PolicyReadDoesNotSatisfyAssess = IsAssignable<
  PolicyAccessContext<'policy_read'>,
  Parameters<typeof assessChange>[0]
> extends false
  ? true
  : never;
type PlainObjectDoesNotSatisfyAssess = IsAssignable<
  {
    spaceId: string;
    fleet: EndpointInternalFleetServicesInterface;
  },
  HasAtLeast<'estate_read'>
> extends false
  ? true
  : never;

const _writeSatisfiesAssess: WriteSatisfiesAssess = true;
const _estateSatisfiesAssess: EstateSatisfiesAssess = true;
const _policyReadDoesNotSatisfyAssess: PolicyReadDoesNotSatisfyAssess = true;
const _plainObjectDoesNotSatisfyAssess: PlainObjectDoesNotSatisfyAssess = true;

const SPACE_ID = 'space-marketing';
const generator = new FleetPackagePolicyGenerator();

const MIXED_STATUS_ABOVE_PAGE: Readonly<Record<string, number>> = {
  all: 27,
  active: 22,
  online: 14,
  offline: 6,
  updating: 3,
  error: 2,
  inactive: 1,
  unenrolled: 2,
  events: 0,
  other: 1,
  orphaned: 1,
  uninstalled: 1,
};

const FUTURE_AND_DEPRECATED_STATUS: Readonly<Record<string, number>> = {
  all: 9,
  active: 6,
  events: 0,
  other: 0,
  total: 6,
  orphaned: 1,
  uninstalled: 2,
  quarantined: 3,
  draining: 4,
};

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

const rawParams = (idOrName = 'policy-id-1'): unknown => ({
  idOrName,
  changes: [{ op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.detect }],
});

const requireStoredPolicy = (policy: ReturnType<typeof createEndpointPolicy>): PolicyConfig => {
  const storedPolicy = policy.inputs[0]?.config?.policy?.value;
  if (storedPolicy == null) {
    throw new Error('expected generated endpoint package policy to include config.policy');
  }
  return storedPolicy;
};

const POPUP_MESSAGE_PATH = /(?:^|\.)popup\.[^.]+\.message$/;

const Gold = licenseMock.createLicense({ license: { type: 'gold', mode: 'gold' } });
const Platinum = licenseMock.createLicense({ license: { type: 'platinum', mode: 'platinum' } });
const Enterprise = licenseMock.createLicense({ license: { type: 'enterprise' } });

const createEstateAccess = async () => {
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
  const licenseService = endpointAppContextService.getLicenseService();
  licenseService.getLicenseType = jest.fn(() => 'enterprise');
  licenseService.getLicenseInformation = jest.fn(() => Enterprise);
  licenseService.isPlatinumPlus = jest.fn(() => true);
  licenseService.isEnterprise = jest.fn(() => true);
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
    endpointAppContextService,
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

const expectNoMixedPopulations = ({
  listAgents,
  fetchAgentList,
  getHostMetadataList,
}: {
  listAgents: jest.Mock;
  fetchAgentList: jest.Mock;
  getHostMetadataList: jest.Mock;
}): void => {
  expect(listAgents).not.toHaveBeenCalled();
  expect(fetchAgentList).not.toHaveBeenCalled();
  expect(getHostMetadataList).not.toHaveBeenCalled();
};

const toExpectedFacts = (
  prepared: ReturnType<typeof prepareChangeSet>,
  endpointAppContextService: Parameters<typeof assessChange>[1]
) =>
  prepared.explicitChanges.map((change) => {
    const entry = getFieldRegistryEntry(change.path);
    if (entry === undefined) {
      throw new Error(`expected registry entry for ${change.path}`);
    }

    return {
      path: change.path,
      from: change.from,
      to: change.to,
      origin: change.origin,
      registry: {
        path: entry.path,
        os: entry.os,
        kind: entry.kind,
        tier: entry.tier,
        documentation: entry.documentation,
        license: entry.license,
        minVersion: entry.minVersion,
        maxVersion: entry.maxVersion,
        source: entry.source,
        userEditable: entry.userEditable,
        productFeatureGate: entry.productFeatureGate,
      },
      eligibility: computePathEligibility(
        change.path,
        toEligibilityContext(endpointAppContextService, prepared.proposedConfig)
      ),
    };
  });

describe('assessChange', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('holds the branded assignability contract without suppression comments', () => {
    expect(_writeSatisfiesAssess).toBe(true);
    expect(_estateSatisfiesAssess).toBe(true);
    expect(_policyReadDoesNotSatisfyAssess).toBe(true);
    expect(_plainObjectDoesNotSatisfyAssess).toBe(true);
  });

  it('returns the facts-only DTO from one resolve, one prepare, and one count', async () => {
    const {
      access,
      endpointAppContextService,
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
      name: 'Endpoint Policy',
      policy_ids: ['agent-policy-a'],
    });
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));
    const getEndpointPolicySpy = jest.spyOn(readPolicyModule, 'getEndpointPolicy');
    const countSpy = jest.spyOn(countEndpointsModule, 'countEndpoints');
    const params = rawParams('  policy-id-1  ');

    const result = await assessChange(access, endpointAppContextService, params);
    const storedPolicy = requireStoredPolicy(policy);
    const prepared = prepareChangeSet(params, storedPolicy);

    expect(getEndpointPolicySpy).toHaveBeenCalledTimes(1);
    expect(getEndpointPolicySpy).toHaveBeenCalledWith(access, { idOrName: 'policy-id-1' });
    expect(countSpy).toHaveBeenCalledTimes(1);
    expect(countSpy).toHaveBeenCalledWith(access, { policyId: 'policy-id-1' });
    expect(getById).toHaveBeenCalledWith(soClient, 'policy-id-1', { spaceId: SPACE_ID });
    expect(ensureInCurrentSpace).toHaveBeenCalledWith({
      integrationPolicyIds: ['policy-id-1'],
    });
    expect(listByName).not.toHaveBeenCalled();
    expect(endpointAppContextService.getInternalFleetServices).toHaveBeenCalledWith(SPACE_ID);
    expect(
      jest
        .mocked(endpointAppContextService.getInternalFleetServices)
        .mock.calls.every(([spaceId]) => spaceId === SPACE_ID)
    ).toBe(true);
    expect(result).toEqual({
      policy: {
        id: 'policy-id-1',
        name: 'Endpoint Policy',
        revision: policy.revision,
        version: 'WzEsMV0=',
      },
      spaceId: SPACE_ID,
      requestedOperations: [
        { op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.detect },
      ],
      requestedImpact: toExpectedFacts(prepared, endpointAppContextService).filter(
        (fact) => fact.origin.kind === 'direct'
      ),
      expandedChanges: toExpectedFacts(prepared, endpointAppContextService),
      normalizedDiff: prepared.normalizedDiff,
      sideEffects: prepared.sideEffects,
      blastRadius: {
        population: 'enrolled_agents',
        source: 'fleet_status_aggregation',
        status: MIXED_STATUS_ABOVE_PAGE,
      },
    });
    expect(Object.keys(result)).toEqual([
      'policy',
      'spaceId',
      'requestedOperations',
      'requestedImpact',
      'expandedChanges',
      'normalizedDiff',
      'sideEffects',
      'blastRadius',
    ]);
    expect(result).not.toHaveProperty('eligible');
    expect(result).not.toHaveProperty('verdict');
    expect(result).not.toHaveProperty('recommendation');
    expect(result.blastRadius.status.all).toBe(27);
    expect(result.blastRadius.status.all).not.toBe(20);
    expectNoMixedPopulations({ listAgents, fetchAgentList, getHostMetadataList });
  });

  it('counts the resolved policy id after a name lookup and preserves mixed statuses above 20', async () => {
    const {
      access,
      endpointAppContextService,
      getById,
      listByName,
      getAgentStatusForAgentPolicy,
      listAgents,
      fetchAgentList,
      getHostMetadataList,
    } = await createEstateAccess();
    const policy = createEndpointPolicy({
      id: 'named-id',
      name: 'Exact Name',
      policy_ids: ['agent-policy-a'],
    });
    getById
      .mockRejectedValueOnce(
        SavedObjectsErrorHelpers.createGenericNotFoundError('fleet-package-policies', 'Exact Name')
      )
      .mockResolvedValue(policy);
    listByName.mockResolvedValue({
      items: [policy],
      total: 1,
      page: 1,
      perPage: 11,
    });
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));
    const countSpy = jest.spyOn(countEndpointsModule, 'countEndpoints');

    const result = await assessChange(access, endpointAppContextService, rawParams('Exact Name'));

    expect(countSpy).toHaveBeenCalledTimes(1);
    expect(countSpy).toHaveBeenCalledWith(access, { policyId: 'named-id' });
    expect(result.policy).toEqual({
      id: 'named-id',
      name: 'Exact Name',
      revision: policy.revision,
      version: 'WzEsMV0=',
    });
    expect(result.blastRadius.status).toEqual(MIXED_STATUS_ABOVE_PAGE);
    expect(result.blastRadius.status.all).toBe(27);
    expect(result.blastRadius.status.all).not.toBe(20);
    expectNoMixedPopulations({ listAgents, fetchAgentList, getHostMetadataList });
  });

  it('preserves future and deprecated numeric status keys verbatim', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'policy-id-1',
        policy_ids: ['agent-policy-a'],
      })
    );
    getAgentStatusForAgentPolicy.mockResolvedValue(
      asFleetAgentStatus({
        ...FUTURE_AND_DEPRECATED_STATUS,
        note: 'ignore',
      })
    );

    const result = await assessChange(access, endpointAppContextService, rawParams());

    expect(result.blastRadius.status).toEqual(FUTURE_AND_DEPRECATED_STATUS);
    expect(result.blastRadius.status).not.toHaveProperty('note');
    expect(result.blastRadius.population).toBe('enrolled_agents');
  });

  it('leaves status.all absent and does not infer a headline', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'policy-id-1',
        policy_ids: ['agent-policy-a'],
      })
    );
    getAgentStatusForAgentPolicy.mockResolvedValue(
      asFleetAgentStatus({
        online: 4,
        offline: 3,
        updating: 1,
      })
    );

    const result = await assessChange(access, endpointAppContextService, rawParams());

    expect(result.blastRadius.status).toEqual({
      online: 4,
      offline: 3,
      updating: 1,
    });
    expect(result.blastRadius.status).not.toHaveProperty('all');
    expect(Object.values(result.blastRadius.status).reduce((sum, value) => sum + value, 0)).toBe(8);
    expect(result.blastRadius).not.toEqual(
      expect.objectContaining({
        status: expect.objectContaining({ all: 8 }),
      })
    );
  });

  it('returns existing not-found for a current-space denial before count', async () => {
    const {
      access,
      endpointAppContextService,
      getById,
      listByName,
      ensureInCurrentSpace,
      getAgentStatusForAgentPolicy,
    } = await createEstateAccess();
    getById.mockResolvedValue(createEndpointPolicy({ id: 'foreign-id', name: 'Foreign' }));
    ensureInCurrentSpace.mockRejectedValue(new NotFoundError('hidden'));
    const countSpy = jest.spyOn(countEndpointsModule, 'countEndpoints');

    const foreign = await assessChange(
      access,
      endpointAppContextService,
      rawParams('foreign-id')
    ).catch((caught: unknown) => caught);
    const missing = new PolicyNotFoundError('foreign-id');

    expect(foreign).toBeInstanceOf(PolicyNotFoundError);
    if (!(foreign instanceof PolicyNotFoundError)) {
      throw new Error('expected PolicyNotFoundError');
    }
    expect(foreign.message).toBe(missing.message);
    expect(foreign.message).toBe('Endpoint policy not found');
    expect(foreign.identifier).toBe('foreign-id');
    expect(foreign.message).not.toMatch(/space|hidden|foreign/i);
    expect(countSpy).not.toHaveBeenCalled();
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(listByName).not.toHaveBeenCalled();
  });

  it('preserves missing-name taxonomy and does not count', async () => {
    const {
      access,
      endpointAppContextService,
      getById,
      listByName,
      ensureInCurrentSpace,
      getAgentStatusForAgentPolicy,
    } = await createEstateAccess();
    getById.mockRejectedValue(SavedObjectsErrorHelpers.createGenericNotFoundError());
    listByName.mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      perPage: 11,
    });
    const countSpy = jest.spyOn(countEndpointsModule, 'countEndpoints');

    await expect(
      assessChange(access, endpointAppContextService, rawParams('Missing'))
    ).rejects.toMatchObject({
      name: 'PolicyNotFoundError',
      identifier: 'Missing',
      message: 'Endpoint policy not found',
    });
    expect(ensureInCurrentSpace).not.toHaveBeenCalled();
    expect(countSpy).not.toHaveBeenCalled();
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
  });

  it('preserves ambiguous-name taxonomy and does not count', async () => {
    const {
      access,
      endpointAppContextService,
      getById,
      listByName,
      ensureInCurrentSpace,
      getAgentStatusForAgentPolicy,
    } = await createEstateAccess();
    getById.mockRejectedValue(SavedObjectsErrorHelpers.createGenericNotFoundError());
    listByName.mockResolvedValue({
      items: [
        createEndpointPolicy({ id: 'dup-0', name: 'Shared Name' }),
        createEndpointPolicy({ id: 'dup-1', name: 'Shared Name' }),
      ],
      total: 2,
      page: 1,
      perPage: 11,
    });
    const countSpy = jest.spyOn(countEndpointsModule, 'countEndpoints');

    await expect(
      assessChange(access, endpointAppContextService, rawParams('Shared Name'))
    ).rejects.toBeInstanceOf(PolicyAmbiguousNameError);
    expect(ensureInCurrentSpace).not.toHaveBeenCalled();
    expect(countSpy).not.toHaveBeenCalled();
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
  });

  it('does not count when preparation refuses the request', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'policy-id-1',
        policy_ids: ['agent-policy-a'],
      })
    );
    const countSpy = jest.spyOn(countEndpointsModule, 'countEndpoints');

    await expect(
      assessChange(access, endpointAppContextService, {
        idOrName: 'policy-id-1',
        changes: [{ op: 'set_field', path: 'windows.popup.device_control.enabled', value: true }],
      })
    ).rejects.toMatchObject({
      name: 'PolicyChangePreparationError',
      code: 'unsupported_operation',
    });
    expect(countSpy).not.toHaveBeenCalled();
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
  });

  it('passes a complete enrolled-agent count map through without adapting it', async () => {
    const { access, endpointAppContextService, getById } = await createEstateAccess();
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'policy-id-1',
        policy_ids: ['agent-policy-a'],
      })
    );
    const blastRadius: EndpointCountResult = {
      population: 'enrolled_agents',
      source: 'fleet_status_aggregation',
      status: MIXED_STATUS_ABOVE_PAGE,
    };
    jest.spyOn(countEndpointsModule, 'countEndpoints').mockResolvedValue(blastRadius);

    const result = await assessChange(access, endpointAppContextService, rawParams());

    expect(result.blastRadius).toBe(blastRadius);
    expect(result.blastRadius).toEqual({
      population: 'enrolled_agents',
      source: 'fleet_status_aggregation',
      status: MIXED_STATUS_ABOVE_PAGE,
    });
  });

  it('assesses a generated-policy device switch without reporting popup messages', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    const storedPolicy = requireStoredPolicy(policy);
    if (
      storedPolicy.windows.popup.device_control == null ||
      storedPolicy.mac.popup.device_control == null
    ) {
      throw new Error('expected generated policy to include initialized device popup objects');
    }
    storedPolicy.windows.popup.device_control.message = 'keep-windows';
    storedPolicy.mac.popup.device_control.message = 'keep-mac';
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));
    const getEndpointPolicySpy = jest.spyOn(readPolicyModule, 'getEndpointPolicy');
    const params = {
      idOrName: 'policy-id-1',
      changes: [{ op: 'set_field', path: 'windows.device_control.enabled', value: false }],
    };

    const result = await assessChange(access, endpointAppContextService, params);
    const prepared = prepareChangeSet(params, storedPolicy);

    expect(getEndpointPolicySpy).toHaveBeenCalledTimes(1);
    expect(result.expandedChanges).toEqual(toExpectedFacts(prepared, endpointAppContextService));
    expect(result.normalizedDiff).toEqual(prepared.normalizedDiff);
    expect(result.expandedChanges.map((change) => change.path)).not.toEqual(
      expect.arrayContaining([
        'windows.popup.device_control.message',
        'mac.popup.device_control.message',
      ])
    );
    expect(result.expandedChanges.every((change) => !POPUP_MESSAGE_PATH.test(change.path))).toBe(
      true
    );
    expect(result.normalizedDiff.every((entry) => !POPUP_MESSAGE_PATH.test(entry.path))).toBe(true);
    expect(prepared.proposedConfig.windows.popup.device_control?.message).toBe('keep-windows');
    expect(prepared.proposedConfig.mac.popup.device_control?.message).toBe('keep-mac');
    expect(prepared.proposedConfig.windows.popup.device_control?.message).not.toBe('');
    expect(prepared.proposedConfig.mac.popup.device_control?.message).not.toBe('');
  });

  it('keeps the missing-popup device-switch refusal after resolve and before count', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    const storedPolicy = requireStoredPolicy(policy);
    delete storedPolicy.windows.popup.device_control;
    getById.mockResolvedValue(policy);
    const countSpy = jest.spyOn(countEndpointsModule, 'countEndpoints');

    await expect(
      assessChange(access, endpointAppContextService, {
        idOrName: 'policy-id-1',
        changes: [{ op: 'set_field', path: 'windows.device_control.enabled', value: false }],
      })
    ).rejects.toMatchObject({
      name: 'PolicyChangePreparationError',
      code: 'unsupported_operation',
      message: DEVICE_CONTROL_MISSING_POPUP_MESSAGE,
    });
    expect(countSpy).not.toHaveBeenCalled();
    expect(getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
  });

  it('marks ransomware prevent ineligible on gold while malware mode stays eligible', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    endpointAppContextService.getLicenseService().getLicenseInformation = jest.fn(() => Gold);
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    const storedPolicy = requireStoredPolicy(policy);
    storedPolicy.windows.ransomware.mode = ProtectionModes.off;
    storedPolicy.windows.malware.mode = ProtectionModes.detect;
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));

    const result = await assessChange(access, endpointAppContextService, {
      idOrName: 'policy-id-1',
      changes: [
        { op: 'set_protection_level', protection: 'ransomware', mode: ProtectionModes.prevent },
        { op: 'set_protection_level', protection: 'malware', mode: ProtectionModes.prevent },
      ],
    });

    expect(
      result.expandedChanges.find((change) => change.path === 'windows.ransomware.mode')
        ?.eligibility
    ).toEqual({ eligible: false, reason: 'license_below_platinum' });
    expect(
      result.expandedChanges.find((change) => change.path === 'windows.malware.mode')?.eligibility
    ).toEqual({ eligible: true });
  });

  it('marks device_control ineligible on platinum while ransomware stays eligible', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    endpointAppContextService.getLicenseService().getLicenseInformation = jest.fn(() => Platinum);
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    const storedPolicy = requireStoredPolicy(policy);
    if (storedPolicy.windows.device_control == null) {
      throw new Error('expected generated policy to include initialized windows.device_control');
    }
    storedPolicy.windows.device_control.enabled = false;
    storedPolicy.windows.ransomware.mode = ProtectionModes.off;
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));

    const result = await assessChange(access, endpointAppContextService, {
      idOrName: 'policy-id-1',
      changes: [
        { op: 'set_field', path: 'windows.device_control.enabled', value: true },
        { op: 'set_protection_level', protection: 'ransomware', mode: ProtectionModes.prevent },
      ],
    });

    expect(
      result.expandedChanges.find((change) => change.path === 'windows.device_control.enabled')
        ?.eligibility
    ).toEqual({ eligible: false, reason: 'license_below_enterprise' });
    expect(
      result.expandedChanges.find((change) => change.path === 'windows.ransomware.mode')
        ?.eligibility
    ).toEqual({ eligible: true });
  });

  it('marks paid paths eligible on enterprise', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    const storedPolicy = requireStoredPolicy(policy);
    if (storedPolicy.windows.device_control == null) {
      throw new Error('expected generated policy to include initialized windows.device_control');
    }
    storedPolicy.windows.device_control.enabled = false;
    storedPolicy.windows.ransomware.mode = ProtectionModes.off;
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));

    const result = await assessChange(access, endpointAppContextService, {
      idOrName: 'policy-id-1',
      changes: [
        { op: 'set_field', path: 'windows.device_control.enabled', value: true },
        { op: 'set_protection_level', protection: 'ransomware', mode: ProtectionModes.prevent },
      ],
    });

    expect(
      result.expandedChanges.find((change) => change.path === 'windows.device_control.enabled')
        ?.eligibility
    ).toEqual({ eligible: true });
    expect(
      result.expandedChanges.find((change) => change.path === 'windows.ransomware.mode')
        ?.eligibility
    ).toEqual({ eligible: true });
  });

  it('marks a protection path ineligible when endpointPolicyProtections is disabled', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    jest
      .spyOn(endpointAppContextService.getProductFeaturesService(), 'isEnabled')
      .mockImplementation((key) => key !== ProductFeatureSecurityKey.endpointPolicyProtections);
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    requireStoredPolicy(policy).windows.malware.mode = ProtectionModes.off;
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));

    const result = await assessChange(access, endpointAppContextService, {
      idOrName: 'policy-id-1',
      changes: [
        { op: 'set_protection_level', protection: 'malware', mode: ProtectionModes.prevent },
      ],
    });

    expect(
      result.expandedChanges.find((change) => change.path === 'windows.malware.mode')?.eligibility
    ).toEqual({ eligible: false, reason: 'endpoint_policy_protections_disabled' });
  });

  it('marks a dated global_manifest_version ineligible when endpointProtectionUpdates is disabled', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    jest
      .spyOn(endpointAppContextService.getProductFeaturesService(), 'isEnabled')
      .mockImplementation((key) => key !== ProductFeatureSecurityKey.endpointProtectionUpdates);
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    requireStoredPolicy(policy).global_manifest_version = 'latest';
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));

    const result = await assessChange(access, endpointAppContextService, {
      idOrName: 'policy-id-1',
      changes: [{ op: 'set_field', path: 'global_manifest_version', value: '2024-01-01' }],
    });

    expect(
      result.expandedChanges.find((change) => change.path === 'global_manifest_version')
        ?.eligibility
    ).toEqual({ eligible: false, reason: 'endpoint_protection_updates_disabled' });
    expect(
      result.expandedChanges.find((change) => change.path === 'global_manifest_version')?.registry
        .productFeatureGate
    ).toBe('endpointProtectionUpdates');
  });

  it('keeps requested intent distinct from empty impact rows on a no-op', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    requireStoredPolicy(policy).windows.malware.mode = ProtectionModes.detect;
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));

    const result = await assessChange(access, endpointAppContextService, {
      idOrName: 'policy-id-1',
      changes: [{ op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.detect }],
    });

    expect(result.requestedOperations).toEqual([
      { op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.detect },
    ]);
    expect(result.requestedImpact).toEqual([]);
    expect(result.expandedChanges).toEqual([]);
    expect(result.normalizedDiff).toEqual([]);
  });

  it('returns direct requested impact separately from coupled expanded changes', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    getById.mockResolvedValue(
      createEndpointPolicy({
        id: 'policy-id-1',
        policy_ids: ['agent-policy-a'],
      })
    );
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));

    const result = await assessChange(access, endpointAppContextService, {
      idOrName: 'policy-id-1',
      changes: [{ op: 'set_protection_enabled', protection: 'malware', enabled: false }],
    });

    const requestedPaths = result.requestedImpact.map((change) => change.path);
    expect(requestedPaths).toEqual(
      expect.arrayContaining(['windows.malware.mode', 'mac.malware.mode', 'linux.malware.mode'])
    );
    expect(requestedPaths.every((path) => path.endsWith('.malware.mode'))).toBe(true);
    expect(result.requestedImpact.every((change) => change.origin.kind === 'direct')).toBe(true);

    const expandedPaths = result.expandedChanges.map((change) => change.path);
    expect(expandedPaths).toEqual(
      expect.arrayContaining(['windows.malware.blocklist', 'windows.popup.malware.enabled'])
    );
    expect(expandedPaths.length).toBeGreaterThan(requestedPaths.length);
  });

  it('reads serverless from the endpoint app context for eligibility', async () => {
    const { access, endpointAppContextService, getById, getAgentStatusForAgentPolicy } =
      await createEstateAccess();
    const isServerlessSpy = jest
      .spyOn(endpointAppContextService, 'isServerless')
      .mockReturnValue(true);
    endpointAppContextService.getLicenseService().getLicenseInformation = jest.fn(() => Gold);
    const policy = createEndpointPolicy({
      id: 'policy-id-1',
      policy_ids: ['agent-policy-a'],
    });
    requireStoredPolicy(policy).windows.ransomware.mode = ProtectionModes.off;
    getById.mockResolvedValue(policy);
    getAgentStatusForAgentPolicy.mockResolvedValue(asFleetAgentStatus(MIXED_STATUS_ABOVE_PAGE));

    const result = await assessChange(access, endpointAppContextService, {
      idOrName: 'policy-id-1',
      changes: [
        { op: 'set_protection_level', protection: 'ransomware', mode: ProtectionModes.prevent },
      ],
    });

    expect(isServerlessSpy).toHaveBeenCalled();
    expect(
      result.expandedChanges.find((change) => change.path === 'windows.ransomware.mode')
        ?.eligibility
    ).toEqual({ eligible: true });
  });
});
