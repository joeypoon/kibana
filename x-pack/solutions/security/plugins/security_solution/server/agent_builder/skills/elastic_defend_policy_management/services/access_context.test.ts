/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock } from '@kbn/core/server/mocks';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import type { EndpointInternalFleetServicesInterface } from '../../../../endpoint/services/fleet/endpoint_fleet_services_factory';
import type { HasAtLeast, PolicyAccessContext, PolicyAccessLevel } from './access_context';
import { createPolicyAccessContext } from './access_context';
import {
  InvalidEndpointPolicyError,
  PolicyAmbiguousNameError,
  PolicyAuthorizationError,
  PolicyConflictError,
  PolicyNotFoundError,
} from './policy_errors';

type IsAssignable<A, B> = A extends B ? true : false;

const getEndpointPolicy = (_access: HasAtLeast<'policy_read'>): void => undefined;
const listEndpointPolicies = (_access: HasAtLeast<'policy_read'>): void => undefined;
const countEndpoints = (_access: HasAtLeast<'estate_read'>): void => undefined;
const readApplyState = (_access: HasAtLeast<'estate_read'>): void => undefined;
const requirePolicyWrite = (_access: HasAtLeast<'policy_write'>): void => undefined;

type WriteSatisfiesEstate = IsAssignable<
  PolicyAccessContext<'policy_write'>,
  HasAtLeast<'estate_read'>
> extends true
  ? true
  : never;
type WriteSatisfiesPolicy = IsAssignable<
  PolicyAccessContext<'policy_write'>,
  HasAtLeast<'policy_read'>
> extends true
  ? true
  : never;
type WriteSatisfiesCount = IsAssignable<
  PolicyAccessContext<'policy_write'>,
  Parameters<typeof countEndpoints>[0]
> extends true
  ? true
  : never;
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
type EstateSatisfiesPolicy = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  HasAtLeast<'policy_read'>
> extends true
  ? true
  : never;
type EstateSatisfiesGet = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  Parameters<typeof getEndpointPolicy>[0]
> extends true
  ? true
  : never;
type EstateSatisfiesList = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  Parameters<typeof listEndpointPolicies>[0]
> extends true
  ? true
  : never;
type EstateDoesNotSatisfyWrite = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  HasAtLeast<'policy_write'>
> extends false
  ? true
  : never;
type PolicyDoesNotSatisfyEstate = IsAssignable<
  PolicyAccessContext<'policy_read'>,
  HasAtLeast<'estate_read'>
> extends false
  ? true
  : never;
type PolicyDoesNotSatisfyWrite = IsAssignable<
  PolicyAccessContext<'policy_read'>,
  HasAtLeast<'policy_write'>
> extends false
  ? true
  : never;
type PolicyDoesNotSatisfyCount = IsAssignable<
  PolicyAccessContext<'policy_read'>,
  Parameters<typeof countEndpoints>[0]
> extends false
  ? true
  : never;
type PolicyDoesNotSatisfyApplyState = IsAssignable<
  PolicyAccessContext<'policy_read'>,
  Parameters<typeof readApplyState>[0]
> extends false
  ? true
  : never;
type EstateDoesNotSatisfyWriteFn = IsAssignable<
  PolicyAccessContext<'estate_read'>,
  Parameters<typeof requirePolicyWrite>[0]
> extends false
  ? true
  : never;
type PlainObjectDoesNotSatisfyPolicy = IsAssignable<
  {
    level: 'policy_write';
    spaceId: string;
    fleet: EndpointInternalFleetServicesInterface;
  },
  HasAtLeast<'policy_read'>
> extends false
  ? true
  : never;
type PlainObjectDoesNotSatisfyEstate = IsAssignable<
  {
    spaceId: string;
    fleet: EndpointInternalFleetServicesInterface;
  },
  HasAtLeast<'estate_read'>
> extends false
  ? true
  : never;
type PlainObjectDoesNotSatisfyWrite = IsAssignable<
  {
    spaceId: string;
    fleet: EndpointInternalFleetServicesInterface;
  },
  HasAtLeast<'policy_write'>
> extends false
  ? true
  : never;
type CreatedWriteKeepsLevel = Awaited<
  ReturnType<typeof createPolicyAccessContext<'policy_write'>>
>['level'] extends 'policy_write'
  ? true
  : never;

const _writeSatisfiesEstate: WriteSatisfiesEstate = true;
const _writeSatisfiesPolicy: WriteSatisfiesPolicy = true;
const _writeSatisfiesCount: WriteSatisfiesCount = true;
const _writeSatisfiesApplyState: WriteSatisfiesApplyState = true;
const _estateSatisfiesApplyState: EstateSatisfiesApplyState = true;
const _estateSatisfiesPolicy: EstateSatisfiesPolicy = true;
const _estateSatisfiesGet: EstateSatisfiesGet = true;
const _estateSatisfiesList: EstateSatisfiesList = true;
const _estateDoesNotSatisfyWrite: EstateDoesNotSatisfyWrite = true;
const _policyDoesNotSatisfyEstate: PolicyDoesNotSatisfyEstate = true;
const _policyDoesNotSatisfyWrite: PolicyDoesNotSatisfyWrite = true;
const _policyDoesNotSatisfyCount: PolicyDoesNotSatisfyCount = true;
const _policyDoesNotSatisfyApplyState: PolicyDoesNotSatisfyApplyState = true;
const _estateDoesNotSatisfyWriteFn: EstateDoesNotSatisfyWriteFn = true;
const _plainObjectDoesNotSatisfyPolicy: PlainObjectDoesNotSatisfyPolicy = true;
const _plainObjectDoesNotSatisfyEstate: PlainObjectDoesNotSatisfyEstate = true;
const _plainObjectDoesNotSatisfyWrite: PlainObjectDoesNotSatisfyWrite = true;
const _createdWriteKeepsLevel: CreatedWriteKeepsLevel = true;

type PrivilegeGrants = Readonly<{
  canReadPolicyManagement: boolean;
  canReadEndpointList: boolean;
  canWritePolicyManagement: boolean;
}>;

const NON_DEFAULT_SPACE_ID = 'space-marketing';

const GRANT_CASES: ReadonlyArray<{
  level: PolicyAccessLevel;
  grants: PrivilegeGrants;
  allowed: boolean;
}> = [
  {
    level: 'policy_read',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    },
    allowed: true,
  },
  {
    level: 'policy_read',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    },
    allowed: true,
  },
  {
    level: 'policy_read',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: true,
    },
    allowed: true,
  },
  {
    level: 'policy_read',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: true,
    },
    allowed: true,
  },
  {
    level: 'policy_read',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
  {
    level: 'policy_read',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
  {
    level: 'policy_read',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: false,
      canWritePolicyManagement: true,
    },
    allowed: false,
  },
  {
    level: 'policy_read',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: true,
      canWritePolicyManagement: true,
    },
    allowed: false,
  },
  {
    level: 'estate_read',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    },
    allowed: true,
  },
  {
    level: 'estate_read',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: true,
    },
    allowed: true,
  },
  {
    level: 'estate_read',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
  {
    level: 'estate_read',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
  {
    level: 'estate_read',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
  {
    level: 'estate_read',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: true,
    },
    allowed: false,
  },
  {
    level: 'estate_read',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: true,
      canWritePolicyManagement: true,
    },
    allowed: false,
  },
  {
    level: 'estate_read',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: false,
      canWritePolicyManagement: true,
    },
    allowed: false,
  },
  {
    level: 'policy_write',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: true,
    },
    allowed: true,
  },
  {
    level: 'policy_write',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
  {
    level: 'policy_write',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: true,
    },
    allowed: false,
  },
  {
    level: 'policy_write',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: true,
      canWritePolicyManagement: true,
    },
    allowed: false,
  },
  {
    level: 'policy_write',
    grants: {
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
  {
    level: 'policy_write',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
  {
    level: 'policy_write',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: false,
      canWritePolicyManagement: true,
    },
    allowed: false,
  },
  {
    level: 'policy_write',
    grants: {
      canReadPolicyManagement: false,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    },
    allowed: false,
  },
];

const createAccessDeps = (grants: PrivilegeGrants) => {
  const endpointAppContextService = createMockEndpointAppContextService();
  const request = httpServerMock.createKibanaRequest();
  const scopedFleet = endpointAppContextService.getInternalFleetServices();
  const getScopedClient = jest.fn().mockReturnValue({ sentinel: 'request-scoped-so-client' });
  const getStartServices = jest.fn(async () => [
    { savedObjects: { getScopedClient } },
  ]) as unknown as StartServicesAccessor;
  const callOrder: string[] = [];

  endpointAppContextService.getInternalFleetServices.mockReset();
  endpointAppContextService.getInternalFleetServices.mockImplementation((spaceId?: string) => {
    callOrder.push(`fleet:${spaceId ?? ''}`);
    return scopedFleet;
  });
  endpointAppContextService.getEndpointAuthz.mockImplementation(async () => {
    callOrder.push('authz');
    return getEndpointAuthzInitialStateMock(grants);
  });

  return {
    endpointAppContextService,
    request,
    scopedFleet,
    getScopedClient,
    getStartServices,
    callOrder,
  };
};

describe('createPolicyAccessContext', () => {
  it('holds the branded assignability contract without suppression comments', () => {
    expect(_writeSatisfiesEstate).toBe(true);
    expect(_writeSatisfiesPolicy).toBe(true);
    expect(_writeSatisfiesCount).toBe(true);
    expect(_writeSatisfiesApplyState).toBe(true);
    expect(_estateSatisfiesApplyState).toBe(true);
    expect(_estateSatisfiesPolicy).toBe(true);
    expect(_estateSatisfiesGet).toBe(true);
    expect(_estateSatisfiesList).toBe(true);
    expect(_estateDoesNotSatisfyWrite).toBe(true);
    expect(_policyDoesNotSatisfyEstate).toBe(true);
    expect(_policyDoesNotSatisfyWrite).toBe(true);
    expect(_policyDoesNotSatisfyCount).toBe(true);
    expect(_policyDoesNotSatisfyApplyState).toBe(true);
    expect(_estateDoesNotSatisfyWriteFn).toBe(true);
    expect(_plainObjectDoesNotSatisfyPolicy).toBe(true);
    expect(_plainObjectDoesNotSatisfyEstate).toBe(true);
    expect(_plainObjectDoesNotSatisfyWrite).toBe(true);
    expect(_createdWriteKeepsLevel).toBe(true);
  });

  it('lets a write context call countEndpoints and an estate context call policy services', async () => {
    const writeDeps = createAccessDeps({
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: true,
    });
    const estateDeps = createAccessDeps({
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    });

    const writeAccess = await createPolicyAccessContext(
      writeDeps.endpointAppContextService,
      { request: writeDeps.request, spaceId: NON_DEFAULT_SPACE_ID },
      'policy_write',
      writeDeps.getStartServices
    );
    const estateAccess = await createPolicyAccessContext(
      estateDeps.endpointAppContextService,
      { request: estateDeps.request, spaceId: NON_DEFAULT_SPACE_ID },
      'estate_read',
      estateDeps.getStartServices
    );

    countEndpoints(writeAccess);
    readApplyState(writeAccess);
    getEndpointPolicy(estateAccess);
    listEndpointPolicies(estateAccess);

    expect(writeAccess.level).toBe('policy_write');
    expect(estateAccess.level).toBe('estate_read');
  });

  it.each(GRANT_CASES)(
    '$level with policy=$grants.canReadPolicyManagement endpoint=$grants.canReadEndpointList write=$grants.canWritePolicyManagement is $allowed',
    async ({ level, grants, allowed }) => {
      const { endpointAppContextService, request, getStartServices, callOrder } =
        createAccessDeps(grants);
      const input = { request, spaceId: NON_DEFAULT_SPACE_ID };

      if (allowed) {
        const access = await createPolicyAccessContext(
          endpointAppContextService,
          input,
          level,
          getStartServices
        );

        expect(access.level).toBe(level);
        expect(access.spaceId).toBe(NON_DEFAULT_SPACE_ID);
        expect(endpointAppContextService.getEndpointAuthz).toHaveBeenCalledTimes(1);
        expect(endpointAppContextService.getEndpointAuthz).toHaveBeenCalledWith(request);
        expect(endpointAppContextService.getInternalFleetServices).toHaveBeenCalledTimes(1);
        expect(endpointAppContextService.getInternalFleetServices).toHaveBeenCalledWith(
          NON_DEFAULT_SPACE_ID
        );
        expect(getStartServices).toHaveBeenCalledTimes(1);
        expect(callOrder).toEqual(['authz', `fleet:${NON_DEFAULT_SPACE_ID}`]);
        return;
      }

      await expect(
        createPolicyAccessContext(endpointAppContextService, input, level, getStartServices)
      ).rejects.toBeInstanceOf(PolicyAuthorizationError);
      expect(endpointAppContextService.getEndpointAuthz).toHaveBeenCalledTimes(1);
      expect(endpointAppContextService.getEndpointAuthz).toHaveBeenCalledWith(request);
      expect(endpointAppContextService.getInternalFleetServices).not.toHaveBeenCalled();
      expect(getStartServices).not.toHaveBeenCalled();
      expect(callOrder).toEqual(['authz']);
    }
  );

  it('rebinds getSoClient to the request-scoped helper client after grants', async () => {
    const { endpointAppContextService, request, scopedFleet, getScopedClient, getStartServices } =
      createAccessDeps({
        canReadPolicyManagement: true,
        canReadEndpointList: false,
        canWritePolicyManagement: false,
      });
    const input = { request, spaceId: NON_DEFAULT_SPACE_ID };

    const access = await createPolicyAccessContext(
      endpointAppContextService,
      input,
      'policy_read',
      getStartServices
    );

    expect(getStartServices).toHaveBeenCalledTimes(1);
    expect(getScopedClient).toHaveBeenCalledTimes(1);
    expect(getScopedClient.mock.calls[0][0]).toBe(request);
    expect(access.fleet.getSoClient()).not.toBe(scopedFleet.getSoClient());
  });

  it('leaves every other fleet member on the internal scoped services', async () => {
    const { endpointAppContextService, request, scopedFleet, getStartServices } = createAccessDeps({
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    });

    const access = await createPolicyAccessContext(
      endpointAppContextService,
      { request, spaceId: NON_DEFAULT_SPACE_ID },
      'policy_read',
      getStartServices
    );

    const accessFleet = access.fleet as unknown as Record<string, unknown>;
    const scopedFleetRecord = scopedFleet as unknown as Record<string, unknown>;
    const scopedFleetKeys = Object.keys(scopedFleetRecord);

    expect(Object.keys(accessFleet).sort()).toEqual([...scopedFleetKeys].sort());
    expect(access.fleet.getSoClient).not.toBe(scopedFleet.getSoClient);

    for (const key of scopedFleetKeys) {
      if (key === 'getSoClient') {
        continue;
      }
      expect(accessFleet[key]).toBe(scopedFleetRecord[key]);
    }
  });

  it('does not create a request-scoped client before grants', async () => {
    const { endpointAppContextService, request, getStartServices, callOrder } = createAccessDeps({
      canReadPolicyManagement: false,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    });

    await expect(
      createPolicyAccessContext(
        endpointAppContextService,
        { request, spaceId: NON_DEFAULT_SPACE_ID },
        'policy_read',
        getStartServices
      )
    ).rejects.toBeInstanceOf(PolicyAuthorizationError);
    expect(getStartServices).not.toHaveBeenCalled();
    expect(endpointAppContextService.getInternalFleetServices).not.toHaveBeenCalled();
    expect(callOrder).toEqual(['authz']);
  });
});

describe('policy errors', () => {
  it('exposes a stable authorization class without request or privilege details', () => {
    const error = new PolicyAuthorizationError();

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('PolicyAuthorizationError');
    expect(error.message).toBe('Not authorized for policy management');
    expect(error.message).not.toMatch(/canRead|canWrite|space|request/i);
  });

  it('treats missing and foreign-space identifiers as the same not-found class', () => {
    const missing = new PolicyNotFoundError('policy-missing');
    const foreign = new PolicyNotFoundError('policy-other-space');

    expect(missing).toBeInstanceOf(PolicyNotFoundError);
    expect(foreign).toBeInstanceOf(PolicyNotFoundError);
    expect(missing.message).toBe(foreign.message);
    expect(missing.message).toBe('Endpoint policy not found');
    expect(missing.identifier).toBe('policy-missing');
    expect(foreign.identifier).toBe('policy-other-space');
  });

  it('bounds ambiguous-name candidates at 10 and reports truncation', () => {
    const candidates = Array.from({ length: 12 }, (_, index) => ({
      id: `id-${index}`,
      name: `name-${index}`,
    }));
    const error = new PolicyAmbiguousNameError(candidates, 12);

    expect(error.name).toBe('PolicyAmbiguousNameError');
    expect(error.candidates).toHaveLength(10);
    expect(error.candidatesTotal).toBe(12);
    expect(error.candidatesTruncated).toBe(true);
    expect(error.candidates[0]).toEqual({ id: 'id-0', name: 'name-0' });
    expect(error.candidates[9]).toEqual({ id: 'id-9', name: 'name-9' });
  });

  it('does not mark ambiguous-name candidates truncated when the total fits', () => {
    const error = new PolicyAmbiguousNameError(
      [
        { id: 'a', name: 'alpha' },
        { id: 'b', name: 'beta' },
      ],
      2
    );

    expect(error.candidates).toHaveLength(2);
    expect(error.candidatesTotal).toBe(2);
    expect(error.candidatesTruncated).toBe(false);
  });

  it('stores exact id and name on a fresh candidate object', () => {
    const fatCandidate = {
      id: 'policy-1',
      name: 'Shared Name',
      description: 'should not leak',
      inputs: [{ type: 'endpoint' }],
      revision: 7,
    };
    const error = new PolicyAmbiguousNameError([fatCandidate], 1);
    const [stored] = error.candidates;

    expect(error.candidates).toHaveLength(1);
    expect(stored).toEqual({ id: 'policy-1', name: 'Shared Name' });
    expect(Object.keys(stored)).toEqual(['id', 'name']);
    expect(stored).not.toBe(fatCandidate);
    expect(error.candidatesTotal).toBe(1);
    expect(error.candidatesTruncated).toBe(false);
  });

  it('exposes invalid-policy and future conflict classes without internal payloads', () => {
    const invalid = new InvalidEndpointPolicyError('policy-1');
    const conflict = new PolicyConflictError();

    expect(invalid.name).toBe('InvalidEndpointPolicyError');
    expect(invalid.message).toBe('Selected policy is not a valid endpoint policy');
    expect(invalid.policyId).toBe('policy-1');
    expect(invalid.message).not.toMatch(/config|version|stack/i);
    expect(conflict.name).toBe('PolicyConflictError');
    expect(conflict.message).toBe('Endpoint policy was modified concurrently');
  });
});
