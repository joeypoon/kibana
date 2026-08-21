/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest, StartServicesAccessor } from '@kbn/core/server';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import type { EndpointInternalFleetServicesInterface } from '../../../../endpoint/services/fleet/endpoint_fleet_services_factory';
import { createRequestScopedReadonlySoClient } from './create_request_scoped_readonly_so_client';
import { PolicyAuthorizationError } from './policy_errors';

const policyAccessBrand: unique symbol = Symbol('policyAccess');

export type PolicyAccessLevel = 'policy_read' | 'estate_read' | 'policy_write';

interface AccessCapabilities {
  policy_read: Readonly<{ policyRead: true }>;
  estate_read: Readonly<{ policyRead: true; estateRead: true }>;
  policy_write: Readonly<{ policyRead: true; estateRead: true; policyWrite: true }>;
}

const ACCESS_CAPABILITIES: AccessCapabilities = {
  policy_read: { policyRead: true },
  estate_read: { policyRead: true, estateRead: true },
  policy_write: { policyRead: true, estateRead: true, policyWrite: true },
};

export type PolicyAccessContext<L extends PolicyAccessLevel> = Readonly<{
  level: L;
  spaceId: string;
  fleet: EndpointInternalFleetServicesInterface;
  [policyAccessBrand]: AccessCapabilities[L];
}>;

export type HasAtLeast<L extends PolicyAccessLevel> = Readonly<{
  spaceId: string;
  fleet: EndpointInternalFleetServicesInterface;
  [policyAccessBrand]: AccessCapabilities[L];
}>;

const hasRequiredGrants = (
  level: PolicyAccessLevel,
  authz: Readonly<{
    canReadPolicyManagement: boolean;
    canReadEndpointList: boolean;
    canWritePolicyManagement: boolean;
  }>
): boolean => {
  const granted: Record<PolicyAccessLevel, boolean> = {
    policy_read: authz.canReadPolicyManagement,
    estate_read: authz.canReadPolicyManagement && authz.canReadEndpointList,
    policy_write:
      authz.canWritePolicyManagement && authz.canReadPolicyManagement && authz.canReadEndpointList,
  };

  return granted[level];
};

export const createPolicyAccessContext = async <L extends PolicyAccessLevel>(
  endpointAppContextService: EndpointAppContextService,
  input: Readonly<{ request: KibanaRequest; spaceId: string }>,
  level: L,
  getStartServices: StartServicesAccessor
): Promise<PolicyAccessContext<L>> => {
  const authz = await endpointAppContextService.getEndpointAuthz(input.request);

  if (!hasRequiredGrants(level, authz)) {
    throw new PolicyAuthorizationError();
  }

  const fleet = endpointAppContextService.getInternalFleetServices(input.spaceId);
  const requestScopedSoClient = await createRequestScopedReadonlySoClient({
    getStartServices,
    request: input.request,
  });

  return {
    level,
    spaceId: input.spaceId,
    fleet: { ...fleet, getSoClient: () => requestScopedSoClient },
    [policyAccessBrand]: ACCESS_CAPABILITIES[level],
  };
};
