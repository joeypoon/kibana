/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest } from '@kbn/core-http-server';
import type { FleetAuthz } from '@kbn/fleet-plugin/common';
import type { EndpointAuthz } from '../../../../../../common/endpoint/types/authz';
import type { PolicyReadDenial, PolicyReadPrivilegeBasis } from '../../domain/read/types';
import { createMissingPrivilegeDenial } from './policy_read_denial';

export interface PolicyReadAuthorizationDependencies {
  readonly getEndpointAuthz: (request: KibanaRequest) => Promise<EndpointAuthz>;
  readonly getFleetAuthz: (request: KibanaRequest) => Promise<FleetAuthz>;
}

export interface PolicyReadAuthorizationGranted {
  readonly granted: true;
  readonly basis: PolicyReadPrivilegeBasis;
}

export interface PolicyReadAuthorizationDenied {
  readonly granted: false;
  readonly basis: PolicyReadPrivilegeBasis;
  readonly denial: PolicyReadDenial;
}

export type PolicyReadAuthorization =
  | PolicyReadAuthorizationGranted
  | PolicyReadAuthorizationDenied;

export const authorizePolicyRead = async (
  { getEndpointAuthz, getFleetAuthz }: PolicyReadAuthorizationDependencies,
  request: KibanaRequest
): Promise<PolicyReadAuthorization> => {
  const [endpointAuthz, fleetAuthz] = await Promise.all([
    getEndpointAuthz(request),
    getFleetAuthz(request),
  ]);

  const basis: PolicyReadPrivilegeBasis = {
    securityPolicyManagementRead: endpointAuthz.canReadPolicyManagement,
    fleetIntegrationPoliciesRead: fleetAuthz.integrations.readIntegrationPolicies,
    fleetAgentsRead: fleetAuthz.fleet.readAgents,
  };

  if (basis.securityPolicyManagementRead || basis.fleetIntegrationPoliciesRead) {
    return { granted: true, basis };
  }

  return {
    granted: false,
    basis,
    denial: createMissingPrivilegeDenial({
      securityPolicyManagementRead: basis.securityPolicyManagementRead,
      fleetAgentPoliciesRead: fleetAuthz.integrations.readIntegrationPolicies,
      fleetIntegrationsRead: fleetAuthz.integrations.readInstalledPackages,
    }),
  };
};
