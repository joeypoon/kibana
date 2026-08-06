/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest, Logger, StartServicesAccessor } from '@kbn/core/server';
import type { AgentClient, PackagePolicyClient } from '@kbn/fleet-plugin/server';
import type { SavedObjectsClientContract } from '@kbn/core-saved-objects-api-server';
import type {
  EndpointAppContextService,
  ScopedEndpointServices,
} from '../../../endpoint/endpoint_app_context_services';
import type { ProductFeaturesService } from '../../../lib/product_features_service';
import type { SecuritySolutionPluginStartDependencies } from '../../../plugin_contract';
import { EndpointError } from '../../../../common/endpoint/errors';
import type { PolicyReadPrivilegeBasis } from './domain/read/types';
import type {
  PolicyReadAuthorizationDependencies,
  PolicyReadOutcome,
} from './services/policy_read';
import { authorizePolicyRead, createPolicyReadSavedObjectsClient } from './services/policy_read';
import type { PolicyApplyStateAgentPolicyService } from './services/policy_apply_state';

export interface DefendPolicyManagementSkillDeps {
  readonly getStartServices: StartServicesAccessor<SecuritySolutionPluginStartDependencies>;
  readonly endpointAppContextService: EndpointAppContextService;
  readonly productFeaturesService: ProductFeaturesService;
  readonly kibanaVersion: string;
  readonly logger: Logger;
}

class FleetUnavailableError extends EndpointError {
  constructor() {
    super(
      'Elastic Defend policies cannot be read because the Fleet plugin is not available in this deployment.'
    );
  }
}

export interface ResolvedPolicyServices {
  readonly packagePolicyService: PackagePolicyClient;
  readonly getAgentClient: () => AgentClient;
  readonly getSoClient: () => SavedObjectsClientContract;
  readonly spaceId: string;
  readonly agentPolicyService: PolicyApplyStateAgentPolicyService;
  readonly getScopedEndpointServices: () => ScopedEndpointServices;
  readonly isCcsEnabled: () => Promise<boolean>;
  readonly authorizationDeps: PolicyReadAuthorizationDependencies;
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
}

export const resolvePolicyServices = async ({
  deps,
  request,
}: {
  deps: DefendPolicyManagementSkillDeps;
  request: KibanaRequest;
}): Promise<PolicyReadOutcome<ResolvedPolicyServices>> => {
  const { getStartServices, endpointAppContextService } = deps;
  const [coreStart, startPlugins] = await getStartServices();
  const { fleet } = startPlugins;

  if (fleet === undefined) {
    throw new FleetUnavailableError();
  }

  const { packagePolicyService, agentService, agentPolicyService, authz } = fleet;
  const spaceId = endpointAppContextService.getActiveSpaceId(request);

  const authorizationDeps: PolicyReadAuthorizationDependencies = {
    getEndpointAuthz: (currentRequest) =>
      endpointAppContextService.getEndpointAuthz(currentRequest),
    getFleetAuthz: (currentRequest) => authz.fromRequest(currentRequest),
  };

  const authorization = await authorizePolicyRead(authorizationDeps, request);

  if (!authorization.granted) {
    return { ok: false, denial: authorization.denial };
  }

  return {
    ok: true,
    value: {
      packagePolicyService,
      getAgentClient: () => agentService.asScoped(request),
      getSoClient: () =>
        createPolicyReadSavedObjectsClient({
          savedObjects: coreStart.savedObjects,
          request,
        }),
      spaceId,
      authorizationDeps,
      privilegeBasis: authorization.basis,
      agentPolicyService: {
        getByIds: (soClient, ids, options) => agentPolicyService.getByIds(soClient, ids, options),
      },
      getScopedEndpointServices: () => endpointAppContextService.asScoped(request),
      isCcsEnabled: () => endpointAppContextService.isCcsEnabled(),
    },
  };
};
