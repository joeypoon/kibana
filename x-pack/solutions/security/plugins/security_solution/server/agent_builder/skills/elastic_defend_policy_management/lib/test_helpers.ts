/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest } from '@kbn/core/server';
import { coreMock, httpServerMock, loggingSystemMock } from '@kbn/core/server/mocks';
import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import type { AgentClient, PackagePolicyClient } from '@kbn/fleet-plugin/server';
import { appContextService as fleetAppContextService } from '@kbn/fleet-plugin/server/services';
import type { FleetAuthz, PackagePolicy } from '@kbn/fleet-plugin/common';
import { createFleetAuthzMock } from '@kbn/fleet-plugin/common/mocks';
import {
  createAppContextStartContractMock,
  createPackagePolicyServiceMock,
} from '@kbn/fleet-plugin/server/mocks';
import { agentBuilderMocks } from '@kbn/agent-builder-plugin/server/mocks';
import type { ToolHandlerContext } from '@kbn/agent-builder-server/tools';
import { EndpointMetadataGenerator } from '../../../../../common/endpoint/data_generators/endpoint_metadata_generator';
import { EndpointPolicyResponseGenerator } from '../../../../../common/endpoint/data_generators/endpoint_policy_response_generator';
import { FleetPackagePolicyGenerator } from '../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import type { PartialEndpointPolicyData } from '../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import { policyFactory } from '../../../../../common/endpoint/models/policy_config';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { buildPolicyFieldRegistry } from '../domain/field_registry/generate_field_registry';
import { normalizePolicyConfig } from '../domain/normalize/normalize_policy_config';
import type { EndpointAuthz } from '../../../../../common/endpoint/types/authz';
import type {
  GetHostPolicyResponse,
  HostInfo,
  HostMetadata,
  HostPolicyResponse,
} from '../../../../../common/endpoint/types';
import { HostPolicyResponseActionStatus } from '../../../../../common/endpoint/types';
import { METADATA_UNITED_INDEX } from '../../../../../common/endpoint/constants';
import type {
  EndpointAppContextService,
  ScopedEndpointServices,
} from '../../../../endpoint/endpoint_app_context_services';
import type { PolicyReadSavedObjectsService } from '../services/policy_read';
import type { PolicyApplyStateAgentPolicyService } from '../services/policy_apply_state';
import type { ProductFeaturesService } from '../../../../lib/product_features_service';
import { createProductFeaturesServiceMock } from '../../../../lib/product_features_service/mocks';
import { LicenseService } from '../../../../../common/license';
import type { DefendPolicyManagementSkillDeps } from '../deps';
import { resetPolicyRegistryCacheForTests } from './policy_registry_cache';
import { TOOL_RESULT_TOKEN_BUDGET, estimateResultTokens } from './bounded_result';

export const PROHIBITED_PACKAGE_POLICY_METHODS = [
  'create',
  'bulkCreate',
  'update',
  'bulkUpdate',
  'delete',
  'upgrade',
  'bulkUpgrade',
  'rollback',
  'restoreRollback',
  'cleanupRollbackSavedObjects',
  'removeOutputFromAll',
  'runExternalCallbacks',
  'inspect',
] as const satisfies ReadonlyArray<keyof PackagePolicyClient>;

export const APPLY_STATE_EXCEPTION_INDEX = METADATA_UNITED_INDEX;

export const ANTI_LEAK_RAW_DATA_MARKERS = [
  '"config":',
  '"inputs":',
  'configNormalized',
  '"policy_ids":',
  'artifact_manifest',
  '"Endpoint":',
  '"HostDetails"',
  '"endpoint_policy_version":',
  '"policy_info":',
  '"policy_response',
] as const;

export const policyGenerator = new FleetPackagePolicyGenerator('defend-policy-skill-seed');

export const createDefendPolicyMock = (overrides: PartialEndpointPolicyData = {}): PackagePolicy =>
  policyGenerator.generateEndpointPackagePolicy({
    id: 'defend-1',
    name: 'Defend policy 1',
    revision: 2,
    version: 'WzEyMyw0XQ==',
    created_at: '2026-01-01T00:00:00.000Z',
    created_by: 'creator',
    updated_at: '2026-02-02T00:00:00.000Z',
    updated_by: 'updater',
    policy_ids: ['agent-policy-1'],
    ...overrides,
  }) as PackagePolicy;

export interface AntiLeakSourceFixtures {
  readonly fleetPolicy: PackagePolicy;
  readonly hostMetadata: HostMetadata;
  readonly hostDetailsWrapped: { HostDetails: HostMetadata };
  readonly hostInfo: HostInfo;
  readonly policyResponseApi: GetHostPolicyResponse;
  readonly configNormalizedCarrier: { configNormalized: unknown };
  readonly serialized: string;
}

export const createAntiLeakSourceFixtures = (
  fleetPolicy: PackagePolicy = createDefendPolicyMock({
    id: 'defend-1',
    revision: 2,
    version: 'WzEyMyw0XQ==',
    package: { name: 'endpoint', title: 'Elastic Defend', version: '9.4.0' },
  }),
  appliedEndpointPolicyId: string = 'endpoint-policy-1'
): AntiLeakSourceFixtures => {
  const metadataGenerator = new EndpointMetadataGenerator();
  const hostMetadata = metadataGenerator.generate({
    Endpoint: {
      policy: {
        applied: {
          id: appliedEndpointPolicyId,
          status: HostPolicyResponseActionStatus.success,
          name: 'test-policy',
          endpoint_policy_version: 2,
          version: 3,
        },
      },
    },
  });
  const hostDetailsWrapped = { HostDetails: hostMetadata };
  const hostInfo = metadataGenerator.generateHostInfo({
    metadata: hostMetadata,
    policy_info: {
      endpoint: { id: appliedEndpointPolicyId, revision: 2 },
      agent: {
        applied: { id: 'agent-policy-1', revision: 3 },
        configured: { id: 'agent-policy-1', revision: 3 },
      },
    },
  });
  const policyResponse: HostPolicyResponse = new EndpointPolicyResponseGenerator().generate({
    Endpoint: {
      policy: {
        applied: {
          id: appliedEndpointPolicyId,
          endpoint_policy_version: 2,
        },
      },
    },
  });
  const policyResponseApi: GetHostPolicyResponse = { policy_response: policyResponse };
  const registry = buildPolicyFieldRegistry({ packageVersion: '9.4.0' });
  const configNormalizedCarrier = {
    configNormalized: normalizePolicyConfig(policyFactory(), registry),
  };

  const fixtures = {
    fleetPolicy,
    hostMetadata,
    hostDetailsWrapped,
    hostInfo,
    policyResponseApi,
    configNormalizedCarrier,
  };

  return {
    ...fixtures,
    serialized: JSON.stringify(fixtures),
  };
};

export interface DefendPolicyManagementToolMocks {
  readonly deps: DefendPolicyManagementSkillDeps;
  readonly request: KibanaRequest;
  readonly context: ToolHandlerContext;
  readonly packagePolicyService: jest.Mocked<PackagePolicyClient>;
  readonly agentClient: jest.Mocked<AgentClient>;
  readonly esClient: ReturnType<typeof elasticsearchClientMock.createScopedClusterClient>;
  readonly applyStateEsClient: ReturnType<typeof elasticsearchClientMock.createElasticsearchClient>;
  readonly agentPolicyService: jest.Mocked<PolicyApplyStateAgentPolicyService>;
  readonly savedObjects: jest.Mocked<PolicyReadSavedObjectsService>;
  readonly logger: ReturnType<typeof loggingSystemMock.createLogger>;
  readonly endpointAppContextService: jest.Mocked<
    Pick<
      EndpointAppContextService,
      'getEndpointAuthz' | 'getActiveSpaceId' | 'getLicenseService' | 'asScoped' | 'isCcsEnabled'
    >
  >;
  readonly productFeaturesService: ProductFeaturesService;
  readonly setPrivileges: (privileges: {
    securityPolicyManagementRead?: boolean;
    fleetIntegrationPoliciesRead?: boolean;
    fleetAgentsRead?: boolean;
    canReadSecuritySolution?: boolean;
  }) => void;
  readonly withoutFleet: () => void;
  readonly calledPackagePolicyMethods: () => string[];
  readonly searchedIndices: () => string[];
  readonly applyStateSearchedIndices: () => string[];
}

export const createDefendPolicyManagementToolMocks = (): DefendPolicyManagementToolMocks => {
  resetPolicyRegistryCacheForTests();

  fleetAppContextService.start(createAppContextStartContractMock());

  const logger = loggingSystemMock.createLogger();
  const esClient = elasticsearchClientMock.createScopedClusterClient();
  const applyStateEsClient = elasticsearchClientMock.createElasticsearchClient();
  const request = httpServerMock.createKibanaRequest({ path: '/s/default/app/security' });
  const packagePolicyService = createPackagePolicyServiceMock();
  const agentPolicyService: jest.Mocked<PolicyApplyStateAgentPolicyService> = {
    getByIds: jest.fn().mockResolvedValue([]),
  };

  const agentClient = {
    getAgentStatusForAgentPolicy: jest.fn().mockResolvedValue({
      all: 0,
      active: 0,
      inactive: 0,
      unenrolled: 0,
      online: 0,
      error: 0,
      offline: 0,
      updating: 0,
      other: 0,
      events: 0,
    }),
    getAgent: jest.fn(),
    getAgentsByKuery: jest.fn(),
    getLatestAgentAvailableVersion: jest.fn(),
    getAgentStatusById: jest.fn(),
    listAgents: jest.fn(),
  } as unknown as jest.Mocked<AgentClient>;

  let fleetAuthz: FleetAuthz = createFleetAuthzMock();
  let endpointAuthz: EndpointAuthz = getEndpointAuthzInitialStateMock();

  const licenseService = new LicenseService();
  const productFeaturesService = createProductFeaturesServiceMock();

  const getActiveSpaceId = jest.fn(() => 'default');

  const scopedEndpointServices: jest.Mocked<ScopedEndpointServices> = {
    isCpsRead: jest.fn(() => false),
    getEsClient: jest.fn(() => applyStateEsClient),
    getSearchClient: jest.fn(),
    getSpaceId: jest.fn(() => getActiveSpaceId()),
    getSpace: jest.fn(),
  } as unknown as jest.Mocked<ScopedEndpointServices>;

  const endpointAppContextService = {
    getEndpointAuthz: jest.fn(async () => endpointAuthz),
    getActiveSpaceId,
    getLicenseService: jest.fn(() => licenseService),
    asScoped: jest.fn(() => scopedEndpointServices),
    isCcsEnabled: jest.fn<Promise<boolean>, []>().mockResolvedValue(false),
  } as unknown as jest.Mocked<
    Pick<
      EndpointAppContextService,
      'getEndpointAuthz' | 'getActiveSpaceId' | 'getLicenseService' | 'asScoped' | 'isCcsEnabled'
    >
  >;

  const coreStart = coreMock.createStart();
  const coreSetup = coreMock.createSetup();

  let fleetStart: unknown = {
    packagePolicyService,
    agentService: {
      asScoped: jest.fn(() => agentClient),
      asInternalUser: agentClient,
      asInternalScopedUser: jest.fn(() => agentClient),
    },
    agentPolicyService,
    authz: { fromRequest: jest.fn(async () => fleetAuthz) },
  };

  coreSetup.getStartServices.mockImplementation(
    async () =>
      [coreStart, { fleet: fleetStart }, {}] as unknown as Awaited<
        ReturnType<typeof coreSetup.getStartServices>
      >
  );

  const deps: DefendPolicyManagementSkillDeps = {
    getStartServices: coreSetup.getStartServices,
    endpointAppContextService: endpointAppContextService as unknown as EndpointAppContextService,
    productFeaturesService,
    kibanaVersion: '9.4.0',
    logger,
  };

  const context: ToolHandlerContext = {
    ...agentBuilderMocks.tools.createHandlerContext(),
    request,
    esClient,
    logger,
    spaceId: 'default',
  };

  return {
    deps,
    request,
    context,
    packagePolicyService,
    agentClient,
    esClient,
    applyStateEsClient,
    agentPolicyService,
    savedObjects: coreStart.savedObjects,
    logger,
    endpointAppContextService,
    productFeaturesService,
    setPrivileges: ({
      securityPolicyManagementRead = false,
      fleetIntegrationPoliciesRead = false,
      fleetAgentsRead = false,
      canReadSecuritySolution = false,
    }) => {
      endpointAuthz = getEndpointAuthzInitialStateMock({
        canReadPolicyManagement: securityPolicyManagementRead,
        canReadSecuritySolution,
      });
      const base = createFleetAuthzMock();
      fleetAuthz = {
        ...base,
        fleet: {
          ...base.fleet,
          all: false,
          setup: false,
          readAgents: fleetAgentsRead,
          readAgentPolicies: false,
          allAgentPolicies: false,
        },
        integrations: {
          ...base.integrations,
          all: false,
          readIntegrationPolicies: fleetIntegrationPoliciesRead,
          readInstalledPackages: false,
          writeIntegrationPolicies: false,
          readPackageSettings: false,
        },
      };
    },
    withoutFleet: () => {
      fleetStart = undefined;
    },
    calledPackagePolicyMethods: () =>
      Object.entries(packagePolicyService)
        .filter(([, value]) => jest.isMockFunction(value) && value.mock.calls.length > 0)
        .map(([name]) => name),
    searchedIndices: () => {
      const indices: string[] = [];

      for (const user of [esClient.asCurrentUser, esClient.asInternalUser]) {
        for (const method of [user.search, user.count, user.openPointInTime]) {
          if (jest.isMockFunction(method)) {
            for (const [params] of method.mock.calls) {
              const index = (params as { index?: string | string[] } | undefined)?.index;

              if (typeof index === 'string') indices.push(index);
              else if (Array.isArray(index)) indices.push(...index);
            }
          }
        }
      }

      return indices;
    },
    applyStateSearchedIndices: () => {
      const indices: string[] = [];

      for (const method of [applyStateEsClient.search, applyStateEsClient.count]) {
        if (jest.isMockFunction(method)) {
          for (const [params] of method.mock.calls) {
            const index = (params as { index?: string | string[] } | undefined)?.index;

            if (typeof index === 'string') indices.push(index);
            else if (Array.isArray(index)) indices.push(...index);
          }
        }
      }

      return indices;
    },
  };
};

export const expectReadOnlyAndNoForbiddenReads = (mocks: DefendPolicyManagementToolMocks): void => {
  const called = mocks.calledPackagePolicyMethods();
  const mutating = PROHIBITED_PACKAGE_POLICY_METHODS.filter((method) => called.includes(method));

  expect(mutating).toEqual([]);
  expect(mocks.searchedIndices()).toEqual([]);
};

export const expectApplyStateReadsWithinException = (
  mocks: DefendPolicyManagementToolMocks
): void => {
  expectReadOnlyAndNoForbiddenReads(mocks);

  const searched = mocks.applyStateSearchedIndices();

  expect(searched.length).toBeGreaterThan(0);
  for (const index of searched) {
    expect(index).toBe(APPLY_STATE_EXCEPTION_INDEX);
  }
};

export const expectWrappedHandlerWithinPlatformBudget = (result: unknown): void => {
  expect(estimateResultTokens(result)).toBeLessThanOrEqual(TOOL_RESULT_TOKEN_BUDGET);
};

export const expectConfiguredNotAppliedIsResultScoped = (payload: {
  readonly configured_not_applied?: string;
}): void => {
  expect(payload.configured_not_applied).toEqual(expect.any(String));
  expect(payload.configured_not_applied).not.toMatch(/read by this skill/i);
  expect(payload.configured_not_applied).toContain('This result');
  expect(payload.configured_not_applied).toContain('this tool');
  expect(payload.configured_not_applied).toContain('security.summarize_defend_policy_apply_state');
};
