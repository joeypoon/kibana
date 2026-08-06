/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest } from '@kbn/core-http-server';
import type { estypes } from '@elastic/elasticsearch';
import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import type { ElasticsearchClientMock } from '@kbn/core/server/mocks';
import type { SavedObjectsClientContract, SavedObjectsServiceStart } from '@kbn/core/server';
import { DEFAULT_SPACE_ID } from '@kbn/core-spaces-common';
import type { AgentPolicy, PackagePolicy } from '@kbn/fleet-plugin/common';
import type { PackagePolicyClient } from '@kbn/fleet-plugin/server';
import { FleetAgentPolicyGenerator } from '../../../../../../common/endpoint/data_generators/fleet_agent_policy_generator';
import { FleetPackagePolicyGenerator } from '../../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import { EndpointMetadataGenerator } from '../../../../../../common/endpoint/data_generators/endpoint_metadata_generator';
import type {
  HostMetadata,
  UnitedAgentMetadataPersistedData,
} from '../../../../../../common/endpoint/types';
import type { ScopedEndpointServices } from '../../../../../endpoint/endpoint_app_context_services';
import type { AuthorizationMocks, PolicyReadMocks } from '../policy_read/mocks';
import { createPolicyReadMocks } from '../policy_read/mocks';
import type {
  PolicyApplyStateAgentPolicyService,
  PolicyApplyStatePackagePolicyService,
} from './summarize_policy_apply_state';

export interface PolicyApplyStateMocks {
  readonly savedObjects: jest.Mocked<SavedObjectsServiceStart>;
  readonly soClient: jest.Mocked<SavedObjectsClientContract>;
  readonly packagePolicyService: jest.Mocked<PackagePolicyClient>;
  readonly authorization: AuthorizationMocks;
  readonly request: KibanaRequest;
  readonly getSoClient: jest.Mock<SavedObjectsClientContract, []>;
  readonly spaceId: string;
  readonly esClient: ElasticsearchClientMock;
  readonly scopedServices: jest.Mocked<ScopedEndpointServices>;
  readonly agentPolicyService: jest.Mocked<PolicyApplyStateAgentPolicyService>;
  readonly isCcsEnabled: jest.Mock<Promise<boolean>, []>;
  readonly metadataGenerator: EndpointMetadataGenerator;
  readonly agentPolicyGenerator: FleetAgentPolicyGenerator;
  readonly packagePolicyGenerator: FleetPackagePolicyGenerator;
}

export const createPolicyApplyStateMocks = ({
  spaceId = DEFAULT_SPACE_ID,
}: { spaceId?: string } = {}): PolicyApplyStateMocks => {
  const policyRead: PolicyReadMocks = createPolicyReadMocks({ spaceId });
  const esClient = elasticsearchClientMock.createElasticsearchClient();

  const scopedServices = {
    isCpsRead: jest.fn(() => false),
    getEsClient: jest.fn(() => esClient),
    getSearchClient: jest.fn(),
    getSpaceId: jest.fn(() => spaceId),
    getSpace: jest.fn(),
  } as unknown as jest.Mocked<ScopedEndpointServices>;

  const agentPolicyService: jest.Mocked<PolicyApplyStateAgentPolicyService> = {
    getByIds: jest.fn().mockResolvedValue([]),
  };

  setupEndpointPackagePolicies(policyRead.packagePolicyService, []);

  policyRead.soClient.find.mockResolvedValue({
    saved_objects: [],
    total: 0,
    per_page: 0,
    page: 1,
  });

  return {
    savedObjects: policyRead.savedObjects,
    soClient: policyRead.soClient,
    packagePolicyService: policyRead.packagePolicyService,
    authorization: policyRead.authorization,
    request: policyRead.request,
    getSoClient: policyRead.getSoClient,
    spaceId,
    esClient,
    scopedServices,
    agentPolicyService,
    isCcsEnabled: jest.fn<Promise<boolean>, []>().mockResolvedValue(false),
    metadataGenerator: new EndpointMetadataGenerator(),
    agentPolicyGenerator: new FleetAgentPolicyGenerator(),
    packagePolicyGenerator: new FleetPackagePolicyGenerator(),
  };
};

export const createUnitedMetadataHit = (
  hostMetadata: HostMetadata,
  agentOverrides: Record<string, unknown> = {},
  agentStatus: string = 'online'
): UnitedAgentMetadataPersistedData =>
  ({
    agent: { id: 'test-agent-id' },
    united: {
      agent: {
        policy_id: 'agent-policy-1',
        policy_revision: 3,
        last_checkin: new Date().toISOString(),
        ...agentOverrides,
      },
      endpoint: hostMetadata,
    },
  } as unknown as UnitedAgentMetadataPersistedData);

export const createUnitedMetadataSearchResponse = (
  hits: UnitedAgentMetadataPersistedData[],
  agentStatuses: string[] = []
): estypes.SearchResponse<UnitedAgentMetadataPersistedData> =>
  ({
    took: 5,
    timed_out: false,
    _shards: { total: 1, successful: 1, skipped: 0, failed: 0 },
    hits: {
      total: { value: hits.length, relation: 'eq' },
      max_score: null,
      hits: hits.map((hit, i) => ({
        _index: '.metrics-endpoint.metadata_united_default',
        _id: `doc-${i}`,
        _score: null,
        _source: hit,
        fields: { status: [agentStatuses[i] ?? 'online'] },
        sort: [Date.now()],
      })),
    },
  } as unknown as estypes.SearchResponse<UnitedAgentMetadataPersistedData>);

export const createAgentPolicy = (overrides: Partial<AgentPolicy> = {}): AgentPolicy => {
  const generator = new FleetAgentPolicyGenerator();
  return {
    ...generator.generate(),
    id: 'agent-policy-1',
    revision: 3,
    ...overrides,
  } as AgentPolicy;
};

export const createEndpointPackagePolicy = (
  overrides: Partial<PackagePolicy> = {}
): PackagePolicy => {
  const generator = new FleetPackagePolicyGenerator();
  return {
    ...generator.generate(),
    id: 'endpoint-policy-1',
    revision: 2,
    policy_ids: ['agent-policy-1'],
    ...overrides,
  } as PackagePolicy;
};

export const setupEndpointPackagePolicies = (
  packagePolicyService: PolicyApplyStatePackagePolicyService,
  policies: PackagePolicy[],
  { total }: { total?: number } = {}
): void => {
  (packagePolicyService.fetchAllItems as jest.Mock).mockResolvedValue({
    async *[Symbol.asyncIterator]() {
      if (policies.length > 0) {
        yield [...policies];
      }
      yield [];
    },
  });

  (packagePolicyService.list as jest.Mock).mockImplementation(
    async (_soClient: unknown, options: { page?: number; perPage?: number }) => {
      const page = options?.page ?? 1;
      const perPage = options?.perPage ?? 1;

      return {
        items: policies.slice(0, perPage),
        total: total ?? policies.length,
        page,
        perPage,
      };
    }
  );
};

export const setupAgentPolicies = (
  agentPolicyService: PolicyApplyStateAgentPolicyService,
  policies: AgentPolicy[]
): void => {
  (agentPolicyService.getByIds as jest.Mock).mockResolvedValue(policies);
};
