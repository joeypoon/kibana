/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import type { ToolHandlerStandardReturn } from '@kbn/agent-builder-server/tools';
import { SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';
import { EndpointMetadataGenerator } from '../../../../../../common/endpoint/data_generators/endpoint_metadata_generator';
import type {
  EndpointStatus as EndpointStatusType,
  HostPolicyResponseActionStatus as HostPolicyResponseActionStatusType,
} from '../../../../../../common/endpoint/types';
import {
  EndpointStatus,
  HostPolicyResponseActionStatus,
} from '../../../../../../common/endpoint/types';
import {
  createAgentPolicy,
  createEndpointPackagePolicy,
  createUnitedMetadataHit,
  createUnitedMetadataSearchResponse,
  setupAgentPolicies,
  setupEndpointPackagePolicies,
} from '../../services/policy_apply_state/mocks';
import { createSummarizeDefendPolicyApplyStateTool } from '.';
import type { DefendPolicyManagementToolMocks } from '../../lib/test_helpers';
import {
  APPLY_STATE_EXCEPTION_INDEX,
  createDefendPolicyManagementToolMocks,
  expectApplyStateReadsWithinException,
  expectWrappedHandlerWithinPlatformBudget,
} from '../../lib/test_helpers';

interface ExemplarPayload {
  endpoint_id: string;
  host_name: string;
  classification: string;
  applied_endpoint_policy_id: string;
  applied_endpoint_policy_revision: number;
  applied_agent_policy_revision: number;
  configured_endpoint_policy_id?: string;
  configured_endpoint_policy_revision?: number;
  configured_agent_policy_revision?: number;
  host_status: string;
  last_checkin?: string;
}

interface DisclosurePayload {
  reason: string;
  detail: string;
  continuation: string;
}

interface ClassifiedPayload {
  message: string;
  population_status: 'classified';
  endpoints: {
    total: number;
    current: number;
    revision_lag: number;
    identity_mismatch: number;
    unknown: number;
    stale_or_offline: number;
  };
  exemplars: { revision_lag: ExemplarPayload[]; identity_mismatch: ExemplarPayload[] };
  freshness: { latest_endpoint_timestamp?: string };
  bounded: boolean;
  disclosures: DisclosurePayload[];
  scope_disclosure: {
    privilege_basis: Record<string, boolean>;
    returned: number;
    total: number;
    omitted_policy_count?: number;
    endpoint_query_scope?: 'loaded_policies_only';
    partial?: DisclosurePayload;
  };
  revision_identity_only: string;
  per_endpoint_diagnosis: string;
}

interface PrivilegeAbsentPayload {
  message: string;
  population_status: 'privilege_absent';
  scope_disclosure: {
    privilege_basis: Record<string, boolean>;
    partial?: DisclosurePayload;
  };
  revision_identity_only: string;
  per_endpoint_diagnosis: string;
}

interface ErrorPayload {
  message: string;
  metadata?: Record<string, unknown>;
}

describe('security.summarize_defend_policy_apply_state', () => {
  let mocks: DefendPolicyManagementToolMocks;
  let tool: ReturnType<typeof createSummarizeDefendPolicyApplyStateTool>;

  const metadataGenerator = new EndpointMetadataGenerator();

  const runTool = async () => (await tool.handler({}, mocks.context)) as ToolHandlerStandardReturn;

  const runClassified = async (): Promise<ClassifiedPayload> => {
    const result = await runTool();

    expect(result.results[0].type).toBe(ToolResultType.other);
    const payload = result.results[0].data as ClassifiedPayload;
    expect(payload.population_status).toBe('classified');

    return payload;
  };

  const createMetadataWithPolicy = (
    appliedPolicyId: string,
    appliedEndpointRevision: number,
    appliedAgentRevision: number,
    status: EndpointStatusType = EndpointStatus.enrolled,
    policyStatus: HostPolicyResponseActionStatusType = HostPolicyResponseActionStatus.success
  ) =>
    metadataGenerator.generate({
      Endpoint: {
        status,
        policy: {
          applied: {
            id: appliedPolicyId,
            status: policyStatus,
            name: 'test-policy',
            endpoint_policy_version: appliedEndpointRevision,
            version: appliedAgentRevision,
          },
        },
      },
    });

  const givenCurrentEstate = () => {
    const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
    const agentPolicy = createAgentPolicy({ revision: 3 });

    setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
    setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
    mocks.applyStateEsClient.search.mockResponse(
      createUnitedMetadataSearchResponse([
        createUnitedMetadataHit(createMetadataWithPolicy(endpointPolicy.id, 2, 3), {
          policy_id: agentPolicy.id,
          policy_revision: 3,
        }),
      ])
    );

    return { endpointPolicy, agentPolicy };
  };

  beforeEach(() => {
    mocks = createDefendPolicyManagementToolMocks();
    tool = createSummarizeDefendPolicyApplyStateTool(mocks.deps);
  });

  describe('authorization', () => {
    it('denies a caller holding neither policy-read privilege, naming what would satisfy it', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });

      const result = await runTool();
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'not_authorized' });
      expect(payload.metadata?.need_any).toEqual([
        'Security > Elastic Defend Policy Management: Read',
        'Fleet > Agent policies: Read and Fleet > Integrations: Read',
      ]);
    });

    it('constructs NO client and issues NO read on the denial path', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });

      await runTool();

      expect(mocks.savedObjects.getScopedClient).not.toHaveBeenCalled();
      expect(mocks.packagePolicyService.fetchAllItems).not.toHaveBeenCalled();
      expect(mocks.packagePolicyService.list).not.toHaveBeenCalled();
      expect(mocks.agentPolicyService.getByIds).not.toHaveBeenCalled();
      expect(mocks.applyStateEsClient.search).not.toHaveBeenCalled();
    });

    it('reads Fleet saved objects through a client built from THE REQUEST once granted', async () => {
      givenCurrentEstate();

      await runTool();

      expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
        excludedExtensions: [SECURITY_EXTENSION_ID],
      });
      expect(mocks.agentPolicyService.getByIds).toHaveBeenCalledWith(
        expect.anything(),
        ['agent-policy-1'],
        expect.objectContaining({ ignoreMissing: true })
      );
    });

    it('issues NO sensitive read for a policy-read-only user', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: true,
        canReadSecuritySolution: false,
      });

      const result = await runTool();

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(mocks.savedObjects.getScopedClient).not.toHaveBeenCalled();
      expect(mocks.packagePolicyService.fetchAllItems).not.toHaveBeenCalled();
      expect(mocks.packagePolicyService.list).not.toHaveBeenCalled();
      expect(mocks.agentPolicyService.getByIds).not.toHaveBeenCalled();
      expect(mocks.applyStateEsClient.search).not.toHaveBeenCalled();
    });

    it('reports privilege_absent with NO counts when the telemetry privilege is absent', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: true,
        canReadSecuritySolution: false,
      });

      const result = await runTool();
      const payload = result.results[0].data as PrivilegeAbsentPayload;

      expect(payload.population_status).toBe('privilege_absent');
      expect(payload.scope_disclosure.privilege_basis).toMatchObject({
        securityPolicyManagementRead: true,
      });
      expect(payload.scope_disclosure.partial).toMatchObject({
        reason: 'missing_privilege',
        detail: expect.stringContaining('Elastic Defend Policy Management read access'),
        continuation: expect.stringContaining('other Elastic Defend Policy Management tools'),
      });
      expect(payload.message).toContain('could not read endpoint data');
      expect(payload.message).toContain('Elastic Defend Policy Management read access');
      expect(payload.message).toContain('other Elastic Defend Policy Management tools');
      expect(JSON.stringify(payload)).not.toContain('Defend policy read access');
      expect(JSON.stringify(payload)).not.toContain('other Defend policy tools');

      expect((payload as unknown as Record<string, unknown>).endpoints).toBeUndefined();
      const serialized = JSON.stringify(payload);
      expect(serialized).not.toContain('"total"');
      expect(serialized).not.toContain('"current"');
      expect(serialized).not.toContain('"revision_lag"');
    });

    it('records the privilege basis that authorized the summary', async () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: true,
        fleetIntegrationPoliciesRead: true,
        fleetAgentsRead: false,
        canReadSecuritySolution: true,
      });
      givenCurrentEstate();

      const payload = await runClassified();

      expect(payload.scope_disclosure.privilege_basis).toEqual({
        securityPolicyManagementRead: true,
        fleetIntegrationPoliciesRead: true,
        fleetAgentsRead: false,
      });
    });
  });

  describe('request identity and active space', () => {
    it('binds the scoped endpoint services to THE REQUEST', async () => {
      givenCurrentEstate();

      await runTool();

      expect(mocks.endpointAppContextService.asScoped).toHaveBeenCalledWith(mocks.request);
    });

    it('reads the active space through the scoped services the request resolved', async () => {
      mocks.endpointAppContextService.getActiveSpaceId.mockReturnValue('finance');
      givenCurrentEstate();

      await runTool();

      expect(mocks.endpointAppContextService.getActiveSpaceId).toHaveBeenCalledWith(mocks.request);
    });

    it('reads the united index through the request-bound exception client', async () => {
      givenCurrentEstate();

      await runTool();

      expectApplyStateReadsWithinException(mocks);
      expect(mocks.applyStateEsClient.search).toHaveBeenCalledTimes(1);
    });
  });

  describe('classification outcomes', () => {
    it('classifies revision lag and carries scalar exemplars', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 5 });

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.applyStateEsClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(createMetadataWithPolicy(endpointPolicy.id, 2, 3), {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const payload = await runClassified();

      expect(payload.endpoints.revision_lag).toBe(1);
      expect(payload.endpoints.current).toBe(0);
      expect(payload.exemplars.revision_lag).toHaveLength(1);
      expect(payload.exemplars.revision_lag[0]).toMatchObject({
        classification: 'revision_lag',
        applied_agent_policy_revision: 3,
        configured_agent_policy_revision: 5,
        applied_endpoint_policy_revision: 2,
        configured_endpoint_policy_revision: 2,
      });
      expect(payload.message).toContain('behind on revision');
    });

    it('omits last_checkin from an exemplar when no usable check-in time exists', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const metadata = {
        ...createMetadataWithPolicy(endpointPolicy.id, 2, 3),
        '@timestamp': 'not-a-date',
      };

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.applyStateEsClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
            last_checkin: '',
          }),
        ])
      );

      const payload = await runClassified();
      const exemplar = payload.exemplars.revision_lag[0];

      expect(payload.endpoints.revision_lag).toBe(1);
      expect(exemplar).toBeDefined();
      expect(exemplar).not.toHaveProperty('last_checkin');
      expect(JSON.stringify(exemplar)).not.toContain('last_checkin');
    });

    it('truncates oversized exemplar host names without dropping counts or disclosures', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const hugeHostName = `host-${'n'.repeat(80_000)}`;

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.applyStateEsClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(
            metadataGenerator.generate({
              host: { hostname: hugeHostName },
              Endpoint: {
                status: EndpointStatus.enrolled,
                policy: {
                  applied: {
                    id: endpointPolicy.id,
                    status: HostPolicyResponseActionStatus.success,
                    name: 'test-policy',
                    endpoint_policy_version: 2,
                    version: 3,
                  },
                },
              },
            }),
            {
              policy_id: agentPolicy.id,
              policy_revision: 3,
            }
          ),
        ])
      );

      const result = await runTool();
      const payload = result.results[0].data as ClassifiedPayload;

      expectWrappedHandlerWithinPlatformBudget(result);
      expect(payload.population_status).toBe('classified');
      expect(payload.endpoints.revision_lag).toBe(1);
      expect(payload.endpoints.total).toBe(1);
      expect(payload.exemplars.revision_lag).toHaveLength(1);
      expect(payload.exemplars.revision_lag[0].host_name.length).toBeLessThan(80_000);
      expect(payload.exemplars.revision_lag[0].host_name).toContain('truncated');
      expect(payload.scope_disclosure.total).toBe(1);
      expect(payload.revision_identity_only).toEqual(expect.any(String));
      expect(payload.disclosures).toEqual(expect.any(Array));
    });
  });

  describe('freshness and statements', () => {
    it('states the revision/identity-only boundary and the per-endpoint routing', async () => {
      givenCurrentEstate();

      const payload = await runClassified();

      expect(payload.revision_identity_only).toMatch(/setting-level applied differences/i);
      expect(payload.per_endpoint_diagnosis).toMatch(
        /elastic-defend-configuration-troubleshooting/
      );
      expect(payload.per_endpoint_diagnosis).toMatch(/Automatic\s+Troubleshooting/);
    });

    it('does not disclose undated freshness for a scanned document that never carried a united body', async () => {
      setupEndpointPackagePolicies(mocks.packagePolicyService, []);
      setupAgentPolicies(mocks.agentPolicyService, []);
      mocks.applyStateEsClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          {
            agent: { id: 'test' },
            united: {},
          } as unknown as ReturnType<typeof createUnitedMetadataHit>,
        ])
      );

      const payload = await runClassified();

      expect(payload.endpoints.total).toBe(1);
      expect(payload.endpoints.unknown).toBe(1);
      expect(payload.freshness.latest_endpoint_timestamp).toBeUndefined();
      expect(
        payload.disclosures.some(({ detail }) => detail.includes('could not be classified'))
      ).toBe(true);
      expect(payload.disclosures.some(({ detail }) => detail.includes('could not be dated'))).toBe(
        false
      );
      expect(
        payload.disclosures.some(({ continuation }) =>
          continuation.includes('check in with metadata that includes @timestamp')
        )
      ).toBe(false);
    });
  });

  describe('scope, identity, and honest continuation', () => {
    it('sets scope_disclosure.returned to the scanned hit count and total to the loaded-policy ES total', async () => {
      const { endpointPolicy, agentPolicy } = givenCurrentEstate();
      const response = createUnitedMetadataSearchResponse([
        createUnitedMetadataHit(createMetadataWithPolicy(endpointPolicy.id, 2, 3), {
          policy_id: agentPolicy.id,
          policy_revision: 3,
        }),
      ]);
      (response.hits as { total: { value: number; relation: string } }).total = {
        value: 7,
        relation: 'eq',
      };
      mocks.applyStateEsClient.search.mockResponse(response);

      const payload = await runClassified();

      expect(payload.endpoints.total).toBe(1);
      expect(payload.scope_disclosure.returned).toBe(1);
      expect(payload.scope_disclosure.total).toBe(7);
      expect(payload.message).not.toMatch(/true total/i);
      expect(payload.message).not.toMatch(/use the endpoint list/i);
      expect(payload.message).not.toMatch(/narrower filter/i);
    });

    it('surfaces omitted policy count and loaded-only scope when package-policy loading is incomplete', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy], { total: 5 });
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.applyStateEsClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(createMetadataWithPolicy(endpointPolicy.id, 2, 3), {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const payload = await runClassified();

      expect(payload.scope_disclosure.omitted_policy_count).toBe(4);
      expect(payload.scope_disclosure.endpoint_query_scope).toBe('loaded_policies_only');
      expect(payload.scope_disclosure.partial).toMatchObject({
        reason: 'result_limit_reached',
      });
      expect(payload.scope_disclosure.partial?.detail).toContain('4 policies were omitted');
      expect(payload.scope_disclosure.partial?.detail).toContain('only the loaded policies');
      expect(payload.scope_disclosure.partial?.continuation).toMatch(
        /no package-policy continuation input/i
      );
      expect(payload.message).toContain('4 omitted');
      expect(payload.message).toContain('only the loaded policies, not the full estate');
      expect(payload.message).not.toMatch(/true estate total/i);
      expect(JSON.stringify(payload)).not.toMatch(/use the endpoint list/i);
      expect(JSON.stringify(payload)).not.toMatch(/narrower filter/i);
    });
  });

  describe('raw data never reaches the result', () => {
    it('keeps the raw united document, agent documents, and policy-response shapes server-side', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 5 });

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.applyStateEsClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(createMetadataWithPolicy(endpointPolicy.id, 2, 3), {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const result = await runTool();
      const payload = result.results[0].data as ClassifiedPayload;
      expect(payload.exemplars.revision_lag).toHaveLength(1);

      const serialized = JSON.stringify(result);

      expect(serialized).toContain('endpoint_id');
      expect(serialized).toContain('host_name');

      expect(serialized).not.toContain('"Endpoint":');
      expect(serialized).not.toContain('"HostDetails"');
      expect(serialized).not.toContain('"endpoint_policy_version":');
      expect(serialized).not.toContain('"policy_info":');
      expect(serialized).not.toContain('"config":');
      expect(serialized).not.toContain('"inputs":');
      expect(serialized).not.toContain('artifact_manifest');
      expect(serialized).not.toContain('"policy_response');
    });

    it('searches only the narrow united-index exception and nothing forbidden', async () => {
      givenCurrentEstate();

      await runTool();

      expectApplyStateReadsWithinException(mocks);
      expect(mocks.applyStateSearchedIndices()).toEqual([APPLY_STATE_EXCEPTION_INDEX]);
    });
  });

  describe('failure', () => {
    it('reports a missing Fleet plugin as an error result rather than throwing', async () => {
      mocks.withoutFleet();

      const result = await runTool();
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'unknown_error' });
      expect(payload.message).toContain('Fleet plugin is not available');
    });

    it('turns an upstream failure into an error result rather than throwing', async () => {
      givenCurrentEstate();
      mocks.applyStateEsClient.search.mockRejectedValue(new Error('united index unavailable'));

      const result = await runTool();
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'unknown_error' });
      expect(payload.message).toContain('united index unavailable');
      expect(mocks.logger.error).toHaveBeenCalled();
    });
  });
});
