/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';
import { createAppContextStartContractMock as fleetCreateAppContextStartContractMock } from '@kbn/fleet-plugin/server/mocks';
import { appContextService as fleetAppContextService } from '@kbn/fleet-plugin/server/services';
import { getEndpointAuthzInitialStateMock } from '../../../../../../common/endpoint/service/authz/mocks';
import type { EndpointMetadataGenerator } from '../../../../../../common/endpoint/data_generators/endpoint_metadata_generator';
import type {
  EndpointStatus as EndpointStatusType,
  HostMetadata,
  HostPolicyResponseActionStatus as HostPolicyResponseActionStatusType,
} from '../../../../../../common/endpoint/types';
import {
  EndpointStatus,
  HostPolicyResponseActionStatus,
} from '../../../../../../common/endpoint/types';
import { buildDefendKuery } from '../policy_read';
import { grantedPrivilegeBasis } from '../policy_read/mocks';
import type { SummarizePolicyApplyStateArgs } from './summarize_policy_apply_state';
import {
  DEFAULT_EXEMPLAR_LIMIT,
  DEFAULT_MAX_ENDPOINTS,
  summarizePolicyApplyState,
} from './summarize_policy_apply_state';
import { PACKAGE_POLICY_LIST_PAGE_SIZE } from './load_endpoint_package_policies';
import type { PolicyApplyStateClassifiedSummary } from './types';
import type { PolicyApplyStateMocks } from './mocks';
import {
  createAgentPolicy,
  createEndpointPackagePolicy,
  createPolicyApplyStateMocks,
  createUnitedMetadataHit,
  createUnitedMetadataSearchResponse,
  setupAgentPolicies,
  setupEndpointPackagePolicies,
} from './mocks';

describe('summarizePolicyApplyState', () => {
  let mocks: PolicyApplyStateMocks;
  let metadataGenerator: EndpointMetadataGenerator;

  const summarize = (overrides: Partial<SummarizePolicyApplyStateArgs> = {}) =>
    summarizePolicyApplyState({
      request: mocks.request,
      privilegeBasis: grantedPrivilegeBasis(),
      getEndpointAuthz: mocks.authorization.getEndpointAuthz,
      scopedServices: mocks.scopedServices,
      isCcsEnabled: mocks.isCcsEnabled,
      getSoClient: mocks.getSoClient,
      packagePolicyService: mocks.packagePolicyService,
      agentPolicyService: mocks.agentPolicyService,
      ...overrides,
    });

  const runClassified = async (
    overrides: Partial<SummarizePolicyApplyStateArgs> = {}
  ): Promise<PolicyApplyStateClassifiedSummary> => {
    const outcome = await summarize(overrides);

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) {
      throw new Error(`expected a classified summary, got denial: ${outcome.denial.message}`);
    }

    expect(outcome.value.populationStatus).toBe('classified');
    if (outcome.value.populationStatus !== 'classified') {
      throw new Error('expected a classified summary');
    }

    return outcome.value;
  };

  beforeEach(() => {
    mocks = createPolicyApplyStateMocks();
    metadataGenerator = mocks.metadataGenerator;
    fleetAppContextService.start(
      fleetCreateAppContextStartContractMock({}, false, {
        withoutSpaceExtensions: mocks.soClient,
      })
    );
  });

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

  describe('authorization is assumed already granted', () => {
    it('obtains nothing while the telemetry privilege is still resolving', async () => {
      mocks.authorization.getEndpointAuthz.mockImplementation(async () => {
        expect(mocks.getSoClient).not.toHaveBeenCalled();
        expect(mocks.scopedServices.getEsClient).not.toHaveBeenCalled();
        expect(mocks.packagePolicyService.fetchAllItems).not.toHaveBeenCalled();
        expect(mocks.packagePolicyService.list).not.toHaveBeenCalled();
        return getEndpointAuthzInitialStateMock();
      });

      const outcome = await summarize();

      expect(outcome.ok).toBe(true);
      expect(mocks.authorization.getEndpointAuthz).toHaveBeenCalledWith(mocks.request);
      expect(mocks.authorization.getFleetAuthz).not.toHaveBeenCalled();
    });
  });

  describe('telemetry privilege gate', () => {
    beforeEach(() => {
      mocks.authorization.getEndpointAuthz.mockImplementation(async () =>
        getEndpointAuthzInitialStateMock({
          canReadPolicyManagement: true,
          canReadSecuritySolution: false,
        })
      );
    });

    it('reports privilege_absent instead of inventing counts', async () => {
      const outcome = await summarize();

      expect(outcome.ok).toBe(true);
      if (!outcome.ok) {
        throw new Error('expected an ok outcome');
      }

      expect(outcome.value.populationStatus).toBe('privilege_absent');
      if (outcome.value.populationStatus !== 'privilege_absent') {
        throw new Error('expected a privilege_absent summary');
      }

      const value = outcome.value as unknown as Record<string, unknown>;
      expect(value.totalEndpoints).toBeUndefined();
      expect(value.currentCount).toBeUndefined();
      expect(value.revisionLagCount).toBeUndefined();
      expect(value.identityMismatchCount).toBeUndefined();
      expect(value.unknownCount).toBeUndefined();
      expect(value.staleOrOfflineCount).toBeUndefined();
      expect(value.exemplars).toBeUndefined();

      const disclosure = outcome.value.disclosures.find(
        ({ reason }) => reason === 'missing_privilege'
      );
      expect(disclosure).toBeDefined();
      expect(disclosure?.detail).toContain('Elastic Defend Policy Management read access');
      expect(disclosure?.continuation).toContain('other Elastic Defend Policy Management tools');
      expect(JSON.stringify(disclosure)).not.toContain('Defend policy read access');
      expect(JSON.stringify(disclosure)).not.toContain('other Defend policy tools');
    });

    it('issues NO sensitive read for a policy-read-only user', async () => {
      await summarize();

      expect(mocks.getSoClient).not.toHaveBeenCalled();
      expect(mocks.savedObjects.getScopedClient).not.toHaveBeenCalled();
      expect(mocks.scopedServices.getEsClient).not.toHaveBeenCalled();
      expect(mocks.esClient.search).not.toHaveBeenCalled();
      expect(mocks.packagePolicyService.fetchAllItems).not.toHaveBeenCalled();
      expect(mocks.packagePolicyService.list).not.toHaveBeenCalled();
      expect(mocks.agentPolicyService.getByIds).not.toHaveBeenCalled();
    });

    it('still reports the active space and the privilege basis', async () => {
      const outcome = await summarize();

      expect(outcome.ok).toBe(true);
      if (outcome.ok && outcome.value.populationStatus === 'privilege_absent') {
        expect(outcome.value.spaceId).toBe(mocks.spaceId);
        expect(outcome.value.privilegeBasis.securityPolicyManagementRead).toBe(true);
      } else {
        throw new Error('expected a privilege_absent summary');
      }
    });

    it('does not tell a Fleet-only caller they hold Elastic Defend Policy Management read', async () => {
      mocks.authorization.getEndpointAuthz.mockImplementation(async () =>
        getEndpointAuthzInitialStateMock({
          canReadPolicyManagement: false,
          canReadSecuritySolution: false,
        })
      );

      const outcome = await summarize({
        privilegeBasis: grantedPrivilegeBasis({
          securityPolicyManagementRead: false,
        }),
      });

      expect(outcome.ok).toBe(true);
      if (!outcome.ok || outcome.value.populationStatus !== 'privilege_absent') {
        throw new Error('expected a privilege_absent summary');
      }

      const disclosure = outcome.value.disclosures.find(
        ({ reason }) => reason === 'missing_privilege'
      );
      expect(disclosure?.detail).toContain('Fleet agent-policies and integrations read access');
      expect(disclosure?.detail).not.toContain('Elastic Defend Policy Management read access');
      expect(outcome.value.privilegeBasis.securityPolicyManagementRead).toBe(false);
    });
  });

  describe('request identity and active space', () => {
    it('reads Fleet saved objects through a client built from THE REQUEST', async () => {
      await runClassified();

      expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
        excludedExtensions: [SECURITY_EXTENSION_ID],
      });
      expect(mocks.packagePolicyService.fetchAllItems).toHaveBeenCalledWith(mocks.soClient, {
        kuery: buildDefendKuery(),
        spaceIds: [mocks.spaceId],
        perPage: PACKAGE_POLICY_LIST_PAGE_SIZE,
      });
      expect(mocks.packagePolicyService.list).toHaveBeenCalledWith(mocks.soClient, {
        kuery: buildDefendKuery(),
        perPage: 1,
        page: 1,
        spaceId: mocks.spaceId,
      });
    });

    it('reads agent policies as the requesting user through the same client', async () => {
      const endpointPolicy = createEndpointPackagePolicy();
      const agentPolicy = createAgentPolicy();
      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(createMetadataWithPolicy(endpointPolicy.id, 2, 3), {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      await runClassified();

      expect(mocks.agentPolicyService.getByIds).toHaveBeenCalledWith(
        mocks.soClient,
        [agentPolicy.id],
        expect.objectContaining({ ignoreMissing: true })
      );
    });

    it('reads the united index through the request-bound read client', async () => {
      await runClassified();

      expect(mocks.scopedServices.getEsClient).toHaveBeenCalledTimes(1);
      expect(mocks.esClient.search).toHaveBeenCalledTimes(1);
    });

    it('reports the active space of the request', async () => {
      const summary = await runClassified();

      expect(summary.spaceId).toBe(mocks.spaceId);
      expect(mocks.scopedServices.getSpaceId).toHaveBeenCalled();
    });

    it('bounds a fanned-out (CPS) read to the active space explicitly', async () => {
      mocks.scopedServices.isCpsRead.mockReturnValue(true);
      (mocks.scopedServices.getSpaceId as jest.Mock).mockReturnValue('finance');
      setupEndpointPackagePolicies(mocks.packagePolicyService, [createEndpointPackagePolicy()]);

      await runClassified();

      const query = mocks.esClient.search.mock.calls[0][0] as Record<string, unknown>;
      expect(JSON.stringify(query)).toContain('united.agent.namespaces');
      expect(JSON.stringify(query)).toContain('finance');
    });

    it('filters the origin read by endpoint policies resolved through the space-scoped SO read', async () => {
      setupEndpointPackagePolicies(mocks.packagePolicyService, [
        createEndpointPackagePolicy({ policy_ids: ['agent-policy-1', 'agent-policy-2'] }),
      ]);

      await runClassified();

      const query = mocks.esClient.search.mock.calls[0][0] as Record<string, unknown>;
      const queryText = JSON.stringify(query);
      expect(queryText).toContain('agent-policy-1');
      expect(queryText).toContain('agent-policy-2');
    });

    it('does not add a CCS prefix to a fanned-out read', async () => {
      mocks.scopedServices.isCpsRead.mockReturnValue(true);
      mocks.isCcsEnabled.mockResolvedValue(true);
      setupEndpointPackagePolicies(mocks.packagePolicyService, [createEndpointPackagePolicy()]);

      await runClassified();

      const query = mocks.esClient.search.mock.calls[0][0] as { index: string };
      expect(query.index).not.toContain('*:');
    });
  });

  describe('current classification', () => {
    it('classifies an endpoint as current when revisions match', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.currentCount).toBe(1);
      expect(summary.revisionLagCount).toBe(0);
      expect(summary.identityMismatchCount).toBe(0);
      expect(summary.unknownCount).toBe(0);
      expect(summary.totalEndpoints).toBe(1);
    });
  });

  describe('revision lag classification', () => {
    it('classifies an endpoint as revision_lag when agent revision is behind', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.revisionLagCount).toBe(1);
      expect(summary.currentCount).toBe(0);
      expect(summary.exemplars.revisionLag).toHaveLength(1);
      expect(summary.exemplars.revisionLag[0].appliedAgentPolicyRevision).toBe(3);
      expect(summary.exemplars.revisionLag[0].configuredAgentPolicyRevision).toBe(5);
    });

    it('omits exemplar check-in when neither a Fleet check-in nor an interpretable timestamp exists', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const metadata = {
        ...createMetadataWithPolicy(endpointPolicy.id, 2, 3),
        '@timestamp': 'not-a-date',
      } as HostMetadata;

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
            last_checkin: '',
          }),
        ])
      );

      const summary = await runClassified();
      const exemplar = summary.exemplars.revisionLag[0];

      expect(summary.revisionLagCount).toBe(1);
      expect(exemplar).toBeDefined();
      expect(exemplar).not.toHaveProperty('lastCheckin');
      expect(JSON.stringify(exemplar)).not.toContain('lastCheckin');
    });

    it('classifies an endpoint as revision_lag when endpoint policy revision is behind', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 5 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.revisionLagCount).toBe(1);
      expect(summary.exemplars.revisionLag[0].appliedEndpointPolicyRevision).toBe(2);
      expect(summary.exemplars.revisionLag[0].configuredEndpointPolicyRevision).toBe(5);
    });
  });

  describe('identity mismatch classification', () => {
    it('classifies an endpoint as identity_mismatch when endpoint policy was reassigned', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ id: 'new-policy', revision: 1 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const metadata = createMetadataWithPolicy('old-policy', 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.identityMismatchCount).toBe(1);
      expect(summary.exemplars.identityMismatch).toHaveLength(1);
      expect(summary.exemplars.identityMismatch[0].appliedEndpointPolicyId).toBe('old-policy');
      expect(summary.exemplars.identityMismatch[0].configuredEndpointPolicyId).toBe('new-policy');
    });

    it('classifies an endpoint as unknown when agent policy was deleted after reassignment', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ id: 'new-agent-policy', revision: 3 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: 'old-agent-policy',
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.unknownCount).toBe(1);
      expect(summary.identityMismatchCount).toBe(0);
    });

    it('yields identity_mismatch for a two-policy reassignment, resolved from an independent assignment', async () => {
      const appliedEndpointPolicy = createEndpointPackagePolicy({
        id: 'endpoint-policy-applied',
        policy_ids: ['agent-policy-applied'],
      });
      const configuredEndpointPolicy = createEndpointPackagePolicy({
        id: 'endpoint-policy-configured',
        policy_ids: ['agent-policy-configured'],
      });
      const appliedAgentPolicy = createAgentPolicy({
        id: 'agent-policy-applied',
        revision: 3,
      });
      const configuredAgentPolicy = createAgentPolicy({
        id: 'agent-policy-configured',
        revision: 1,
      });

      setupEndpointPackagePolicies(mocks.packagePolicyService, [
        appliedEndpointPolicy,
        configuredEndpointPolicy,
      ]);
      setupAgentPolicies(mocks.agentPolicyService, [appliedAgentPolicy, configuredAgentPolicy]);

      const metadata = createMetadataWithPolicy('endpoint-policy-applied', 2, 3);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: 'agent-policy-configured',
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.identityMismatchCount).toBe(1);
      expect(summary.revisionLagCount).toBe(0);
      expect(summary.unknownCount).toBe(0);
      const exemplar = summary.exemplars.identityMismatch[0];
      expect(exemplar.appliedEndpointPolicyId).toBe('endpoint-policy-applied');
      expect(exemplar.configuredEndpointPolicyId).toBe('endpoint-policy-configured');
    });

    it('sources the configured agent-policy id from the Fleet assignment, not from the applied id', async () => {
      const appliedEndpointPolicy = createEndpointPackagePolicy({
        id: 'endpoint-policy-applied',
        policy_ids: ['agent-policy-applied'],
      });
      const configuredEndpointPolicy = createEndpointPackagePolicy({
        id: 'endpoint-policy-configured',
        policy_ids: ['agent-policy-configured'],
      });
      const appliedAgentPolicy = createAgentPolicy({
        id: 'agent-policy-applied',
        revision: 3,
      });
      const configuredAgentPolicy = createAgentPolicy({
        id: 'agent-policy-configured',
        revision: 5,
      });

      setupEndpointPackagePolicies(mocks.packagePolicyService, [
        appliedEndpointPolicy,
        configuredEndpointPolicy,
      ]);
      setupAgentPolicies(mocks.agentPolicyService, [appliedAgentPolicy, configuredAgentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(createMetadataWithPolicy('endpoint-policy-applied', 2, 3), {
            policy_id: 'agent-policy-configured',
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.identityMismatchCount).toBe(1);
      expect(mocks.agentPolicyService.getByIds).toHaveBeenCalledWith(
        mocks.soClient,
        expect.arrayContaining(['agent-policy-configured']),
        expect.objectContaining({ ignoreMissing: true })
      );
    });
  });

  describe('unknown classification', () => {
    it('classifies an endpoint as unknown when no applied policy id is reported', async () => {
      const endpointPolicy = createEndpointPackagePolicy();
      const agentPolicy = createAgentPolicy();
      const metadata = createMetadataWithPolicy('', 0, 0);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([createUnitedMetadataHit(metadata)])
      );

      const summary = await runClassified();

      expect(summary.unknownCount).toBe(1);
      expect(summary.currentCount).toBe(0);
    });
  });

  describe('missing enrichment', () => {
    it('classifies an endpoint as unknown when agent policy is not found', async () => {
      const endpointPolicy = createEndpointPackagePolicy();
      const metadata = metadataGenerator.generate();

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, []);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([createUnitedMetadataHit(metadata)])
      );

      const summary = await runClassified();

      expect(summary.unknownCount).toBe(1);
      expect(summary.disclosures.some((d) => d.reason === 'upstream_failure')).toBe(true);
    });

    it('classifies an endpoint as unknown when endpoint package policy is not found', async () => {
      const agentPolicy = createAgentPolicy();
      const metadata = metadataGenerator.generate();

      setupEndpointPackagePolicies(mocks.packagePolicyService, []);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([createUnitedMetadataHit(metadata)])
      );

      const summary = await runClassified();

      expect(summary.unknownCount).toBe(1);
    });

    it('handles missing endpoint and agent documents gracefully', async () => {
      setupEndpointPackagePolicies(mocks.packagePolicyService, []);
      setupAgentPolicies(mocks.agentPolicyService, []);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          {
            agent: { id: 'test' },
            united: {},
          } as unknown as ReturnType<typeof createUnitedMetadataHit>,
        ])
      );

      const summary = await runClassified();

      expect(summary.unknownCount).toBe(1);
    });
  });

  describe('stale/offline endpoints', () => {
    it('counts offline endpoints separately', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse(
          [
            createUnitedMetadataHit(metadata, {
              policy_id: agentPolicy.id,
              policy_revision: 3,
            }),
          ],
          ['offline']
        )
      );

      const summary = await runClassified();

      expect(summary.staleOrOfflineCount).toBe(1);
      expect(summary.disclosures.some((d) => d.detail.includes('offline'))).toBe(true);
    });

    it('counts inactive endpoints separately', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse(
          [
            createUnitedMetadataHit(metadata, {
              policy_id: agentPolicy.id,
              policy_revision: 3,
            }),
          ],
          ['inactive']
        )
      );

      const summary = await runClassified();

      expect(summary.staleOrOfflineCount).toBe(1);
    });
  });

  describe('bounded exemplars', () => {
    it('caps revision lag exemplars at the limit', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 5 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 1, 1);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);

      const hits = Array.from({ length: 10 }, () =>
        createUnitedMetadataHit(metadata, {
          policy_id: agentPolicy.id,
          policy_revision: 1,
        })
      );
      mocks.esClient.search.mockResponse(createUnitedMetadataSearchResponse(hits));

      const summary = await runClassified();

      expect(summary.revisionLagCount).toBe(10);
      expect(summary.exemplars.revisionLag.length).toBeLessThanOrEqual(DEFAULT_EXEMPLAR_LIMIT);
    });

    it('caps identity mismatch exemplars at the limit', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ id: 'new', revision: 1 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const metadata = createMetadataWithPolicy('old', 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);

      const hits = Array.from({ length: 10 }, () =>
        createUnitedMetadataHit(metadata, {
          policy_id: agentPolicy.id,
          policy_revision: 3,
        })
      );
      mocks.esClient.search.mockResponse(createUnitedMetadataSearchResponse(hits));

      const summary = await runClassified();

      expect(summary.identityMismatchCount).toBe(10);
      expect(summary.exemplars.identityMismatch.length).toBeLessThanOrEqual(DEFAULT_EXEMPLAR_LIMIT);
    });

    it('respects a custom exemplar limit', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 5 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 1, 1);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);

      const hits = Array.from({ length: 5 }, () =>
        createUnitedMetadataHit(metadata, {
          policy_id: agentPolicy.id,
          policy_revision: 1,
        })
      );
      mocks.esClient.search.mockResponse(createUnitedMetadataSearchResponse(hits));

      const summary = await runClassified({ exemplarLimit: 2 });

      expect(summary.exemplars.revisionLag).toHaveLength(2);
    });
  });

  describe('bounded endpoints', () => {
    it('discloses when the endpoint bound is hit', async () => {
      const endpointPolicy = createEndpointPackagePolicy();
      const agentPolicy = createAgentPolicy();
      const metadata = metadataGenerator.generate();

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);

      const boundedHits = Array.from({ length: 5 }, () => createUnitedMetadataHit(metadata));
      const response = createUnitedMetadataSearchResponse(boundedHits);
      (response.hits as { total: { value: number; relation: string } }).total = {
        value: DEFAULT_MAX_ENDPOINTS + 1,
        relation: 'eq',
      };
      mocks.esClient.search.mockResponse(response);

      const summary = await runClassified({ maxEndpoints: 5 });

      expect(summary.bounded).toBe(true);
      expect(summary.totalEndpoints).toBe(5);
      expect(summary.endpointQueryTotal).toBe(DEFAULT_MAX_ENDPOINTS + 1);

      const disclosure = summary.disclosures.find(
        ({ reason }) => reason === 'result_limit_reached'
      );
      expect(disclosure).toBeDefined();
      expect(disclosure?.detail).toContain('5 of');
      expect(disclosure?.detail).toContain('endpoints matching the loaded Elastic Defend policies');
      expect(disclosure?.detail).not.toMatch(/estate/i);
      expect(disclosure?.continuation).toMatch(/no endpoint filter or list input/i);
      expect(disclosure?.continuation).not.toMatch(/use the endpoint list/i);
      expect(disclosure?.continuation).not.toMatch(/narrower filter/i);
    });

    it('requests the united index with the endpoint bound as the page size', async () => {
      setupEndpointPackagePolicies(mocks.packagePolicyService, [createEndpointPackagePolicy()]);
      mocks.esClient.search.mockResponse(createUnitedMetadataSearchResponse([]));

      await runClassified({ maxEndpoints: 123 });

      const query = mocks.esClient.search.mock.calls[0][0] as { size: number; from: number };
      expect(query.size).toBe(123);
      expect(query.from).toBe(0);
    });
  });

  describe('freshness', () => {
    it('reports the latest endpoint timestamp', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const now = Date.now();
      const older = now - 60_000;
      const metadata1 = metadataGenerator.generate({ '@timestamp': older });
      const metadata2 = metadataGenerator.generate({ '@timestamp': now });

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata1, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
          createUnitedMetadataHit(metadata2, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.freshness.latestEndpointTimestamp).toBe(new Date(now).toISOString());
    });

    it('resolves freshness from an ISO date-string timestamp on a real document shape', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const isoTimestamp = '2026-04-01T12:00:00.000Z';
      const metadata = {
        ...metadataGenerator.generate({ '@timestamp': Date.parse(isoTimestamp) }),
        '@timestamp': isoTimestamp,
      } as HostMetadata;

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.freshness.latestEndpointTimestamp).toBe(isoTimestamp);
      expect(summary.disclosures.some(({ detail }) => detail.includes('could not be dated'))).toBe(
        false
      );
    });

    it('reports undefined freshness when no endpoints exist', async () => {
      setupEndpointPackagePolicies(mocks.packagePolicyService, []);
      setupAgentPolicies(mocks.agentPolicyService, []);
      mocks.esClient.search.mockResponse(createUnitedMetadataSearchResponse([]));

      const summary = await runClassified();

      expect(summary.freshness.latestEndpointTimestamp).toBeUndefined();
      expect(summary.totalEndpoints).toBe(0);
      expect(summary.disclosures.some(({ detail }) => detail.includes('could not be dated'))).toBe(
        false
      );
    });

    it('discloses when endpoints were scanned but none could be dated', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const metadata = {
        ...createMetadataWithPolicy(endpointPolicy.id, 2, 3),
        '@timestamp': 'not-a-date',
      } as HostMetadata;

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.totalEndpoints).toBe(1);
      expect(summary.freshness.latestEndpointTimestamp).toBeUndefined();
      expect(summary.disclosures).toEqual(
        expect.arrayContaining([
          {
            reason: 'upstream_failure',
            detail: expect.stringContaining('1 endpoint'),
            continuation: expect.stringContaining('could not be dated'),
          },
        ])
      );
      expect(summary.disclosures.some(({ detail }) => detail.includes('could not be dated'))).toBe(
        true
      );
    });

    it('does not disclose undated freshness for a scanned document that never carried a united body', async () => {
      setupEndpointPackagePolicies(mocks.packagePolicyService, []);
      setupAgentPolicies(mocks.agentPolicyService, []);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          {
            agent: { id: 'test' },
            united: {},
          } as unknown as ReturnType<typeof createUnitedMetadataHit>,
        ])
      );

      const summary = await runClassified();

      expect(summary.totalEndpoints).toBe(1);
      expect(summary.unknownCount).toBe(1);
      expect(summary.freshness.latestEndpointTimestamp).toBeUndefined();
      expect(
        summary.disclosures.some(({ detail }) => detail.includes('could not be classified'))
      ).toBe(true);
      expect(summary.disclosures.some(({ detail }) => detail.includes('could not be dated'))).toBe(
        false
      );
      expect(
        summary.disclosures.some(({ continuation }) =>
          continuation.includes('check in with metadata that includes @timestamp')
        )
      ).toBe(false);
    });
  });

  describe('raw-document absence', () => {
    it('never returns raw HostMetadata in exemplars', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 5 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 1, 1);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 1,
          }),
        ])
      );

      const summary = await runClassified();

      for (const exemplar of summary.exemplars.revisionLag) {
        expect(exemplar).not.toHaveProperty('Endpoint');
        expect(exemplar).not.toHaveProperty('agent');
        expect(exemplar).not.toHaveProperty('host');
        expect(exemplar).not.toHaveProperty('event');
        expect(exemplar).not.toHaveProperty('data_stream');
        expect(exemplar).not.toHaveProperty('elastic');
      }

      const resultJson = JSON.stringify(summary);
      expect(resultJson).not.toContain('"Endpoint"');
      expect(resultJson).not.toContain('"data_stream"');
      expect(resultJson).not.toContain('"elastic"');
    });

    it('output contains only scalar derived values', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 5 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 1, 1);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 1,
          }),
        ])
      );

      const summary = await runClassified();

      expect(typeof summary.totalEndpoints).toBe('number');
      expect(typeof summary.currentCount).toBe('number');
      expect(typeof summary.revisionLagCount).toBe('number');
      expect(typeof summary.identityMismatchCount).toBe('number');
      expect(typeof summary.unknownCount).toBe('number');
      expect(typeof summary.staleOrOfflineCount).toBe('number');
      expect(typeof summary.bounded).toBe('boolean');
      expect(Array.isArray(summary.disclosures)).toBe(true);

      if (summary.exemplars.revisionLag.length > 0) {
        const exemplar = summary.exemplars.revisionLag[0];
        expect(typeof exemplar.endpointId).toBe('string');
        expect(typeof exemplar.hostName).toBe('string');
        expect(typeof exemplar.classification).toBe('string');
        expect(typeof exemplar.appliedEndpointPolicyId).toBe('string');
        expect(typeof exemplar.appliedEndpointPolicyRevision).toBe('number');
        expect(typeof exemplar.appliedAgentPolicyRevision).toBe('number');
        expect(typeof exemplar.hostStatus).toBe('string');
        expect(typeof exemplar.lastCheckin).toBe('string');
      }
    });
  });

  describe('multiple endpoints', () => {
    it('aggregates counts across endpoints', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const currentMetadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);
      const laggingMetadata = createMetadataWithPolicy(endpointPolicy.id, 1, 1);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(currentMetadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
          createUnitedMetadataHit(laggingMetadata, {
            policy_id: agentPolicy.id,
            policy_revision: 1,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.totalEndpoints).toBe(2);
      expect(summary.currentCount).toBe(1);
      expect(summary.revisionLagCount).toBe(1);
      expect(summary.identityMismatchCount).toBe(0);
    });
  });

  describe('CCS', () => {
    it('adds the CCS prefix when CCS is enabled and the read does not fan out', async () => {
      setupEndpointPackagePolicies(mocks.packagePolicyService, []);
      setupAgentPolicies(mocks.agentPolicyService, []);
      mocks.isCcsEnabled.mockResolvedValue(true);
      mocks.esClient.search.mockResponse(createUnitedMetadataSearchResponse([]));

      await runClassified();

      const query = mocks.esClient.search.mock.calls[0][0] as { index: string };
      expect(query.index).toContain('*:');
    });
  });

  describe('version-suffixed agent policy ids', () => {
    it('classifies current when united.agent.policy_id has a version suffix', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 3 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: `${agentPolicy.id}#9.2`,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.currentCount).toBe(1);
      expect(summary.unknownCount).toBe(0);
      expect(summary.revisionLagCount).toBe(0);
      expect(summary.identityMismatchCount).toBe(0);
    });

    it('classifies revision_lag when united.agent.policy_id has a version suffix', async () => {
      const endpointPolicy = createEndpointPackagePolicy({ revision: 2 });
      const agentPolicy = createAgentPolicy({ revision: 5 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: `${agentPolicy.id}#9.3`,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.revisionLagCount).toBe(1);
      expect(summary.unknownCount).toBe(0);
      expect(summary.currentCount).toBe(0);
    });

    it('strips suffixes from collected ids used for Fleet getByIds and the united-index filter', async () => {
      const endpointPolicy = createEndpointPackagePolicy({
        policy_ids: ['agent-policy-1#9.2'],
        revision: 2,
      });
      const agentPolicy = createAgentPolicy({ id: 'agent-policy-1', revision: 3 });
      const metadata = createMetadataWithPolicy(endpointPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [endpointPolicy]);
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: 'agent-policy-1#9.2',
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified();

      expect(summary.currentCount).toBe(1);
      expect(summary.unknownCount).toBe(0);
      expect(mocks.agentPolicyService.getByIds).toHaveBeenCalledWith(
        mocks.soClient,
        ['agent-policy-1'],
        expect.objectContaining({ ignoreMissing: true })
      );

      const queryText = JSON.stringify(mocks.esClient.search.mock.calls[0][0]);
      expect(queryText).toContain('agent-policy-1');
      expect(queryText).toContain('agent-policy-1#*');
      expect(queryText).not.toContain('agent-policy-1#9.2#*');
    });
  });

  describe('package-policy load bound', () => {
    it('discloses loaded-only scope and the exact omitted policy count when the cap is hit', async () => {
      const loadedPolicy = createEndpointPackagePolicy({
        id: 'loaded-policy',
        policy_ids: ['loaded-agent-policy'],
      });
      const agentPolicy = createAgentPolicy({ id: 'loaded-agent-policy', revision: 3 });
      const metadata = createMetadataWithPolicy(loadedPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [loadedPolicy], { total: 4 });
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(metadata, {
            policy_id: agentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified({ maxLoadedPackagePolicies: 1 });

      expect(summary.packagePolicyLoad).toEqual({
        loaded: 1,
        total: 4,
        omitted: 3,
        complete: false,
      });

      const disclosure = summary.disclosures.find(
        ({ reason, detail }) => reason === 'result_limit_reached' && detail.includes('omitted')
      );
      expect(disclosure?.detail).toContain('loaded 1 of 4');
      expect(disclosure?.detail).toContain('3 policies were omitted');
      expect(disclosure?.detail).toContain('only the loaded policies');
      expect(disclosure?.detail).not.toMatch(/true estate total/i);
      expect(disclosure?.continuation).toMatch(/no package-policy continuation input/i);
    });

    it('queries Elasticsearch only with ids from loaded package policies', async () => {
      const loadedPolicy = createEndpointPackagePolicy({
        id: 'loaded-policy',
        policy_ids: ['loaded-agent-policy'],
      });

      setupEndpointPackagePolicies(mocks.packagePolicyService, [loadedPolicy], { total: 4 });
      mocks.esClient.search.mockResponse(createUnitedMetadataSearchResponse([]));

      await runClassified({ maxLoadedPackagePolicies: 1 });

      const queryText = JSON.stringify(mocks.esClient.search.mock.calls[0][0]);
      expect(queryText).toContain('loaded-agent-policy');
      expect(queryText).not.toContain('omitted-agent-policy');
    });

    it('keeps an incomplete CPS read on loaded policy ids and does not admit omitted-policy hits', async () => {
      mocks.scopedServices.isCpsRead.mockReturnValue(true);
      (mocks.scopedServices.getSpaceId as jest.Mock).mockReturnValue('finance');

      const loadedPolicy = createEndpointPackagePolicy({
        id: 'loaded-policy',
        policy_ids: ['loaded-agent-policy'],
      });
      const omittedPolicy = createEndpointPackagePolicy({
        id: 'omitted-policy',
        policy_ids: ['omitted-agent-policy'],
      });
      const loadedAgentPolicy = createAgentPolicy({ id: 'loaded-agent-policy', revision: 3 });
      const loadedMetadata = createMetadataWithPolicy(loadedPolicy.id, 2, 3);
      const omittedHit = createUnitedMetadataHit(createMetadataWithPolicy(omittedPolicy.id, 2, 3), {
        policy_id: omittedPolicy.policy_ids?.[0],
        policy_revision: 3,
        namespaces: ['finance'],
      });

      setupEndpointPackagePolicies(mocks.packagePolicyService, [loadedPolicy], { total: 4 });
      setupAgentPolicies(mocks.agentPolicyService, [loadedAgentPolicy]);
      mocks.esClient.search.mockResponse(
        createUnitedMetadataSearchResponse([
          createUnitedMetadataHit(loadedMetadata, {
            policy_id: loadedAgentPolicy.id,
            policy_revision: 3,
          }),
        ])
      );

      const summary = await runClassified({ maxLoadedPackagePolicies: 1 });

      const queryText = JSON.stringify(mocks.esClient.search.mock.calls[0][0]);
      expect(queryText).toContain('loaded-agent-policy');
      expect(queryText).not.toContain('united.agent.namespaces');
      expect(queryText).not.toContain(omittedPolicy.id);
      expect(queryText).not.toContain(omittedHit.united.agent.policy_id);

      expect(summary.packagePolicyLoad).toEqual({
        loaded: 1,
        total: 4,
        omitted: 3,
        complete: false,
      });
      expect(summary.totalEndpoints).toBe(1);
      expect(summary.currentCount).toBe(1);
      expect(summary.endpointQueryTotal).toBe(1);
    });

    it('keeps the loaded-policy Elasticsearch total distinct from an estate-wide total', async () => {
      const loadedPolicy = createEndpointPackagePolicy();
      const agentPolicy = createAgentPolicy();
      const metadata = createMetadataWithPolicy(loadedPolicy.id, 2, 3);

      setupEndpointPackagePolicies(mocks.packagePolicyService, [loadedPolicy], { total: 9 });
      setupAgentPolicies(mocks.agentPolicyService, [agentPolicy]);

      const response = createUnitedMetadataSearchResponse([
        createUnitedMetadataHit(metadata, {
          policy_id: agentPolicy.id,
          policy_revision: 3,
        }),
      ]);
      (response.hits as { total: { value: number; relation: string } }).total = {
        value: 12,
        relation: 'eq',
      };
      mocks.esClient.search.mockResponse(response);

      const summary = await runClassified({ maxLoadedPackagePolicies: 1 });

      expect(summary.totalEndpoints).toBe(1);
      expect(summary.endpointQueryTotal).toBe(12);
      expect(summary.packagePolicyLoad.omitted).toBe(8);

      const disclosure = summary.disclosures.find((d) => d.detail.includes('omitted'));
      expect(disclosure?.detail).toContain('not the full estate');
      expect(disclosure?.detail).not.toContain('12');
    });
  });

  describe('finite package-policy list', () => {
    it('walks fetchAllItems once and queries total once without offset pages', async () => {
      setupEndpointPackagePolicies(mocks.packagePolicyService, [createEndpointPackagePolicy()]);
      mocks.esClient.search.mockResponse(createUnitedMetadataSearchResponse([]));

      await runClassified();

      expect(mocks.packagePolicyService.fetchAllItems).toHaveBeenCalledTimes(1);
      expect(mocks.packagePolicyService.list).toHaveBeenCalledTimes(1);
      expect(mocks.packagePolicyService.list).toHaveBeenCalledWith(
        mocks.soClient,
        expect.objectContaining({ page: 1, perPage: 1, spaceId: mocks.spaceId })
      );
    });
  });
});
