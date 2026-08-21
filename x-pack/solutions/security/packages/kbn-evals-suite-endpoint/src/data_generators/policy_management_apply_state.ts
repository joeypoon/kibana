/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Client } from '@elastic/elasticsearch';
import { API_VERSIONS, packagePolicyRouteService } from '@kbn/fleet-plugin/common';
import type { KbnClient } from '@kbn/test';
import type { ToolingLog } from '@kbn/tooling-log';
import {
  metadataCurrentIndexPattern,
  METADATA_UNITED_INDEX,
} from '@kbn/security-solution-plugin/common/endpoint/constants';
import {
  deleteIndexedFleetEndpointPolicies,
  indexFleetEndpointPolicy,
} from '@kbn/security-solution-plugin/common/endpoint/data_loaders/index_fleet_endpoint_policy';
import type { IndexedFleetEndpointPolicyResponse } from '@kbn/security-solution-plugin/common/endpoint/data_loaders/index_fleet_endpoint_policy';
import { cleanupPolicyManagementPackagePolicy } from './policy_management_package_policy';
import { cleanupPolicyManagementSeededData } from './cleanup';

export const EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME = 'eval-agent-pm-apply-state';
export const EVAL_PM_APPLY_STATE_AGENT_POLICY_NAME = 'eval-agent-pm-apply-state-agent';
export const EVAL_PM_APPLY_STATE_AGENT_ID = 'eval-agent-pm-apply-state-001';
export const EVAL_PM_APPLY_STATE_HOST_NAME = 'eval-pm-apply-state-host';

export const POLICY_MANAGEMENT_APPLY_STATE_SEED_ERROR =
  'seedPolicyManagementApplyState: indexFleetEndpointPolicy returned no integration policy';
export const POLICY_MANAGEMENT_APPLY_STATE_ITEM_ERROR =
  'seedPolicyManagementApplyState: Fleet package policy GET did not return a PolicyData item';
export const POLICY_MANAGEMENT_APPLY_STATE_ASSIGNMENT_ERROR =
  'seedPolicyManagementApplyState: persisted policy_ids must contain exactly one unique nonempty agent-policy id';
export const POLICY_MANAGEMENT_APPLY_STATE_REVISION_ERROR =
  'seedPolicyManagementApplyState: package policy revision did not increase after update';
export const POLICY_MANAGEMENT_APPLY_STATE_READINESS_TIMEOUT =
  'Timed out waiting for policy-management apply-state readiness';

const PUBLIC_V1_HEADERS = {
  'elastic-api-version': API_VERSIONS.public.v1,
};

const TRANSFORM_POLL_INTERVAL_MS = 5_000;
const DEFAULT_TRANSFORM_WAIT_MS = 180_000;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isFiniteNumber = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);

const readString = (value: unknown): string | undefined =>
  typeof value === 'string' && value.length > 0 ? value : undefined;

const readBoolean = (value: unknown): boolean | undefined =>
  typeof value === 'boolean' ? value : undefined;

const canonicalizeAgentPolicyId = (value: unknown): string | undefined => {
  const raw = readString(value);
  if (raw === undefined) {
    return undefined;
  }
  return raw.replace(/#\d+\.\d+$/, '');
};

const readAppliedRevision = (value: unknown): number | undefined => {
  if (isFiniteNumber(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return undefined;
};

const deleteFleetAgent = async (internalEsClient: Client, agentId: string): Promise<void> => {
  await internalEsClient.delete(
    {
      index: '.fleet-agents',
      id: agentId,
      refresh: true,
    },
    { ignore: [404] }
  );
};

export interface SeededPolicyManagementApplyState {
  id: string;
  name: string;
  indexed: IndexedFleetEndpointPolicyResponse;
  agentId: string;
  agentPolicyId: string;
  packageRevision: number;
  appliedPackageRevision: number;
}

export interface PolicyManagementApplyStateReadiness {
  agentId: string;
  agentPolicyId: string;
  packagePolicyId: string;
  packageRevision: number;
  appliedPackageRevision: number;
}

interface ObservedApplyStateFacts {
  metadataCurrentFound: boolean;
  agentId?: string;
  endpointAgentId?: string;
  fleetAgentId?: string;
  active?: boolean;
  agentPolicyId?: string;
  packagePolicyId?: string;
  appliedPackageRevision?: number;
}

const uniqueAssignedAgentPolicyIds = (policyIds: unknown): string[] | undefined => {
  if (policyIds === undefined) {
    return [];
  }
  if (!Array.isArray(policyIds)) {
    return undefined;
  }

  return [
    ...new Set(
      policyIds.filter(
        (policyId): policyId is string => typeof policyId === 'string' && policyId.length > 0
      )
    ),
  ];
};

const readPackagePolicyItem = async (kbnClient: KbnClient, id: string): Promise<unknown> => {
  const response = await kbnClient.request<{ item: unknown }>({
    path: packagePolicyRouteService.getInfoPath(id),
    method: 'GET',
    headers: PUBLIC_V1_HEADERS,
  });
  return response.data.item;
};

const readRevision = (item: unknown): number => {
  if (!isRecord(item) || !isFiniteNumber(item.revision)) {
    throw new Error(POLICY_MANAGEMENT_APPLY_STATE_ITEM_ERROR);
  }
  return item.revision;
};

const readUniqueAssignedAgentPolicyId = (item: unknown): string => {
  if (!isRecord(item)) {
    throw new Error(POLICY_MANAGEMENT_APPLY_STATE_ITEM_ERROR);
  }

  const uniqueIds = uniqueAssignedAgentPolicyIds(item.policy_ids);
  if (uniqueIds === undefined) {
    throw new Error(POLICY_MANAGEMENT_APPLY_STATE_ITEM_ERROR);
  }

  const [agentPolicyId] = uniqueIds;
  if (uniqueIds.length !== 1 || agentPolicyId === undefined) {
    throw new Error(POLICY_MANAGEMENT_APPLY_STATE_ASSIGNMENT_ERROR);
  }

  return agentPolicyId;
};

const omitManagedPackagePolicyFields = (item: Record<string, unknown>): Record<string, unknown> => {
  const {
    created_by: _createdBy,
    created_at: _createdAt,
    updated_by: _updatedBy,
    updated_at: _updatedAt,
    id: _id,
    version: _version,
    revision: _revision,
    ...updateBody
  } = item;

  return updateBody;
};

const firstHitSource = (response: unknown): unknown => {
  if (!isRecord(response) || !isRecord(response.hits) || !Array.isArray(response.hits.hits)) {
    return undefined;
  }
  const [hit] = response.hits.hits;
  return isRecord(hit) ? hit._source : undefined;
};

const extractUnitedFacts = (
  source: unknown
): Omit<ObservedApplyStateFacts, 'metadataCurrentFound'> => {
  if (!isRecord(source)) {
    return {};
  }

  const agent = isRecord(source.agent) ? source.agent : undefined;
  const united = isRecord(source.united) ? source.united : undefined;
  const unitedEndpoint = united && isRecord(united.endpoint) ? united.endpoint : undefined;
  const unitedAgent = united && isRecord(united.agent) ? united.agent : undefined;
  const endpointAgent =
    unitedEndpoint && isRecord(unitedEndpoint.agent) ? unitedEndpoint.agent : undefined;
  const fleetAgent = unitedAgent && isRecord(unitedAgent.agent) ? unitedAgent.agent : undefined;
  const applied =
    unitedEndpoint &&
    isRecord(unitedEndpoint.Endpoint) &&
    isRecord(unitedEndpoint.Endpoint.policy) &&
    isRecord(unitedEndpoint.Endpoint.policy.applied)
      ? unitedEndpoint.Endpoint.policy.applied
      : undefined;
  const policyBaseId = unitedAgent ? readString(unitedAgent.policy_base_id) : undefined;
  const policyId = unitedAgent ? canonicalizeAgentPolicyId(unitedAgent.policy_id) : undefined;

  return {
    agentId: agent ? readString(agent.id) : undefined,
    endpointAgentId: endpointAgent ? readString(endpointAgent.id) : undefined,
    fleetAgentId: fleetAgent ? readString(fleetAgent.id) : undefined,
    active: unitedAgent ? readBoolean(unitedAgent.active) : undefined,
    agentPolicyId: policyBaseId ?? policyId,
    packagePolicyId: applied ? readString(applied.id) : undefined,
    appliedPackageRevision: applied
      ? readAppliedRevision(applied.endpoint_policy_version)
      : undefined,
  };
};

const formatExpectedReadiness = (expected: PolicyManagementApplyStateReadiness): string =>
  `agentId=${expected.agentId} agentPolicyId=${expected.agentPolicyId} packagePolicyId=${expected.packagePolicyId} packageRevision=${expected.packageRevision} appliedPackageRevision=${expected.appliedPackageRevision}`;

const formatObservedFacts = (facts: ObservedApplyStateFacts): string =>
  `metadataCurrentFound=${facts.metadataCurrentFound} agentId=${
    facts.agentId ?? 'none'
  } endpointAgentId=${facts.endpointAgentId ?? 'none'} fleetAgentId=${
    facts.fleetAgentId ?? 'none'
  } active=${facts.active ?? 'none'} agentPolicyId=${
    facts.agentPolicyId ?? 'none'
  } packagePolicyId=${facts.packagePolicyId ?? 'none'} appliedPackageRevision=${
    facts.appliedPackageRevision ?? 'none'
  }`;

const isExactAgentCurrent = (source: unknown, agentId: string): boolean => {
  if (!isRecord(source) || !isRecord(source.agent)) {
    return false;
  }
  return readString(source.agent.id) === agentId;
};

const isExpectedApplyStateReady = (
  facts: ObservedApplyStateFacts,
  expected: PolicyManagementApplyStateReadiness
): boolean => {
  if (!facts.metadataCurrentFound) {
    return false;
  }
  if (expected.appliedPackageRevision >= expected.packageRevision) {
    return false;
  }

  return (
    facts.agentId === expected.agentId &&
    facts.endpointAgentId === expected.agentId &&
    facts.fleetAgentId === expected.agentId &&
    facts.active === true &&
    facts.agentPolicyId === expected.agentPolicyId &&
    facts.packagePolicyId === expected.packagePolicyId &&
    facts.appliedPackageRevision === expected.appliedPackageRevision
  );
};

const exactSeededAgentQuery = (agentId: string) => ({
  bool: {
    should: [
      { term: { 'agent.id': agentId } },
      { term: { 'united.endpoint.agent.id': agentId } },
      { term: { 'united.agent.agent.id': agentId } },
    ],
    minimum_should_match: 1,
  },
});

export const waitForPolicyManagementTransformPropagation = async (
  esClient: Client,
  log: ToolingLog,
  expected: PolicyManagementApplyStateReadiness,
  options?: {
    maxWaitMs?: number;
    pollIntervalMs?: number;
  }
): Promise<void> => {
  const maxWaitMs = options?.maxWaitMs ?? DEFAULT_TRANSFORM_WAIT_MS;
  const pollIntervalMs = options?.pollIntervalMs ?? TRANSFORM_POLL_INTERVAL_MS;
  const start = Date.now();
  let lastObserved: ObservedApplyStateFacts = { metadataCurrentFound: false };
  const query = exactSeededAgentQuery(expected.agentId);
  log.info(
    `Waiting for policy-management apply-state readiness: ${formatExpectedReadiness(expected)}`
  );

  while (Date.now() - start < maxWaitMs) {
    try {
      const [currentResponse, unitedResponse] = await Promise.all([
        esClient.search({
          index: metadataCurrentIndexPattern,
          query,
          size: 1,
          ignore_unavailable: true,
        }),
        esClient.search({
          index: METADATA_UNITED_INDEX,
          query,
          size: 1,
          ignore_unavailable: true,
        }),
      ]);

      lastObserved = {
        metadataCurrentFound: isExactAgentCurrent(
          firstHitSource(currentResponse),
          expected.agentId
        ),
        ...extractUnitedFacts(firstHitSource(unitedResponse)),
      };

      log.debug(`Policy-management apply-state readiness: ${formatObservedFacts(lastObserved)}`);

      if (isExpectedApplyStateReady(lastObserved, expected)) {
        log.info('Policy-management apply-state readiness complete');
        return;
      }
    } catch (err) {
      log.debug(`Error checking policy-management apply-state readiness: ${err}`);
    }

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }

  throw new Error(
    `${POLICY_MANAGEMENT_APPLY_STATE_READINESS_TIMEOUT} after ${maxWaitMs}ms. ` +
      `Expected ${formatExpectedReadiness(expected)}; last observed ${formatObservedFacts(
        lastObserved
      )}`
  );
};

const seedApplyStateDocuments = async ({
  esClient,
  internalEsClient,
  agentPolicyId,
  packagePolicyId,
  packagePolicyName,
  appliedPackageRevision,
  agentPolicyRevision,
}: {
  esClient: Client;
  internalEsClient: Client;
  agentPolicyId: string;
  packagePolicyId: string;
  packagePolicyName: string;
  appliedPackageRevision: number;
  agentPolicyRevision: number;
}): Promise<void> => {
  const now = new Date().toISOString();

  await esClient.create({
    index: 'metrics-endpoint.metadata-default',
    id: `eval-metadata-${EVAL_PM_APPLY_STATE_HOST_NAME}-${Date.now()}`,
    refresh: true,
    document: {
      '@timestamp': now,
      event: {
        kind: 'metric',
        dataset: 'endpoint.metadata',
        module: 'endpoint',
      },
      data_stream: {
        type: 'metrics',
        dataset: 'endpoint.metadata',
        namespace: 'default',
      },
      agent: { id: EVAL_PM_APPLY_STATE_AGENT_ID, type: 'endpoint', version: '9.5.0-SNAPSHOT' },
      host: {
        name: EVAL_PM_APPLY_STATE_HOST_NAME,
        hostname: EVAL_PM_APPLY_STATE_HOST_NAME,
        os: { name: 'Windows', version: '10', type: 'windows', full: 'Windows 10' },
      },
      Endpoint: {
        status: 'enrolled',
        policy: {
          applied: {
            status: 'success',
            name: packagePolicyName,
            id: packagePolicyId,
            version: agentPolicyRevision,
            endpoint_policy_version: appliedPackageRevision,
          },
        },
      },
      elastic: { agent: { id: EVAL_PM_APPLY_STATE_AGENT_ID } },
    },
  });

  await internalEsClient.index({
    index: '.fleet-agents',
    id: EVAL_PM_APPLY_STATE_AGENT_ID,
    refresh: true,
    document: {
      '@timestamp': now,
      updated_at: now,
      type: 'PERMANENT',
      active: true,
      enrolled_at: now,
      last_checkin: now,
      status: 'online',
      last_known_status: 'online',
      last_checkin_status: 'online',
      policy_id: agentPolicyId,
      policy_revision_idx: agentPolicyRevision,
      agent: { id: EVAL_PM_APPLY_STATE_AGENT_ID, version: '9.5.0-SNAPSHOT' },
      local_metadata: { host: { name: EVAL_PM_APPLY_STATE_HOST_NAME } },
      packages: ['endpoint'],
    },
  });
};

export const seedPolicyManagementApplyState = async ({
  kbnClient,
  esClient,
  internalEsClient,
  log,
}: {
  kbnClient: KbnClient;
  esClient: Client;
  internalEsClient: Client;
  log: ToolingLog;
}): Promise<SeededPolicyManagementApplyState> => {
  const captured: IndexedFleetEndpointPolicyResponse[] = [];

  try {
    const indexed = await indexFleetEndpointPolicy(
      kbnClient,
      EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME,
      undefined,
      EVAL_PM_APPLY_STATE_AGENT_POLICY_NAME,
      log
    );
    captured.push(indexed);

    const integrationPolicy = indexed.integrationPolicies[0];
    if (integrationPolicy === undefined) {
      throw new Error(POLICY_MANAGEMENT_APPLY_STATE_SEED_ERROR);
    }

    const initialItem = await readPackagePolicyItem(kbnClient, integrationPolicy.id);
    if (!isRecord(initialItem)) {
      throw new Error(POLICY_MANAGEMENT_APPLY_STATE_ITEM_ERROR);
    }

    const appliedPackageRevision = readRevision(initialItem);
    const agentPolicyId = readUniqueAssignedAgentPolicyId(initialItem);

    await kbnClient.request({
      path: packagePolicyRouteService.getUpdatePath(integrationPolicy.id),
      method: 'PUT',
      headers: PUBLIC_V1_HEADERS,
      body: omitManagedPackagePolicyFields(structuredClone(initialItem)),
    });

    const persistedItem = await readPackagePolicyItem(kbnClient, integrationPolicy.id);
    const packageRevision = readRevision(persistedItem);
    if (packageRevision <= appliedPackageRevision) {
      throw new Error(POLICY_MANAGEMENT_APPLY_STATE_REVISION_ERROR);
    }

    const [agentPolicy] = indexed.agentPolicies;
    const agentPolicyRevision =
      agentPolicy !== undefined && isFiniteNumber(agentPolicy.revision) ? agentPolicy.revision : 1;

    await seedApplyStateDocuments({
      esClient,
      internalEsClient,
      agentPolicyId,
      packagePolicyId: integrationPolicy.id,
      packagePolicyName: integrationPolicy.name,
      appliedPackageRevision,
      agentPolicyRevision,
    });

    await waitForPolicyManagementTransformPropagation(esClient, log, {
      agentId: EVAL_PM_APPLY_STATE_AGENT_ID,
      agentPolicyId,
      packagePolicyId: integrationPolicy.id,
      packageRevision,
      appliedPackageRevision,
    });

    log.info(
      `Seeded apply-state Fleet package policy ${integrationPolicy.name} (${integrationPolicy.id}) with applied revision ${appliedPackageRevision} and current revision ${packageRevision}.`
    );

    return {
      id: integrationPolicy.id,
      name: integrationPolicy.name,
      indexed,
      agentId: EVAL_PM_APPLY_STATE_AGENT_ID,
      agentPolicyId,
      packageRevision,
      appliedPackageRevision,
    };
  } catch (error) {
    await deleteFleetAgent(internalEsClient, EVAL_PM_APPLY_STATE_AGENT_ID);
    for (const indexed of captured) {
      await deleteIndexedFleetEndpointPolicies(kbnClient, indexed);
    }
    await cleanupPolicyManagementSeededData({ esClient, internalEsClient });
    throw error;
  }
};

export const cleanupPolicyManagementApplyState = async ({
  kbnClient,
  esClient,
  internalEsClient,
  seeded,
}: {
  kbnClient: KbnClient;
  esClient: Client;
  internalEsClient: Client;
  seeded: SeededPolicyManagementApplyState;
}): Promise<void> => {
  await deleteFleetAgent(internalEsClient, seeded.agentId);
  await cleanupPolicyManagementPackagePolicy({ kbnClient, indexed: seeded.indexed });
  await cleanupPolicyManagementSeededData({ esClient, internalEsClient });
};
