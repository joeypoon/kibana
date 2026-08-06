/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Client } from '@elastic/elasticsearch';
import type { ToolingLog } from '@kbn/tooling-log';
import { METADATA_UNITED_INDEX } from '@kbn/security-solution-plugin/common/endpoint/constants';
import { evaluate } from '../evaluate';
import {
  cleanupPolicyManagementApplyStateData,
  POLICY_MANAGEMENT_APPLY_STATE_AGENT_ID_PARENT_PREFIX,
} from './cleanup';
import type { DefendPolicyEstateHandle } from './defend_policy_estate_lifecycle';
import type { DefendPolicyFixture } from './defend_policy_fixture_estate';

export const APPLY_STATE_LAG_AGENT_ID_PREFIX = POLICY_MANAGEMENT_APPLY_STATE_AGENT_ID_PARENT_PREFIX;

const SHORT_RUN_PATTERN = /^[0-9a-z]{12}$/;

export const requireApplyStateLagShortRun = (shortRun: string): string => {
  if (!SHORT_RUN_PATTERN.test(shortRun)) {
    throw new Error(
      `apply-state-lag shortRun must be 12 [0-9a-z] characters, got ${JSON.stringify(shortRun)}`
    );
  }

  return shortRun;
};

export const buildApplyStateLagAgentIdPrefix = (shortRun: string): string =>
  `${APPLY_STATE_LAG_AGENT_ID_PREFIX}${requireApplyStateLagShortRun(shortRun)}-`;

export const buildApplyStateLagAgentId = (shortRun: string): string =>
  `${buildApplyStateLagAgentIdPrefix(shortRun)}lag-01`;

export const buildApplyStateLagHostName = (shortRun: string): string =>
  `eval-host-pm-${requireApplyStateLagShortRun(shortRun)}-lag-01`;

const METADATA_INDEX = 'metrics-endpoint.metadata-default';
const FLEET_AGENTS_INDEX = '.fleet-agents';
const UNITED_JOIN_POLL_INTERVAL_MS = 5_000;
const UNITED_JOIN_MAX_WAIT_MS = 180_000;
const APPLIED_ENDPOINT_POLICY_VERSION = 1;
const APPLIED_AGENT_POLICY_VERSION = 1;
const FLEET_POLICY_REVISION_IDX = 1;
const AGENT_VERSION = '9.5.0-SNAPSHOT';
const HOST_OS = {
  name: 'Windows',
  version: '10',
  type: 'windows',
  full: 'Windows 10',
} as const;

interface SeedClients {
  esClient: Client;
  internalEsClient: Client;
}

interface UnitedApplyStateHit {
  united?: {
    agent?: {
      active?: boolean;
      policy_id?: string;
      agent?: { id?: string };
    };
    endpoint?: {
      agent?: { id?: string };
      Endpoint?: {
        policy?: {
          applied?: {
            id?: string;
            endpoint_policy_version?: number | string;
          };
        };
      };
    };
  };
}

const unitedJoinQuery = (agentId: string) => ({
  bool: {
    filter: [
      { term: { 'agent.id': agentId } },
      { exists: { field: 'united.endpoint.agent.id' } },
      { exists: { field: 'united.agent.agent.id' } },
    ],
  },
});

const hasJoinedUnitedIds = (united: UnitedApplyStateHit['united'] | undefined): boolean =>
  Boolean(united?.endpoint?.agent?.id && united?.agent?.agent?.id);

const requireNearDuplicateLagTarget = (fixture: DefendPolicyFixture): string => {
  if (fixture.label !== 'nearDuplicate') {
    throw new Error(
      `apply-state-lag host must attach to nearDuplicate, not ${fixture.label}. ` +
        'unassigned and assignedZeroAgents must stay unused for the unused-policy example.'
    );
  }

  if (fixture.revision < 2) {
    throw new Error(
      `apply-state-lag requires nearDuplicate.revision >= 2 to prove revision_lag, ` +
        `but it is ${fixture.revision}.`
    );
  }

  const [agentPolicyId] = fixture.agentPolicyIds;
  if (!agentPolicyId) {
    throw new Error(
      'apply-state-lag requires nearDuplicate.agentPolicyIds[0] so the united query can join the host.'
    );
  }

  return agentPolicyId;
};

export const seedApplyStateLagHost = async (
  clients: SeedClients,
  fixture: DefendPolicyFixture,
  shortRun: string
): Promise<void> => {
  const agentPolicyId = requireNearDuplicateLagTarget(fixture);
  const agentId = buildApplyStateLagAgentId(shortRun);
  const hostName = buildApplyStateLagHostName(shortRun);
  const now = new Date().toISOString();

  await clients.esClient.create({
    index: METADATA_INDEX,
    id: `eval-metadata-${hostName}-${Date.now()}`,
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
      agent: { id: agentId, type: 'endpoint', version: AGENT_VERSION },
      host: { name: hostName, hostname: hostName, os: HOST_OS },
      Endpoint: {
        status: 'enrolled',
        policy: {
          applied: {
            status: 'success',
            name: fixture.name,
            id: fixture.packagePolicyId,
            endpoint_policy_version: APPLIED_ENDPOINT_POLICY_VERSION,
            version: APPLIED_AGENT_POLICY_VERSION,
          },
        },
      },
      elastic: { agent: { id: agentId } },
      labels: { manual_eval_host: hostName },
    },
  });

  await clients.internalEsClient.index({
    index: FLEET_AGENTS_INDEX,
    id: agentId,
    refresh: true,
    document: {
      '@timestamp': now,
      agent: { id: agentId, version: AGENT_VERSION },
      local_metadata: { host: { name: hostName } },
      active: true,
      enrolled_at: now,
      updated_at: now,
      last_checkin: now,
      status: 'online',
      last_known_status: 'online',
      last_checkin_status: 'online',
      policy_revision_idx: FLEET_POLICY_REVISION_IDX,
      policy_id: agentPolicyId,
    },
  });
};

export const assertUnitedApplyStateLagHit = async (
  esClient: Client,
  fixture: DefendPolicyFixture,
  shortRun: string
): Promise<void> => {
  const agentPolicyId = requireNearDuplicateLagTarget(fixture);
  const agentId = buildApplyStateLagAgentId(shortRun);

  const response = await esClient.search<UnitedApplyStateHit>({
    index: METADATA_UNITED_INDEX,
    size: 1,
    query: { term: { 'agent.id': agentId } },
    ignore_unavailable: true,
  });

  const united = response.hits.hits[0]?._source?.united;
  if (!united?.agent || !united.endpoint) {
    throw new Error(
      `apply-state-lag: united index has no joined hit for ${agentId}; ` +
        'refusing to converse against an empty population.'
    );
  }

  if (united.agent.active !== true) {
    throw new Error(`apply-state-lag: united.agent.active must be true for ${agentId}.`);
  }

  const observedPolicyId =
    typeof united.agent.policy_id === 'string' ? united.agent.policy_id.split('#')[0] : undefined;
  if (observedPolicyId !== agentPolicyId) {
    throw new Error(
      `apply-state-lag: united.agent.policy_id is ${united.agent.policy_id}, expected ${agentPolicyId}.`
    );
  }

  const applied = united.endpoint.Endpoint?.policy?.applied;
  if (applied?.id !== fixture.packagePolicyId) {
    throw new Error(
      `apply-state-lag: applied package-policy id is ${applied?.id}, expected ${fixture.packagePolicyId}.`
    );
  }

  const appliedEndpointRevision = Number(applied?.endpoint_policy_version);
  if (!Number.isFinite(appliedEndpointRevision) || appliedEndpointRevision >= fixture.revision) {
    throw new Error(
      `apply-state-lag: applied endpoint_policy_version ${applied?.endpoint_policy_version} ` +
        `must be < nearDuplicate.revision ${fixture.revision}.`
    );
  }

  if (!hasJoinedUnitedIds(united)) {
    throw new Error(`apply-state-lag: united hit for ${agentId} is missing endpoint or agent id.`);
  }
};

export const waitForUnitedApplyStateLagJoin = async (
  esClient: Client,
  log: ToolingLog,
  shortRun: string,
  maxWaitMs = UNITED_JOIN_MAX_WAIT_MS
): Promise<void> => {
  const agentId = buildApplyStateLagAgentId(shortRun);
  const start = Date.now();
  log.info(`Waiting for joined united hit for ${agentId} (endpoint + fleet agent ids)`);

  for (;;) {
    try {
      const response = await esClient.search<UnitedApplyStateHit>({
        index: METADATA_UNITED_INDEX,
        size: 1,
        query: unitedJoinQuery(agentId),
        ignore_unavailable: true,
      });
      if (hasJoinedUnitedIds(response.hits.hits[0]?._source?.united)) {
        log.info(`Joined united hit is present for ${agentId}`);
        return;
      }
    } catch (err) {
      log.debug(`Error checking united join: ${err}`);
    }

    const elapsed = Date.now() - start;
    if (elapsed >= maxWaitMs) {
      throw new Error(
        `Timed out waiting for joined united hit for ${agentId} after ${maxWaitMs}ms. ` +
          'endpoint-only united documents are not sufficient.'
      );
    }

    await new Promise((resolve) =>
      setTimeout(resolve, Math.min(UNITED_JOIN_POLL_INTERVAL_MS, maxWaitMs - elapsed))
    );
  }
};

export const setupApplyStateLagHost = async ({
  esClient,
  internalEsClient,
  log,
  fixture,
  shortRun,
  maxWaitMs = UNITED_JOIN_MAX_WAIT_MS,
}: SeedClients & {
  log: ToolingLog;
  fixture: DefendPolicyFixture;
  shortRun: string;
  maxWaitMs?: number;
}): Promise<void> => {
  const clients = { esClient, internalEsClient };
  const agentIdPrefix = buildApplyStateLagAgentIdPrefix(shortRun);

  try {
    await cleanupPolicyManagementApplyStateData(clients, agentIdPrefix);
    await seedApplyStateLagHost(clients, fixture, shortRun);
    await waitForUnitedApplyStateLagJoin(esClient, log, shortRun, maxWaitMs);
    await assertUnitedApplyStateLagHit(esClient, fixture, shortRun);
  } catch (error) {
    await cleanupPolicyManagementApplyStateData(clients, agentIdPrefix);
    throw error;
  }
};

type ApplyStateLagHostBeforeAll = (
  hook: (fixtures: { esClient: Client; internalEsClient: Client; log: ToolingLog }) => Promise<void>
) => void;

type ApplyStateLagHostAfterAll = (
  hook: (fixtures: { esClient: Client; internalEsClient: Client }) => Promise<void>
) => void;

export interface ApplyStateLagHostLifecycleHooks {
  readonly beforeAll: ApplyStateLagHostBeforeAll;
  readonly afterAll: ApplyStateLagHostAfterAll;
}

type DefendPolicyEstateGetter = (setupFailureMessage: string) => DefendPolicyEstateHandle;

let applyStateLagEstateGetter: DefendPolicyEstateGetter | undefined;

export const registerApplyStateLagHostCleanup = (
  hooks: Pick<ApplyStateLagHostLifecycleHooks, 'afterAll'> = evaluate
): void => {
  hooks.afterAll(async ({ esClient, internalEsClient }) => {
    const getEstate = applyStateLagEstateGetter;
    if (!getEstate) {
      return;
    }

    const { shortRun } = getEstate(
      'apply-state-lag: fixture estate was not built before host cleanup'
    );
    await cleanupPolicyManagementApplyStateData(
      { esClient, internalEsClient },
      buildApplyStateLagAgentIdPrefix(shortRun)
    );
  });
};

export const registerApplyStateLagHostSetup = (
  getEstate: DefendPolicyEstateGetter,
  hooks: Pick<ApplyStateLagHostLifecycleHooks, 'beforeAll'> = evaluate
): void => {
  applyStateLagEstateGetter = getEstate;

  hooks.beforeAll(async ({ esClient, internalEsClient, log }) => {
    const { nearDuplicate, shortRun } = getEstate(
      'apply-state-lag: fixture estate was not built before host seed'
    );
    await setupApplyStateLagHost({
      esClient,
      internalEsClient,
      log,
      fixture: nearDuplicate,
      shortRun,
    });
  });
};
