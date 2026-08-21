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
import { POLICY_MANAGEMENT_AGENT_ID_PREFIX } from './cleanup';
import {
  cleanupPolicyManagementApplyState,
  EVAL_PM_APPLY_STATE_AGENT_ID,
  EVAL_PM_APPLY_STATE_AGENT_POLICY_NAME,
  EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME,
  POLICY_MANAGEMENT_APPLY_STATE_READINESS_TIMEOUT,
  POLICY_MANAGEMENT_APPLY_STATE_REVISION_ERROR,
  POLICY_MANAGEMENT_APPLY_STATE_SEED_ERROR,
  seedPolicyManagementApplyState,
  waitForPolicyManagementTransformPropagation,
} from './policy_management_apply_state';

jest.mock(
  '@kbn/security-solution-plugin/common/endpoint/data_loaders/index_fleet_endpoint_policy',
  () => ({
    indexFleetEndpointPolicy: jest.fn(),
    deleteIndexedFleetEndpointPolicies: jest.fn(),
  })
);

const createLog = (): jest.Mocked<ToolingLog> =>
  ({
    error: jest.fn(),
    warning: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  } as unknown as jest.Mocked<ToolingLog>);

const APPLY_STATE_PACKAGE_POLICY_ID = 'apply-state-package-policy-id';
const APPLY_STATE_AGENT_POLICY_ID = 'apply-state-agent-policy-id';
const STALE_PREFIX_AGENT_ID = 'eval-agent-pm-stale-other';

const EXPECTED_READINESS = {
  agentId: EVAL_PM_APPLY_STATE_AGENT_ID,
  agentPolicyId: APPLY_STATE_AGENT_POLICY_ID,
  packagePolicyId: APPLY_STATE_PACKAGE_POLICY_ID,
  packageRevision: 2,
  appliedPackageRevision: 1,
};

const createIndexed = (): IndexedFleetEndpointPolicyResponse =>
  ({
    integrationPolicies: [
      { id: APPLY_STATE_PACKAGE_POLICY_ID, name: EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME },
    ],
    agentPolicies: [
      { id: APPLY_STATE_AGENT_POLICY_ID, name: EVAL_PM_APPLY_STATE_AGENT_POLICY_NAME, revision: 1 },
    ],
  } as IndexedFleetEndpointPolicyResponse);

const createItem = ({
  revision,
  policyIds = [APPLY_STATE_AGENT_POLICY_ID],
}: {
  revision: number;
  policyIds?: string[];
}) => ({
  id: APPLY_STATE_PACKAGE_POLICY_ID,
  name: EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME,
  revision,
  version: 'WzFd',
  created_by: 'elastic',
  created_at: '2026-01-01T00:00:00.000Z',
  updated_by: 'elastic',
  updated_at: '2026-01-01T00:00:00.000Z',
  policy_ids: policyIds,
  inputs: [{ type: 'endpoint', enabled: true, streams: [], config: { policy: { value: {} } } }],
});

const createUnitedSource = ({
  agentId = EVAL_PM_APPLY_STATE_AGENT_ID,
  agentPolicyId = APPLY_STATE_AGENT_POLICY_ID,
  packagePolicyId = APPLY_STATE_PACKAGE_POLICY_ID,
  appliedPackageRevision = 1,
  active = true,
}: {
  agentId?: string;
  agentPolicyId?: string;
  packagePolicyId?: string;
  appliedPackageRevision?: number;
  active?: boolean;
} = {}) => ({
  agent: { id: agentId },
  united: {
    endpoint: {
      agent: { id: agentId },
      Endpoint: {
        policy: {
          applied: {
            id: packagePolicyId,
            endpoint_policy_version: appliedPackageRevision,
            version: 1,
          },
        },
      },
    },
    agent: {
      agent: { id: agentId },
      active,
      policy_id: agentPolicyId,
      policy_revision_idx: 1,
    },
  },
});

const createSearchClient = ({
  currentSource = { agent: { id: EVAL_PM_APPLY_STATE_AGENT_ID } },
  unitedSource = createUnitedSource(),
}: {
  currentSource?: Record<string, unknown> | undefined;
  unitedSource?: Record<string, unknown> | undefined;
} = {}): Client =>
  ({
    search: jest.fn(async ({ index }: { index: string }) => {
      if (index === metadataCurrentIndexPattern) {
        return {
          hits: { hits: currentSource === undefined ? [] : [{ _source: currentSource }] },
        };
      }
      return {
        hits: { hits: unitedSource === undefined ? [] : [{ _source: unitedSource }] },
      };
    }),
    create: jest.fn().mockResolvedValue({}),
    deleteByQuery: jest.fn().mockResolvedValue({}),
  } as unknown as Client);

describe('policy management apply-state fixtures', () => {
  beforeEach(() => {
    jest.mocked(indexFleetEndpointPolicy).mockReset();
    jest.mocked(deleteIndexedFleetEndpointPolicies).mockReset();
    jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
      integrationPolicies: undefined,
      agentPolicies: undefined,
    });
  });

  it('uses apply-state names on the eval-agent-pm- prefix', () => {
    for (const name of [
      EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME,
      EVAL_PM_APPLY_STATE_AGENT_POLICY_NAME,
      EVAL_PM_APPLY_STATE_AGENT_ID,
    ]) {
      expect(name.startsWith('eval-agent-pm-')).toBe(true);
      expect(name.startsWith('eval-agent-ts-')).toBe(false);
      expect(name.startsWith('eval-agent-forensic-')).toBe(false);
    }
  });

  it('returns when the exact seeded agent exposes the expected assigned versus applied state', async () => {
    const esClient = createSearchClient();

    await waitForPolicyManagementTransformPropagation(esClient, createLog(), EXPECTED_READINESS);

    expect(esClient.search).toHaveBeenCalledTimes(2);
    expect(esClient.search).toHaveBeenCalledWith({
      index: metadataCurrentIndexPattern,
      query: {
        bool: {
          should: [
            { term: { 'agent.id': EVAL_PM_APPLY_STATE_AGENT_ID } },
            { term: { 'united.endpoint.agent.id': EVAL_PM_APPLY_STATE_AGENT_ID } },
            { term: { 'united.agent.agent.id': EVAL_PM_APPLY_STATE_AGENT_ID } },
          ],
          minimum_should_match: 1,
        },
      },
      size: 1,
      ignore_unavailable: true,
    });
    expect(esClient.search).toHaveBeenCalledWith({
      index: METADATA_UNITED_INDEX,
      query: {
        bool: {
          should: [
            { term: { 'agent.id': EVAL_PM_APPLY_STATE_AGENT_ID } },
            { term: { 'united.endpoint.agent.id': EVAL_PM_APPLY_STATE_AGENT_ID } },
            { term: { 'united.agent.agent.id': EVAL_PM_APPLY_STATE_AGENT_ID } },
          ],
          minimum_should_match: 1,
        },
      },
      size: 1,
      ignore_unavailable: true,
    });
    expect(
      (esClient.search as jest.Mock).mock.calls.some((call) => call[0].query?.prefix !== undefined)
    ).toBe(false);
  });

  it('does not treat a stale prefix-matching united document as ready and reports expected identity and last observed facts', async () => {
    const esClient = createSearchClient({
      unitedSource: createUnitedSource({ agentId: STALE_PREFIX_AGENT_ID }),
    });

    await expect(
      waitForPolicyManagementTransformPropagation(esClient, createLog(), EXPECTED_READINESS, {
        maxWaitMs: 20,
        pollIntervalMs: 0,
      })
    ).rejects.toThrow(
      new RegExp(
        `${POLICY_MANAGEMENT_APPLY_STATE_READINESS_TIMEOUT} after 20ms\\. ` +
          `Expected agentId=${EVAL_PM_APPLY_STATE_AGENT_ID} agentPolicyId=${APPLY_STATE_AGENT_POLICY_ID} packagePolicyId=${APPLY_STATE_PACKAGE_POLICY_ID} packageRevision=2 appliedPackageRevision=1; ` +
          `last observed metadataCurrentFound=true agentId=${STALE_PREFIX_AGENT_ID} endpointAgentId=${STALE_PREFIX_AGENT_ID} fleetAgentId=${STALE_PREFIX_AGENT_ID} active=true agentPolicyId=${APPLY_STATE_AGENT_POLICY_ID} packagePolicyId=${APPLY_STATE_PACKAGE_POLICY_ID} appliedPackageRevision=1`
      )
    );
    expect(STALE_PREFIX_AGENT_ID.startsWith(POLICY_MANAGEMENT_AGENT_ID_PREFIX)).toBe(true);
    expect(STALE_PREFIX_AGENT_ID).not.toBe(EVAL_PM_APPLY_STATE_AGENT_ID);
  });

  it('seeds a Fleet agent and endpoint metadata with an applied revision behind the live package policy', async () => {
    const indexed = createIndexed();
    jest.mocked(indexFleetEndpointPolicy).mockResolvedValue(indexed);

    let persistedRevision = 1;
    const request = jest.fn(
      async ({
        method,
        path,
        body,
      }: {
        method: string;
        path: string;
        body?: Record<string, unknown>;
      }) => {
        if (method === 'PUT') {
          expect(body).not.toHaveProperty('revision');
          persistedRevision = 2;
          return { data: { item: body } };
        }
        if (
          method === 'GET' &&
          path === packagePolicyRouteService.getInfoPath(APPLY_STATE_PACKAGE_POLICY_ID)
        ) {
          return { data: { item: createItem({ revision: persistedRevision }) } };
        }
        throw new Error(`unexpected ${method} ${path}`);
      }
    );

    const esClient = createSearchClient();
    const internalEsClient = {
      index: jest.fn().mockResolvedValue({}),
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;

    const seeded = await seedPolicyManagementApplyState({
      kbnClient: { request } as unknown as KbnClient,
      esClient,
      internalEsClient,
      log: createLog(),
    });

    expect(seeded.packageRevision).toBe(2);
    expect(seeded.appliedPackageRevision).toBe(1);
    expect(seeded.appliedPackageRevision).not.toBe(seeded.packageRevision);
    expect(seeded.agentId).toBe(EVAL_PM_APPLY_STATE_AGENT_ID);
    expect(seeded.agentPolicyId).toBe(APPLY_STATE_AGENT_POLICY_ID);

    expect(esClient.create).toHaveBeenCalledWith(
      expect.objectContaining({
        index: 'metrics-endpoint.metadata-default',
        document: expect.objectContaining({
          agent: expect.objectContaining({ id: EVAL_PM_APPLY_STATE_AGENT_ID }),
          Endpoint: {
            status: 'enrolled',
            policy: {
              applied: expect.objectContaining({
                id: APPLY_STATE_PACKAGE_POLICY_ID,
                endpoint_policy_version: 1,
              }),
            },
          },
        }),
      })
    );
    expect(internalEsClient.index).toHaveBeenCalledWith(
      expect.objectContaining({
        index: '.fleet-agents',
        id: EVAL_PM_APPLY_STATE_AGENT_ID,
        document: expect.objectContaining({
          policy_id: APPLY_STATE_AGENT_POLICY_ID,
          agent: expect.objectContaining({ id: EVAL_PM_APPLY_STATE_AGENT_ID }),
          updated_at: expect.any(String),
        }),
      })
    );
    const metadataTimestamp = (esClient.create as jest.Mock).mock.calls[0][0].document[
      '@timestamp'
    ];
    const fleetUpdatedAt = (internalEsClient.index as jest.Mock).mock.calls[0][0].document
      .updated_at;
    expect(fleetUpdatedAt).not.toBe('');
    expect(fleetUpdatedAt).toBe(metadataTimestamp);
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({
        path: packagePolicyRouteService.getUpdatePath(APPLY_STATE_PACKAGE_POLICY_ID),
        method: 'PUT',
        headers: { 'elastic-api-version': API_VERSIONS.public.v1 },
      })
    );
    expect(esClient.search).toHaveBeenCalledWith(
      expect.objectContaining({
        index: METADATA_UNITED_INDEX,
        query: expect.objectContaining({
          bool: expect.objectContaining({
            should: expect.arrayContaining([
              { term: { 'agent.id': EVAL_PM_APPLY_STATE_AGENT_ID } },
            ]),
          }),
        }),
      })
    );
    expect(deleteIndexedFleetEndpointPolicies).not.toHaveBeenCalled();
  });

  it('throws and cleans captured policies plus prefix-scoped docs when revision does not increase', async () => {
    const indexed = createIndexed();
    jest.mocked(indexFleetEndpointPolicy).mockResolvedValue(indexed);

    const request = jest.fn(async ({ method }: { method: string }) => {
      if (method === 'PUT') {
        return { data: { item: createItem({ revision: 1 }) } };
      }
      return { data: { item: createItem({ revision: 1 }) } };
    });
    const esClient = {
      create: jest.fn(),
      search: jest.fn(),
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;
    const internalEsClient = {
      index: jest.fn(),
      delete: jest.fn().mockResolvedValue({}),
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;
    const client = { request } as unknown as KbnClient;

    await expect(
      seedPolicyManagementApplyState({
        kbnClient: client,
        esClient,
        internalEsClient,
        log: createLog(),
      })
    ).rejects.toThrow(POLICY_MANAGEMENT_APPLY_STATE_REVISION_ERROR);

    expect(internalEsClient.delete).toHaveBeenCalledWith(
      { index: '.fleet-agents', id: EVAL_PM_APPLY_STATE_AGENT_ID, refresh: true },
      { ignore: [404] }
    );
    expect((internalEsClient.delete as jest.Mock).mock.invocationCallOrder[0]).toBeLessThan(
      (deleteIndexedFleetEndpointPolicies as jest.Mock).mock.invocationCallOrder[0]
    );
    expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(client, indexed);
    expect(esClient.deleteByQuery).toHaveBeenCalledWith(
      expect.objectContaining({
        query: { prefix: { 'agent.id': POLICY_MANAGEMENT_AGENT_ID_PREFIX } },
      })
    );
    expect(esClient.create).not.toHaveBeenCalled();
    expect(esClient.search).not.toHaveBeenCalled();
  });

  it('throws and cleans up when Fleet returns no integration policy', async () => {
    const indexed = {
      ...createIndexed(),
      integrationPolicies: [],
    };
    jest.mocked(indexFleetEndpointPolicy).mockResolvedValue(indexed);

    const esClient = { deleteByQuery: jest.fn().mockResolvedValue({}) } as unknown as Client;
    const internalEsClient = {
      delete: jest.fn().mockResolvedValue({}),
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;
    const kbnClient = { request: jest.fn() } as unknown as KbnClient;

    await expect(
      seedPolicyManagementApplyState({
        kbnClient,
        esClient,
        internalEsClient,
        log: createLog(),
      })
    ).rejects.toThrow(POLICY_MANAGEMENT_APPLY_STATE_SEED_ERROR);

    expect(internalEsClient.delete).toHaveBeenCalledWith(
      { index: '.fleet-agents', id: EVAL_PM_APPLY_STATE_AGENT_ID, refresh: true },
      { ignore: [404] }
    );
    expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(kbnClient, indexed);
  });

  it('cleans captured Fleet policies and prefix-scoped apply-state documents', async () => {
    const indexed = createIndexed();
    const esClient = { deleteByQuery: jest.fn().mockResolvedValue({}) } as unknown as Client;
    const internalEsClient = {
      delete: jest.fn().mockResolvedValue({}),
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;
    const kbnClient = {} as KbnClient;

    await cleanupPolicyManagementApplyState({
      kbnClient,
      esClient,
      internalEsClient,
      seeded: {
        id: APPLY_STATE_PACKAGE_POLICY_ID,
        name: EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME,
        indexed,
        agentId: EVAL_PM_APPLY_STATE_AGENT_ID,
        agentPolicyId: APPLY_STATE_AGENT_POLICY_ID,
        packageRevision: 2,
        appliedPackageRevision: 1,
      },
    });

    expect(internalEsClient.delete).toHaveBeenCalledWith(
      { index: '.fleet-agents', id: EVAL_PM_APPLY_STATE_AGENT_ID, refresh: true },
      { ignore: [404] }
    );
    expect((internalEsClient.delete as jest.Mock).mock.invocationCallOrder[0]).toBeLessThan(
      (deleteIndexedFleetEndpointPolicies as jest.Mock).mock.invocationCallOrder[0]
    );
    expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(kbnClient, indexed);
    const prefixes = [
      ...(esClient.deleteByQuery as jest.Mock).mock.calls,
      ...(internalEsClient.deleteByQuery as jest.Mock).mock.calls,
    ].map((call) => call[0].query.prefix['agent.id']);
    expect(new Set(prefixes)).toEqual(new Set([POLICY_MANAGEMENT_AGENT_ID_PREFIX]));
  });
});
