/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  API_VERSIONS,
  agentRouteService,
  packagePolicyRouteService,
} from '@kbn/fleet-plugin/common';
import { AgentStatusKueryHelper } from '@kbn/fleet-plugin/common/services';
import type { KbnClient } from '@kbn/test';
import type { ToolingLog } from '@kbn/tooling-log';
import {
  deleteIndexedFleetEndpointPolicies,
  indexFleetEndpointPolicy,
} from '@kbn/security-solution-plugin/common/endpoint/data_loaders/index_fleet_endpoint_policy';
import type { IndexedFleetEndpointPolicyResponse } from '@kbn/security-solution-plugin/common/endpoint/data_loaders/index_fleet_endpoint_policy';
import { policyFactory } from '@kbn/security-solution-plugin/common/endpoint/models/policy_config';
import type { PolicyConfig } from '@kbn/security-solution-plugin/common/endpoint/types';
import {
  AntivirusRegistrationModes,
  PolicyOperatingSystem,
  ProtectionModes,
} from '@kbn/security-solution-plugin/common/endpoint/types';
import type { Client } from '@elastic/elasticsearch';
import {
  cleanupPolicyManagementComparePolicies,
  cleanupPolicyManagementDuplicatePolicies,
  cleanupPolicyManagementEstatePolicies,
  cleanupPolicyManagementLeftoverFleetPolicies,
  cleanupPolicyManagementPackagePolicy,
  EVAL_PM_AGENT_POLICY_NAME,
  EVAL_PM_FLEET_AGENT_POLICY_NAMES,
  EVAL_PM_FLEET_PACKAGE_POLICY_NAMES,
  EVAL_PM_COMPARE_DETECT_AGENT_POLICY_NAME,
  EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
  EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
  EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
  EVAL_PM_DUPLICATE_A_AGENT_POLICY_NAME,
  EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME,
  EVAL_PM_DUPLICATE_B_AGENT_POLICY_NAME,
  EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME,
  EVAL_PM_PACKAGE_POLICY_NAME,
  EVAL_PM_USED_AGENT_ID,
  POLICY_MANAGEMENT_COMPARE_POLICY_ITEM_ERROR,
  POLICY_MANAGEMENT_COMPARE_POLICY_PERSIST_ERROR,
  POLICY_MANAGEMENT_COMPARE_POLICY_SEED_ERROR,
  POLICY_MANAGEMENT_PACKAGE_POLICY_ASSIGNMENT_ERROR,
  POLICY_MANAGEMENT_PACKAGE_POLICY_ITEM_ERROR,
  POLICY_MANAGEMENT_PACKAGE_POLICY_MALWARE_ERROR,
  POLICY_MANAGEMENT_PACKAGE_POLICY_SEED_ERROR,
  POLICY_MANAGEMENT_PACKAGE_POLICY_STATUS_COUNT_ERROR,
  POLICY_MANAGEMENT_PACKAGE_POLICY_STATUS_RESULT_ERROR,
  seedPolicyManagementComparePolicies,
  seedPolicyManagementDuplicatePolicies,
  seedPolicyManagementEstatePolicies,
  seedPolicyManagementPackagePolicy,
  seedPolicyManagementUsageEvidence,
} from './policy_management_package_policy';

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

const kbnClient = {} as KbnClient;

const createIndexed = ({
  integrationPolicies,
  agentPolicyName,
}: {
  integrationPolicies: Array<{ id: string; name: string }>;
  agentPolicyName: string;
}): IndexedFleetEndpointPolicyResponse =>
  ({
    integrationPolicies,
    agentPolicies: [{ id: `${agentPolicyName}-id`, name: agentPolicyName }],
  } as IndexedFleetEndpointPolicyResponse);

const createMalwareOffPolicy = (): PolicyConfig => {
  const policy = policyFactory();
  for (const os of [
    PolicyOperatingSystem.windows,
    PolicyOperatingSystem.mac,
    PolicyOperatingSystem.linux,
  ]) {
    policy[os].malware.mode = ProtectionModes.off;
  }
  return policy;
};

const createPackagePolicyItem = ({
  id,
  name,
  policy,
  policyIds = ['agent-policy-id'],
}: {
  id: string;
  name: string;
  policy: PolicyConfig;
  policyIds?: string[];
}) => ({
  id,
  name,
  revision: 1,
  version: 'WzFd',
  created_by: 'elastic',
  created_at: '2026-01-01T00:00:00.000Z',
  updated_by: 'elastic',
  updated_at: '2026-01-01T00:00:00.000Z',
  enabled: true,
  policy_ids: policyIds,
  inputs: [
    {
      type: 'endpoint',
      enabled: true,
      streams: [],
      config: {
        artifact_manifest: { value: {} },
        policy: { value: policy },
      },
    },
  ],
});

const createInitialPolicy = (antivirusEnabled: boolean): PolicyConfig => {
  const policy = policyFactory();
  policy.windows.antivirus_registration.enabled = antivirusEnabled;
  return policy;
};

const getPolicyConfigFromBody = (body: {
  inputs: Array<{ config: { policy: { value: PolicyConfig } } }>;
}): PolicyConfig => {
  const [input] = body.inputs;
  if (input === undefined) {
    throw new Error('compare fixture test: PUT body missing endpoint input');
  }
  return input.config.policy.value;
};

const createCompareKbnClient = ({
  itemsById,
  persistEnabledByMode,
  persistDetectMalwareMode,
}: {
  itemsById: Map<string, ReturnType<typeof createPackagePolicyItem>>;
  persistEnabledByMode: boolean;
  persistDetectMalwareMode?: ProtectionModes;
}): { client: KbnClient; request: jest.Mock } => {
  const putBodiesById = new Map<
    string,
    {
      inputs: Array<{ config: { policy: { value: PolicyConfig } } }>;
    }
  >();
  const request = jest.fn(
    async ({
      method,
      path,
      body,
    }: {
      method: string;
      path: string;
      body?: {
        inputs: Array<{ config: { policy: { value: PolicyConfig } } }>;
      };
    }) => {
      const id = path.split('/').pop();
      if (id === undefined) {
        throw new Error('compare fixture test: request path missing id');
      }

      if (method === 'PUT') {
        if (body === undefined) {
          throw new Error('compare fixture test: PUT missing body');
        }
        putBodiesById.set(id, body);
        return { data: { item: body } };
      }

      if (method === 'GET' && putBodiesById.has(id)) {
        const putBody = putBodiesById.get(id);
        if (putBody === undefined) {
          throw new Error('compare fixture test: missing PUT body for persist GET');
        }
        const persistedPolicy = structuredClone(getPolicyConfigFromBody(putBody));
        if (persistEnabledByMode) {
          persistedPolicy.windows.antivirus_registration.enabled =
            persistedPolicy.windows.malware.mode === ProtectionModes.prevent;
        }
        if (id === 'detect-id' && persistDetectMalwareMode !== undefined) {
          persistedPolicy.windows.malware.mode = persistDetectMalwareMode;
          persistedPolicy.mac.malware.mode = persistDetectMalwareMode;
          persistedPolicy.linux.malware.mode = persistDetectMalwareMode;
        }
        const seededName =
          id === 'prevent-id'
            ? EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME
            : EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME;
        return {
          data: {
            item: createPackagePolicyItem({
              id,
              name: seededName,
              policy: persistedPolicy,
            }),
          },
        };
      }

      const initialItem = itemsById.get(id);
      if (initialItem === undefined) {
        throw new Error(`compare fixture test: missing GET item for ${id}`);
      }
      return { data: { item: structuredClone(initialItem) } };
    }
  );

  return { client: { request } as unknown as KbnClient, request };
};

const CAPTURED_PACKAGE_POLICY_ID = 'captured-package-policy-id';
const ASSIGNED_AGENT_POLICY_ID = 'agent-policy-id';

const createPaidSeedIndexed = (): IndexedFleetEndpointPolicyResponse =>
  createIndexed({
    integrationPolicies: [{ id: CAPTURED_PACKAGE_POLICY_ID, name: EVAL_PM_PACKAGE_POLICY_NAME }],
    agentPolicyName: EVAL_PM_AGENT_POLICY_NAME,
  });

const createPersistedPaidItem = ({
  policy = createMalwareOffPolicy(),
  policyIds = [ASSIGNED_AGENT_POLICY_ID],
}: {
  policy?: PolicyConfig;
  policyIds?: string[];
} = {}) =>
  createPackagePolicyItem({
    id: CAPTURED_PACKAGE_POLICY_ID,
    name: EVAL_PM_PACKAGE_POLICY_NAME,
    policy,
    policyIds,
  });

const createPaidSeedRequest = ({
  item,
  status,
}: {
  item?: unknown;
  status?: unknown;
} = {}): jest.Mock =>
  jest.fn(async ({ method, path }: { method: string; path: string }) => {
    if (
      method === 'GET' &&
      path === packagePolicyRouteService.getInfoPath(CAPTURED_PACKAGE_POLICY_ID)
    ) {
      if (item === undefined) {
        throw new Error('paid fixture test: package policy GET failed');
      }
      return { data: { item } };
    }
    if (method === 'GET' && path === agentRouteService.getStatusPath()) {
      if (status === undefined) {
        throw new Error('paid fixture test: agent status GET failed');
      }
      return { data: status };
    }
    throw new Error(`paid fixture test: unexpected ${method} ${path}`);
  });

const mockPaidSeedIndex = (indexed: IndexedFleetEndpointPolicyResponse): void => {
  jest.mocked(indexFleetEndpointPolicy).mockResolvedValue(indexed);
  jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
    integrationPolicies: undefined,
    agentPolicies: undefined,
  });
};

describe('policy management package policy fixtures', () => {
  beforeEach(() => {
    jest.mocked(indexFleetEndpointPolicy).mockReset();
    jest.mocked(deleteIndexedFleetEndpointPolicies).mockReset();
  });

  it('uses stable names disjoint from troubleshooting and forensic prefixes', () => {
    expect(EVAL_PM_PACKAGE_POLICY_NAME).toBe('eval-agent-pm-assess');
    expect(EVAL_PM_AGENT_POLICY_NAME).toBe('eval-agent-pm-assess-agent');

    for (const name of [EVAL_PM_PACKAGE_POLICY_NAME, EVAL_PM_AGENT_POLICY_NAME]) {
      expect(name.startsWith('eval-agent-ts-')).toBe(false);
      expect(name.startsWith('eval-agent-forensic-')).toBe(false);
      expect(name.startsWith('eval-agent-pm-')).toBe(true);
    }
  });

  it('seeds through indexFleetEndpointPolicy and returns captured Fleet ids', async () => {
    const indexed = createPaidSeedIndexed();
    mockPaidSeedIndex(indexed);
    const request = createPaidSeedRequest({
      item: createPersistedPaidItem(),
      status: { results: { all: 0 } },
    });
    const client = { request } as unknown as KbnClient;

    const log = createLog();
    const seeded = await seedPolicyManagementPackagePolicy({ kbnClient: client, log });

    expect(indexFleetEndpointPolicy).toHaveBeenCalledTimes(1);
    expect(indexFleetEndpointPolicy).toHaveBeenCalledWith(
      client,
      EVAL_PM_PACKAGE_POLICY_NAME,
      undefined,
      EVAL_PM_AGENT_POLICY_NAME,
      log
    );
    expect(jest.mocked(indexFleetEndpointPolicy).mock.calls[0]).toHaveLength(5);
    expect(seeded).toEqual({
      id: CAPTURED_PACKAGE_POLICY_ID,
      name: EVAL_PM_PACKAGE_POLICY_NAME,
      indexed,
    });
    expect(deleteIndexedFleetEndpointPolicies).not.toHaveBeenCalled();
    expect(request).toHaveBeenCalledTimes(2);
    expect(request).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        path: packagePolicyRouteService.getInfoPath(CAPTURED_PACKAGE_POLICY_ID),
        method: 'GET',
        headers: { 'elastic-api-version': API_VERSIONS.public.v1 },
      })
    );
    expect(request).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        path: agentRouteService.getStatusPath(),
        method: 'GET',
        headers: { 'elastic-api-version': API_VERSIONS.public.v1 },
        query: {
          policyId: ASSIGNED_AGENT_POLICY_ID,
          kuery: `not (${AgentStatusKueryHelper.buildKueryForUnenrolledAgents()})`,
        },
      })
    );
  });

  it('does not invent a policy when Fleet returns no captured integration policy', async () => {
    const indexed = createIndexed({
      integrationPolicies: [],
      agentPolicyName: EVAL_PM_AGENT_POLICY_NAME,
    });
    jest.mocked(indexFleetEndpointPolicy).mockResolvedValue(indexed);
    jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
      integrationPolicies: undefined,
      agentPolicies: undefined,
    });

    await expect(
      seedPolicyManagementPackagePolicy({ kbnClient, log: createLog() })
    ).rejects.toThrow(POLICY_MANAGEMENT_PACKAGE_POLICY_SEED_ERROR);

    expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(1);
    expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(kbnClient, indexed);
  });

  it('cleans only the captured indexed Fleet policies', async () => {
    const indexed = createIndexed({
      integrationPolicies: [
        { id: 'captured-package-policy-id', name: EVAL_PM_PACKAGE_POLICY_NAME },
      ],
      agentPolicyName: EVAL_PM_AGENT_POLICY_NAME,
    });
    jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
      integrationPolicies: undefined,
      agentPolicies: undefined,
    });

    await cleanupPolicyManagementPackagePolicy({ kbnClient, indexed });

    expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(1);
    expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(kbnClient, indexed);
  });

  describe('paid fixture persisted postconditions', () => {
    const expectCleanupAfterFailure = async ({
      error,
      item,
      status,
      request,
    }: {
      error: string;
      item?: unknown;
      status?: unknown;
      request?: jest.Mock;
    }): Promise<jest.Mock> => {
      const indexed = createPaidSeedIndexed();
      mockPaidSeedIndex(indexed);
      const requestFn =
        request ??
        createPaidSeedRequest({
          item,
          status,
        });
      const client = { request: requestFn } as unknown as KbnClient;

      await expect(
        seedPolicyManagementPackagePolicy({ kbnClient: client, log: createLog() })
      ).rejects.toThrow(error);

      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(1);
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(client, indexed);
      return requestFn;
    };

    it('throws and cleans up when persisted item is not PolicyData', async () => {
      await expectCleanupAfterFailure({
        error: POLICY_MANAGEMENT_PACKAGE_POLICY_ITEM_ERROR,
        item: { id: CAPTURED_PACKAGE_POLICY_ID },
      });
    });

    it('throws and cleans up when persisted malware is not off on every OS', async () => {
      await expectCleanupAfterFailure({
        error: POLICY_MANAGEMENT_PACKAGE_POLICY_MALWARE_ERROR,
        item: createPersistedPaidItem({ policy: policyFactory() }),
      });
    });

    it('throws and cleans up when persisted malware modes are mixed across OS', async () => {
      const policy = createMalwareOffPolicy();
      policy.mac.malware.mode = ProtectionModes.prevent;

      await expectCleanupAfterFailure({
        error: POLICY_MANAGEMENT_PACKAGE_POLICY_MALWARE_ERROR,
        item: createPersistedPaidItem({ policy }),
      });
    });

    it('throws and cleans up when persisted assignment ids are empty', async () => {
      await expectCleanupAfterFailure({
        error: POLICY_MANAGEMENT_PACKAGE_POLICY_ASSIGNMENT_ERROR,
        item: createPersistedPaidItem({ policyIds: [] }),
      });
    });

    it('throws and cleans up when persisted assignment ids are not unique', async () => {
      await expectCleanupAfterFailure({
        error: POLICY_MANAGEMENT_PACKAGE_POLICY_ASSIGNMENT_ERROR,
        item: createPersistedPaidItem({
          policyIds: [ASSIGNED_AGENT_POLICY_ID, 'second-agent-policy-id'],
        }),
      });
    });

    it('throws and cleans up when Fleet status results.all is greater than zero', async () => {
      const request = await expectCleanupAfterFailure({
        error: POLICY_MANAGEMENT_PACKAGE_POLICY_STATUS_COUNT_ERROR,
        item: createPersistedPaidItem(),
        status: { results: { all: 1 } },
      });

      expect(request).toHaveBeenCalledTimes(2);
    });

    it('throws and cleans up when Fleet status results.all is absent', async () => {
      await expectCleanupAfterFailure({
        error: POLICY_MANAGEMENT_PACKAGE_POLICY_STATUS_RESULT_ERROR,
        item: createPersistedPaidItem(),
        status: { results: {} },
      });
    });

    it('throws and cleans up when Fleet status results.all is not numeric', async () => {
      await expectCleanupAfterFailure({
        error: POLICY_MANAGEMENT_PACKAGE_POLICY_STATUS_RESULT_ERROR,
        item: createPersistedPaidItem(),
        status: { results: { all: '0' } },
      });
    });

    it('throws and cleans up when the persisted package-policy GET fails', async () => {
      await expectCleanupAfterFailure({
        error: 'paid fixture test: package policy GET failed',
      });
    });

    it('throws and cleans up when the Fleet agent-status GET fails', async () => {
      const request = await expectCleanupAfterFailure({
        error: 'paid fixture test: agent status GET failed',
        item: createPersistedPaidItem(),
      });

      expect(request).toHaveBeenCalledTimes(2);
    });
  });

  describe('live compare prevent/detect pair', () => {
    const preventIndexed = createIndexed({
      integrationPolicies: [
        { id: 'prevent-id', name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME },
      ],
      agentPolicyName: EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
    });
    const detectIndexed = createIndexed({
      integrationPolicies: [{ id: 'detect-id', name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME }],
      agentPolicyName: EVAL_PM_COMPARE_DETECT_AGENT_POLICY_NAME,
    });

    const mockIndexByName = () => {
      jest.mocked(indexFleetEndpointPolicy).mockImplementation(async (_client, policyName) => {
        if (policyName === EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME) {
          return preventIndexed;
        }
        if (policyName === EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME) {
          return detectIndexed;
        }
        throw new Error(`unexpected package policy name ${policyName}`);
      });
    };

    const createItemsById = () => {
      const preventPolicy = createInitialPolicy(false);
      const detectPolicy = createInitialPolicy(true);
      return new Map([
        [
          'prevent-id',
          createPackagePolicyItem({
            id: 'prevent-id',
            name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
            policy: preventPolicy,
          }),
        ],
        [
          'detect-id',
          createPackagePolicyItem({
            id: 'detect-id',
            name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
            policy: detectPolicy,
          }),
        ],
      ]);
    };

    it('uses disjoint compare names that stay on the eval-agent-pm- prefix', () => {
      const names = [
        EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
        EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
        EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
        EVAL_PM_COMPARE_DETECT_AGENT_POLICY_NAME,
      ];

      expect(new Set(names).size).toBe(4);
      expect(names).not.toContain(EVAL_PM_PACKAGE_POLICY_NAME);
      expect(names).not.toContain(EVAL_PM_AGENT_POLICY_NAME);

      for (const name of names) {
        expect(name.startsWith('eval-agent-ts-')).toBe(false);
        expect(name.startsWith('eval-agent-forensic-')).toBe(false);
        expect(name.startsWith('eval-agent-pm-compare-')).toBe(true);
      }
    });

    it('indexes both sides, writes helper-produced bodies, and verifies persisted PolicyConfig', async () => {
      mockIndexByName();
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const { client, request } = createCompareKbnClient({
        itemsById: createItemsById(),
        persistEnabledByMode: true,
      });
      const log = createLog();
      const seeded = await seedPolicyManagementComparePolicies({ kbnClient: client, log });

      expect(indexFleetEndpointPolicy).toHaveBeenCalledTimes(2);
      expect(indexFleetEndpointPolicy).toHaveBeenNthCalledWith(
        1,
        client,
        EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
        undefined,
        EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
        log
      );
      expect(indexFleetEndpointPolicy).toHaveBeenNthCalledWith(
        2,
        client,
        EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
        undefined,
        EVAL_PM_COMPARE_DETECT_AGENT_POLICY_NAME,
        log
      );
      expect(seeded.prevent).toEqual({
        id: 'prevent-id',
        name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
        indexed: preventIndexed,
      });
      expect(seeded.detect).toEqual({
        id: 'detect-id',
        name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
        indexed: detectIndexed,
      });
      expect(deleteIndexedFleetEndpointPolicies).not.toHaveBeenCalled();

      expect(request).toHaveBeenCalledTimes(6);
      expect(request).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({
          path: packagePolicyRouteService.getInfoPath('prevent-id'),
          method: 'GET',
          headers: { 'elastic-api-version': API_VERSIONS.public.v1 },
        })
      );
      expect(request).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          path: packagePolicyRouteService.getUpdatePath('prevent-id'),
          method: 'PUT',
          headers: { 'elastic-api-version': API_VERSIONS.public.v1 },
        })
      );
      expect(request).toHaveBeenNthCalledWith(
        3,
        expect.objectContaining({
          path: packagePolicyRouteService.getInfoPath('prevent-id'),
          method: 'GET',
          headers: { 'elastic-api-version': API_VERSIONS.public.v1 },
        })
      );
      expect(request).toHaveBeenNthCalledWith(
        4,
        expect.objectContaining({
          path: packagePolicyRouteService.getInfoPath('detect-id'),
          method: 'GET',
        })
      );
      expect(request).toHaveBeenNthCalledWith(
        5,
        expect.objectContaining({
          path: packagePolicyRouteService.getUpdatePath('detect-id'),
          method: 'PUT',
        })
      );
      expect(request).toHaveBeenNthCalledWith(
        6,
        expect.objectContaining({
          path: packagePolicyRouteService.getInfoPath('detect-id'),
          method: 'GET',
        })
      );

      const preventPut = request.mock.calls[1][0];
      const detectPut = request.mock.calls[4][0];
      expect(preventPut.body).not.toHaveProperty('id');
      expect(preventPut.body).not.toHaveProperty('revision');
      expect(preventPut.body).not.toHaveProperty('version');
      expect(preventPut.body).not.toHaveProperty('created_by');
      expect(preventPut.body).not.toHaveProperty('created_at');
      expect(preventPut.body).not.toHaveProperty('updated_by');
      expect(preventPut.body).not.toHaveProperty('updated_at');

      const preventConfig = getPolicyConfigFromBody(preventPut.body);
      const detectConfig = getPolicyConfigFromBody(detectPut.body);

      for (const os of [
        PolicyOperatingSystem.windows,
        PolicyOperatingSystem.mac,
        PolicyOperatingSystem.linux,
      ]) {
        expect(preventConfig[os].malware.mode).toBe(ProtectionModes.prevent);
        expect(preventConfig[os].popup.malware.enabled).toBe(true);
        expect(detectConfig[os].malware.mode).toBe(ProtectionModes.detect);
        expect(detectConfig[os].popup.malware.enabled).toBe(false);
      }

      expect(preventConfig.windows.antivirus_registration.mode).toBe(
        AntivirusRegistrationModes.sync
      );
      expect(detectConfig.windows.antivirus_registration.mode).toBe(
        AntivirusRegistrationModes.sync
      );
      expect(preventConfig.windows.antivirus_registration.enabled).toBe(false);
      expect(detectConfig.windows.antivirus_registration.enabled).toBe(true);
    });

    it('throws and deletes every captured resource when persisted derivation does not match', async () => {
      mockIndexByName();
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const { client } = createCompareKbnClient({
        itemsById: createItemsById(),
        persistEnabledByMode: false,
      });

      await expect(
        seedPolicyManagementComparePolicies({ kbnClient: client, log: createLog() })
      ).rejects.toThrow(POLICY_MANAGEMENT_COMPARE_POLICY_PERSIST_ERROR);

      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(1);
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(client, preventIndexed);
    });

    it('throws and deletes captured resources when GET item is not PolicyData', async () => {
      mockIndexByName();
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const request = jest.fn(async () => ({ data: { item: { id: 'prevent-id' } } }));
      const client = { request } as unknown as KbnClient;

      await expect(
        seedPolicyManagementComparePolicies({ kbnClient: client, log: createLog() })
      ).rejects.toThrow(POLICY_MANAGEMENT_COMPARE_POLICY_ITEM_ERROR);

      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(1);
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(client, preventIndexed);
    });

    it('deletes every captured resource when the second side fails after the first indexed', async () => {
      jest
        .mocked(indexFleetEndpointPolicy)
        .mockResolvedValueOnce(preventIndexed)
        .mockRejectedValueOnce(new Error('detect index failed'));
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const { client } = createCompareKbnClient({
        itemsById: createItemsById(),
        persistEnabledByMode: true,
      });

      await expect(
        seedPolicyManagementComparePolicies({ kbnClient: client, log: createLog() })
      ).rejects.toThrow('detect index failed');

      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(1);
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledWith(client, preventIndexed);
    });

    it('deletes both captured resources when the second persist verification fails', async () => {
      mockIndexByName();
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const { client } = createCompareKbnClient({
        itemsById: createItemsById(),
        persistEnabledByMode: true,
        persistDetectMalwareMode: ProtectionModes.off,
      });

      await expect(
        seedPolicyManagementComparePolicies({ kbnClient: client, log: createLog() })
      ).rejects.toThrow(POLICY_MANAGEMENT_COMPARE_POLICY_PERSIST_ERROR);

      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(2);
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenNthCalledWith(1, client, preventIndexed);
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenNthCalledWith(2, client, detectIndexed);
    });

    it('throws when Fleet returns no integration policy and still deletes the captured index', async () => {
      jest.mocked(indexFleetEndpointPolicy).mockResolvedValue(
        createIndexed({
          integrationPolicies: [],
          agentPolicyName: EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
        })
      );
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });
      const { client } = createCompareKbnClient({
        itemsById: createItemsById(),
        persistEnabledByMode: true,
      });

      await expect(
        seedPolicyManagementComparePolicies({ kbnClient: client, log: createLog() })
      ).rejects.toThrow(POLICY_MANAGEMENT_COMPARE_POLICY_SEED_ERROR);

      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(1);
    });

    it('cleans both successful compare resources', async () => {
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      await cleanupPolicyManagementComparePolicies({
        kbnClient,
        seeded: {
          prevent: {
            id: 'prevent-id',
            name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
            indexed: preventIndexed,
          },
          detect: {
            id: 'detect-id',
            name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
            indexed: detectIndexed,
          },
        },
      });

      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(2);
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenNthCalledWith(
        1,
        kbnClient,
        preventIndexed
      );
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenNthCalledWith(
        2,
        kbnClient,
        detectIndexed
      );
    });
  });

  describe('duplicate pair and enrolled-agent usage', () => {
    const firstIndexed = createIndexed({
      integrationPolicies: [{ id: 'dup-a-id', name: EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME }],
      agentPolicyName: EVAL_PM_DUPLICATE_A_AGENT_POLICY_NAME,
    });
    const secondIndexed = createIndexed({
      integrationPolicies: [{ id: 'dup-b-id', name: EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME }],
      agentPolicyName: EVAL_PM_DUPLICATE_B_AGENT_POLICY_NAME,
    });

    const createDuplicateItemsById = () => {
      const firstPolicy = createInitialPolicy(true);
      const secondPolicy = createInitialPolicy(true);
      return new Map([
        [
          'dup-a-id',
          createPackagePolicyItem({
            id: 'dup-a-id',
            name: EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME,
            policy: firstPolicy,
          }),
        ],
        [
          'dup-b-id',
          createPackagePolicyItem({
            id: 'dup-b-id',
            name: EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME,
            policy: secondPolicy,
          }),
        ],
      ]);
    };

    const mockDuplicateIndexByName = () => {
      jest.mocked(indexFleetEndpointPolicy).mockImplementation(async (_client, policyName) => {
        if (policyName === EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME) {
          return firstIndexed;
        }
        if (policyName === EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME) {
          return secondIndexed;
        }
        throw new Error(`unexpected package policy name ${policyName}`);
      });
    };

    it('uses disjoint duplicate names on the eval-agent-pm- prefix', () => {
      const names = [
        EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME,
        EVAL_PM_DUPLICATE_A_AGENT_POLICY_NAME,
        EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME,
        EVAL_PM_DUPLICATE_B_AGENT_POLICY_NAME,
        EVAL_PM_USED_AGENT_ID,
      ];

      expect(new Set(names).size).toBe(5);
      for (const name of names) {
        expect(name.startsWith('eval-agent-pm-')).toBe(true);
        expect(name.startsWith('eval-agent-ts-')).toBe(false);
        expect(name.startsWith('eval-agent-forensic-')).toBe(false);
      }
    });

    it('writes identical detect-mode configs on both duplicate sides', async () => {
      mockDuplicateIndexByName();
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const { client, request } = createCompareKbnClient({
        itemsById: createDuplicateItemsById(),
        persistEnabledByMode: true,
      });
      const seeded = await seedPolicyManagementDuplicatePolicies({
        kbnClient: client,
        log: createLog(),
      });

      expect(seeded.first.id).toBe('dup-a-id');
      expect(seeded.second.id).toBe('dup-b-id');
      expect(deleteIndexedFleetEndpointPolicies).not.toHaveBeenCalled();

      const firstPut = request.mock.calls.find((call) => call[0].method === 'PUT');
      const secondPut = [...request.mock.calls].reverse().find((call) => call[0].method === 'PUT');
      expect(firstPut).toBeDefined();
      expect(secondPut).toBeDefined();
      const firstConfig = getPolicyConfigFromBody(firstPut?.[0].body);
      const secondConfig = getPolicyConfigFromBody(secondPut?.[0].body);

      for (const os of [
        PolicyOperatingSystem.windows,
        PolicyOperatingSystem.mac,
        PolicyOperatingSystem.linux,
      ]) {
        expect(firstConfig[os].malware.mode).toBe(ProtectionModes.detect);
        expect(secondConfig[os].malware.mode).toBe(ProtectionModes.detect);
        expect(firstConfig[os].popup.malware.enabled).toBe(true);
        expect(secondConfig[os].popup.malware.enabled).toBe(true);
      }
    });

    it('indexes enrolled-agent usage evidence against the supplied agent policy', async () => {
      const internalEsClient = {
        index: jest.fn().mockResolvedValue({}),
      } as unknown as Client;

      const seeded = await seedPolicyManagementUsageEvidence({
        internalEsClient,
        agentPolicyId: 'prevent-agent-policy-id',
        log: createLog(),
      });

      expect(seeded).toEqual({
        agentId: EVAL_PM_USED_AGENT_ID,
        agentPolicyId: 'prevent-agent-policy-id',
      });
      expect(internalEsClient.index).toHaveBeenCalledWith(
        expect.objectContaining({
          index: '.fleet-agents',
          id: EVAL_PM_USED_AGENT_ID,
          document: expect.objectContaining({
            active: true,
            status: 'online',
            policy_id: 'prevent-agent-policy-id',
            agent: expect.objectContaining({ id: EVAL_PM_USED_AGENT_ID }),
          }),
        })
      );
    });

    it('seeds drift, duplicates, and enrolled-agent usage as one estate fixture', async () => {
      const preventIndexed = createIndexed({
        integrationPolicies: [
          { id: 'prevent-id', name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME },
        ],
        agentPolicyName: EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
      });
      const detectIndexed = createIndexed({
        integrationPolicies: [
          { id: 'detect-id', name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME },
        ],
        agentPolicyName: EVAL_PM_COMPARE_DETECT_AGENT_POLICY_NAME,
      });

      jest.mocked(indexFleetEndpointPolicy).mockImplementation(async (_client, policyName) => {
        if (policyName === EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME) {
          return preventIndexed;
        }
        if (policyName === EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME) {
          return detectIndexed;
        }
        if (policyName === EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME) {
          return firstIndexed;
        }
        if (policyName === EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME) {
          return secondIndexed;
        }
        throw new Error(`unexpected package policy name ${policyName}`);
      });
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const itemsById = new Map([
        [
          'prevent-id',
          createPackagePolicyItem({
            id: 'prevent-id',
            name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
            policy: createInitialPolicy(false),
          }),
        ],
        [
          'detect-id',
          createPackagePolicyItem({
            id: 'detect-id',
            name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
            policy: createInitialPolicy(true),
          }),
        ],
        ...createDuplicateItemsById(),
      ]);
      const { client } = createCompareKbnClient({
        itemsById,
        persistEnabledByMode: true,
      });
      const internalEsClient = {
        index: jest.fn().mockResolvedValue({}),
      } as unknown as Client;

      const seeded = await seedPolicyManagementEstatePolicies({
        kbnClient: client,
        internalEsClient,
        log: createLog(),
      });

      expect(seeded.compare.prevent.id).toBe('prevent-id');
      expect(seeded.compare.detect.id).toBe('detect-id');
      expect(seeded.duplicates.first.id).toBe('dup-a-id');
      expect(seeded.duplicates.second.id).toBe('dup-b-id');
      expect(seeded.usage.agentId).toBe(EVAL_PM_USED_AGENT_ID);
      expect(seeded.usage.agentPolicyId).toBe(`${EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME}-id`);
      expect(internalEsClient.index).toHaveBeenCalledTimes(1);
      expect(deleteIndexedFleetEndpointPolicies).not.toHaveBeenCalled();
    });

    it('releases the usage agent before captured policies when estate seeding fails', async () => {
      const preventIndexed = createIndexed({
        integrationPolicies: [
          { id: 'prevent-id', name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME },
        ],
        agentPolicyName: EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
      });
      const detectIndexed = createIndexed({
        integrationPolicies: [
          { id: 'detect-id', name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME },
        ],
        agentPolicyName: EVAL_PM_COMPARE_DETECT_AGENT_POLICY_NAME,
      });

      jest.mocked(indexFleetEndpointPolicy).mockImplementation(async (_client, policyName) => {
        if (policyName === EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME) {
          return preventIndexed;
        }
        if (policyName === EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME) {
          return detectIndexed;
        }
        if (policyName === EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME) {
          return firstIndexed;
        }
        if (policyName === EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME) {
          return secondIndexed;
        }
        throw new Error(`unexpected package policy name ${policyName}`);
      });
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const itemsById = new Map([
        [
          'prevent-id',
          createPackagePolicyItem({
            id: 'prevent-id',
            name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
            policy: createInitialPolicy(false),
          }),
        ],
        [
          'detect-id',
          createPackagePolicyItem({
            id: 'detect-id',
            name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
            policy: createInitialPolicy(true),
          }),
        ],
        ...createDuplicateItemsById(),
      ]);
      const { client } = createCompareKbnClient({
        itemsById,
        persistEnabledByMode: true,
      });
      const internalEsClient = {
        index: jest.fn().mockRejectedValue(new Error('usage index failed')),
        delete: jest.fn().mockResolvedValue({}),
      } as unknown as Client;

      await expect(
        seedPolicyManagementEstatePolicies({
          kbnClient: client,
          internalEsClient,
          log: createLog(),
        })
      ).rejects.toThrow('usage index failed');

      expect(internalEsClient.delete).toHaveBeenCalledWith(
        { index: '.fleet-agents', id: EVAL_PM_USED_AGENT_ID, refresh: true },
        { ignore: [404] }
      );
      expect((internalEsClient.delete as jest.Mock).mock.invocationCallOrder[0]).toBeLessThan(
        (deleteIndexedFleetEndpointPolicies as jest.Mock).mock.invocationCallOrder[0]
      );
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(4);
    });

    it('cleans estate Fleet resources', async () => {
      jest.mocked(deleteIndexedFleetEndpointPolicies).mockResolvedValue({
        integrationPolicies: undefined,
        agentPolicies: undefined,
      });

      const preventIndexed = createIndexed({
        integrationPolicies: [
          { id: 'prevent-id', name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME },
        ],
        agentPolicyName: EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
      });
      const detectIndexed = createIndexed({
        integrationPolicies: [
          { id: 'detect-id', name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME },
        ],
        agentPolicyName: EVAL_PM_COMPARE_DETECT_AGENT_POLICY_NAME,
      });

      const internalEsClient = {
        delete: jest.fn().mockResolvedValue({}),
      } as unknown as Client;

      await cleanupPolicyManagementEstatePolicies({
        kbnClient,
        internalEsClient,
        seeded: {
          compare: {
            prevent: {
              id: 'prevent-id',
              name: EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
              indexed: preventIndexed,
            },
            detect: {
              id: 'detect-id',
              name: EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
              indexed: detectIndexed,
            },
          },
          duplicates: {
            first: {
              id: 'dup-a-id',
              name: EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME,
              indexed: firstIndexed,
            },
            second: {
              id: 'dup-b-id',
              name: EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME,
              indexed: secondIndexed,
            },
          },
          usage: {
            agentId: EVAL_PM_USED_AGENT_ID,
            agentPolicyId: 'prevent-agent-policy-id',
          },
        },
      });

      expect(internalEsClient.delete).toHaveBeenCalledWith(
        { index: '.fleet-agents', id: EVAL_PM_USED_AGENT_ID, refresh: true },
        { ignore: [404] }
      );
      expect((internalEsClient.delete as jest.Mock).mock.invocationCallOrder[0]).toBeLessThan(
        (deleteIndexedFleetEndpointPolicies as jest.Mock).mock.invocationCallOrder[0]
      );
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(4);
      await cleanupPolicyManagementDuplicatePolicies({
        kbnClient,
        seeded: {
          first: {
            id: 'dup-a-id',
            name: EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME,
            indexed: firstIndexed,
          },
          second: {
            id: 'dup-b-id',
            name: EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME,
            indexed: secondIndexed,
          },
        },
      });
      expect(deleteIndexedFleetEndpointPolicies).toHaveBeenCalledTimes(6);
    });
  });

  describe('leftover Fleet policy pre-clean', () => {
    const createListingClient = ({
      packagePolicyIds = [],
      agentPolicyIds = [],
    }: {
      packagePolicyIds?: string[];
      agentPolicyIds?: string[];
    }) => {
      const request = jest.fn(
        async ({
          path,
          method,
          query,
        }: {
          path: string;
          method: string;
          query?: { kuery?: string };
        }) => {
          if (method === 'GET') {
            const isAgentPolicy = path.includes('agent_policies');
            if (isAgentPolicy && query?.kuery?.startsWith('fleet-agent-policies.')) {
              throw new Error(
                "KQLSyntaxError: This key 'fleet-agent-policies.name' does NOT exist"
              );
            }
            const ids = isAgentPolicy ? agentPolicyIds : packagePolicyIds;
            return { data: { items: ids.map((id) => ({ id })) } };
          }
          return { data: {} };
        }
      );
      return { request } as unknown as KbnClient & { request: jest.Mock };
    };

    it('covers every seeded Fleet name', () => {
      expect(EVAL_PM_FLEET_PACKAGE_POLICY_NAMES).toEqual([
        EVAL_PM_PACKAGE_POLICY_NAME,
        EVAL_PM_COMPARE_PREVENT_PACKAGE_POLICY_NAME,
        EVAL_PM_COMPARE_DETECT_PACKAGE_POLICY_NAME,
        EVAL_PM_DUPLICATE_A_PACKAGE_POLICY_NAME,
        EVAL_PM_DUPLICATE_B_PACKAGE_POLICY_NAME,
      ]);
      expect(EVAL_PM_FLEET_AGENT_POLICY_NAMES).toEqual([
        EVAL_PM_AGENT_POLICY_NAME,
        EVAL_PM_COMPARE_PREVENT_AGENT_POLICY_NAME,
        EVAL_PM_COMPARE_DETECT_AGENT_POLICY_NAME,
        EVAL_PM_DUPLICATE_A_AGENT_POLICY_NAME,
        EVAL_PM_DUPLICATE_B_AGENT_POLICY_NAME,
      ]);
    });

    it('deletes leftovers, package policies before agent policies', async () => {
      const client = createListingClient({
        packagePolicyIds: ['leftover-pkg'],
        agentPolicyIds: ['leftover-agent'],
      });

      await cleanupPolicyManagementLeftoverFleetPolicies({
        kbnClient: client,
        log: createLog(),
        packagePolicyNames: [EVAL_PM_PACKAGE_POLICY_NAME],
        agentPolicyNames: [EVAL_PM_AGENT_POLICY_NAME],
      });

      const deletes = client.request.mock.calls
        .map(([options]) => options)
        .filter((options) => options.method === 'POST');

      expect(deletes).toHaveLength(2);
      expect(deletes[0].body).toEqual({ packagePolicyIds: ['leftover-pkg'], force: true });
      expect(deletes[1].body).toEqual({ agentPolicyId: 'leftover-agent', force: true });
    });

    it('deletes nothing when no leftovers exist', async () => {
      const client = createListingClient({});

      await cleanupPolicyManagementLeftoverFleetPolicies({
        kbnClient: client,
        log: createLog(),
        packagePolicyNames: [EVAL_PM_PACKAGE_POLICY_NAME],
        agentPolicyNames: [EVAL_PM_AGENT_POLICY_NAME],
      });

      expect(
        client.request.mock.calls.filter(([options]) => options.method === 'POST')
      ).toHaveLength(0);
    });

    it('falls back to the other saved-object type when Fleet rejects the first', async () => {
      const client = createListingClient({ agentPolicyIds: ['leftover-agent'] });

      await cleanupPolicyManagementLeftoverFleetPolicies({
        kbnClient: client,
        log: createLog(),
        packagePolicyNames: [],
        agentPolicyNames: [EVAL_PM_AGENT_POLICY_NAME],
      });

      const kueries = client.request.mock.calls
        .map(([options]) => options.query?.kuery)
        .filter((kuery): kuery is string => typeof kuery === 'string');

      expect(kueries[0]).toContain('ingest-agent-policies.name');
      const deletes = client.request.mock.calls
        .map(([options]) => options)
        .filter((options) => options.method === 'POST');
      expect(deletes).toHaveLength(1);
      expect(deletes[0].body).toEqual({ agentPolicyId: 'leftover-agent', force: true });
    });

    it('warns and continues when a lookup or delete fails', async () => {
      const request = jest.fn(async ({ path }: { path: string }) => {
        if (path.includes('agent_policies')) {
          return { data: { items: [] } };
        }
        throw new Error('fleet unavailable');
      });
      const client = { request } as unknown as KbnClient;
      const log = createLog();

      await expect(
        cleanupPolicyManagementLeftoverFleetPolicies({
          kbnClient: client,
          log,
          packagePolicyNames: [EVAL_PM_PACKAGE_POLICY_NAME],
          agentPolicyNames: [EVAL_PM_AGENT_POLICY_NAME],
        })
      ).resolves.toBeUndefined();

      expect(log.warning).toHaveBeenCalledWith(
        expect.stringContaining(EVAL_PM_PACKAGE_POLICY_NAME)
      );
    });
  });
});
