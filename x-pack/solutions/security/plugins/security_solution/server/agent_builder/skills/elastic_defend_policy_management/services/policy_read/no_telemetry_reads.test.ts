/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

// This jest project maps `@kbn/core/server` to a two-symbol stub (see
// `server/__mocks__/module_name_map.js`) to avoid pulling core's memory leaks into every suite.
// Fleet's real `getByIDs` — which `packagePolicyService.get` delegates to — imports
// `isSavedObjectErrorResult` from that path, so the stub is widened here rather than globally.
// Sourced from `@kbn/core-saved-objects-api-server`, which is where core re-exports it from.
jest.mock('@kbn/core/server', () => {
  const { SavedObjectsUtils } = jest.requireActual('@kbn/core-saved-objects-utils-server');
  const { SavedObjectsErrorHelpers } = jest.requireActual('@kbn/core-saved-objects-server');
  const { isSavedObjectErrorResult } = jest.requireActual('@kbn/core-saved-objects-api-server');

  return { SavedObjectsUtils, SavedObjectsErrorHelpers, isSavedObjectErrorResult };
});

import type { SavedObjectsClientContract } from '@kbn/core-saved-objects-api-server';
import { savedObjectsClientMock } from '@kbn/core/server/mocks';
import {
  LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE,
  PACKAGE_POLICY_SAVED_OBJECT_TYPE,
  PACKAGES_SAVED_OBJECT_TYPE,
} from '@kbn/fleet-plugin/common';
import type { MockedFleetAppContext } from '@kbn/fleet-plugin/server/mocks';
import { createAppContextStartContractMock as fleetCreateAppContextStartContractMock } from '@kbn/fleet-plugin/server/mocks';
import {
  appContextService as fleetAppContextService,
  packagePolicyService as realPackagePolicyService,
} from '@kbn/fleet-plugin/server/services';
import { readDefendPolicy } from './read_defend_policy_management';
import { readDefendPolicyInventory } from './inventory_traversal';
import { traverseEstate } from './estate_accounting';
import type { PolicyReadMocks } from './mocks';
import { createDefendPolicyMock, createPolicyReadMocks, grantedPrivilegeBasis } from './mocks';

const ALLOWED_FLEET_SO_TYPES: readonly string[] = [
  PACKAGE_POLICY_SAVED_OBJECT_TYPE,
  LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE,
  PACKAGES_SAVED_OBJECT_TYPE,
];

const clearMockCalls = (client: object): void => {
  const visited = new Set<object>();

  const walk = (current: object): void => {
    if (visited.has(current)) {
      return;
    }

    visited.add(current);

    for (const value of Object.values(current)) {
      if (jest.isMockFunction(value)) {
        value.mockClear();
      } else if (value && typeof value === 'object') {
        walk(value);
      }
    }
  };

  walk(client);
};

describe('Defend policy read issues no telemetry, agent-log, or policy-response queries', () => {
  let soClient: jest.Mocked<SavedObjectsClientContract>;
  let fleetAppContext: MockedFleetAppContext;
  let mocks: PolicyReadMocks;

  beforeEach(() => {
    soClient = savedObjectsClientMock.create();
    soClient.find.mockResolvedValue({
      saved_objects: [],
      total: 0,
      page: 1,
      per_page: 20,
      pit_id: 'some_pit_id',
    });
    soClient.bulkGet.mockResolvedValue({ saved_objects: [] });
    soClient.get.mockResolvedValue({
      id: 'endpoint',
      type: PACKAGES_SAVED_OBJECT_TYPE,
      references: [],
      attributes: {},
    });

    fleetAppContext = fleetCreateAppContextStartContractMock({}, false, { internal: soClient });
    fleetAppContextService.start(fleetAppContext);
    clearMockCalls(fleetAppContext.elasticsearch.client.asInternalUser);

    mocks = createPolicyReadMocks();
    mocks.savedObjects.getScopedClient.mockReturnValue(soClient);
  });

  afterEach(() => {
    fleetAppContextService.stop();
  });

  const collectMockStringArguments = (clients: readonly object[]): string[] => {
    const indices: string[] = [];

    const walkArguments = (value: unknown): void => {
      if (typeof value === 'string') {
        indices.push(value);
        return;
      }

      if (Array.isArray(value)) {
        value.forEach(walkArguments);
        return;
      }

      if (value && typeof value === 'object') {
        Object.values(value).forEach(walkArguments);
      }
    };

    const visited = new Set<object>();

    const collectFromClient = (client: object): void => {
      if (visited.has(client)) {
        return;
      }

      visited.add(client);

      for (const property of Object.values(client)) {
        if (jest.isMockFunction(property)) {
          property.mock.calls.forEach(walkArguments);
        } else if (property && typeof property === 'object') {
          collectFromClient(property);
        }
      }
    };

    clients.forEach(collectFromClient);

    return indices;
  };

  const collectSavedObjectTypes = (client: jest.Mocked<SavedObjectsClientContract>): string[] => {
    const types: string[] = [];

    const pushType = (value: unknown): void => {
      if (typeof value === 'string') {
        types.push(value);
        return;
      }

      if (Array.isArray(value)) {
        value.forEach(pushType);
      }
    };

    for (const [options] of client.find.mock.calls) {
      pushType(options?.type);
    }

    for (const [type] of client.get.mock.calls) {
      pushType(type);
    }

    for (const [objects] of client.bulkGet.mock.calls) {
      for (const object of objects ?? []) {
        pushType(object?.type);
      }
    }

    if (jest.isMockFunction(client.openPointInTimeForType)) {
      for (const [type] of client.openPointInTimeForType.mock.calls) {
        pushType(type);
      }
    }

    if (jest.isMockFunction(client.createPointInTimeFinder)) {
      for (const [options] of client.createPointInTimeFinder.mock.calls) {
        pushType(options?.type);
      }
    }

    return types;
  };

  const expectConfiguredPolicyReadsAreFleetSoOnly = (): void => {
    const esClient = fleetAppContext.elasticsearch.client.asInternalUser;
    const searched = collectMockStringArguments([esClient]);
    const soTypes = collectSavedObjectTypes(soClient);

    expect(searched).toEqual([]);
    expect(soTypes.length).toBeGreaterThan(0);
    for (const type of soTypes) {
      expect(ALLOWED_FLEET_SO_TYPES).toContain(type);
    }
  };

  it('searches no ES index and only Fleet saved objects while reading one policy', async () => {
    soClient.bulkGet.mockResolvedValue({
      saved_objects: [
        {
          id: 'defend-1',
          type: LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE,
          references: [],
          attributes: createDefendPolicyMock(),
        },
      ],
    });

    const result = await readDefendPolicy({
      packagePolicyService: realPackagePolicyService,
      privilegeBasis: grantedPrivilegeBasis(),
      derivations: mocks.derivations,
      spaceId: mocks.spaceId,
      getSoClient: () => soClient,
      policyId: 'defend-1',
    });

    expect(result.ok).toBe(true);
    expect(soClient.bulkGet).toHaveBeenCalled();
    expectConfiguredPolicyReadsAreFleetSoOnly();
  });

  it('searches no ES index and only Fleet saved objects while traversing the estate', async () => {
    await traverseEstate<number>({
      packagePolicyService: realPackagePolicyService,
      soClient,
      spaceId: mocks.spaceId,
      kuery: `${LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE}.package.name: "endpoint"`,
      logger: mocks.logger,
      visit: () => undefined,
      finalize: () => 0,
    });

    expect(soClient.find).toHaveBeenCalled();
    expectConfiguredPolicyReadsAreFleetSoOnly();
  });

  it('searches no ES index and only Fleet saved objects while reading the inventory', async () => {
    const result = await readDefendPolicyInventory({
      packagePolicyService: realPackagePolicyService,
      privilegeBasis: grantedPrivilegeBasis(),
      getSoClient: () => soClient,
      spaceId: mocks.spaceId,
      search: 'prod',
      resolveRegistry: mocks.resolveRegistry,
      logger: mocks.logger,
    });

    expect(result.ok).toBe(true);
    expect(soClient.find).toHaveBeenCalled();
    expect(soClient.search).not.toHaveBeenCalled();
    expectConfiguredPolicyReadsAreFleetSoOnly();
  });

  it('observes ES searches issued through nested client namespaces and `transport.request`', async () => {
    const esClient = fleetAppContext.elasticsearch.client.asInternalUser;
    const esqlQuery = 'FROM observed-collector-index | LIMIT 1';

    await esClient.esql.query({ query: esqlQuery });

    const afterEsql = collectMockStringArguments([esClient]);

    expect(afterEsql).toContain(esqlQuery);
    expect(afterEsql.length).toBeGreaterThan(0);

    const transportPath = '/observed-collector-index/_search';

    await esClient.transport.request({ method: 'GET', path: transportPath });

    const afterTransport = collectMockStringArguments([esClient]);

    expect(afterTransport).toContain(transportPath);
  });

  it('names the Fleet saved-object types configured-policy reads may touch', () => {
    expect(ALLOWED_FLEET_SO_TYPES).toEqual([
      PACKAGE_POLICY_SAVED_OBJECT_TYPE,
      LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE,
      PACKAGES_SAVED_OBJECT_TYPE,
    ]);
  });
});
