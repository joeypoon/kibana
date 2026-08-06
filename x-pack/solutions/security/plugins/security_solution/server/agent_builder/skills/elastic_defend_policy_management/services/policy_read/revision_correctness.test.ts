/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  SavedObjectsClientContract,
  SavedObjectsFindOptions,
  SavedObjectsFindResponse,
  SavedObjectsFindResult,
} from '@kbn/core-saved-objects-api-server';
import { loggingSystemMock, savedObjectsClientMock } from '@kbn/core/server/mocks';
import { fromKueryExpression } from '@kbn/es-query';
import type { KueryNode } from '@kbn/es-query';
import { LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE } from '@kbn/fleet-plugin/common';
import { createAppContextStartContractMock as fleetCreateAppContextStartContractMock } from '@kbn/fleet-plugin/server/mocks';
import {
  appContextService as fleetAppContextService,
  packagePolicyService as realPackagePolicyService,
} from '@kbn/fleet-plugin/server/services';
import { buildCurrentRevisionFilter } from '@kbn/fleet-plugin/server/services/package_policy';
import type { PackagePolicySOAttributes } from '@kbn/fleet-plugin/server/types';
import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { readDefendPolicyInventory } from './inventory_traversal';
import { traverseEstate } from './estate_accounting';
import type { PolicyReadMocks } from './mocks';
import { createPolicyReadMocks, grantedPrivilegeBasis } from './mocks';

const CURRENT_ID = 'pkg-1';
const PREVIOUS_REVISION_ID = 'pkg-1:prev';

const buildAttributes = (
  overrides: Partial<PackagePolicySOAttributes> = {}
): PackagePolicySOAttributes => ({
  name: 'Defend policy 1',
  enabled: true,
  revision: 2,
  created_at: '2026-01-01T00:00:00.000Z',
  created_by: 'creator',
  updated_at: '2026-02-02T00:00:00.000Z',
  updated_by: 'updater',
  policy_ids: ['agent-policy-1'],
  package: { name: 'endpoint', title: 'Elastic Defend', version: '9.2.0' },
  inputs: [
    {
      id: 'endpoint-input',
      type: 'endpoint',
      enabled: true,
      streams: [],
      config: {
        artifact_manifest: {
          value: { manifest_version: '1.0.0', schema_version: 'v1', artifacts: {} },
        },
        policy: { value: policyFactory() },
      },
    },
  ],
  ...overrides,
});

type PackagePolicyFindResult = SavedObjectsFindResult<PackagePolicySOAttributes>;

const fixture: PackagePolicyFindResult[] = [
  {
    id: CURRENT_ID,
    type: LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE,
    references: [],
    score: 1,
    sort: [1],
    version: 'WzEsMV0=',
    attributes: buildAttributes({ latest_revision: true }),
  },
  {
    id: PREVIOUS_REVISION_ID,
    type: LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE,
    references: [],
    score: 1,
    sort: [2],
    version: 'WzEsMF0=',
    attributes: buildAttributes({ revision: 1, latest_revision: false }),
  },
];

const matchesFilter = (node: KueryNode, document: PackagePolicyFindResult): boolean => {
  if (node.type !== 'function') {
    throw new Error(`Unsupported kuery node type [${node.type}]`);
  }

  const args = node.arguments as KueryNode[];

  if (node.function === 'and') {
    return args.every((argument) => matchesFilter(argument, document));
  }

  if (node.function === 'or') {
    return args.some((argument) => matchesFilter(argument, document));
  }

  if (node.function === 'not') {
    return !matchesFilter(args[0], document);
  }

  if (node.function === 'is') {
    const [field, expected] = args;
    const attributePath = String(field.value).replace(
      `${LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE}.attributes.`,
      ''
    );
    const actual = attributePath
      .split('.')
      .reduce<unknown>(
        (value, key) =>
          value && typeof value === 'object' ? (value as Record<string, unknown>)[key] : undefined,
        document.attributes
      );

    return actual !== undefined && String(actual) === String(expected.value);
  }

  throw new Error(`Unsupported kuery function [${node.function}]`);
};

const toFindResponse = (
  saved_objects: PackagePolicyFindResult[]
): SavedObjectsFindResponse<PackagePolicySOAttributes> => ({
  saved_objects,
  total: saved_objects.length,
  page: 1,
  per_page: 20,
  pit_id: 'some_pit_id',
});

describe('Defend policy read revision correctness', () => {
  let soClient: jest.Mocked<SavedObjectsClientContract>;
  let mocks: PolicyReadMocks;

  beforeEach(() => {
    soClient = savedObjectsClientMock.create();
    fleetAppContextService.start(
      fleetCreateAppContextStartContractMock({}, false, { internal: soClient })
    );

    mocks = createPolicyReadMocks();
    mocks.savedObjects.getScopedClient.mockReturnValue(soClient);
  });

  afterEach(() => {
    fleetAppContextService.stop();
  });

  describe('the inventory read', () => {
    it('returns exactly ONE record for a policy that has a previous revision', async () => {
      let page = 0;

      soClient.find.mockImplementation(async (options: SavedObjectsFindOptions) => {
        const filterNode = fromKueryExpression(String(options.filter));
        page += 1;

        return toFindResponse(
          page === 1 ? fixture.filter((document) => matchesFilter(filterNode, document)) : []
        );
      });

      const result = await readDefendPolicyInventory({
        packagePolicyService: realPackagePolicyService,
        privilegeBasis: grantedPrivilegeBasis(),
        getSoClient: () => soClient,
        spaceId: 'default',
        resolveRegistry: mocks.resolveRegistry,
        logger: mocks.logger,
      });

      expect(result.ok).toBe(true);
      expect(result.ok === true && result.value.items.map(({ identity }) => identity.id)).toEqual([
        CURRENT_ID,
      ]);
      expect(result.ok === true && result.value.scope.total).toBe(1);
    });

    it('hands Fleet the shared Defend kuery, so the exclusion is Fleet-shaped end to end', async () => {
      soClient.find.mockResolvedValue(toFindResponse([]));

      await readDefendPolicyInventory({
        packagePolicyService: realPackagePolicyService,
        privilegeBasis: grantedPrivilegeBasis(),
        getSoClient: () => soClient,
        spaceId: 'default',
        resolveRegistry: mocks.resolveRegistry,
        logger: mocks.logger,
      });

      expect(buildCurrentRevisionFilter(LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE)).toBe(
        `NOT ${LEGACY_PACKAGE_POLICY_SAVED_OBJECT_TYPE}.attributes.latest_revision:false`
      );
      const filter = String(soClient.find.mock.calls[0][0].filter);
      expect(filter).toContain('latest_revision');
      expect(filter).toContain('endpoint');
    });
  });

  describe('the estate traversal', () => {
    it('returns exactly ONE record from the estate traversal as well', async () => {
      let page = 0;

      soClient.find.mockImplementation(async (options: SavedObjectsFindOptions) => {
        const filterNode = fromKueryExpression(String(options.filter));
        page += 1;

        return toFindResponse(
          page === 1 ? fixture.filter((document) => matchesFilter(filterNode, document)) : []
        );
      });

      const seen: string[] = [];

      await traverseEstate<readonly string[]>({
        packagePolicyService: realPackagePolicyService,
        soClient,
        spaceId: 'default',
        logger: loggingSystemMock.createLogger(),
        visit: (policy) => {
          seen.push(policy.id);
        },
        finalize: () => [...seen],
      });

      expect(seen).toEqual([CURRENT_ID]);
    });
  });
});
