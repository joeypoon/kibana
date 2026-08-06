/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { PACKAGE_POLICY_SAVED_OBJECT_TYPE } from '@kbn/fleet-plugin/common';
import { readDefendPolicyInventory } from './inventory_traversal';
import type { ReadDefendPolicyInventoryOptions } from './inventory_traversal';
import type { PolicyReadMocks } from './mocks';
import {
  createDefendPolicyMock,
  createPolicyReadMocks,
  createRegistryResolveMock,
  grantedPrivilegeBasis,
  mockFetchAllItems,
  PROHIBITED_PACKAGE_POLICY_METHODS,
} from './mocks';

describe('readDefendPolicyInventory', () => {
  let mocks: PolicyReadMocks;

  const read = (overrides: Partial<ReadDefendPolicyInventoryOptions> = {}) =>
    readDefendPolicyInventory({
      packagePolicyService: mocks.packagePolicyService,
      privilegeBasis: grantedPrivilegeBasis(),
      getSoClient: mocks.getSoClient,
      spaceId: mocks.spaceId,
      resolveRegistry: mocks.resolveRegistry,
      logger: mocks.logger,
      ...overrides,
    });

  beforeEach(() => {
    mocks = createPolicyReadMocks({ spaceId: 'finance' });
    mockFetchAllItems(mocks.packagePolicyService, [[createDefendPolicyMock()]]);
  });

  describe('authorization is assumed already granted', () => {
    it('reads through a client with the security extension excluded', async () => {
      await read();

      expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
        excludedExtensions: [SECURITY_EXTENSION_ID],
      });
    });
  });

  describe('the traversal itself', () => {
    it('traverses through Fleet `fetchAllItems` in the active space with the shared Defend kuery', async () => {
      await read({ search: 'Prod Windows Servers' });

      expect(mocks.packagePolicyService.fetchAllItems).toHaveBeenCalledWith(mocks.soClient, {
        spaceIds: ['finance'],
        kuery:
          `${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.package.name: "endpoint" AND ` +
          `${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name: *Prod* AND ` +
          `${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name: *Windows* AND ` +
          `${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name: *Servers*`,
      });
    });

    it('returns one snapshot per policy across all pages, with coverage accounting', async () => {
      mockFetchAllItems(mocks.packagePolicyService, [
        [createDefendPolicyMock({ id: 'a' }), createDefendPolicyMock({ id: 'b' })],
        [createDefendPolicyMock({ id: 'c' })],
      ]);

      const result = await read();

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.value.items.map(({ identity }) => identity.id)).toEqual(['a', 'b', 'c']);
        expect(result.value.scope.returned).toBe(3);
        expect(result.value.scope.total).toBe(3);
        expect(result.value.scope.partial).toBeUndefined();
        expect(result.value.accounting).toEqual({
          policiesTraversed: 3,
          pagesFetched: 2,
          complete: true,
        });
      }
    });

    it('carries the privilege basis, including a withheld Fleet agent read', async () => {
      const privilegeBasis = grantedPrivilegeBasis({
        fleetIntegrationPoliciesRead: false,
        fleetAgentsRead: false,
      });

      const result = await read({ privilegeBasis });

      expect(result.ok === true && result.value.scope.privilegeBasis).toEqual(privilegeBasis);
    });

    it('claims a space scope only when Fleet stamped `spaceIds` onto the result', async () => {
      mockFetchAllItems(mocks.packagePolicyService, [
        [createDefendPolicyMock({ spaceIds: ['finance'] })],
      ]);

      const result = await read();

      expect(result.ok === true && result.value.scope.spaceId).toBe('finance');
    });

    it('claims no space scope when Fleet reported no space dimension', async () => {
      const result = await read();

      expect(result.ok === true && result.value.scope).not.toHaveProperty('spaceId');
      expect(result.ok === true && result.value.scope.partial).toBeUndefined();
    });

    it('drops a non-Defend policy Fleet returned rather than mapping it as Defend', async () => {
      const nginxPolicy: PackagePolicy = {
        ...createDefendPolicyMock({ id: 'nginx-a' }),
        package: { name: 'nginx', title: 'Nginx', version: '2.1.0' },
      };
      mockFetchAllItems(mocks.packagePolicyService, [[createDefendPolicyMock(), nginxPolicy]]);

      const result = await read();

      expect(result.ok === true && result.value.items.map(({ identity }) => identity.id)).toEqual([
        'defend-1',
      ]);
    });

    it('never calls a prohibited Fleet method', async () => {
      await read();

      for (const method of PROHIBITED_PACKAGE_POLICY_METHODS) {
        expect(mocks.packagePolicyService[method]).not.toHaveBeenCalled();
      }
    });
  });

  describe('malformed policies and registry gaps', () => {
    it('skips a policy with no Defend input and logs it, rather than failing the inventory', async () => {
      const broken = { ...createDefendPolicyMock({ id: 'broken' }), inputs: [] };
      mockFetchAllItems(mocks.packagePolicyService, [[broken, createDefendPolicyMock()]]);

      const result = await read();

      expect(result.ok === true && result.value.items.map(({ identity }) => identity.id)).toEqual([
        'defend-1',
      ]);
      expect(mocks.logger.warn).toHaveBeenCalledWith(expect.stringContaining('broken'));
    });

    it('discloses a registry-coverage gap naming the unsupported package version', async () => {
      mockFetchAllItems(mocks.packagePolicyService, [
        [
          createDefendPolicyMock({
            id: 'uncovered',
            name: 'Production endpoints - EU',
            package: { name: 'endpoint', title: 'Elastic Defend', version: '8.4.0' },
          }),
          createDefendPolicyMock({
            id: 'covered',
            package: { name: 'endpoint', title: 'Elastic Defend', version: '9.2.0' },
          }),
        ],
      ]);

      const result = await read({
        resolveRegistry: createRegistryResolveMock({ knownVersions: ['9.2.0'] }),
      });

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.value.items.map(({ identity }) => identity.id)).toEqual(['covered']);
        expect(result.value.scope.partial?.reason).toBe('upstream_failure');
        expect(result.value.scope.partial?.detail).toContain('8.4.0');
        expect(result.value.scope.partial?.detail).toContain(
          '1 Elastic Defend policy was left out'
        );
        const serialized = JSON.stringify(result.value.scope.partial);
        expect(serialized).not.toContain('uncovered');
        expect(serialized).not.toContain('Production endpoints - EU');
      }
    });

    it('keeps nearestKnownVersion on the registry-unknown error so the skip log can disclose it', async () => {
      mockFetchAllItems(mocks.packagePolicyService, [
        [
          createDefendPolicyMock({
            id: 'uncovered',
            package: { name: 'endpoint', title: 'Elastic Defend', version: '8.4.0' },
          }),
        ],
      ]);

      const result = await read({
        resolveRegistry: createRegistryResolveMock({
          knownVersions: ['9.2.0'],
          nearestKnownVersion: '9.4.0',
        }),
      });

      expect(result.ok === true && result.value.items).toEqual([]);
      expect(mocks.logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('the nearest known version is [9.4.0]')
      );
    });
  });

  describe('identity-only mapping', () => {
    it('returns visit order across pages and omits config, normalized config, and hash', async () => {
      mockFetchAllItems(mocks.packagePolicyService, [
        [
          createDefendPolicyMock({ id: 'a', name: 'Zulu' }),
          createDefendPolicyMock({ id: 'b', name: 'Alpha' }),
        ],
        [createDefendPolicyMock({ id: 'c', name: 'Mike' })],
      ]);

      const result = await read();

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.value.items.map(({ identity, name }) => ({ id: identity.id, name }))).toEqual(
          [
            { id: 'a', name: 'Zulu' },
            { id: 'b', name: 'Alpha' },
            { id: 'c', name: 'Mike' },
          ]
        );

        for (const item of result.value.items) {
          expect(item).not.toHaveProperty('config');
          expect(item).not.toHaveProperty('configNormalized');
          expect(item).not.toHaveProperty('configHash');
        }
      }
    });

    it('does not snapshot, normalize, or hash a page of listed policies', async () => {
      mockFetchAllItems(mocks.packagePolicyService, [
        Array.from({ length: 20 }, (_, index) =>
          createDefendPolicyMock({
            id: `p-${index}`,
            name: `Policy ${index}`,
          })
        ),
      ]);

      const result = await read();

      expect(result.ok === true && result.value.items).toHaveLength(20);
      expect(mocks.derivations.normalize).not.toHaveBeenCalled();
      expect(mocks.derivations.hash).not.toHaveBeenCalled();

      if (result.ok) {
        for (const item of result.value.items) {
          expect(item).not.toHaveProperty('config');
          expect(item).not.toHaveProperty('configNormalized');
          expect(item).not.toHaveProperty('configHash');
        }
      }
    });
  });

  describe('an interrupted traversal is disclosed, never presented as complete', () => {
    it('reports result_limit_reached when the work bound is hit', async () => {
      mockFetchAllItems(mocks.packagePolicyService, [
        [createDefendPolicyMock({ id: 'a' }), createDefendPolicyMock({ id: 'b' })],
      ]);

      const result = await read({ maxPoliciesTraversed: 1 });

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.value.items.map(({ identity }) => identity.id)).toEqual(['a']);
        expect(result.value.accounting.complete).toBe(false);
        expect(result.value.accounting.incompleteReason).toBe('result_limit_reached');
        expect(result.value.scope.partial?.reason).toBe('result_limit_reached');
      }
    });

    it('reports an upstream failure when the iterator throws mid-stream', async () => {
      mocks.packagePolicyService.fetchAllItems.mockResolvedValue({
        async *[Symbol.asyncIterator]() {
          yield [createDefendPolicyMock({ id: 'a' })];
          throw new Error('point in time closed');
        },
      });

      const result = await read();

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.value.items.map(({ identity }) => identity.id)).toEqual(['a']);
        expect(result.value.accounting.complete).toBe(false);
        expect(result.value.scope.partial?.reason).toBe('upstream_failure');
        expect(result.value.scope.partial?.continuation.length).toBeGreaterThan(0);
      }
    });
  });
});
