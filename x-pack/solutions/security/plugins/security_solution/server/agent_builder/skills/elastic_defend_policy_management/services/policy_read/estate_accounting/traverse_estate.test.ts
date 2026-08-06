/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { loggingSystemMock, savedObjectsClientMock } from '@kbn/core/server/mocks';
import { SavedObjectsErrorHelpers } from '@kbn/core/server';
import type { MockedLogger } from '@kbn/logging-mocks';
import type { PackagePolicyClient } from '@kbn/fleet-plugin/server';
import { createPackagePolicyServiceMock } from '@kbn/fleet-plugin/server/mocks';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { traverseEstate } from './traverse_estate';

const policyPage = (ids: readonly string[]): PackagePolicy[] =>
  ids.map((id) => ({ id, policy_ids: [`ap-${id}`] } as PackagePolicy));

const iterableOf = (pages: ReadonlyArray<readonly string[]>): AsyncIterable<PackagePolicy[]> => ({
  async *[Symbol.asyncIterator]() {
    for (const page of pages) {
      yield policyPage(page);
    }
    yield [];
  },
});

const failingIterableAfter = (
  pages: ReadonlyArray<readonly string[]>,
  error: Error
): AsyncIterable<PackagePolicy[]> => ({
  async *[Symbol.asyncIterator]() {
    for (const page of pages) {
      yield policyPage(page);
    }
    throw error;
  },
});

describe('traverseEstate', () => {
  let packagePolicyService: jest.Mocked<PackagePolicyClient>;
  let soClient: ReturnType<typeof savedObjectsClientMock.create>;
  let logger: MockedLogger;
  let visited: string[];

  const traverse = (
    overrides: Partial<Parameters<typeof traverseEstate<readonly string[]>>[0]> = {}
  ) =>
    traverseEstate<readonly string[]>({
      packagePolicyService,
      soClient,
      spaceId: 'default',
      logger,
      visit: (policy) => {
        visited.push(policy.id);
      },
      finalize: () => [...visited],
      ...overrides,
    });

  beforeEach(() => {
    packagePolicyService = createPackagePolicyServiceMock();
    soClient = savedObjectsClientMock.create();
    logger = loggingSystemMock.createLogger();
    visited = [];
  });

  describe('complete traversal', () => {
    it('consumes multiple pages and reports accurate pagesFetched and policiesTraversed', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(
        iterableOf([['a', 'b', 'c'], ['d', 'e', 'f'], ['g']])
      );

      const { aggregate, accounting } = await traverse();

      expect(aggregate).toEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g']);
      expect(accounting).toEqual({
        policiesTraversed: 7,
        pagesFetched: 3,
        complete: true,
      });
    });

    it('does not count the iterator terminator page', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([['a']]));

      const { accounting } = await traverse();

      expect(accounting.pagesFetched).toBe(1);
      expect(accounting.policiesTraversed).toBe(1);
    });

    it('reports a complete traversal of zero policies for an empty estate', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([]));

      const { accounting } = await traverse();

      expect(accounting).toEqual({ policiesTraversed: 0, pagesFetched: 0, complete: true });
      expect(accounting.incompleteReason).toBeUndefined();
    });

    it('uses the PIT iterator, passing spaceId as an array and forwarding the kuery', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([['a']]));

      await traverse({ spaceId: 'team-a', kuery: 'package.name: "endpoint"' });

      expect(packagePolicyService.fetchAllItems).toHaveBeenCalledWith(soClient, {
        spaceIds: ['team-a'],
        kuery: 'package.name: "endpoint"',
      });
    });

    it('never reaches for a single-page fetch that would silently truncate', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([['a']]));

      await traverse();

      expect(packagePolicyService.list).not.toHaveBeenCalled();
      expect(packagePolicyService.getPackagePolicySavedObjects).not.toHaveBeenCalled();
      expect(soClient.find).not.toHaveBeenCalled();
    });

    it('touches no Fleet write, upgrade, or inspect method', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([['a']]));

      await traverse();

      for (const method of [
        'create',
        'bulkCreate',
        'update',
        'bulkUpdate',
        'delete',
        'upgrade',
        'bulkUpgrade',
        'rollback',
        'inspect',
      ] as const) {
        expect(packagePolicyService[method]).not.toHaveBeenCalled();
      }
    });
  });

  describe('interrupted traversal', () => {
    it('reports complete: false with upstream_failure when the iterator throws mid-stream', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(
        failingIterableAfter([['a', 'b'], ['c']], new Error('point in time closed'))
      );

      const { aggregate, accounting } = await traverse();

      expect(aggregate).toEqual(['a', 'b', 'c']);
      expect(accounting).toEqual({
        policiesTraversed: 3,
        pagesFetched: 2,
        complete: false,
        incompleteReason: 'upstream_failure',
      });
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('point in time closed'));
    });

    it('reports missing_privilege when the saved-objects client refuses the read', async () => {
      packagePolicyService.fetchAllItems.mockRejectedValue(
        SavedObjectsErrorHelpers.decorateForbiddenError(new Error('forbidden'))
      );

      const { accounting } = await traverse();

      expect(accounting).toEqual({
        policiesTraversed: 0,
        pagesFetched: 0,
        complete: false,
        incompleteReason: 'missing_privilege',
      });
    });

    it('reports missing_privilege for a not-authorized error too', async () => {
      packagePolicyService.fetchAllItems.mockRejectedValue(
        SavedObjectsErrorHelpers.decorateNotAuthorizedError(new Error('nope'))
      );

      const { accounting } = await traverse();

      expect(accounting.incompleteReason).toBe('missing_privilege');
    });

    it('reports result_limit_reached and stops visiting once the traversal bound is hit', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(
        iterableOf([
          ['a', 'b', 'c'],
          ['d', 'e', 'f'],
        ])
      );

      const { aggregate, accounting } = await traverse({ maxPoliciesTraversed: 4 });

      expect(aggregate).toEqual(['a', 'b', 'c', 'd']);
      expect(accounting).toEqual({
        policiesTraversed: 4,
        pagesFetched: 2,
        complete: false,
        incompleteReason: 'result_limit_reached',
      });
    });

    it('stops immediately rather than draining remaining pages after the bound is hit', async () => {
      let pagesYielded = 0;
      packagePolicyService.fetchAllItems.mockResolvedValue({
        async *[Symbol.asyncIterator]() {
          for (const page of [['a'], ['b'], ['c']]) {
            pagesYielded += 1;
            yield policyPage(page);
          }
          yield [];
        },
      });

      const { accounting } = await traverse({ maxPoliciesTraversed: 1 });

      expect(accounting.complete).toBe(false);
      expect(pagesYielded).toBe(2);
      expect(accounting.policiesTraversed).toBe(1);
    });

    it('marks the traversal incomplete when the visitor itself throws', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([['a', 'b']]));

      const { accounting } = await traverse({
        visit: (policy) => {
          if (policy.id === 'b') {
            throw new Error('aggregation failed');
          }
          visited.push(policy.id);
        },
      });

      expect(accounting.complete).toBe(false);
      expect(accounting.incompleteReason).toBe('upstream_failure');
      expect(accounting.policiesTraversed).toBe(1);
    });
  });

  describe('forbidden data sources', () => {
    it('queries no endpoint telemetry, metrics, or policy-response index', async () => {
      packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([['a']]));

      await traverse({ kuery: 'package.name: "endpoint"' });

      const everyArgument = JSON.stringify([
        ...packagePolicyService.fetchAllItems.mock.calls.map(([, options]) => options),
        ...soClient.find.mock.calls,
      ]);

      for (const forbidden of [
        'metrics-endpoint',
        'metrics-endpoint.metadata_united',
        'metrics-endpoint.policy',
        'logs-elastic_agent.endpoint_security',
        '.ds-metrics-endpoint',
      ]) {
        expect(everyArgument).not.toContain(forbidden);
      }
    });
  });
});
