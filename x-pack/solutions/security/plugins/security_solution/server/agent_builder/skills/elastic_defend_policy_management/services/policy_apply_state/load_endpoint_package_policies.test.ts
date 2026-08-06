/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { savedObjectsClientMock } from '@kbn/core/server/mocks';
import { createPackagePolicyServiceMock } from '@kbn/fleet-plugin/server/mocks';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import type { PackagePolicyClient } from '@kbn/fleet-plugin/server';
import { buildDefendKuery } from '../policy_read';
import {
  DEFAULT_MAX_LOADED_PACKAGE_POLICIES,
  PACKAGE_POLICY_LIST_PAGE_SIZE,
  loadEndpointPackagePolicies,
} from './load_endpoint_package_policies';

const SPACE_ID = 'finance';

const policy = (id: string): PackagePolicy =>
  ({ id, revision: 1, policy_ids: [`agent-${id}`] } as PackagePolicy);

const iterableOf = (
  pages: ReadonlyArray<readonly PackagePolicy[]>
): AsyncIterable<PackagePolicy[]> => ({
  async *[Symbol.asyncIterator]() {
    for (const page of pages) {
      yield [...page];
    }
    yield [];
  },
});

const trackingIterable = (
  pages: ReadonlyArray<readonly PackagePolicy[]>,
  yielded: number[]
): AsyncIterable<PackagePolicy[]> => ({
  async *[Symbol.asyncIterator]() {
    for (const [index, page] of pages.entries()) {
      yielded.push(index + 1);
      yield [...page];
    }
    yield [];
  },
});

describe('loadEndpointPackagePolicies', () => {
  let packagePolicyService: jest.Mocked<PackagePolicyClient>;
  let soClient: ReturnType<typeof savedObjectsClientMock.create>;

  const load = (overrides: Partial<Parameters<typeof loadEndpointPackagePolicies>[2]> = {}) =>
    loadEndpointPackagePolicies(packagePolicyService, soClient, {
      spaceId: SPACE_ID,
      ...overrides,
    });

  const stubTotal = (total: number) => {
    packagePolicyService.list.mockResolvedValue({
      items: [],
      total,
      page: 1,
      perPage: 1,
    });
  };

  beforeEach(() => {
    packagePolicyService = createPackagePolicyServiceMock();
    soClient = savedObjectsClientMock.create();
    packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([]));
    stubTotal(0);
  });

  it('uses a distinctly named package-policy cap rather than the endpoint work bound', () => {
    expect(DEFAULT_MAX_LOADED_PACKAGE_POLICIES).toBe(20_000);
  });

  it('returns a complete empty load from the iterable plus one total query', async () => {
    const loaded = await load();

    expect(packagePolicyService.fetchAllItems).toHaveBeenCalledTimes(1);
    expect(packagePolicyService.fetchAllItems).toHaveBeenCalledWith(soClient, {
      kuery: buildDefendKuery(),
      spaceIds: [SPACE_ID],
      perPage: PACKAGE_POLICY_LIST_PAGE_SIZE,
    });
    expect(packagePolicyService.list).toHaveBeenCalledTimes(1);
    expect(packagePolicyService.list).toHaveBeenCalledWith(soClient, {
      kuery: buildDefendKuery(),
      perPage: 1,
      page: 1,
      spaceId: SPACE_ID,
    });
    expect(loaded).toEqual({
      items: [],
      loaded: 0,
      total: 0,
      omitted: 0,
      complete: true,
    });
  });

  it('returns a complete load when the iterable covers Fleet total', async () => {
    const items = [policy('a')];
    packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([items]));
    stubTotal(1);

    const loaded = await load();

    expect(packagePolicyService.fetchAllItems).toHaveBeenCalledTimes(1);
    expect(packagePolicyService.list).toHaveBeenCalledTimes(1);
    expect(loaded).toEqual({
      items,
      loaded: 1,
      total: 1,
      omitted: 0,
      complete: true,
    });
  });

  it('consumes further iterable pages until complete and does not walk list by offset', async () => {
    const all = [policy('a'), policy('b'), policy('c')];
    packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([[all[0], all[1]], [all[2]]]));
    stubTotal(all.length);

    const loaded = await load({ pageSize: 2 });

    expect(packagePolicyService.fetchAllItems).toHaveBeenCalledTimes(1);
    expect(packagePolicyService.fetchAllItems).toHaveBeenCalledWith(soClient, {
      kuery: buildDefendKuery(),
      spaceIds: [SPACE_ID],
      perPage: 2,
    });
    expect(packagePolicyService.list).toHaveBeenCalledTimes(1);
    expect(packagePolicyService.list.mock.calls.map(([, options]) => options?.page)).toEqual([1]);
    expect(loaded).toEqual({
      items: all,
      loaded: 3,
      total: 3,
      omitted: 0,
      complete: true,
    });
  });

  it('stops at the named cap by slicing the last iterable page and reports the exact omitted count', async () => {
    const all = [policy('a'), policy('b'), policy('c'), policy('d'), policy('e')];
    packagePolicyService.fetchAllItems.mockResolvedValue(
      iterableOf([[all[0], all[1]], [all[2], all[3]], [all[4]]])
    );
    stubTotal(all.length);

    const loaded = await load({ maxLoaded: 3, pageSize: 2 });

    expect(loaded).toEqual({
      items: [policy('a'), policy('b'), policy('c')],
      loaded: 3,
      total: 5,
      omitted: 2,
      complete: false,
    });
  });

  it('reports incomplete when the default cap is hit and Fleet list total is lower', async () => {
    const item = policy('p');
    const page = Array.from({ length: DEFAULT_MAX_LOADED_PACKAGE_POLICIES }, () => item);
    packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([page]));
    stubTotal(10_000);

    const loaded = await load();

    expect(loaded.loaded).toBe(DEFAULT_MAX_LOADED_PACKAGE_POLICIES);
    expect(loaded.items).toHaveLength(DEFAULT_MAX_LOADED_PACKAGE_POLICIES);
    expect(loaded.complete).toBe(false);
    expect(loaded.omitted).toBe(1);
    expect(loaded.total).toBe(DEFAULT_MAX_LOADED_PACKAGE_POLICIES + 1);
    expect(loaded.total).toBeGreaterThanOrEqual(loaded.loaded + loaded.omitted);
  });

  it('never reports complete when collection stops exactly at the cap even if Fleet total matches loaded', async () => {
    const items = [policy('a'), policy('b'), policy('c')];
    packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([items]));
    stubTotal(3);

    const loaded = await load({ maxLoaded: 3 });

    expect(loaded).toEqual({
      items,
      loaded: 3,
      total: 4,
      omitted: 1,
      complete: false,
    });
  });

  it('keeps an oversized final page bounded and reports omitted when Fleet total is below loaded', async () => {
    const page = [policy('a'), policy('b'), policy('c'), policy('d'), policy('e')];
    packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([page]));
    stubTotal(2);

    const loaded = await load({ maxLoaded: 3 });

    expect(loaded).toEqual({
      items: [policy('a'), policy('b'), policy('c')],
      loaded: 3,
      total: 4,
      omitted: 1,
      complete: false,
    });
  });

  it('does not pull trailing iterable pages after the cap is reached', async () => {
    const yielded: number[] = [];
    packagePolicyService.fetchAllItems.mockResolvedValue(
      trackingIterable(
        [[policy('a'), policy('b')], [policy('c'), policy('d')], [policy('e')]],
        yielded
      )
    );
    stubTotal(5);

    await load({ maxLoaded: 3, pageSize: 2 });

    expect(yielded).toEqual([1, 2]);
    expect(packagePolicyService.list).toHaveBeenCalledTimes(1);
    expect(packagePolicyService.list).toHaveBeenCalledWith(
      soClient,
      expect.objectContaining({ page: 1, perPage: 1, spaceId: SPACE_ID })
    );
  });

  it('keeps fetchAllItems page size constant and discards items beyond the cap', async () => {
    const all = [policy('a'), policy('b'), policy('c'), policy('d'), policy('e')];
    packagePolicyService.fetchAllItems.mockResolvedValue(
      iterableOf([[all[0], all[1]], [all[2], all[3]], [all[4]]])
    );
    stubTotal(all.length);

    const loaded = await load({ maxLoaded: 3, pageSize: 2 });

    expect(packagePolicyService.fetchAllItems).toHaveBeenCalledWith(
      soClient,
      expect.objectContaining({ perPage: 2 })
    );
    expect(loaded.items).toEqual([policy('a'), policy('b'), policy('c')]);
    expect(loaded.items).toHaveLength(3);
  });

  it('passes the active space to both Fleet calls', async () => {
    packagePolicyService.fetchAllItems.mockResolvedValue(iterableOf([[policy('a')]]));
    stubTotal(1);

    await load({ spaceId: 'team-a' });

    expect(packagePolicyService.fetchAllItems).toHaveBeenCalledWith(soClient, {
      kuery: buildDefendKuery(),
      spaceIds: ['team-a'],
      perPage: PACKAGE_POLICY_LIST_PAGE_SIZE,
    });
    expect(packagePolicyService.list).toHaveBeenCalledWith(soClient, {
      kuery: buildDefendKuery(),
      perPage: 1,
      page: 1,
      spaceId: 'team-a',
    });
  });
});
