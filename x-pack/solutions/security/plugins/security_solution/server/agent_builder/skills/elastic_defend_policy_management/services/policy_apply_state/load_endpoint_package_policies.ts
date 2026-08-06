/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SavedObjectsClientContract } from '@kbn/core-saved-objects-api-server';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import type { PackagePolicyClient } from '@kbn/fleet-plugin/server';
import { buildDefendKuery } from '../policy_read';

export const DEFAULT_MAX_LOADED_PACKAGE_POLICIES = 20_000;

export const PACKAGE_POLICY_LIST_PAGE_SIZE = 1_000;

export interface LoadedEndpointPackagePolicies {
  readonly items: PackagePolicy[];
  readonly loaded: number;
  readonly total: number;
  readonly omitted: number;
  readonly complete: boolean;
}

export interface LoadEndpointPackagePoliciesOptions {
  readonly spaceId: string;
  readonly maxLoaded?: number;
  readonly pageSize?: number;
}

export const loadEndpointPackagePolicies = async (
  packagePolicyService: Pick<PackagePolicyClient, 'fetchAllItems' | 'list'>,
  soClient: SavedObjectsClientContract,
  {
    spaceId,
    maxLoaded = DEFAULT_MAX_LOADED_PACKAGE_POLICIES,
    pageSize = PACKAGE_POLICY_LIST_PAGE_SIZE,
  }: LoadEndpointPackagePoliciesOptions
): Promise<LoadedEndpointPackagePolicies> => {
  const kuery = buildDefendKuery();
  const items: PackagePolicy[] = [];

  const iterator = await packagePolicyService.fetchAllItems(soClient, {
    kuery,
    spaceIds: [spaceId],
    perPage: pageSize,
  });

  let hitCap = false;

  for await (const page of iterator) {
    if (page.length > 0) {
      items.push(...page.slice(0, maxLoaded - items.length));

      if (items.length >= maxLoaded) {
        hitCap = true;
        break;
      }
    }
  }

  const { total: listTotal } = await packagePolicyService.list(soClient, {
    kuery,
    perPage: 1,
    page: 1,
    spaceId,
  });

  const loaded = items.length;

  if (hitCap) {
    const total = Math.max(listTotal, loaded + 1);
    const omitted = Math.max(1, total - loaded);

    return {
      items,
      loaded,
      total,
      omitted,
      complete: false,
    };
  }

  const omitted = Math.max(0, listTotal - loaded);

  return {
    items,
    loaded,
    total: listTotal,
    omitted,
    complete: omitted === 0,
  };
};
