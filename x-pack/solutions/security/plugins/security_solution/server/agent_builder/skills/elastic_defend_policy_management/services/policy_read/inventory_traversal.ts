/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SavedObjectsClientContract } from '@kbn/core-saved-objects-api-server';
import type { Logger } from '@kbn/logging';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import type {
  EstateAccounting,
  PartialResultDisclosure,
  PolicyReadPrivilegeBasis,
  ScopeDisclosure,
} from '../../domain/read/types';
import { buildDefendKuery } from './defend_kuery';
import type {
  PolicyReadOutcome,
  PolicyReadPackagePolicyService,
} from './read_defend_policy_management';
import {
  buildScopeDisclosure,
  createRegistryCoverageDisclosure,
  createResultLimitDisclosure,
  createUpstreamFailureDisclosure,
} from './scope_disclosure';
import type { PolicyInventoryIdentity, PolicyRegistryResolve } from './to_policy_snapshot';
import {
  isDefendPackagePolicy,
  PolicyRegistryVersionUnknownError,
  toPolicyInventoryIdentity,
} from './to_policy_snapshot';
import { traverseEstate } from './estate_accounting';

export interface ReadDefendPolicyInventoryOptions {
  readonly packagePolicyService: PolicyReadPackagePolicyService;
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
  readonly getSoClient: () => SavedObjectsClientContract;
  readonly spaceId: string;
  readonly search?: string;
  readonly resolveRegistry: PolicyRegistryResolve;
  readonly logger: Logger;
  readonly maxPoliciesTraversed?: number;
}

export interface DefendPolicyInventory {
  readonly items: readonly PolicyInventoryIdentity[];
  readonly scope: ScopeDisclosure;
  readonly accounting: EstateAccounting;
}

interface InventoryFold {
  readonly items: readonly PolicyInventoryIdentity[];
  readonly registryGapVersions: readonly string[];
  readonly excluded: number;
  readonly spaceEnforced: boolean;
}

export const readDefendPolicyInventory = async ({
  packagePolicyService,
  privilegeBasis,
  getSoClient,
  spaceId,
  search,
  resolveRegistry,
  logger,
  maxPoliciesTraversed,
}: ReadDefendPolicyInventoryOptions): Promise<PolicyReadOutcome<DefendPolicyInventory>> => {
  const fold: MutableInventoryFold = {
    items: [],
    registryGapVersions: new Set<string>(),
    excluded: 0,
    spaceEnforced: false,
  };

  const { aggregate, accounting } = await traverseEstate<InventoryFold>({
    packagePolicyService,
    soClient: getSoClient(),
    spaceId,
    kuery: buildDefendKuery(search),
    logger,
    ...(maxPoliciesTraversed === undefined ? {} : { maxPoliciesTraversed }),
    visit: foldPolicyInto(fold, resolveRegistry, logger),
    finalize: () => ({
      items: [...fold.items],
      registryGapVersions: Array.from(fold.registryGapVersions),
      excluded: fold.excluded,
      spaceEnforced: fold.spaceEnforced,
    }),
  });

  return {
    ok: true,
    value: {
      items: aggregate.items,
      scope: buildScopeDisclosure({
        privilegeBasis,
        returned: aggregate.items.length,
        total: accounting.policiesTraversed,
        enforcedSpaceId: aggregate.spaceEnforced ? spaceId : undefined,
        partial: resolvePartialDisclosure(aggregate, accounting),
      }),
      accounting,
    },
  };
};

interface MutableInventoryFold {
  items: PolicyInventoryIdentity[];
  registryGapVersions: Set<string>;
  excluded: number;
  spaceEnforced: boolean;
}

const foldPolicyInto =
  (fold: MutableInventoryFold, resolveRegistry: PolicyRegistryResolve, logger: Logger) =>
  (policy: PackagePolicy): void => {
    if (!isDefendPackagePolicy(policy)) {
      return;
    }

    if ((policy.spaceIds?.length ?? 0) > 0) {
      fold.spaceEnforced = true;
    }

    try {
      fold.items.push(toPolicyInventoryIdentity(policy, resolveRegistry));
    } catch (error) {
      if (error instanceof PolicyRegistryVersionUnknownError) {
        fold.registryGapVersions.add(error.detail.requestedVersion);
      }

      fold.excluded += 1;
      logger.warn(
        `Skipping Elastic Defend package policy [${policy.id}]: ${error?.message ?? error}`
      );
    }
  };

const resolvePartialDisclosure = (
  { registryGapVersions, excluded, items }: InventoryFold,
  accounting: EstateAccounting
): PartialResultDisclosure | undefined => {
  if (registryGapVersions.length > 0) {
    return createRegistryCoverageDisclosure(registryGapVersions, excluded);
  }

  if (accounting.complete) {
    return undefined;
  }

  if (accounting.incompleteReason === 'result_limit_reached') {
    return createResultLimitDisclosure({
      returned: items.length,
      total: accounting.policiesTraversed,
    });
  }

  return createUpstreamFailureDisclosure('policy inventory traversal', items.length);
};
