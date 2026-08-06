/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SavedObjectsClientContract } from '@kbn/core-saved-objects-api-server';
import type { PackagePolicyInput } from '@kbn/fleet-plugin/common';
import type { PackagePolicyClient } from '@kbn/fleet-plugin/server';
import type {
  PolicyReadDenial,
  PolicyReadPrivilegeBasis,
  PolicySnapshot,
} from '../../domain/read/types';
import { createNotFoundDenial } from './policy_read_denial';
import { DefendPolicyInputNotFoundError, isPolicyNotFoundError } from './policy_read_errors';
import type { PolicyConfigDerivations } from './to_policy_snapshot';
import { isDefendPackagePolicy, toPolicySnapshot } from './to_policy_snapshot';

export type PolicyReadPackagePolicyService = Pick<PackagePolicyClient, 'get' | 'fetchAllItems'>;

export type PolicyReadOutcome<TValue> =
  | { readonly ok: true; readonly value: TValue }
  | { readonly ok: false; readonly denial: PolicyReadDenial };

export interface DefendPolicyRead {
  readonly snapshot: PolicySnapshot;
  readonly inputs: readonly PackagePolicyInput[];
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
}

export interface ReadDefendPolicyOptions {
  readonly packagePolicyService: PolicyReadPackagePolicyService;
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
  readonly derivations: PolicyConfigDerivations;
  readonly spaceId: string;
  readonly getSoClient: () => SavedObjectsClientContract;
  readonly policyId: string;
}

export const readDefendPolicy = async ({
  packagePolicyService,
  privilegeBasis,
  derivations,
  spaceId,
  getSoClient,
  policyId,
}: ReadDefendPolicyOptions): Promise<PolicyReadOutcome<DefendPolicyRead>> => {
  const policy = await packagePolicyService
    .get(getSoClient(), policyId, { spaceId })
    .catch((error: unknown) => {
      if (isPolicyNotFoundError(error)) {
        return null;
      }

      throw error;
    });

  if (policy === undefined || policy === null || !isDefendPackagePolicy(policy)) {
    return { ok: false, denial: createNotFoundDenial(policyId) };
  }

  try {
    return {
      ok: true,
      value: {
        snapshot: toPolicySnapshot(policy, derivations),
        inputs: policy.inputs,
        privilegeBasis,
      },
    };
  } catch (error) {
    if (error instanceof DefendPolicyInputNotFoundError) {
      return { ok: false, denial: createNotFoundDenial(policyId) };
    }

    throw error;
  }
};
