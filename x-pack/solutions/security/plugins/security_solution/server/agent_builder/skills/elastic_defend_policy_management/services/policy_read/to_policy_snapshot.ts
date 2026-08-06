/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PackagePolicy, PackagePolicyInput } from '@kbn/fleet-plugin/common';
import { ENDPOINT_PACKAGE_NAME } from '../../../../../../common/detection_engine/constants';
import type {
  PolicyFieldRegistry,
  RegistryVersionUnknown,
} from '../../domain/field_registry/types';
import type { NormalizedPolicyConfig } from '../../domain/normalize/types';
import type {
  PolicyProvenance,
  PolicySnapshot,
  PolicySnapshotIdentity,
} from '../../domain/read/types';
import {
  DefendPolicyInputNotFoundError,
  PolicyRegistryVersionUnknownError,
} from './policy_read_errors';
export {
  DefendPolicyInputNotFoundError,
  PolicyRegistryVersionUnknownError,
} from './policy_read_errors';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';

const ENDPOINT_INPUT_TYPE = 'endpoint';

export type PolicyInventoryIdentity = Omit<
  PolicySnapshot,
  'config' | 'configNormalized' | 'configHash'
>;

export type PolicyRegistryResolve = (
  packageVersion: string
) => PolicyFieldRegistry | RegistryVersionUnknown;

export interface PolicyConfigDerivations {
  readonly normalize: (
    config: PolicyConfig,
    packageVersion: string
  ) => NormalizedPolicyConfig | RegistryVersionUnknown;
  readonly hash: (normalized: NormalizedPolicyConfig) => string;
}

interface RequiredDefendEndpointPolicy {
  readonly identity: PolicyInventoryIdentity;
  readonly config: PolicyConfig;
}

export const isDefendPackagePolicy = (policy: PackagePolicy): boolean =>
  policy.package?.name === ENDPOINT_PACKAGE_NAME;

const requireDefendEndpointConfig = (policy: PackagePolicy): RequiredDefendEndpointPolicy => {
  if (!isDefendPackagePolicy(policy)) {
    throw new DefendPolicyInputNotFoundError(
      `Package policy [${policy.id}] is not an Elastic Defend policy.`
    );
  }

  const endpointInput: PackagePolicyInput | undefined = policy.inputs.find(
    (input) => input.type === ENDPOINT_INPUT_TYPE
  );
  const config: PolicyConfig | undefined = endpointInput?.config?.policy?.value;

  if (!config) {
    throw new DefendPolicyInputNotFoundError(
      `Package policy [${policy.id}] has no Elastic Defend input configuration at inputs[type=endpoint].config.policy.value.`
    );
  }

  const {
    created_at: createdAt,
    created_by: createdBy,
    updated_at: updatedAt,
    updated_by: updatedBy,
  } = policy;

  const provenance: PolicyProvenance = { createdAt, createdBy, updatedAt, updatedBy };

  const snapshotIdentity: PolicySnapshotIdentity = {
    id: policy.id,
    revision: policy.revision,
    version: policy.version,
    updatedAt,
  };

  return {
    identity: {
      identity: snapshotIdentity,
      name: policy.name,
      description: policy.description,
      packageName: ENDPOINT_PACKAGE_NAME,
      packageVersion: policy.package?.version ?? '',
      spaceIds: policy.spaceIds,
      policyIds: policy.policy_ids,
      provenance,
    },
    config,
  };
};

const assertRegistryKnown = (packageVersion: string, resolve: PolicyRegistryResolve): void => {
  const resolved = resolve(packageVersion);

  if ('status' in resolved) {
    throw new PolicyRegistryVersionUnknownError(resolved);
  }
};

export const toPolicyInventoryIdentity = (
  policy: PackagePolicy,
  resolve: PolicyRegistryResolve
): PolicyInventoryIdentity => {
  const { identity } = requireDefendEndpointConfig(policy);

  assertRegistryKnown(identity.packageVersion, resolve);

  return identity;
};

export const toPolicySnapshot = (
  policy: PackagePolicy,
  { normalize, hash }: PolicyConfigDerivations
): PolicySnapshot => {
  const required = requireDefendEndpointConfig(policy);
  const config = structuredClone(required.config);
  const configNormalized = normalize(config, required.identity.packageVersion);

  if ('status' in configNormalized) {
    throw new PolicyRegistryVersionUnknownError(configNormalized);
  }

  return {
    ...required.identity,
    config,
    configNormalized,
    configHash: hash(configNormalized),
  };
};
