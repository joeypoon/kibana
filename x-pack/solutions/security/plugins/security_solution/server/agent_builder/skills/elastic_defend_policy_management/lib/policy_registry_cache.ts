/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import semverCoerce from 'semver/functions/coerce';
import type { PolicyFieldRegistry, RegistryVersionUnknown } from '../domain/field_registry/types';
import { buildPolicyFieldRegistry } from '../domain/field_registry/generate_field_registry';
import type { PolicyFieldIndex } from '../domain/normalize/field_index';
import { buildPolicyFieldIndex } from '../domain/normalize/field_index';
import { normalizeWithIndex } from '../domain/normalize/normalize_policy_config';
import { hashPolicyConfig } from '../domain/compare/hash_policy_config';
import type { PolicyConfigDerivations } from '../services/policy_read';
import type { PolicyConfig } from '../../../../../common/endpoint/types';
import type { NormalizedPolicyConfig } from '../domain/normalize/types';

const registriesByRequestedVersion = new Map<string, PolicyFieldRegistry>();

let indicesByRegistry = new WeakMap<PolicyFieldRegistry, PolicyFieldIndex>();

export const resolvePolicyFieldRegistry = (
  packageVersion: string,
  { referenceVersion }: { referenceVersion?: string } = {}
): PolicyFieldRegistry | RegistryVersionUnknown => {
  const cached = registriesByRequestedVersion.get(packageVersion);

  if (cached !== undefined) {
    return cached;
  }

  if (semverCoerce(packageVersion.trim()) === null) {
    return {
      status: 'registry_version_unknown',
      requestedVersion: packageVersion,
      ...(referenceVersion === undefined ? {} : { nearestKnownVersion: referenceVersion }),
    };
  }

  const registry = buildPolicyFieldRegistry({ packageVersion });

  registriesByRequestedVersion.set(packageVersion, registry);

  return registry;
};

const getPolicyFieldIndex = (registry: PolicyFieldRegistry): PolicyFieldIndex => {
  const cached = indicesByRegistry.get(registry);

  if (cached !== undefined) {
    return cached;
  }

  const index = buildPolicyFieldIndex(registry);
  indicesByRegistry.set(registry, index);

  return index;
};

export const createPolicyConfigDerivations = ({
  referenceVersion,
}: { referenceVersion?: string } = {}): PolicyConfigDerivations => ({
  normalize: (
    config: PolicyConfig,
    packageVersion: string
  ): NormalizedPolicyConfig | RegistryVersionUnknown => {
    const registry = resolvePolicyFieldRegistry(packageVersion, { referenceVersion });

    if ('status' in registry) {
      return registry;
    }

    return normalizeWithIndex(config, getPolicyFieldIndex(registry));
  },
  hash: hashPolicyConfig,
});

export const resetPolicyRegistryCacheForTests = (): void => {
  registriesByRequestedVersion.clear();
  indicesByRegistry = new WeakMap();
};
