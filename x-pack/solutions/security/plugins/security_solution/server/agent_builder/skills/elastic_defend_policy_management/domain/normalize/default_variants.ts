/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyConfig, PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import {
  policyFactory,
  policyFactoryWithoutPaidEnterpriseFeatures,
  policyFactoryWithoutPaidFeatures,
  policyFactoryWithSupportedFeatures,
} from '../../../../../../common/endpoint/models/policy_config';
import { POLICY_OPERATING_SYSTEMS } from './field_index';
import { collectPolicyLeafPaths } from './leaf_paths';

interface DefaultVariantDimension {
  readonly input: string;
  readonly variants: readonly PolicyConfig[];
}

const DEFAULT_VARIANT_DIMENSIONS: readonly DefaultVariantDimension[] = [
  {
    input: 'the license tier in effect when the policy was created',
    variants: [
      policyFactory(),
      policyFactoryWithSupportedFeatures(),
      policyFactoryWithoutPaidFeatures(),
      policyFactoryWithoutPaidEnterpriseFeatures(),
    ],
  },
  {
    input: 'whether the deployment was on Elastic Cloud when the policy was created',
    variants: [policyFactory({ cloud: false }), policyFactory({ cloud: true })],
  },
  {
    input: 'the cluster telemetry opt-in state when the policy was created',
    variants: [
      policyFactory({ isGlobalTelemetryEnabled: false }),
      policyFactory({ isGlobalTelemetryEnabled: true }),
    ],
  },
];

export interface UnrecoverableDefault {
  readonly input: string;
  readonly candidates: readonly unknown[];
}

export interface UnrecoverableDefaults {
  readonly byOs: ReadonlyMap<PolicyOperatingSystem, ReadonlyMap<string, UnrecoverableDefault>>;
  readonly root: ReadonlyMap<string, UnrecoverableDefault>;
}

const recordDisagreements = (
  paths: ReadonlyArray<ReadonlyMap<string, unknown>>,
  input: string,
  into: Map<string, UnrecoverableDefault>
): void => {
  const [first, ...rest] = paths;

  for (const [keyPath, value] of first) {
    if (!into.has(keyPath)) {
      const disagrees = rest.some((other) => !other.has(keyPath) || other.get(keyPath) !== value);
      if (disagrees) {
        const candidates = new Set<unknown>([value]);

        for (const other of rest) {
          if (other.has(keyPath)) {
            candidates.add(other.get(keyPath));
          }
        }

        into.set(keyPath, { input, candidates: [...candidates] });
      }
    }
  }
};

let cached: UnrecoverableDefaults | undefined;

export const getUnrecoverableDefaults = (): UnrecoverableDefaults => {
  if (cached !== undefined) {
    return cached;
  }

  const byOs = new Map<PolicyOperatingSystem, Map<string, UnrecoverableDefault>>(
    POLICY_OPERATING_SYSTEMS.map((os) => [os, new Map<string, UnrecoverableDefault>()])
  );
  const root = new Map<string, UnrecoverableDefault>();

  for (const { input, variants } of DEFAULT_VARIANT_DIMENSIONS) {
    for (const os of POLICY_OPERATING_SYSTEMS) {
      const branchOfOs = byOs.get(os);

      if (branchOfOs !== undefined) {
        recordDisagreements(
          variants.map((variant) => collectPolicyLeafPaths(variant[os])),
          input,
          branchOfOs
        );
      }
    }

    recordDisagreements(
      variants.map(({ global_manifest_version: pin, global_telemetry_enabled: telemetry }) =>
        collectPolicyLeafPaths({
          global_manifest_version: pin,
          global_telemetry_enabled: telemetry,
        })
      ),
      input,
      root
    );
  }

  cached = { byOs, root };

  return cached;
};
