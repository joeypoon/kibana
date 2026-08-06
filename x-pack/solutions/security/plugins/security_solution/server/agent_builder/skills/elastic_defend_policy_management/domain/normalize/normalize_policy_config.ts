/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyConfig, PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import type { PolicyFieldRegistry } from '../field_registry/types';
import { buildPolicyFieldIndex, POLICY_OPERATING_SYSTEMS } from './field_index';
import type { PolicyFieldIndex } from './field_index';
import { isExcludedKeyPath } from './exclusions';
import { collectPolicyLeafPaths } from './leaf_paths';
import { classifyPopupMessage } from './popup_message';
import type { NormalizedPolicyConfig } from './types';

export const normalizePolicyConfig = (
  config: PolicyConfig,
  registry: PolicyFieldRegistry
): NormalizedPolicyConfig => normalizeWithIndex(config, buildPolicyFieldIndex(registry));

export const normalizeWithIndex = (
  config: PolicyConfig,
  index: PolicyFieldIndex
): NormalizedPolicyConfig => {
  const perOs = {} as Record<PolicyOperatingSystem, Record<string, unknown>>;
  const unrecognizedPerOs = {} as Record<PolicyOperatingSystem, Record<string, unknown>>;

  for (const os of POLICY_OPERATING_SYSTEMS) {
    const known = index.byOs.get(os);
    const branch: Record<string, unknown> = {};
    const unrecognized: Record<string, unknown> = {};

    for (const [keyPath, value] of collectPolicyLeafPaths(config[os])) {
      if (!isExcludedKeyPath(keyPath)) {
        const popupState = classifyPopupMessage(keyPath, value);
        const comparable = popupState === undefined ? value : popupState;

        if (known !== undefined && known.has(keyPath)) {
          branch[keyPath] = comparable;
        } else {
          const scopedToAnotherOs = POLICY_OPERATING_SYSTEMS.some(
            (other) => other !== os && index.byOs.get(other)?.has(keyPath) === true
          );

          if (!scopedToAnotherOs) {
            unrecognized[keyPath] = comparable;
          }
        }
      }
    }

    perOs[os] = branch;
    unrecognizedPerOs[os] = unrecognized;
  }

  return {
    globalManifestVersion: config.global_manifest_version,
    globalTelemetryEnabled: config.global_telemetry_enabled,
    perOs,
    unrecognizedPerOs,
  };
};
