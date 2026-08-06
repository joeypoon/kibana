/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyFieldRecord, PolicyFieldRegistry } from '../field_registry/types';
import { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import { isExcludedFromComparison } from './exclusions';

export const POLICY_OPERATING_SYSTEMS: readonly PolicyOperatingSystem[] = [
  PolicyOperatingSystem.windows,
  PolicyOperatingSystem.mac,
  PolicyOperatingSystem.linux,
];

export interface PolicyFieldIndex {
  readonly byOs: ReadonlyMap<PolicyOperatingSystem, ReadonlyMap<string, PolicyFieldRecord>>;
  readonly root: ReadonlyMap<string, PolicyFieldRecord>;
}

export const buildPolicyFieldIndex = (registry: PolicyFieldRegistry): PolicyFieldIndex => {
  const byOs = new Map<PolicyOperatingSystem, Map<string, PolicyFieldRecord>>(
    POLICY_OPERATING_SYSTEMS.map((os) => [os, new Map<string, PolicyFieldRecord>()])
  );
  const root = new Map<string, PolicyFieldRecord>();

  for (const field of registry.fields) {
    if (!isExcludedFromComparison(field)) {
      if (field.os.length === 0) {
        root.set(field.keyPath, field);
      } else {
        for (const os of field.os) {
          byOs.get(os)?.set(field.keyPath, field);
        }
      }
    }
  }

  return { byOs, root };
};
