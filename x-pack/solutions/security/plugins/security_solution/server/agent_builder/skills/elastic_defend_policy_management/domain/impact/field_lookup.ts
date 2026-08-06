/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import type { PolicyFieldRecord, PolicyFieldRegistry } from '../field_registry/types';
import { isExcludedFromComparison } from '../normalize/exclusions';

export interface ImpactFieldLookup {
  readonly osScoped: ReadonlyMap<string, ReadonlyMap<PolicyOperatingSystem, PolicyFieldRecord>>;
  readonly root: ReadonlyMap<string, PolicyFieldRecord>;
}

export const buildImpactFieldLookup = (registry: PolicyFieldRegistry): ImpactFieldLookup => {
  const osScoped = new Map<string, Map<PolicyOperatingSystem, PolicyFieldRecord>>();
  const root = new Map<string, PolicyFieldRecord>();

  for (const field of registry.fields) {
    if (field.configurable && !isExcludedFromComparison(field)) {
      if (field.os.length === 0) {
        root.set(field.keyPath, field);
      } else {
        let byOs = osScoped.get(field.keyPath);

        if (byOs === undefined) {
          byOs = new Map<PolicyOperatingSystem, PolicyFieldRecord>();
          osScoped.set(field.keyPath, byOs);
        }

        for (const os of field.os) {
          byOs.set(os, field);
        }
      }
    }
  }

  return { osScoped, root };
};

type FieldResolutionFailure = 'unknown_key_path' | 'not_applicable_for_os';

type FieldResolution =
  | { readonly field: PolicyFieldRecord }
  | { readonly failure: FieldResolutionFailure; readonly detail: string };

const formatOsList = (byOs: ReadonlyMap<PolicyOperatingSystem, PolicyFieldRecord>): string =>
  [...byOs.keys()].join(', ');

export const resolveProposedField = (
  lookup: ImpactFieldLookup,
  keyPath: string,
  os?: PolicyOperatingSystem
): FieldResolution => {
  const osScopedEntry = lookup.osScoped.get(keyPath);
  const rootEntry = lookup.root.get(keyPath);

  if (os === undefined) {
    if (rootEntry !== undefined) {
      return { field: rootEntry };
    }

    if (osScopedEntry !== undefined) {
      return {
        failure: 'not_applicable_for_os',
        detail: `[${keyPath}] is scoped to an operating system and cannot be set at the policy root. It applies to: ${formatOsList(
          osScopedEntry
        )}.`,
      };
    }

    return {
      failure: 'unknown_key_path',
      detail: `No configurable Elastic Defend policy field matches [${keyPath}].`,
    };
  }

  if (osScopedEntry !== undefined) {
    const field = osScopedEntry.get(os);

    if (field !== undefined) {
      return { field };
    }

    return {
      failure: 'not_applicable_for_os',
      detail: `[${keyPath}] exists but does not apply to [${os}]. It applies to: ${formatOsList(
        osScopedEntry
      )}.`,
    };
  }

  if (rootEntry !== undefined) {
    return {
      failure: 'not_applicable_for_os',
      detail: `[${keyPath}] is a policy-root field and is not scoped per operating system, so it cannot be set for [${os}] alone.`,
    };
  }

  return {
    failure: 'unknown_key_path',
    detail: `No configurable Elastic Defend policy field matches [${keyPath}].`,
  };
};

export const toAbsoluteKeyPath = (keyPath: string, os?: PolicyOperatingSystem): string =>
  os === undefined ? keyPath : `${os}.${keyPath}`;

const OS_BRANCHES: readonly PolicyOperatingSystem[] = [
  PolicyOperatingSystem.windows,
  PolicyOperatingSystem.mac,
  PolicyOperatingSystem.linux,
];

export const splitAbsoluteKeyPath = (
  absoluteKeyPath: string
): { readonly keyPath: string; readonly os?: PolicyOperatingSystem } => {
  for (const os of OS_BRANCHES) {
    const prefix = `${os}.`;

    if (absoluteKeyPath.startsWith(prefix)) {
      return { os, keyPath: absoluteKeyPath.slice(prefix.length) };
    }
  }

  return { keyPath: absoluteKeyPath };
};
