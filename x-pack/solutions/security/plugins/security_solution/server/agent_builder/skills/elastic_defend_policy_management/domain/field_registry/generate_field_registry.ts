/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import {
  AntivirusRegistrationModes,
  DeviceControlAccessLevel,
  PolicyOperatingSystem,
  ProtectionModes,
} from '../../../../../../common/endpoint/types';

import { AdvancedPolicySchema } from '../../../../../../common/endpoint/service/policy/field_registry/advanced_policy_schema';
import { parseDocumentedDefault } from './parse_documented_default';
import { compareVersionToPartialBound } from './applicability';
import type {
  PolicyFieldCategory,
  PolicyFieldRecord,
  PolicyFieldRegistry,
  PolicyFieldValueType,
} from './types';

const OS_BRANCHES: readonly PolicyOperatingSystem[] = [
  PolicyOperatingSystem.windows,
  PolicyOperatingSystem.mac,
  PolicyOperatingSystem.linux,
];

const CATEGORY_BY_LEADING_SEGMENT: Readonly<Record<string, PolicyFieldCategory>> = {
  malware: 'protection',
  ransomware: 'protection',
  memory_protection: 'protection',
  behavior_protection: 'protection',
  popup: 'popup',
  events: 'events',
  device_control: 'device_control',
  antivirus_registration: 'antivirus_registration',
  attack_surface_reduction: 'attack_surface_reduction',
  logging: 'logging',
  advanced: 'advanced',
  meta: 'meta',
};

const ENUM_VALUES_BY_KEY_PATH: Readonly<Record<string, readonly string[]>> = {
  'malware.mode': Object.values(ProtectionModes),
  'ransomware.mode': Object.values(ProtectionModes),
  'memory_protection.mode': Object.values(ProtectionModes),
  'behavior_protection.mode': Object.values(ProtectionModes),
  'antivirus_registration.mode': Object.values(AntivirusRegistrationModes),
  'device_control.usb_storage': Object.values(DeviceControlAccessLevel),
};

const categoryForKeyPath = (keyPath: string, isOsScoped: boolean): PolicyFieldCategory => {
  const [leadingSegment] = keyPath.split('.');
  const mapped = CATEGORY_BY_LEADING_SEGMENT[leadingSegment];

  if (mapped !== undefined) {
    return mapped;
  }

  return isOsScoped ? 'advanced' : 'global';
};

interface ResolvedDefault {
  readonly value?: boolean | number | string;
  readonly source: PolicyFieldRecord['defaultSource'];
  readonly type: PolicyFieldValueType;
}

const typeOfFactoryValue = (keyPath: string, value: unknown): PolicyFieldValueType => {
  if (ENUM_VALUES_BY_KEY_PATH[keyPath] !== undefined) {
    return 'enum';
  }

  if (typeof value === 'boolean') {
    return 'boolean';
  }

  if (typeof value === 'number') {
    return 'number';
  }

  return typeof value === 'string' ? 'string' : 'unknown';
};

const resolveFactoryAdvancedDefault = (
  os: PolicyOperatingSystem | undefined,
  keyPath: string,
  osLeaves: ReadonlyMap<PolicyOperatingSystem, ReadonlyMap<string, unknown>>
): ResolvedDefault | undefined => {
  if (os === undefined) {
    return undefined;
  }

  const value = osLeaves.get(os)?.get(keyPath);

  if (typeof value !== 'boolean' && typeof value !== 'number' && typeof value !== 'string') {
    return undefined;
  }

  return { value, source: 'policy_factory', type: typeOfFactoryValue(keyPath, value) };
};

const resolveAdvancedDefault = (
  os: PolicyOperatingSystem | undefined,
  keyPath: string,
  documentation: string,
  packageVersion: string,
  osLeaves: ReadonlyMap<PolicyOperatingSystem, ReadonlyMap<string, unknown>>
): ResolvedDefault => {
  const parsed = parseDocumentedDefault({ documentation });

  if (parsed.status === 'parsed') {
    return { value: parsed.value, source: 'advanced_schema_documentation', type: parsed.type };
  }

  if (parsed.status === 'version_conditional') {
    const [earlier, later] = parsed.branches;
    const declaredType = earlier.type === later.type ? earlier.type : 'unknown';

    const earlierComparison = compareVersionToPartialBound(packageVersion, earlier.boundary);
    const laterComparison = compareVersionToPartialBound(packageVersion, later.boundary);

    if (earlierComparison !== null && earlierComparison <= 0) {
      return {
        value: earlier.value,
        source: 'advanced_schema_documentation',
        type: declaredType,
      };
    }

    if (laterComparison !== null && laterComparison >= 0) {
      return {
        value: later.value,
        source: 'advanced_schema_documentation',
        type: declaredType,
      };
    }

    return (
      resolveFactoryAdvancedDefault(os, keyPath, osLeaves) ?? {
        source: 'unknown',
        type: declaredType,
      }
    );
  }

  return (
    resolveFactoryAdvancedDefault(os, keyPath, osLeaves) ?? { source: 'unknown', type: 'unknown' }
  );
};

const buildAdvancedRecords = (
  packageVersion: string,
  osLeaves: ReadonlyMap<PolicyOperatingSystem, ReadonlyMap<string, unknown>>
): PolicyFieldRecord[] =>
  AdvancedPolicySchema.map(
    ({
      key,
      first_supported_version: firstSupportedVersion,
      last_supported_version: lastSupportedVersion,
      license,
      documentation,
    }): PolicyFieldRecord => {
      const [leadingSegment, ...remainder] = key.split('.');
      const os = OS_BRANCHES.find((branch) => branch === leadingSegment);

      const keyPath = os === undefined ? key : remainder.join('.');
      const resolved = resolveAdvancedDefault(os, keyPath, documentation, packageVersion, osLeaves);

      return {
        keyPath,
        os: os === undefined ? [] : [os],
        category: categoryForKeyPath(keyPath, os !== undefined),
        type: resolved.type,
        ...(resolved.value === undefined ? {} : { default: resolved.value }),
        defaultSource: resolved.source,
        firstSupportedVersion,
        ...(lastSupportedVersion === undefined ? {} : { lastSupportedVersion }),
        ...(license === undefined ? {} : { license }),
        documentation,
        configurable: true,
      };
    }
  );

const collectLeaves = (
  branch: Record<string, unknown>,
  prefix: string,
  into: Map<string, unknown>
): void => {
  for (const [segment, value] of Object.entries(branch)) {
    const path = prefix === '' ? segment : `${prefix}.${segment}`;
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      collectLeaves(value as Record<string, unknown>, path, into);
    } else if (value !== undefined) {
      into.set(path, value);
    }
  }
};

export const collectFactoryLeaves = (): {
  readonly rootLeaves: ReadonlyMap<string, unknown>;
  readonly osLeaves: ReadonlyMap<PolicyOperatingSystem, ReadonlyMap<string, unknown>>;
} => {
  const policy = policyFactory();
  const rootLeaves = new Map<string, unknown>();
  const osLeaves = new Map<PolicyOperatingSystem, ReadonlyMap<string, unknown>>();

  for (const [segment, value] of Object.entries(policy)) {
    const osBranch = OS_BRANCHES.find((branch) => branch === segment);

    if (osBranch !== undefined) {
      const branchLeaves = new Map<string, unknown>();
      collectLeaves(value as Record<string, unknown>, '', branchLeaves);
      osLeaves.set(osBranch, branchLeaves);
    } else if (typeof value === 'object' && value !== null) {
      collectLeaves(value as Record<string, unknown>, segment, rootLeaves);
    } else if (value !== undefined) {
      rootLeaves.set(segment, value);
    }
  }

  return { rootLeaves, osLeaves };
};

const factoryRecord = (
  keyPath: string,
  value: unknown,
  os: readonly PolicyOperatingSystem[]
): PolicyFieldRecord => {
  const category = categoryForKeyPath(keyPath, os.length > 0);
  const enumValues = ENUM_VALUES_BY_KEY_PATH[keyPath];

  return {
    keyPath,
    os,
    category,
    type: typeOfFactoryValue(keyPath, value),
    ...(enumValues === undefined ? {} : { enumValues }),
    default: value,
    defaultSource: 'policy_factory',
    configurable: category !== 'meta',
  };
};

export const buildPolicyFieldRegistry = ({
  packageVersion,
}: {
  packageVersion: string;
}): PolicyFieldRegistry => {
  const byIdentity = new Map<string, PolicyFieldRecord>();
  const identity = ({ keyPath, os }: PolicyFieldRecord): string => `${os.join(',')}|${keyPath}`;
  const { rootLeaves, osLeaves } = collectFactoryLeaves();

  for (const record of buildAdvancedRecords(packageVersion, osLeaves)) {
    byIdentity.set(identity(record), record);
  }

  for (const [keyPath, value] of rootLeaves) {
    const record = factoryRecord(keyPath, value, []);
    const key = identity(record);

    if (!byIdentity.has(key)) {
      byIdentity.set(key, record);
    }
  }

  for (const [os, branchLeaves] of osLeaves) {
    for (const [keyPath, value] of branchLeaves) {
      const record = factoryRecord(keyPath, value, [os]);
      const key = identity(record);

      if (!byIdentity.has(key)) {
        byIdentity.set(key, record);
      }
    }
  }

  const fields = [...byIdentity.values()].sort((left, right) => {
    const osComparison = left.os.join(',').localeCompare(right.os.join(','));

    return osComparison !== 0 ? osComparison : left.keyPath.localeCompare(right.keyPath);
  });

  return { packageVersion, fields };
};
