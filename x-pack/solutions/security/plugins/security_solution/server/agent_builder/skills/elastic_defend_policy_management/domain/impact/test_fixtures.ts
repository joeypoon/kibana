/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import type { PolicyFieldRecord, PolicyFieldRegistry } from '../field_registry/types';
import { normalizePolicyConfig } from '../normalize/normalize_policy_config';
import { hashPolicyConfig } from '../compare/hash_policy_config';
import type { PolicySnapshot } from '../read/types';

export const TEST_PACKAGE_VERSION = '8.16.0';

const ALL_OS: readonly PolicyOperatingSystem[] = [
  PolicyOperatingSystem.windows,
  PolicyOperatingSystem.mac,
  PolicyOperatingSystem.linux,
];

export const TEST_REGISTRY_FIELDS: readonly PolicyFieldRecord[] = [
  {
    keyPath: 'malware.mode',
    os: ALL_OS,
    category: 'protection',
    type: 'enum',
    enumValues: [ProtectionModes.detect, ProtectionModes.prevent, ProtectionModes.off],
    default: ProtectionModes.prevent,
    defaultSource: 'policy_factory',
    firstSupportedVersion: '7.9',
    configurable: true,
  },
  {
    keyPath: 'malware.blocklist',
    os: ALL_OS,
    category: 'protection',
    type: 'boolean',
    default: true,
    defaultSource: 'policy_factory',
    firstSupportedVersion: '7.9',
    configurable: true,
  },
  {
    keyPath: 'antivirus_registration.enabled',
    os: [PolicyOperatingSystem.windows],
    category: 'antivirus_registration',
    type: 'boolean',
    default: false,
    defaultSource: 'policy_factory',
    firstSupportedVersion: '7.11',
    configurable: true,
  },
  {
    keyPath: 'events.file',
    os: ALL_OS,
    category: 'events',
    type: 'boolean',
    default: true,
    defaultSource: 'policy_factory',
    firstSupportedVersion: '7.9',
    configurable: true,
  },
  {
    keyPath: 'advanced.retired_setting',
    os: ALL_OS,
    category: 'advanced',
    type: 'string',
    default: 'legacy',
    defaultSource: 'advanced_schema_documentation',
    firstSupportedVersion: '7.9',
    lastSupportedVersion: '8.10',
    configurable: true,
  },
  {
    keyPath: 'advanced.future_setting',
    os: ALL_OS,
    category: 'advanced',
    type: 'string',
    default: 'off',
    defaultSource: 'advanced_schema_documentation',
    firstSupportedVersion: '9.4',
    configurable: true,
  },
  {
    keyPath: 'global_manifest_version',
    os: [],
    category: 'global',
    type: 'string',
    default: 'latest',
    defaultSource: 'policy_factory',
    firstSupportedVersion: '8.7',
    configurable: true,
  },
  {
    keyPath: 'meta.license',
    os: [],
    category: 'meta',
    type: 'string',
    defaultSource: 'unknown',
    configurable: false,
  },
  {
    keyPath: 'popup.malware.message',
    os: ALL_OS,
    category: 'popup',
    type: 'string',
    default: '',
    defaultSource: 'policy_factory',
    firstSupportedVersion: '7.9',
    configurable: true,
  },
];

export const buildTestRegistry = (
  packageVersion: string = TEST_PACKAGE_VERSION
): PolicyFieldRegistry => ({ packageVersion, fields: TEST_REGISTRY_FIELDS });

export interface BuildTestSnapshotOptions {
  readonly revision?: number;
  readonly version?: string;
  readonly packageVersion?: string;
  readonly policyIds?: readonly string[];
}

export const buildTestSnapshot = ({
  revision = 4,
  version = 'WzEyMyw0NV0=',
  packageVersion = TEST_PACKAGE_VERSION,
  policyIds = ['agent-policy-1'],
}: BuildTestSnapshotOptions = {}): PolicySnapshot => {
  const config = policyFactory();
  const registry = buildTestRegistry(packageVersion);
  const configNormalized = normalizePolicyConfig(config, registry);

  return {
    identity: {
      id: 'endpoint-policy-1',
      revision,
      version,
      updatedAt: '2026-01-15T10:00:00.000Z',
    },
    name: 'Protect all the things',
    packageName: 'endpoint',
    packageVersion,
    policyIds,
    provenance: {
      createdAt: '2026-01-01T10:00:00.000Z',
      createdBy: 'elastic',
      updatedAt: '2026-01-15T10:00:00.000Z',
      updatedBy: 'elastic',
    },
    config,
    configNormalized,
    configHash: hashPolicyConfig(configNormalized),
  };
};
