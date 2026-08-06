/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';

export type PolicyFieldDefaultSource =
  | 'advanced_schema_documentation'
  | 'policy_factory'
  | 'unknown';

export type PolicyFieldCategory =
  | 'meta'
  | 'global'
  | 'protection'
  | 'popup'
  | 'events'
  | 'device_control'
  | 'antivirus_registration'
  | 'attack_surface_reduction'
  | 'advanced'
  | 'logging';

export type PolicyFieldValueType = 'boolean' | 'number' | 'string' | 'enum' | 'unknown';

export interface PolicyFieldRecord {
  readonly keyPath: string;
  readonly os: readonly PolicyOperatingSystem[];
  readonly category: PolicyFieldCategory;
  readonly type: PolicyFieldValueType;
  readonly enumValues?: readonly string[];
  readonly default?: unknown;
  readonly defaultSource: PolicyFieldDefaultSource;
  readonly firstSupportedVersion?: string;
  readonly lastSupportedVersion?: string;
  readonly license?: string;
  readonly documentation?: string;
  readonly configurable: boolean;
}

export interface PolicyFieldRegistry {
  readonly packageVersion: string;
  readonly fields: readonly PolicyFieldRecord[];
}

export type PolicyFieldApplicability =
  | 'applicable'
  | 'unsupported'
  | 'version_unavailable'
  | 'unknown';

export interface RegistryVersionUnknown {
  readonly status: 'registry_version_unknown';
  readonly requestedVersion: string;
  readonly nearestKnownVersion?: string;
}
