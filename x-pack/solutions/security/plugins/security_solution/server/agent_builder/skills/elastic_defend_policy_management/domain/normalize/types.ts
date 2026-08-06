/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';

export interface NormalizedPolicyConfig {
  readonly globalManifestVersion: string;
  readonly globalTelemetryEnabled: boolean;
  readonly perOs: Readonly<Record<PolicyOperatingSystem, Readonly<Record<string, unknown>>>>;
  readonly unrecognizedPerOs: Readonly<
    Record<PolicyOperatingSystem, Readonly<Record<string, unknown>>>
  >;
}

export type PopupMessageState = 'default' | 'customized';

export type ExplicitVsDefault = 'explicit' | 'default' | 'indeterminate';

export type StoredIndeterminateReason =
  | 'license_gated_default_unrecoverable'
  | 'creation_input_unrecoverable'
  | 'no_recoverable_default'
  | 'registry_default_missing';

export interface AnnotatedPolicyField {
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
  readonly value: unknown;
  readonly defaultValue?: unknown;
  readonly state: ExplicitVsDefault;
  readonly indeterminateReason?: string;
  readonly indeterminateReasonCode?: StoredIndeterminateReason;
}
