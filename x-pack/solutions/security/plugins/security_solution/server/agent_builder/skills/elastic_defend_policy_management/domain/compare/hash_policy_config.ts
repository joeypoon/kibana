/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import objectHash from 'object-hash';
import type { NormalizedPolicyConfig } from '../normalize/types';

const POLICY_CONFIG_HASH_OPTIONS = {
  algorithm: 'sha256',
  encoding: 'hex',
  unorderedObjects: true,
  respectType: false,
} as const;

export const areStoredValuesEqual = (left: unknown, right: unknown): boolean =>
  objectHash(left, POLICY_CONFIG_HASH_OPTIONS) === objectHash(right, POLICY_CONFIG_HASH_OPTIONS);

export const hashPolicyConfig = (normalized: NormalizedPolicyConfig): string =>
  objectHash(
    {
      globalTelemetryEnabled: normalized.globalTelemetryEnabled,
      perOs: normalized.perOs,
      unrecognizedPerOs: normalized.unrecognizedPerOs,
    },
    POLICY_CONFIG_HASH_OPTIONS
  );
