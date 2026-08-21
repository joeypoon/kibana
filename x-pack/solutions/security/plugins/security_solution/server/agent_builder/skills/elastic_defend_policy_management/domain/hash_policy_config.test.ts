/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { policyFactory } from '../../../../../common/endpoint/models/policy_config';
import type { PolicyConfig } from '../../../../../common/endpoint/types';
import type { diffPolicyConfig } from './diff';
import { hashPolicyConfig } from './hash_policy_config';
import type { NormalizedPolicyConfig } from './normalized_policy_config';
import { normalize } from './normalize';

type IsAssignable<A, B> = A extends B ? true : false;
type RawMustNotAssignToNormalized = IsAssignable<PolicyConfig, NormalizedPolicyConfig> extends false
  ? true
  : never;
type RawMustNotAssignToHash = IsAssignable<
  PolicyConfig,
  Parameters<typeof hashPolicyConfig>[0]
> extends false
  ? true
  : never;
type RawMustNotAssignToDiff = IsAssignable<
  PolicyConfig,
  Parameters<typeof diffPolicyConfig>[0]
> extends false
  ? true
  : never;
type NormalizedMustAssignToHash = IsAssignable<
  NormalizedPolicyConfig,
  Parameters<typeof hashPolicyConfig>[0]
> extends true
  ? true
  : never;

const _rawMustNotAssignToNormalized: RawMustNotAssignToNormalized = true;
const _rawMustNotAssignToHash: RawMustNotAssignToHash = true;
const _rawMustNotAssignToDiff: RawMustNotAssignToDiff = true;
const _normalizedMustAssignToHash: NormalizedMustAssignToHash = true;

void _rawMustNotAssignToNormalized;
void _rawMustNotAssignToHash;
void _rawMustNotAssignToDiff;
void _normalizedMustAssignToHash;

describe('hashPolicyConfig', () => {
  it('changes when popup enabled differs', () => {
    const left = policyFactory();
    const right = policyFactory();
    right.windows.popup.malware.enabled = !left.windows.popup.malware.enabled;

    expect(hashPolicyConfig(normalize(left))).not.toEqual(hashPolicyConfig(normalize(right)));
  });

  it('is unchanged by key reorder of semantically identical policies', () => {
    const factory = policyFactory();
    const reordered: PolicyConfig = {
      linux: factory.linux,
      mac: factory.mac,
      windows: factory.windows,
      global_telemetry_enabled: factory.global_telemetry_enabled,
      global_manifest_version: factory.global_manifest_version,
      meta: factory.meta,
    };

    expect(hashPolicyConfig(normalize(factory))).toEqual(hashPolicyConfig(normalize(reordered)));
  });
});
