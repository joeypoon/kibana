/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import type { PolicyFieldValueType } from '../field_registry/types';
import type { PolicySnapshotIdentity } from '../read/types';

export interface PolicyChangeOperation {
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
  readonly expectedCurrentValue?: unknown;
  readonly proposedValue: unknown;
}

export interface PolicyChangeProposal {
  readonly policyId: string;
  readonly identity: Pick<PolicySnapshotIdentity, 'revision' | 'version'>;
  readonly operations: readonly PolicyChangeOperation[];
}

export type PolicyChangeRejectionReason =
  | 'unknown_key_path'
  | 'not_applicable_for_os'
  | 'outside_version_window'
  | 'identity_mismatch'
  | 'stale_snapshot'
  | 'current_value_mismatch'
  | 'too_many_operations';

export interface PolicyChangeRejection {
  readonly reason: PolicyChangeRejectionReason;
  readonly message: string;
  readonly keyPath?: string;
  readonly os?: PolicyOperatingSystem;
  readonly currentIdentity?: PolicySnapshotIdentity;
}

export interface PolicyChangeLeafDiff {
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
  readonly before: unknown;
  readonly after: unknown;
  readonly defaultValue?: unknown;
  readonly type?: PolicyFieldValueType;
  readonly enumValues?: readonly string[];
  readonly documentation?: string;
}

export interface PolicyValidatorOutcome {
  readonly validator: 'package_policy' | 'license' | 'product_features';
  readonly passed: boolean;
  readonly message?: string;
}

export interface PolicyChangeAssessment {
  readonly proposal: PolicyChangeProposal;
  readonly assessedIdentity: PolicySnapshotIdentity;
  readonly diffs: readonly PolicyChangeLeafDiff[];
  readonly validatorOutcomes: readonly PolicyValidatorOutcome[];
  readonly verifiedConfigurationEffects: readonly string[];
  readonly likelyPopulationEffects: readonly string[];
  readonly unknowns: readonly string[];
  readonly applied: false;
}
