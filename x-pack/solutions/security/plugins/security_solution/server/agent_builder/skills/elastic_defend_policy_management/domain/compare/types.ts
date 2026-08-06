/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';

export interface PolicyFieldDifference {
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
  readonly leftPresent: boolean;
  readonly rightPresent: boolean;
  readonly left: unknown;
  readonly right: unknown;
  readonly unrecognized?: boolean;
}

export interface PolicyComparison {
  readonly leftId: string;
  readonly rightId: string;
  readonly configIdentical: boolean;
  readonly protectionUpdatesPinDiffers: boolean;
  readonly leftGlobalManifestVersion: string;
  readonly rightGlobalManifestVersion: string;
  readonly differences: readonly PolicyFieldDifference[];
  readonly notComparable: readonly PolicyFieldDifference[];
}

export interface DuplicateGroupMember {
  readonly id: string;
  readonly name: string;
  readonly revision: number;
  readonly packageVersion: string;
  readonly policyIds: readonly string[];
}

export interface DuplicateGroup {
  readonly configHash: string;
  readonly members: readonly DuplicateGroupMember[];
  readonly differsOnlyByProtectionUpdatesPin: boolean;
}

export interface DuplicateAnalysisAccounting {
  readonly policiesConsidered: number;
  readonly duplicateGroupCount: number;
  readonly policiesInDuplicateGroups: number;
}
