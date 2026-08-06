/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { NormalizedPolicyConfig } from '../normalize/types';
import { hashPolicyConfig } from './hash_policy_config';
import type { DuplicateAnalysisAccounting, DuplicateGroup, DuplicateGroupMember } from './types';

export interface DuplicateCandidate {
  readonly id: string;
  readonly name: string;
  readonly revision: number;
  readonly packageVersion: string;
  readonly policyIds: readonly string[];
  readonly configNormalized: NormalizedPolicyConfig;
}

interface GroupDuplicatePoliciesArgs {
  readonly policies: readonly DuplicateCandidate[];
}

const toMember = ({
  id,
  name,
  revision,
  packageVersion,
  policyIds,
}: DuplicateCandidate): DuplicateGroupMember => ({
  id,
  name,
  revision,
  packageVersion,
  policyIds: [...policyIds].sort(),
});

export const groupDuplicatePolicies = ({
  policies,
}: GroupDuplicatePoliciesArgs): {
  groups: DuplicateGroup[];
  accounting: DuplicateAnalysisAccounting;
} => {
  const byHash = new Map<string, DuplicateCandidate[]>();

  for (const candidate of policies) {
    const configHash = hashPolicyConfig(candidate.configNormalized);
    const existing = byHash.get(configHash);

    if (existing === undefined) {
      byHash.set(configHash, [candidate]);
    } else {
      existing.push(candidate);
    }
  }

  const groups: DuplicateGroup[] = [];
  let policiesInDuplicateGroups = 0;

  for (const [configHash, members] of byHash) {
    if (members.length >= 2) {
      const pins = new Set(
        members.map(({ configNormalized }) => configNormalized.globalManifestVersion)
      );

      policiesInDuplicateGroups += members.length;

      groups.push({
        configHash,
        members: members.map(toMember),
        differsOnlyByProtectionUpdatesPin: pins.size > 1,
      });
    }
  }

  return {
    groups,
    accounting: {
      policiesConsidered: policies.length,
      duplicateGroupCount: groups.length,
      policiesInDuplicateGroups,
    },
  };
};
