/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PartialResultDisclosure, PolicyReadPrivilegeBasis } from '../../domain/read/types';

export type PolicyApplyStateClassification =
  | 'current'
  | 'revision_lag'
  | 'identity_mismatch'
  | 'unknown';

export interface PolicyApplyStateExemplar {
  readonly endpointId: string;
  readonly hostName: string;
  readonly classification: PolicyApplyStateClassification;
  readonly appliedEndpointPolicyId: string;
  readonly appliedEndpointPolicyRevision: number;
  readonly appliedAgentPolicyRevision: number;
  readonly configuredEndpointPolicyId?: string;
  readonly configuredEndpointPolicyRevision?: number;
  readonly configuredAgentPolicyRevision?: number;
  readonly hostStatus: string;
  readonly lastCheckin?: string;
}

export interface PolicyApplyStateFreshness {
  readonly latestEndpointTimestamp?: string;
}

export interface PolicyApplyStatePackagePolicyLoad {
  readonly loaded: number;
  readonly total: number;
  readonly omitted: number;
  readonly complete: boolean;
}

export interface PolicyApplyStateClassifiedSummary {
  readonly populationStatus: 'classified';
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
  readonly spaceId: string;
  readonly totalEndpoints: number;
  readonly endpointQueryTotal: number;
  readonly packagePolicyLoad: PolicyApplyStatePackagePolicyLoad;
  readonly currentCount: number;
  readonly revisionLagCount: number;
  readonly identityMismatchCount: number;
  readonly unknownCount: number;
  readonly staleOrOfflineCount: number;
  readonly exemplars: {
    readonly revisionLag: readonly PolicyApplyStateExemplar[];
    readonly identityMismatch: readonly PolicyApplyStateExemplar[];
  };
  readonly freshness: PolicyApplyStateFreshness;
  readonly disclosures: readonly PartialResultDisclosure[];
  readonly bounded: boolean;
}

export interface PolicyApplyStatePrivilegeAbsentSummary {
  readonly populationStatus: 'privilege_absent';
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
  readonly spaceId: string;
  readonly disclosures: readonly PartialResultDisclosure[];
}

export type PolicyApplyStateSummary =
  | PolicyApplyStateClassifiedSummary
  | PolicyApplyStatePrivilegeAbsentSummary;
