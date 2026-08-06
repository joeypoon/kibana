/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import type { NormalizedPolicyConfig } from '../normalize/types';

export interface PolicySnapshotIdentity {
  readonly id: string;
  readonly revision: number;
  readonly version?: string;
  readonly updatedAt: string;
}

export interface PolicyProvenance {
  readonly createdAt: string;
  readonly createdBy: string;
  readonly updatedAt: string;
  readonly updatedBy: string;
}

export interface PolicySnapshot {
  readonly identity: PolicySnapshotIdentity;
  readonly name: string;
  readonly description?: string;
  readonly packageName: string;
  readonly packageVersion: string;
  readonly spaceIds?: readonly string[];
  readonly policyIds: readonly string[];
  readonly provenance: PolicyProvenance;
  readonly config: PolicyConfig;
  readonly configNormalized: NormalizedPolicyConfig;
  readonly configHash: string;
}

export interface PolicyReadPrivilegeBasis {
  readonly securityPolicyManagementRead: boolean;
  readonly fleetIntegrationPoliciesRead: boolean;
  readonly fleetAgentsRead: boolean;
}

export type PartialResultReason = 'missing_privilege' | 'result_limit_reached' | 'upstream_failure';

export interface PartialResultDisclosure {
  readonly reason: PartialResultReason;
  readonly detail: string;
  readonly continuation: string;
}

export interface ScopeDisclosure {
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
  readonly returned: number;
  readonly total: number;
  readonly spaceId?: string;
  readonly partial?: PartialResultDisclosure;
}

export type PolicyReadDenialReason = 'missing_privilege' | 'not_found';

export interface PolicyReadDenial {
  readonly reason: PolicyReadDenialReason;
  readonly message: string;
  readonly needAny?: readonly string[];
}

export interface EstateAccounting {
  readonly policiesTraversed: number;
  readonly pagesFetched: number;
  readonly complete: boolean;
  readonly incompleteReason?: PartialResultReason;
}

export type AssignmentEvidenceStatus = 'counted' | 'privilege_absent' | 'lookup_incomplete';

export interface AssignmentEvidence {
  readonly policyId: string;
  readonly agentPolicyIds: readonly string[];
  readonly status: AssignmentEvidenceStatus;
  readonly agentCount?: number;
  readonly detail?: string;
}

export type PolicyUseState =
  | 'likely_unused_unassigned'
  | 'likely_unused_no_agents'
  | 'in_use'
  | 'undetermined';

export interface PolicyUseClassification {
  readonly policyId: string;
  readonly state: PolicyUseState;
  readonly evidence: string;
  readonly assignmentEvidence: AssignmentEvidence;
}
