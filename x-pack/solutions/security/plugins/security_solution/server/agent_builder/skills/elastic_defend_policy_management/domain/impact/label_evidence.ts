/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AssignmentEvidence, PolicySnapshotIdentity } from '../read/types';
import type { PolicyChangeLeafDiff, PolicyValidatorOutcome } from './types';

interface LabelEvidenceArgs {
  readonly identity: PolicySnapshotIdentity;
  readonly diffs: readonly PolicyChangeLeafDiff[];
  readonly validatorOutcomes: readonly PolicyValidatorOutcome[];
  readonly population: AssignmentEvidence;
}

interface LabelledEvidence {
  readonly verifiedConfigurationEffects: readonly string[];
  readonly likelyPopulationEffects: readonly string[];
  readonly unknowns: readonly string[];
}

export const ADVISORY_NOT_APPLIED_STATEMENT = 'advisory_not_applied';

export const META_PERSIST_REWRITES_UNKNOWN = 'persist:meta_license_cloud_billable_unknown';

export const labelChangeEvidence = ({
  identity,
  diffs,
  validatorOutcomes,
  population,
}: LabelEvidenceArgs): LabelledEvidence => ({
  verifiedConfigurationEffects: [
    ADVISORY_NOT_APPLIED_STATEMENT,
    `assessed_identity:${identity.id}:${identity.revision}:${identity.version ?? 'unversioned'}`,
    diffs.length === 0 ? 'configuration:no_change' : `configuration:changed:${diffs.length}`,
    ...validatorOutcomes.map(({ validator, passed, message }) =>
      passed
        ? `validator:${validator}:passed`
        : `validator:${validator}:failed${message === undefined ? '' : `:${message}`}`
    ),
  ],
  likelyPopulationEffects: buildPopulationEvidence(population),
  unknowns: buildUnknownEvidence(diffs, validatorOutcomes),
});

const buildPopulationEvidence = ({
  agentPolicyIds,
  status,
  agentCount,
  detail,
}: AssignmentEvidence): string[] => {
  if (agentPolicyIds.length === 0) {
    return ['population:unassigned'];
  }

  const evidence = [`population:assigned:${agentPolicyIds.length}`];

  if (status === 'counted' && agentCount !== undefined) {
    evidence.push(`population:active_agents:${agentCount}`);
  } else {
    evidence.push(`population:${status}`);
  }

  if (detail !== undefined) {
    evidence.push(`population:detail:${detail}`);
  }

  return evidence;
};

const buildUnknownEvidence = (
  diffs: readonly PolicyChangeLeafDiff[],
  validatorOutcomes: readonly PolicyValidatorOutcome[]
): string[] => {
  const unknowns = [
    'runtime:policy_execution_unknown',
    'runtime:application_unknown',
    'runtime:endpoint_availability_unknown',
    'runtime:detection_alert_performance_unknown',
    META_PERSIST_REWRITES_UNKNOWN,
  ];

  if (diffs.length > 0) {
    unknowns.push('runtime:change_timing_unknown');
  }

  if (validatorOutcomes.some(({ passed }) => !passed)) {
    unknowns.push('validation:write_acceptance_unknown');
  }

  return unknowns;
};
