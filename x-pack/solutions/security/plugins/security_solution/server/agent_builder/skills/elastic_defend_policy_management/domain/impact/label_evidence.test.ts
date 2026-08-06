/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import type { AssignmentEvidence, PolicySnapshotIdentity } from '../read/types';
import type { PolicyChangeLeafDiff, PolicyValidatorOutcome } from './types';
import { ADVISORY_NOT_APPLIED_STATEMENT, labelChangeEvidence } from './label_evidence';

const IDENTITY: PolicySnapshotIdentity = {
  id: 'endpoint-policy-1',
  revision: 7,
  version: 'WzEyMyw0NV0=',
  updatedAt: '2026-01-15T10:00:00.000Z',
};

const DIFFS: readonly PolicyChangeLeafDiff[] = [
  {
    keyPath: 'malware.mode',
    os: PolicyOperatingSystem.windows,
    before: ProtectionModes.prevent,
    after: ProtectionModes.detect,
    defaultValue: ProtectionModes.prevent,
  },
];

const COUNTED_POPULATION: AssignmentEvidence = {
  policyId: 'endpoint-policy-1',
  agentPolicyIds: ['agent-policy-1', 'agent-policy-2'],
  status: 'counted',
  agentCount: 42,
};

const assess = (
  population: AssignmentEvidence = COUNTED_POPULATION,
  validatorOutcomes: readonly PolicyValidatorOutcome[] = []
) =>
  labelChangeEvidence({
    identity: IDENTITY,
    diffs: DIFFS,
    validatorOutcomes,
    population,
  });

describe('labelChangeEvidence', () => {
  it('uses concise stable evidence tiers and preserves advisory-not-applied semantics', () => {
    expect(assess()).toEqual({
      verifiedConfigurationEffects: [
        ADVISORY_NOT_APPLIED_STATEMENT,
        'assessed_identity:endpoint-policy-1:7:WzEyMyw0NV0=',
        'configuration:changed:1',
      ],
      likelyPopulationEffects: ['population:assigned:2', 'population:active_agents:42'],
      unknowns: [
        'runtime:policy_execution_unknown',
        'runtime:application_unknown',
        'runtime:endpoint_availability_unknown',
        'runtime:detection_alert_performance_unknown',
        'persist:meta_license_cloud_billable_unknown',
        'runtime:change_timing_unknown',
      ],
    });
    expect(ADVISORY_NOT_APPLIED_STATEMENT).toBe('advisory_not_applied');
  });

  it('preserves failing validator messages verbatim behind a stable reason code', () => {
    const message = 'Platinum license does not support this action. Please upgrade your license.';

    expect(
      assess(COUNTED_POPULATION, [{ validator: 'license', passed: false, message }])
        .verifiedConfigurationEffects
    ).toContain(`validator:license:failed:${message}`);
  });

  it('does not invent an agent count when agent-read privilege is absent', () => {
    expect(
      assess({
        policyId: 'endpoint-policy-1',
        agentPolicyIds: ['agent-policy-1'],
        status: 'privilege_absent',
      }).likelyPopulationEffects
    ).toEqual(['population:assigned:1', 'population:privilege_absent']);
  });

  it('keeps assignment count and status without joining agent policy ids', () => {
    const agentPolicyIds = Array.from(
      { length: 1000 },
      (_, index) => `aaaaaaaa-bbbb-4ccc-8ddd-${index.toString().padStart(12, '0')}`
    );

    const { likelyPopulationEffects } = labelChangeEvidence({
      identity: IDENTITY,
      diffs: DIFFS,
      validatorOutcomes: [],
      population: {
        policyId: 'endpoint-policy-1',
        agentPolicyIds,
        status: 'lookup_incomplete',
        detail:
          'The affected agent population is incomplete: 1000 distinct assigned agent policies exceed the lookup bound.',
      },
    });

    expect(likelyPopulationEffects).toEqual([
      'population:assigned:1000',
      'population:lookup_incomplete',
      'population:detail:The affected agent population is incomplete: 1000 distinct assigned agent policies exceed the lookup bound.',
    ]);

    const serialized = likelyPopulationEffects.join('\n');
    expect(agentPolicyIds.some((id) => serialized.includes(id))).toBe(false);
  });

  it('reports unassigned and no-change states as stable codes', () => {
    expect(
      labelChangeEvidence({
        identity: IDENTITY,
        diffs: [],
        validatorOutcomes: [],
        population: {
          policyId: 'endpoint-policy-1',
          agentPolicyIds: [],
          status: 'counted',
          agentCount: 0,
        },
      })
    ).toMatchObject({
      verifiedConfigurationEffects: expect.arrayContaining(['configuration:no_change']),
      likelyPopulationEffects: ['population:unassigned'],
    });
  });

  it('adds write acceptance uncertainty when a validator fails', () => {
    expect(
      assess(COUNTED_POPULATION, [{ validator: 'product_features', passed: false }]).unknowns
    ).toContain('validation:write_acceptance_unknown');
  });
});
