/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AssignmentEvidence, PolicyUseClassification } from '../read/types';
import { classifyPolicyUse, POLICY_USE_STATES } from './classify_policy_use';

const evidenceOf = (overrides: Partial<AssignmentEvidence> = {}): AssignmentEvidence => ({
  policyId: 'pkg-policy-1',
  agentPolicyIds: ['agent-policy-a'],
  status: 'counted',
  agentCount: 3,
  ...overrides,
});

const DELETION_LANGUAGE = [
  /\bdelete\b/i,
  /\bdeleting\b/i,
  /\bdeletion\b/i,
  /\bremove\b/i,
  /\bremoving\b/i,
  /\bsafe to\b/i,
  /\byou should\b/i,
  /\bclean up\b/i,
  /\bunused policy\b/i,
];

const expectNoDeletionRecommendation = (result: PolicyUseClassification): void => {
  const prose = result.evidence;

  for (const pattern of DELETION_LANGUAGE) {
    const disclaimerFree = prose.replace(/is not a recommendation to delete anything\./g, '');
    expect(disclaimerFree).not.toMatch(pattern);
  }
};

describe('classifyPolicyUse', () => {
  it('classifies an unassigned policy as likely_unused_unassigned without needing an agent lookup', () => {
    const result = classifyPolicyUse(
      evidenceOf({ agentPolicyIds: [], status: 'privilege_absent', agentCount: undefined }),
      []
    );

    expect(result.state).toBe('likely_unused_unassigned');
    expect(result.policyId).toBe('pkg-policy-1');
    expect(result.evidence).toContain('policy_ids');
    expect(result.evidence).toContain('No agent lookup was needed');
    expectNoDeletionRecommendation(result);
  });

  it('prefers the unassigned state over any agent evidence, because assignment alone decides it', () => {
    const result = classifyPolicyUse(evidenceOf({ status: 'counted', agentCount: 12 }), []);

    expect(result.state).toBe('likely_unused_unassigned');
    expect(result.assignmentEvidence.agentCount).toBeUndefined();
  });

  it('classifies assigned + counted + zero agents as likely_unused_no_agents with the exact evidence', () => {
    const evidence = evidenceOf({ status: 'counted', agentCount: 0 });
    const result = classifyPolicyUse(evidence, ['agent-policy-a']);

    expect(result.state).toBe('likely_unused_no_agents');
    expect(result.assignmentEvidence).toEqual(evidence);
    expect(result.assignmentEvidence.agentCount).toBe(0);
    expect(result.evidence).toContain('fleet.readAgents');
    expect(result.evidence).toContain('0 agents');
    expect(result.evidence).toContain('agent-policy-a');
    expectNoDeletionRecommendation(result);
  });

  it('classifies assigned + counted + non-zero agents as in_use', () => {
    const result = classifyPolicyUse(evidenceOf({ status: 'counted', agentCount: 4 }), [
      'agent-policy-a',
    ]);

    expect(result.state).toBe('in_use');
    expect(result.evidence).toContain('4 agents');
    expectNoDeletionRecommendation(result);
  });

  it('uses singular agent phrasing for a count of one', () => {
    const result = classifyPolicyUse(evidenceOf({ status: 'counted', agentCount: 1 }), [
      'agent-policy-a',
    ]);

    expect(result.state).toBe('in_use');
    expect(result.evidence).toContain('1 agent enrolled');
  });

  describe('degraded evidence', () => {
    it('returns undetermined when the lookup was not attempted because the privilege is absent', () => {
      const result = classifyPolicyUse(
        evidenceOf({ status: 'privilege_absent', agentCount: undefined }),
        ['agent-policy-a']
      );

      expect(result.state).toBe('undetermined');
      expect(result.evidence).toContain('not looked up');
      expect(result.evidence).toContain('fleet.readAgents');
      expect(result.evidence).toContain('withheld');
      expectNoDeletionRecommendation(result);
    });

    it('returns undetermined when the lookup was attempted but incomplete, and surfaces the detail', () => {
      const result = classifyPolicyUse(
        evidenceOf({
          status: 'lookup_incomplete',
          agentCount: undefined,
          detail: 'agent lookup failed for agent policy agent-policy-b',
        }),
        ['agent-policy-a', 'agent-policy-b']
      );

      expect(result.state).toBe('undetermined');
      expect(result.evidence).toContain('did not cover every one of them');
      expect(result.evidence).toContain('agent lookup failed for agent policy agent-policy-b');
      expectNoDeletionRecommendation(result);
    });

    it('emits NO agent count in either degraded state, even when one rode along on the input', () => {
      for (const status of ['privilege_absent', 'lookup_incomplete'] as const) {
        const result = classifyPolicyUse(evidenceOf({ status, agentCount: 0 }), ['agent-policy-a']);

        expect(result.state).toBe('undetermined');
        expect(result.assignmentEvidence.agentCount).toBeUndefined();
        expect('agentCount' in result.assignmentEvidence).toBe(false);
        expect(result.evidence).not.toMatch(/\b0 agents\b/);
      }
    });

    it('preserves the detail field on the emitted evidence while still dropping the count', () => {
      const result = classifyPolicyUse(
        evidenceOf({ status: 'lookup_incomplete', agentCount: 7, detail: 'page 3 of 9 missing' }),
        ['agent-policy-a']
      );

      expect(result.assignmentEvidence.detail).toBe('page 3 of 9 missing');
      expect(result.assignmentEvidence.agentCount).toBeUndefined();
    });
  });

  describe('invariants', () => {
    const allCases: ReadonlyArray<[AssignmentEvidence, readonly string[]]> = [
      [evidenceOf({ agentPolicyIds: [], status: 'counted', agentCount: 0 }), []],
      [evidenceOf({ status: 'counted', agentCount: 0 }), ['agent-policy-a']],
      [evidenceOf({ status: 'counted', agentCount: 9 }), ['agent-policy-a']],
      [evidenceOf({ status: 'privilege_absent', agentCount: undefined }), ['agent-policy-a']],
      [
        evidenceOf({ status: 'lookup_incomplete', agentCount: undefined, detail: 'timed out' }),
        ['agent-policy-a', 'agent-policy-b'],
      ],
    ];

    it('never produces an output that recommends deletion, for any input', () => {
      for (const [evidence, policyIds] of allCases) {
        expectNoDeletionRecommendation(classifyPolicyUse(evidence, policyIds));
      }
    });

    it('always produces a non-empty plain-language basis', () => {
      for (const [evidence, policyIds] of allCases) {
        expect(classifyPolicyUse(evidence, policyIds).evidence.length).toBeGreaterThan(40);
      }
    });

    it('covers every declared state across the case matrix', () => {
      const observed = new Set(
        allCases.map(([evidence, policyIds]) => classifyPolicyUse(evidence, policyIds).state)
      );

      expect([...observed].sort()).toEqual([...POLICY_USE_STATES].sort());
    });

    it('does not mutate its inputs', () => {
      const evidence = evidenceOf({ status: 'counted', agentCount: 0 });
      const snapshot = JSON.stringify(evidence);
      const policyIds = ['agent-policy-a'];

      classifyPolicyUse(evidence, policyIds);

      expect(JSON.stringify(evidence)).toBe(snapshot);
      expect(policyIds).toEqual(['agent-policy-a']);
    });
  });

  it('names multiple agent policies in the basis so the evidence is auditable', () => {
    const result = classifyPolicyUse(
      evidenceOf({
        agentPolicyIds: ['agent-policy-a', 'agent-policy-b'],
        status: 'counted',
        agentCount: 0,
      }),
      ['agent-policy-a', 'agent-policy-b']
    );

    expect(result.evidence).toContain('2 agent policies (agent-policy-a, agent-policy-b)');
  });
});
