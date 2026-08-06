/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AssignmentEvidence, PolicyUseClassification, PolicyUseState } from '../read/types';

const withoutAgentCount = (evidence: AssignmentEvidence): AssignmentEvidence => ({
  policyId: evidence.policyId,
  agentPolicyIds: evidence.agentPolicyIds,
  status: evidence.status,
  ...(evidence.detail === undefined ? {} : { detail: evidence.detail }),
});

const describeAgentPolicies = (agentPolicyIds: readonly string[]): string =>
  agentPolicyIds.length === 1
    ? `agent policy ${agentPolicyIds[0]}`
    : `${agentPolicyIds.length} agent policies (${agentPolicyIds.join(', ')})`;

export const classifyPolicyUse = (
  evidence: AssignmentEvidence,
  policyIds: readonly string[]
): PolicyUseClassification => {
  const { policyId, status, agentCount, agentPolicyIds } = evidence;

  if (policyIds.length === 0) {
    return {
      policyId,
      state: 'likely_unused_unassigned',
      evidence:
        'This policy is not assigned to any agent policy, so no agent can receive it. Basis: the ' +
        'policy has an empty `policy_ids` list. No agent lookup was needed to establish this. ' +
        'This describes configuration only and is not a recommendation to delete anything.',
      assignmentEvidence: withoutAgentCount(evidence),
    };
  }

  if (status === 'privilege_absent') {
    return {
      policyId,
      state: 'undetermined',
      evidence:
        `This policy is assigned to ${describeAgentPolicies(agentPolicyIds)}, but whether any ` +
        'agent is enrolled could not be determined: the agent count was not looked up because ' +
        'the `fleet.readAgents` privilege is absent. Fleet would have reported zero agents ' +
        'regardless, with no signal that the number was withheld, so no count is reported here. ' +
        'Grant `fleet.readAgents` to resolve this.',
      assignmentEvidence: withoutAgentCount(evidence),
    };
  }

  if (status === 'lookup_incomplete') {
    return {
      policyId,
      state: 'undetermined',
      evidence:
        `This policy is assigned to ${describeAgentPolicies(agentPolicyIds)}, but the agent ` +
        `lookup did not cover every one of them, so any total would be a partial count presented ` +
        `as a complete one. No count is reported here.${
          evidence.detail === undefined ? '' : ` What was missed: ${evidence.detail}`
        }`,
      assignmentEvidence: withoutAgentCount(evidence),
    };
  }

  if (agentCount === 0) {
    return {
      policyId,
      state: 'likely_unused_no_agents',
      evidence:
        `This policy is assigned to ${describeAgentPolicies(agentPolicyIds)}, and a complete ` +
        'agent lookup performed with the `fleet.readAgents` privilege found 0 agents enrolled in ' +
        'those agent policies. Basis: Fleet agent enrollment records, counted per agent policy. ' +
        'This describes configuration and enrollment only — it does not confirm what any endpoint ' +
        'is currently running, and is not a recommendation to delete anything.',
      assignmentEvidence: evidence,
    };
  }

  return {
    policyId,
    state: 'in_use',
    evidence:
      `This policy is assigned to ${describeAgentPolicies(agentPolicyIds)}, and a complete agent ` +
      `lookup found ${agentCount} agent${agentCount === 1 ? '' : 's'} enrolled in ` +
      'those agent policies. Basis: Fleet agent enrollment records, counted per agent policy.',
    assignmentEvidence: evidence,
  };
};

export const POLICY_USE_STATES: readonly PolicyUseState[] = [
  'likely_unused_unassigned',
  'likely_unused_no_agents',
  'in_use',
  'undetermined',
];
