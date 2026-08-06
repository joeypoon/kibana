/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger } from '@kbn/core/server';
import type { AgentClient } from '@kbn/fleet-plugin/server';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { removeVersionSuffixFromPolicyId } from '@kbn/fleet-plugin/common/services/version_specific_policies_utils';
import type { AssignmentEvidence, PolicyReadPrivilegeBasis } from '../../../domain/read/types';

export const DEFAULT_MAX_AGENT_POLICY_LOOKUPS = 200;

export type AssignmentEvidenceInputPolicy = Pick<PackagePolicy, 'id' | 'policy_ids'>;

export interface CollectAssignmentEvidenceOptions {
  readonly policies: readonly AssignmentEvidenceInputPolicy[];
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
  readonly getAgentClient: () => AgentClient;
  readonly logger: Logger;
  readonly maxAgentPolicyLookups?: number;
}

interface AgentPolicyLookupResult {
  readonly enrolledAgents: number;
}

const uniqueSortedBaseAgentPolicyIds = (policyIds: readonly string[]): string[] => {
  const baseIds = new Set<string>();

  for (const policyId of policyIds) {
    if (policyId) {
      baseIds.add(removeVersionSuffixFromPolicyId(policyId));
    }
  }

  return [...baseIds].sort();
};

export const collectAssignmentEvidence = async ({
  policies,
  privilegeBasis,
  getAgentClient,
  logger,
  maxAgentPolicyLookups = DEFAULT_MAX_AGENT_POLICY_LOOKUPS,
}: CollectAssignmentEvidenceOptions): Promise<AssignmentEvidence[]> => {
  const agentPolicyIdsByPolicy = new Map<string, string[]>(
    policies.map((policy) => [policy.id, uniqueSortedBaseAgentPolicyIds(policy.policy_ids ?? [])])
  );

  if (!privilegeBasis.fleetAgentsRead) {
    logger.debug(
      `collectAssignmentEvidence(): skipping agent lookup for ${policies.length} policy(ies); 'fleet.readAgents' is absent`
    );

    return policies.map((policy) => ({
      policyId: policy.id,
      agentPolicyIds: agentPolicyIdsByPolicy.get(policy.id) ?? [],
      status: 'privilege_absent',
      detail:
        "The agent lookup was not attempted because the 'fleet.readAgents' privilege is absent. " +
        'Fleet would have reported 0 agents without indicating that the count was withheld, so no ' +
        'count is reported.',
    }));
  }

  const allAgentPolicyIds = uniqueSortedBaseAgentPolicyIds(
    policies.flatMap((policy) => policy.policy_ids ?? [])
  );
  const lookupIds = allAgentPolicyIds.slice(0, maxAgentPolicyLookups);
  const skippedIds = new Set(allAgentPolicyIds.slice(maxAgentPolicyLookups));

  const agentClient = getAgentClient();
  const resultsByAgentPolicyId = new Map<string, AgentPolicyLookupResult>();
  const failuresByAgentPolicyId = new Map<string, string>();

  for (const agentPolicyId of lookupIds) {
    try {
      const status = await agentClient.getAgentStatusForAgentPolicy(agentPolicyId);

      resultsByAgentPolicyId.set(agentPolicyId, {
        enrolledAgents: Math.max(status.all - status.unenrolled, 0),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      logger.warn(
        `collectAssignmentEvidence(): agent status lookup failed for agent policy [${agentPolicyId}]: ${message}`
      );
      failuresByAgentPolicyId.set(agentPolicyId, message);
    }
  }

  return policies.map((policy) => {
    const agentPolicyIds = agentPolicyIdsByPolicy.get(policy.id) ?? [];

    if (agentPolicyIds.length === 0) {
      return {
        policyId: policy.id,
        agentPolicyIds,
        status: 'counted',
        agentCount: 0,
        detail:
          'This policy is not assigned to any agent policy, so no agent lookup was required; the ' +
          'count is the sum over an empty set of agent policies, not a Fleet-reported number.',
      };
    }

    const notLookedUp = agentPolicyIds.filter((id) => skippedIds.has(id));
    const failed = agentPolicyIds.filter((id) => failuresByAgentPolicyId.has(id));

    if (notLookedUp.length > 0 || failed.length > 0) {
      const reasons: string[] = [];

      if (notLookedUp.length > 0) {
        reasons.push(
          `${notLookedUp.length} of ${agentPolicyIds.length} assigned agent policies were not ` +
            `interrogated because the per-request bound of ${maxAgentPolicyLookups} agent-policy ` +
            `lookups was reached (not interrogated: ${notLookedUp.join(', ')})`
        );
      }

      for (const id of failed) {
        reasons.push(
          `the agent lookup for agent policy ${id} failed: ${failuresByAgentPolicyId.get(id)}`
        );
      }

      return {
        policyId: policy.id,
        agentPolicyIds,
        status: 'lookup_incomplete',
        detail: `${reasons.join(
          '; '
        )}. Any total would cover only part of this policy's agent policies, so no count is reported.`,
      };
    }

    const agentCount = agentPolicyIds.reduce(
      (total, id) => total + (resultsByAgentPolicyId.get(id)?.enrolledAgents ?? 0),
      0
    );

    return {
      policyId: policy.id,
      agentPolicyIds,
      status: 'counted',
      agentCount,
      detail:
        `Counted agents still enrolled in ${agentPolicyIds.length} agent polic` +
        `${agentPolicyIds.length === 1 ? 'y' : 'ies'} via Fleet agent enrollment records ` +
        '(offline and inactive agents are counted as enrolled).',
    };
  });
};
