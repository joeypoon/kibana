/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AgentClient } from '@kbn/fleet-plugin/server';
import type { Logger } from '@kbn/core/server';
import { removeVersionSuffixFromPolicyId } from '@kbn/fleet-plugin/common/services/version_specific_policies_utils';

import type { AssignmentEvidence } from '../../domain/read/types';

export const MAX_AFFECTED_POPULATION_LOOKUPS = 200;

export interface FetchAffectedPopulationArgs {
  readonly policyId: string;
  readonly agentPolicyIds: readonly string[];
  readonly canReadFleetAgents: boolean;
  readonly getAgentClient: () => AgentClient;
  readonly logger: Logger;
}

const uniqueBaseAgentPolicyIds = (policyIds: readonly string[]): string[] => {
  const baseIds = new Set<string>();

  for (const policyId of policyIds) {
    baseIds.add(removeVersionSuffixFromPolicyId(policyId));
  }

  return [...baseIds];
};

export const fetchAffectedPopulation = async ({
  policyId,
  agentPolicyIds,
  canReadFleetAgents,
  getAgentClient,
  logger,
}: FetchAffectedPopulationArgs): Promise<AssignmentEvidence> => {
  const uniqueAgentPolicyIds = uniqueBaseAgentPolicyIds(agentPolicyIds);

  if (uniqueAgentPolicyIds.length === 0) {
    return {
      policyId,
      agentPolicyIds: [],
      status: 'counted',
      agentCount: 0,
      detail:
        'Read from the Fleet package policy: it is not assigned to any agent policy, so no agent lookup was needed.',
    };
  }

  if (!canReadFleetAgents) {
    return {
      policyId,
      agentPolicyIds: uniqueAgentPolicyIds,
      status: 'privilege_absent',
      detail:
        'The affected agent population could not be determined: it requires the Fleet "Agents: Read" privilege. No agent count is reported, because Fleet reports zero agents to callers without that privilege and a zero could not be distinguished from a real absence.',
    };
  }

  if (uniqueAgentPolicyIds.length > MAX_AFFECTED_POPULATION_LOOKUPS) {
    return {
      policyId,
      agentPolicyIds: uniqueAgentPolicyIds,
      status: 'lookup_incomplete',
      detail: `The affected agent population is incomplete: ${uniqueAgentPolicyIds.length} distinct assigned agent policies exceed the lookup bound of ${MAX_AFFECTED_POPULATION_LOOKUPS}, so no total is reported.`,
    };
  }

  const agentClient = getAgentClient();

  let agentCount = 0;

  for (const agentPolicyId of uniqueAgentPolicyIds) {
    try {
      const { active } = await agentClient.getAgentStatusForAgentPolicy(agentPolicyId);

      agentCount += active;
    } catch (error) {
      logger.debug(
        `fetchAffectedPopulation(): agent status lookup failed for agent policy [${agentPolicyId}]: ${error.message}`
      );

      return {
        policyId,
        agentPolicyIds: uniqueAgentPolicyIds,
        status: 'lookup_incomplete',
        detail: `The affected agent population is incomplete: the Fleet agent-status lookup for agent policy [${agentPolicyId}] failed, so no total is reported.`,
      };
    }
  }

  const assignmentEvidence: AssignmentEvidence = {
    policyId,
    agentPolicyIds: uniqueAgentPolicyIds,
    status: 'counted',
    agentCount,
    detail: `Counted agents currently active in Fleet agent enrollment records across ${
      uniqueAgentPolicyIds.length
    } assigned agent ${
      uniqueAgentPolicyIds.length === 1 ? 'policy' : 'policies'
    } (inactive and unenrolled agents are excluded).`,
  };

  return assignmentEvidence;
};
