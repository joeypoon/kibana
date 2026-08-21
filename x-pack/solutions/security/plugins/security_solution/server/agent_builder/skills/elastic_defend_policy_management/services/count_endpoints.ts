/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SavedObjectsErrorHelpers } from '@kbn/core/server';
import { KQLSyntaxError } from '@kbn/es-query';
import {
  AgentStatusKueryHelper,
  buildPolicyBaseIdsWithFallbackKuery,
} from '@kbn/fleet-plugin/common/services';
import type { HasAtLeast } from './access_context';
import { PolicyNotFoundError } from './policy_errors';
import {
  getPackagePolicyById,
  isRecognizedLookupMiss,
  uniqueAgentPolicyIds,
} from './policy_lookup';

export type EndpointCountSource = 'fleet_status_aggregation' | 'no_agent_policy_assignments';

export type EndpointCountResult = Readonly<{
  population: 'enrolled_agents';
  source: EndpointCountSource;
  status: Readonly<Record<string, number>>;
}>;

const EMPTY_ENROLLED_AGENT_COUNT: EndpointCountResult = {
  population: 'enrolled_agents',
  source: 'no_agent_policy_assignments',
  status: {},
};

const hasHttpStatus = (error: Error, statusCode: number): boolean =>
  ('statusCode' in error && error.statusCode === statusCode) ||
  ('output' in error &&
    typeof error.output === 'object' &&
    error.output != null &&
    'statusCode' in error.output &&
    error.output.statusCode === statusCode);

const isCollapseQueryRejected = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  if (error instanceof KQLSyntaxError || error.name === 'KQLSyntaxError') {
    return true;
  }

  if (error.message.startsWith('KQLSyntaxError')) {
    return true;
  }

  if (SavedObjectsErrorHelpers.isBadRequestError(error) || hasHttpStatus(error, 400)) {
    return true;
  }

  if ('meta' in error && error.meta instanceof Error && error.meta !== error) {
    return isCollapseQueryRejected(error.meta);
  }

  return false;
};

const toNumericOwnStatus = (summary: unknown): Record<string, number> => {
  if (summary == null || typeof summary !== 'object') {
    return {};
  }

  const status: Record<string, number> = {};

  for (const [key, value] of Object.entries(summary)) {
    if (typeof value === 'number' && Number.isFinite(value)) {
      status[key] = value;
    }
  }

  return status;
};

const sumNumericOwnStatuses = (summaries: readonly unknown[]): Record<string, number> => {
  const totals: Record<string, number> = {};

  for (const summary of summaries) {
    for (const [key, value] of Object.entries(toNumericOwnStatus(summary))) {
      totals[key] = (totals[key] ?? 0) + value;
    }
  }

  return totals;
};

const buildExcludeUnenrolledAgentsKuery = (): string =>
  `not (${AgentStatusKueryHelper.buildKueryForUnenrolledAgents()})`;

const buildEnrolledAgentsFilterKuery = (policyKuery?: string): string => {
  const excludeUnenrolled = buildExcludeUnenrolledAgentsKuery();

  if (policyKuery === undefined || policyKuery.length === 0) {
    return excludeUnenrolled;
  }

  return `(${policyKuery}) and ${excludeUnenrolled}`;
};

const ensurePolicyInCurrentSpace = async (
  access: HasAtLeast<'estate_read'>,
  policyId: string
): Promise<void> => {
  try {
    await access.fleet.ensureInCurrentSpace({ integrationPolicyIds: [policyId] });
  } catch (error) {
    if (error instanceof Error && isRecognizedLookupMiss(error)) {
      throw new PolicyNotFoundError(policyId);
    }

    throw error;
  }
};

const getEnrolledAgentStatus = async (
  access: HasAtLeast<'estate_read'>,
  agentPolicyIds: readonly string[]
): Promise<Record<string, number>> => {
  const [singleId] = agentPolicyIds;

  if (agentPolicyIds.length === 1 && singleId !== undefined) {
    return toNumericOwnStatus(
      await access.fleet.agent.getAgentStatusForAgentPolicy(
        singleId,
        buildEnrolledAgentsFilterKuery()
      )
    );
  }

  try {
    return toNumericOwnStatus(
      await access.fleet.agent.getAgentStatusForAgentPolicy(
        undefined,
        buildEnrolledAgentsFilterKuery(buildPolicyBaseIdsWithFallbackKuery([...agentPolicyIds]))
      )
    );
  } catch (error) {
    if (!isCollapseQueryRejected(error)) {
      throw error;
    }
  }

  const summaries: unknown[] = [];

  for (const agentPolicyId of agentPolicyIds) {
    summaries.push(
      await access.fleet.agent.getAgentStatusForAgentPolicy(
        agentPolicyId,
        buildEnrolledAgentsFilterKuery()
      )
    );
  }

  return sumNumericOwnStatuses(summaries);
};

export const countEndpoints = async (
  access: HasAtLeast<'estate_read'>,
  args: Readonly<{ policyId: string }>
): Promise<EndpointCountResult> => {
  const policyId = args.policyId.trim();

  await ensurePolicyInCurrentSpace(access, policyId);

  const policy = await getPackagePolicyById(access, policyId);

  if (policy === undefined || policy.package?.name !== 'endpoint') {
    throw new PolicyNotFoundError(policyId);
  }

  const agentPolicyIds = uniqueAgentPolicyIds(policy.policy_ids);

  if (agentPolicyIds.length === 0) {
    return EMPTY_ENROLLED_AGENT_COUNT;
  }

  return {
    population: 'enrolled_agents',
    source: 'fleet_status_aggregation',
    status: await getEnrolledAgentStatus(access, agentPolicyIds),
  };
};
