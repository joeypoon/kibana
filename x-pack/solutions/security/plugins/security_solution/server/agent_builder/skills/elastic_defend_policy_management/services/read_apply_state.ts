/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest } from '@kbn/core/server';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import { INITIAL_POLICY_ID } from '../../../../endpoint/routes/policy';
import {
  evaluateUnitedOutOfDate,
  buildUnitedApplyStateSearch,
} from './apply_state/apply_state_united_aggregation';
import { normalizeIntegerRevision } from './apply_state/normalize_integer_revision';
import {
  LATEST_POLICY_RESPONSE_AGENT_TERMS_SIZE,
  searchLatestPolicyResponses,
  type LatestPolicyResponseHit,
} from '../../../../endpoint/services/policy_response/latest_policy_response_aggregation';
import type { HasAtLeast } from './access_context';
import { PolicyNotFoundError } from './policy_errors';
import { getPackagePolicyById, uniqueAgentPolicyIds } from './policy_lookup';
import { getEndpointPolicy, type PolicyIdentity } from './read_policy';

export type OutOfDateSource =
  | 'united_metadata_tuple_aggregation'
  | 'no_agent_policy_assignments'
  | 'united_index_missing';

export type FailureSource =
  | 'policy_response_latest_per_agent'
  | 'no_agent_policy_assignments'
  | 'united_index_missing'
  | 'united_agent_id_set_empty';

export type OutOfDateCount = Readonly<{
  value: number;
  classified_hosts: number;
  unclassified_overflow_hosts: number;
  truncated: boolean;
  source: OutOfDateSource;
  population: 'readable_united_endpoint_hosts_canonical_assignment_matches_target_agent_policy_ids';
}>;

export type FailureCount = Readonly<{
  value: number;
  classified_hosts: number;
  upstream_unclassified_hosts: number;
  response_unclassified_agents: number;
  truncated: boolean;
  source: FailureSource;
  population: 'latest_policy_responses_current_package_revision';
}>;

export type ApplyStateDto = Readonly<{
  policy: Pick<PolicyIdentity, 'id' | 'name' | 'revision'>;
  spaceId: string;
  out_of_date: OutOfDateCount;
  current_policy_response_failures: FailureCount;
}>;

const OUT_OF_DATE_POPULATION =
  'readable_united_endpoint_hosts_canonical_assignment_matches_target_agent_policy_ids' as const;
const FAILURE_POPULATION = 'latest_policy_responses_current_package_revision' as const;

const APPLY_STATE_POLICY_RESPONSE_SOURCE_FIELDS = [
  '_id',
  'agent.id',
  'host.os.name',
  'Endpoint.policy.applied.actions',
  'Endpoint.policy.applied.id',
  'Endpoint.policy.applied.version',
  'Endpoint.policy.applied.endpoint_policy_version',
] as const;

const isIndexNotFoundException = (error: unknown): boolean => {
  if (error == null || typeof error !== 'object') {
    return false;
  }

  const candidate = error as {
    meta?: { body?: { error?: { type?: unknown } } };
    body?: { error?: { type?: unknown } };
  };

  return (
    candidate.meta?.body?.error?.type === 'index_not_found_exception' ||
    candidate.body?.error?.type === 'index_not_found_exception'
  );
};

const toPolicyIdentity = (
  policy: Pick<PolicyIdentity, 'id' | 'name' | 'revision'>
): Pick<PolicyIdentity, 'id' | 'name' | 'revision'> => ({
  id: policy.id,
  name: policy.name,
  revision: policy.revision,
});

const toOutOfDateCount = (
  source: OutOfDateSource,
  counts: Readonly<{
    value: number;
    classifiedHosts: number;
    overflowHosts: number;
  }>
): OutOfDateCount => ({
  value: counts.value,
  classified_hosts: counts.classifiedHosts,
  unclassified_overflow_hosts: counts.overflowHosts,
  truncated: counts.overflowHosts > 0,
  source,
  population: OUT_OF_DATE_POPULATION,
});

const toFailureCount = (
  source: FailureSource,
  counts: Readonly<{
    value: number;
    classifiedHosts: number;
    upstreamUnclassifiedHosts: number;
    responseUnclassifiedAgents: number;
  }>
): FailureCount => ({
  value: counts.value,
  classified_hosts: counts.classifiedHosts,
  upstream_unclassified_hosts: counts.upstreamUnclassifiedHosts,
  response_unclassified_agents: counts.responseUnclassifiedAgents,
  truncated: counts.upstreamUnclassifiedHosts > 0 || counts.responseUnclassifiedAgents > 0,
  source,
  population: FAILURE_POPULATION,
});

const EMPTY_OUT_OF_DATE_COUNTS = {
  value: 0,
  classifiedHosts: 0,
  overflowHosts: 0,
} as const;

const EMPTY_FAILURE_COUNTS = {
  value: 0,
  classifiedHosts: 0,
  upstreamUnclassifiedHosts: 0,
  responseUnclassifiedAgents: 0,
} as const;

const hasFailureOrWarningAction = (actions: unknown): boolean => {
  if (!Array.isArray(actions)) {
    return false;
  }

  return actions.some((action) => {
    if (action == null || typeof action !== 'object') {
      return false;
    }

    const { status } = action as { status?: unknown };
    return status === 'failure' || status === 'warning';
  });
};

const isCurrentPolicyResponseFailure = (
  hit: LatestPolicyResponseHit,
  packagePolicy: Readonly<{ id: string; revision: number }>
): boolean => {
  const applied = hit._source?.Endpoint?.policy?.applied;

  if (applied == null || typeof applied !== 'object') {
    return false;
  }

  const { id, endpoint_policy_version: endpointPolicyVersion } = applied;

  if (id === INITIAL_POLICY_ID) {
    return false;
  }

  if (id !== packagePolicy.id) {
    return false;
  }

  if (normalizeIntegerRevision(endpointPolicyVersion) !== packagePolicy.revision) {
    return false;
  }

  return hasFailureOrWarningAction(applied.actions);
};

const loadConfiguredRevisions = async (
  access: HasAtLeast<'estate_read'>,
  agentPolicyIds: readonly string[]
): Promise<Readonly<Record<string, { id: string; revision: number }>>> => {
  const agentPolicies = await access.fleet.agentPolicy.getByIds(
    access.fleet.getSoClient(),
    [...agentPolicyIds],
    { ignoreMissing: true }
  );
  const configuredByAgentPolicyId: Record<string, { id: string; revision: number }> = {};

  for (const agentPolicy of agentPolicies) {
    configuredByAgentPolicyId[agentPolicy.id] = {
      id: agentPolicy.id,
      revision: agentPolicy.revision,
    };
  }

  return configuredByAgentPolicyId;
};

export const readApplyState = async (
  access: HasAtLeast<'estate_read'>,
  endpointAppContextService: EndpointAppContextService,
  input: Readonly<{ idOrName: string }>,
  request: KibanaRequest
): Promise<ApplyStateDto> => {
  const resolved = await getEndpointPolicy(access, { idOrName: input.idOrName });
  const policy = toPolicyIdentity(resolved.policy);
  const spaceId = access.spaceId;
  const packagePolicy = await getPackagePolicyById(access, resolved.policy.id);

  if (packagePolicy === undefined || packagePolicy.package?.name !== 'endpoint') {
    throw new PolicyNotFoundError(resolved.policy.id);
  }

  const agentPolicyIds = uniqueAgentPolicyIds(packagePolicy.policy_ids);

  if (agentPolicyIds.length === 0) {
    return {
      policy,
      spaceId,
      out_of_date: toOutOfDateCount('no_agent_policy_assignments', EMPTY_OUT_OF_DATE_COUNTS),
      current_policy_response_failures: toFailureCount(
        'no_agent_policy_assignments',
        EMPTY_FAILURE_COUNTS
      ),
    };
  }

  const configuredByAgentPolicyId = await loadConfiguredRevisions(access, agentPolicyIds);
  const esClient = endpointAppContextService.getReadEsClient(request);
  const ccsEnabled = await endpointAppContextService.isCcsEnabled();
  const isCpsRead = endpointAppContextService.isCpsRead(request);
  const currentPackagePolicy = { id: packagePolicy.id, revision: packagePolicy.revision };

  let unitedAggregations: unknown;

  try {
    const unitedResult = await esClient.search(
      buildUnitedApplyStateSearch({
        agentPolicyIds,
        ccsEnabled,
        ...(isCpsRead ? { cpsSpaceId: spaceId } : {}),
      })
    );
    unitedAggregations = unitedResult.aggregations;
  } catch (error) {
    if (isIndexNotFoundException(error)) {
      return {
        policy,
        spaceId,
        out_of_date: toOutOfDateCount('united_index_missing', EMPTY_OUT_OF_DATE_COUNTS),
        current_policy_response_failures: toFailureCount(
          'united_index_missing',
          EMPTY_FAILURE_COUNTS
        ),
      };
    }

    throw error;
  }

  const evaluation = evaluateUnitedOutOfDate({
    aggregations: unitedAggregations,
    packagePolicy: currentPackagePolicy,
    configuredByAgentPolicyId,
  });
  const outOfDate = toOutOfDateCount('united_metadata_tuple_aggregation', {
    value: evaluation.outOfDateHosts,
    classifiedHosts: evaluation.classifiedHosts,
    overflowHosts: evaluation.overflowHosts,
  });

  if (evaluation.agentIds.length === 0) {
    return {
      policy,
      spaceId,
      out_of_date: outOfDate,
      current_policy_response_failures: toFailureCount('united_agent_id_set_empty', {
        ...EMPTY_FAILURE_COUNTS,
        upstreamUnclassifiedHosts: evaluation.agentOverflow,
      }),
    };
  }

  const latestResponses = await searchLatestPolicyResponses(esClient, {
    agentIds: evaluation.agentIds,
    termsSize: LATEST_POLICY_RESPONSE_AGENT_TERMS_SIZE,
    ccsEnabled: ccsEnabled && !isCpsRead,
    sourceFields: APPLY_STATE_POLICY_RESPONSE_SOURCE_FIELDS,
    excludeInitialPolicy: false,
  });

  return {
    policy,
    spaceId,
    out_of_date: outOfDate,
    current_policy_response_failures: toFailureCount('policy_response_latest_per_agent', {
      value: latestResponses.hits.filter((hit) =>
        isCurrentPolicyResponseFailure(hit, currentPackagePolicy)
      ).length,
      classifiedHosts: latestResponses.hits.length,
      upstreamUnclassifiedHosts: evaluation.agentOverflow,
      responseUnclassifiedAgents: latestResponses.overflowAgents,
    }),
  };
};
