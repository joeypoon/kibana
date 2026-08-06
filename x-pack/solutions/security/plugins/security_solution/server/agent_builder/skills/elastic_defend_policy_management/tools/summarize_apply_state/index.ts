/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType } from '@kbn/agent-builder-common/tools';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import type {
  PolicyApplyStateClassifiedSummary,
  PolicyApplyStateExemplar,
  PolicyApplyStatePrivilegeAbsentSummary,
} from '../../services/policy_apply_state';
import { summarizePolicyApplyState } from '../../services/policy_apply_state';
import { buildScopeDisclosure } from '../../services/policy_read';
import type { DefendPolicyManagementSkillDeps } from '../../deps';
import { resolvePolicyServices } from '../../deps';
import { MAX_EXEMPLAR_STRING_CHARS, truncateBoundedString } from '../../lib/bounded_result';
import {
  PER_ENDPOINT_DIAGNOSIS_ROUTING_STATEMENT,
  REVISION_IDENTITY_ONLY_STATEMENT,
  toPrivilegeBasisPayload,
  toScopeDisclosurePayload,
  toolDenial,
  toolException,
  toolSuccess,
} from '../../lib/tool_results';

export const SUMMARIZE_DEFEND_POLICY_APPLY_STATE_TOOL_ID =
  'security.summarize_defend_policy_apply_state';

const summarizeDefendPolicyApplyStateSchema = z.object({}).strict();

interface ApplyStateExemplarPayload {
  readonly endpoint_id: string;
  readonly host_name: string;
  readonly classification: string;
  readonly applied_endpoint_policy_id: string;
  readonly applied_endpoint_policy_revision: number;
  readonly applied_agent_policy_revision: number;
  readonly configured_endpoint_policy_id?: string;
  readonly configured_endpoint_policy_revision?: number;
  readonly configured_agent_policy_revision?: number;
  readonly host_status: string;
  readonly last_checkin?: string;
}

const toExemplarPayload = ({
  endpointId,
  hostName,
  classification,
  appliedEndpointPolicyId,
  appliedEndpointPolicyRevision,
  appliedAgentPolicyRevision,
  configuredEndpointPolicyId,
  configuredEndpointPolicyRevision,
  configuredAgentPolicyRevision,
  hostStatus,
  lastCheckin,
}: PolicyApplyStateExemplar): ApplyStateExemplarPayload => ({
  endpoint_id: endpointId,
  host_name: truncateBoundedString(hostName, MAX_EXEMPLAR_STRING_CHARS),
  classification,
  applied_endpoint_policy_id: appliedEndpointPolicyId,
  applied_endpoint_policy_revision: appliedEndpointPolicyRevision,
  applied_agent_policy_revision: appliedAgentPolicyRevision,
  ...(configuredEndpointPolicyId === undefined
    ? {}
    : { configured_endpoint_policy_id: configuredEndpointPolicyId }),
  ...(configuredEndpointPolicyRevision === undefined
    ? {}
    : { configured_endpoint_policy_revision: configuredEndpointPolicyRevision }),
  ...(configuredAgentPolicyRevision === undefined
    ? {}
    : { configured_agent_policy_revision: configuredAgentPolicyRevision }),
  host_status: hostStatus,
  ...(lastCheckin === undefined ? {} : { last_checkin: lastCheckin }),
});

export const createSummarizeDefendPolicyApplyStateTool = (
  deps: DefendPolicyManagementSkillDeps
): BuiltinSkillBoundedTool<typeof summarizeDefendPolicyApplyStateSchema> => ({
  id: SUMMARIZE_DEFEND_POLICY_APPLY_STATE_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Summarize, fleet-wide, how the Elastic Defend policy each endpoint reports as APPLIED compares ' +
    'with what is currently CONFIGURED: aggregate endpoint counts classified as current, ' +
    'revision_lag (same policy, older revision), identity_mismatch (a different policy than now ' +
    'configured), or unknown (could not be classified), with a few exemplars, evidence freshness, ' +
    'and completeness disclosures. Use for "are my endpoints behind on policy" and rollout-lag ' +
    'questions. Reports revision/identity lag ONLY — it cannot show setting-level applied ' +
    'differences. For one specific host, use the elastic-defend-configuration-troubleshooting ' +
    'skill instead. Read-only.',
  schema: summarizeDefendPolicyApplyStateSchema,
  handler: async (_input, { request }) => {
    try {
      const resolved = await resolvePolicyServices({ deps, request });
      if (!resolved.ok) {
        return toolDenial(resolved.denial);
      }

      const services = resolved.value;
      const outcome = await summarizePolicyApplyState({
        request,
        privilegeBasis: services.privilegeBasis,
        getEndpointAuthz: services.authorizationDeps.getEndpointAuthz,
        scopedServices: services.getScopedEndpointServices(),
        isCcsEnabled: services.isCcsEnabled,
        getSoClient: services.getSoClient,
        packagePolicyService: services.packagePolicyService,
        agentPolicyService: services.agentPolicyService,
      });

      if (!outcome.ok) {
        return toolDenial(outcome.denial);
      }

      const summary = outcome.value;

      if (summary.populationStatus === 'privilege_absent') {
        return toolSuccess(toPrivilegeAbsentPayload(summary), {
          logger: deps.logger,
          toolId: SUMMARIZE_DEFEND_POLICY_APPLY_STATE_TOOL_ID,
        });
      }

      return toolSuccess(toClassifiedPayload(summary), {
        logger: deps.logger,
        toolId: SUMMARIZE_DEFEND_POLICY_APPLY_STATE_TOOL_ID,
      });
    } catch (error) {
      return toolException(error, {
        logger: deps.logger,
        toolId: SUMMARIZE_DEFEND_POLICY_APPLY_STATE_TOOL_ID,
        operation: 'summarizing assigned-versus-applied Elastic Defend policy state',
      });
    }
  },
});

const toClassifiedPayload = (summary: PolicyApplyStateClassifiedSummary) => {
  const {
    totalEndpoints,
    endpointQueryTotal,
    packagePolicyLoad,
    currentCount,
    revisionLagCount,
    identityMismatchCount,
    unknownCount,
    staleOrOfflineCount,
  } = summary;

  const packagePolicyDisclosure = packagePolicyLoad.complete
    ? undefined
    : summary.disclosures.find(
        ({ reason, detail }) => reason === 'result_limit_reached' && detail.includes('omitted')
      );
  const boundDisclosure = summary.disclosures.find(
    ({ reason, detail }) =>
      reason === 'result_limit_reached' && detail.includes('endpoints matching')
  );
  const partial = packagePolicyDisclosure ?? boundDisclosure;

  return {
    message: buildClassifiedMessage(summary),
    population_status: summary.populationStatus,
    endpoints: {
      total: totalEndpoints,
      current: currentCount,
      revision_lag: revisionLagCount,
      identity_mismatch: identityMismatchCount,
      unknown: unknownCount,
      stale_or_offline: staleOrOfflineCount,
    },
    exemplars: {
      revision_lag: summary.exemplars.revisionLag.map(toExemplarPayload),
      identity_mismatch: summary.exemplars.identityMismatch.map(toExemplarPayload),
    },
    freshness: {
      ...(summary.freshness.latestEndpointTimestamp === undefined
        ? {}
        : { latest_endpoint_timestamp: summary.freshness.latestEndpointTimestamp }),
    },
    bounded: summary.bounded,
    disclosures: summary.disclosures,
    scope_disclosure: {
      ...toScopeDisclosurePayload(
        buildScopeDisclosure({
          privilegeBasis: summary.privilegeBasis,
          returned: totalEndpoints,
          total: endpointQueryTotal,
          ...(partial === undefined ? {} : { partial }),
        })
      ),
      ...(packagePolicyLoad.complete
        ? {}
        : {
            omitted_policy_count: packagePolicyLoad.omitted,
            endpoint_query_scope: 'loaded_policies_only' as const,
          }),
    },
    revision_identity_only: REVISION_IDENTITY_ONLY_STATEMENT,
    per_endpoint_diagnosis: PER_ENDPOINT_DIAGNOSIS_ROUTING_STATEMENT,
  };
};

const toPrivilegeAbsentPayload = (summary: PolicyApplyStatePrivilegeAbsentSummary) => {
  const disclosure = summary.disclosures.find(({ reason }) => reason === 'missing_privilege');
  const detail = disclosure?.detail ?? 'the required endpoint-telemetry privilege is absent.';
  const continuation = disclosure?.continuation ?? '';

  return {
    message:
      `The assigned-versus-applied summary could not read endpoint data: ${detail} ${continuation}`.trim(),
    population_status: summary.populationStatus,
    scope_disclosure: {
      privilege_basis: toPrivilegeBasisPayload(summary.privilegeBasis),
      ...(disclosure === undefined
        ? {}
        : {
            partial: disclosure,
          }),
    },
    revision_identity_only: REVISION_IDENTITY_ONLY_STATEMENT,
    per_endpoint_diagnosis: PER_ENDPOINT_DIAGNOSIS_ROUTING_STATEMENT,
  };
};

const buildClassifiedMessage = (summary: PolicyApplyStateClassifiedSummary): string => {
  const {
    totalEndpoints,
    currentCount,
    revisionLagCount,
    identityMismatchCount,
    unknownCount,
    staleOrOfflineCount,
    packagePolicyLoad,
  } = summary;

  const parts = [
    `Assigned-versus-applied policy state for ${totalEndpoints} endpoint${
      totalEndpoints === 1 ? '' : 's'
    } you can see: ${currentCount} current, ${revisionLagCount} behind on revision, ` +
      `${identityMismatchCount} on a different policy identity than now configured, and ` +
      `${unknownCount} that could not be classified.`,
  ];

  if (staleOrOfflineCount > 0) {
    parts.push(
      `${staleOrOfflineCount} endpoint${
        staleOrOfflineCount === 1 ? ' is' : 's are'
      } offline or inactive; their applied state reflects their last successful check-in, not their current configuration.`
    );
  }

  if (!packagePolicyLoad.complete) {
    parts.push(
      `Package-policy loading stopped after ${packagePolicyLoad.loaded} of ${packagePolicyLoad.total} Elastic Defend policies (${packagePolicyLoad.omitted} omitted). Endpoint counts and Elasticsearch totals cover only the loaded policies, not the full estate.`
    );
  }

  if (summary.bounded) {
    parts.push(
      'The summary stopped at its endpoint work bound, so it does not cover every endpoint matching the loaded Elastic Defend policies; the result_limit_reached disclosure names the scanned count and the Elasticsearch total for that loaded-policy query.'
    );
  }

  return parts.join(' ');
};
