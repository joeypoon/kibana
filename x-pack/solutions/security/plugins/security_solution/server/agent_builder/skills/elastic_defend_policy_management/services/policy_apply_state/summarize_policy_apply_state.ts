/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { uniq } from 'lodash';
import type { KibanaRequest } from '@kbn/core-http-server';
import type { SavedObjectsClientContract } from '@kbn/core-saved-objects-api-server';
import type { SearchHit, SearchTotalHits } from '@elastic/elasticsearch/lib/api/types';
import type { AgentPolicy, PackagePolicy } from '@kbn/fleet-plugin/common';
import type { AgentPolicyServiceInterface, PackagePolicyClient } from '@kbn/fleet-plugin/server';
import { removeVersionSuffixFromPolicyId } from '@kbn/fleet-plugin/common/services/version_specific_policies_utils';
import type {
  HostInfo,
  HostMetadata,
  UnitedAgentMetadataPersistedData,
} from '../../../../../../common/endpoint/types';
import { HostStatus } from '../../../../../../common/endpoint/types';
import type { PartialResultDisclosure, PolicyReadPrivilegeBasis } from '../../domain/read/types';
import { isPolicyOutOfDate } from '../../../../../../common/endpoint/service/policy/apply_state';
import { buildUnitedIndexQuery } from '../../../../../endpoint/routes/metadata/query_builders';
import { mapToHostMetadata } from '../../../../../endpoint/routes/metadata/support/query_strategies';
import {
  catchAndWrapError,
  DEFAULT_ENDPOINT_HOST_STATUS,
  fleetAgentStatusToEndpointHostStatus,
} from '../../../../../endpoint/utils';
import type { ScopedEndpointServices } from '../../../../../endpoint/endpoint_app_context_services';
import type { PolicyReadAuthorizationDependencies, PolicyReadOutcome } from '../policy_read';
import {
  DEFAULT_MAX_LOADED_PACKAGE_POLICIES,
  loadEndpointPackagePolicies,
} from './load_endpoint_package_policies';
import type {
  PolicyApplyStateClassification,
  PolicyApplyStateExemplar,
  PolicyApplyStatePackagePolicyLoad,
  PolicyApplyStateSummary,
} from './types';

export const DEFAULT_MAX_ENDPOINTS = 10_000;

export const DEFAULT_EXEMPLAR_LIMIT = 5;

export type PolicyApplyStatePackagePolicyService = Pick<
  PackagePolicyClient,
  'fetchAllItems' | 'list'
>;

export type PolicyApplyStateAgentPolicyService = Pick<AgentPolicyServiceInterface, 'getByIds'>;

export interface SummarizePolicyApplyStateArgs {
  readonly request: KibanaRequest;
  readonly privilegeBasis: PolicyReadPrivilegeBasis;
  readonly getEndpointAuthz: PolicyReadAuthorizationDependencies['getEndpointAuthz'];
  readonly scopedServices: ScopedEndpointServices;
  readonly isCcsEnabled: () => Promise<boolean>;
  readonly getSoClient: () => SavedObjectsClientContract;
  readonly packagePolicyService: PolicyApplyStatePackagePolicyService;
  readonly agentPolicyService: PolicyApplyStateAgentPolicyService;
  readonly maxEndpoints?: number;
  readonly maxLoadedPackagePolicies?: number;
  readonly packagePolicyPageSize?: number;
  readonly exemplarLimit?: number;
}

export const summarizePolicyApplyState = async ({
  request,
  privilegeBasis,
  getEndpointAuthz,
  scopedServices,
  isCcsEnabled,
  getSoClient,
  packagePolicyService,
  agentPolicyService,
  maxEndpoints = DEFAULT_MAX_ENDPOINTS,
  maxLoadedPackagePolicies = DEFAULT_MAX_LOADED_PACKAGE_POLICIES,
  packagePolicyPageSize,
  exemplarLimit = DEFAULT_EXEMPLAR_LIMIT,
}: SummarizePolicyApplyStateArgs): Promise<PolicyReadOutcome<PolicyApplyStateSummary>> => {
  const endpointAuthz = await getEndpointAuthz(request);
  const spaceId = scopedServices.getSpaceId();

  if (!endpointAuthz.canReadSecuritySolution) {
    return {
      ok: true,
      value: {
        populationStatus: 'privilege_absent',
        privilegeBasis,
        spaceId,
        disclosures: [createMetadataPrivilegeDisclosure(privilegeBasis)],
      },
    };
  }

  const soClient = getSoClient();

  const packagePolicyLoad = await loadEndpointPackagePolicies(packagePolicyService, soClient, {
    spaceId,
    maxLoaded: maxLoadedPackagePolicies,
    ...(packagePolicyPageSize === undefined ? {} : { pageSize: packagePolicyPageSize }),
  });
  const endpointPolicies = packagePolicyLoad.items;
  const endpointPolicyIds = uniqueBasePolicyIds(
    endpointPolicies.flatMap((policy) => policy.policy_ids ?? [])
  );

  const cpsRead = scopedServices.isCpsRead();
  const ccsEnabled = await isCcsEnabled();

  const query = await buildUnitedIndexQuery(
    soClient,
    { page: 0, pageSize: maxEndpoints },
    endpointPolicyIds,
    ccsEnabled,
    cpsRead && packagePolicyLoad.complete ? spaceId : undefined
  );

  const response = await scopedServices
    .getEsClient()
    .search<UnitedAgentMetadataPersistedData>(query)
    .catch(catchAndWrapError);

  const { hits: docs, total: docsCount } = response?.hits ?? {};
  const endpointQueryTotal = (docsCount as unknown as SearchTotalHits)?.value ?? 0;
  const scanned = (docs ?? []).length;

  const agentPolicyIds = uniqueBasePolicyIds(
    (docs ?? []).map((doc) => doc._source?.united?.agent?.policy_id ?? '')
  );

  const agentPolicies =
    agentPolicyIds.length === 0
      ? []
      : (await agentPolicyService
          .getByIds(soClient, agentPolicyIds, { ignoreMissing: true })
          .catch(catchAndWrapError)) ?? [];

  const agentPoliciesMap = agentPolicies.reduce<Record<string, AgentPolicy>>((acc, policy) => {
    acc[removeVersionSuffixFromPolicyId(policy.id)] = { ...policy };
    return acc;
  }, {});

  const endpointPoliciesMap = endpointPolicies.reduce<Record<string, PackagePolicy>>(
    (acc, packagePolicy) => {
      for (const policyId of packagePolicy.policy_ids ?? []) {
        const baseId = removeVersionSuffixFromPolicyId(policyId);
        if (baseId) {
          acc[baseId] = packagePolicy;
        }
      }
      return acc;
    },
    {}
  );

  const packagePolicyById = new Map(
    endpointPolicies.map((packagePolicy) => [packagePolicy.id, packagePolicy])
  );

  const disclosures: PartialResultDisclosure[] = [];

  if (!packagePolicyLoad.complete) {
    disclosures.push(createPackagePolicyLoadIncompleteDisclosure(packagePolicyLoad));
  }

  if (endpointQueryTotal > maxEndpoints) {
    disclosures.push(createEndpointResultBoundDisclosure(scanned, endpointQueryTotal));
  }

  const fold: MutableApplyStateFold = {
    currentCount: 0,
    revisionLagCount: 0,
    identityMismatchCount: 0,
    unknownCount: 0,
    staleOrOfflineCount: 0,
    timestampInterpretedCount: 0,
    latestTimestamp: undefined,
    revisionLagExemplars: [],
    identityMismatchExemplars: [],
  };

  for (const doc of docs ?? []) {
    foldDoc(fold, doc, agentPoliciesMap, endpointPoliciesMap, packagePolicyById, exemplarLimit);
  }

  const {
    currentCount,
    revisionLagCount,
    identityMismatchCount,
    unknownCount,
    staleOrOfflineCount,
    timestampInterpretedCount,
    latestTimestamp,
    revisionLagExemplars,
    identityMismatchExemplars,
  } = fold;

  if (unknownCount > 0) {
    disclosures.push({
      reason: 'upstream_failure',
      detail:
        `${unknownCount} endpoint${unknownCount === 1 ? '' : 's'} could not be classified ` +
        `because current Fleet policy data was unavailable.`,
      continuation:
        'This usually means the endpoint was recently enrolled or its policy was deleted. ' +
        'Re-run after the next check-in cycle.',
    });
  }

  if (staleOrOfflineCount > 0) {
    disclosures.push({
      reason: 'upstream_failure',
      detail:
        `${staleOrOfflineCount} endpoint${staleOrOfflineCount === 1 ? ' is' : 's are'} ` +
        `offline or inactive. Their reported applied state may be stale.`,
      continuation:
        'Applied state for offline endpoints reflects their last successful check-in, ' +
        'not their current configuration.',
    });
  }

  if (timestampInterpretedCount > 0 && latestTimestamp === undefined) {
    disclosures.push(createUndatedEndpointFreshnessDisclosure(timestampInterpretedCount));
  }

  return {
    ok: true,
    value: {
      populationStatus: 'classified',
      privilegeBasis,
      spaceId,
      totalEndpoints: scanned,
      endpointQueryTotal,
      packagePolicyLoad: {
        loaded: packagePolicyLoad.loaded,
        total: packagePolicyLoad.total,
        omitted: packagePolicyLoad.omitted,
        complete: packagePolicyLoad.complete,
      },
      currentCount,
      revisionLagCount,
      identityMismatchCount,
      unknownCount,
      staleOrOfflineCount,
      exemplars: {
        revisionLag: revisionLagExemplars,
        identityMismatch: identityMismatchExemplars,
      },
      freshness: {
        latestEndpointTimestamp:
          latestTimestamp === undefined ? undefined : new Date(latestTimestamp).toISOString(),
      },
      disclosures,
      bounded: endpointQueryTotal > maxEndpoints,
    },
  };
};

const createMetadataPrivilegeDisclosure = (
  privilegeBasis: PolicyReadPrivilegeBasis
): PartialResultDisclosure => {
  const heldPolicyRead = privilegeBasis.securityPolicyManagementRead
    ? 'Elastic Defend Policy Management read access'
    : 'Fleet agent-policies and integrations read access';

  return {
    reason: 'missing_privilege',
    detail:
      'The assigned-versus-applied summary reads endpoint telemetry, which requires read access ' +
      `to the Security app. You hold ${heldPolicyRead} but not that, so no endpoint data ` +
      'was read and no population figures are reported — not even zeros.',
    continuation:
      'Ask an administrator for read access to the Security app, or review configured policy ' +
      'state with the other Elastic Defend Policy Management tools, which need only policy read access.',
  };
};

const createPackagePolicyLoadIncompleteDisclosure = ({
  loaded,
  total,
  omitted,
}: PolicyApplyStatePackagePolicyLoad): PartialResultDisclosure => ({
  reason: 'result_limit_reached',
  detail:
    `The summary loaded ${loaded} of ${total} Elastic Defend package policies; ${omitted} ` +
    `${
      omitted === 1 ? 'policy was' : 'policies were'
    } omitted. Endpoint counts and Elasticsearch ` +
    `totals cover only the loaded policies, not the full estate.`,
  continuation:
    'This tool has no package-policy continuation input, so the omitted policies are not included.',
});

const createEndpointResultBoundDisclosure = (
  scanned: number,
  endpointQueryTotal: number
): PartialResultDisclosure => ({
  reason: 'result_limit_reached',
  detail:
    `The summary covers ${scanned} of ${endpointQueryTotal} endpoints matching the loaded ` +
    `Elastic Defend policies. Endpoints beyond this bound are not included.`,
  continuation:
    'This tool has no endpoint filter or list input; remaining matching endpoints are not in this result.',
});

const createUndatedEndpointFreshnessDisclosure = (scanned: number): PartialResultDisclosure => ({
  reason: 'upstream_failure',
  detail:
    `The summary scanned ${scanned} endpoint${scanned === 1 ? '' : 's'} that could not be dated, ` +
    `so evidence freshness could not be determined.`,
  continuation:
    'Freshness is omitted because the scanned endpoint documents could not be dated. ' +
    'Re-run after endpoints check in with metadata that includes @timestamp.',
});

const toCanonicalTimestampMs = (value: number | string | undefined): number | undefined => {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }

  if (typeof value !== 'string') {
    return undefined;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

const uniqueBasePolicyIds = (ids: readonly string[]): string[] =>
  uniq(ids.map((id) => removeVersionSuffixFromPolicyId(id)).filter((id) => id.length > 0));

type AgentDoc = UnitedAgentMetadataPersistedData['united']['agent'];

interface MutableApplyStateFold {
  currentCount: number;
  revisionLagCount: number;
  identityMismatchCount: number;
  unknownCount: number;
  staleOrOfflineCount: number;
  timestampInterpretedCount: number;
  latestTimestamp: number | undefined;
  revisionLagExemplars: PolicyApplyStateExemplar[];
  identityMismatchExemplars: PolicyApplyStateExemplar[];
}

const foldDoc = (
  fold: MutableApplyStateFold,
  doc: SearchHit<UnitedAgentMetadataPersistedData>,
  agentPoliciesMap: Record<string, AgentPolicy>,
  endpointPoliciesMap: Record<string, PackagePolicy>,
  packagePolicyById: Map<string, PackagePolicy>,
  exemplarLimit: number
): void => {
  const { endpoint, agent: agentDoc } = doc?._source?.united ?? {};
  if (!endpoint || !agentDoc) {
    fold.unknownCount++;
    return;
  }

  fold.timestampInterpretedCount++;

  const metadata = mapToHostMetadata(endpoint);
  const reported = metadata.Endpoint.policy.applied;

  const configuredAgentPolicyId = removeVersionSuffixFromPolicyId(agentDoc.policy_id ?? '');
  const configuredAgentPolicy = agentPoliciesMap[configuredAgentPolicyId];
  const configuredEndpointPolicy = endpointPoliciesMap[configuredAgentPolicyId];

  const appliedAgentPolicyId = resolveAppliedAgentPolicyId(
    reported.id,
    packagePolicyById,
    configuredAgentPolicyId
  );

  const policyInfo = buildPolicyInfo(
    agentDoc,
    configuredAgentPolicy,
    configuredEndpointPolicy,
    appliedAgentPolicyId
  );
  const classification = classifyEndpoint(reported, policyInfo);

  const runtimeStatus = doc?.fields?.status?.[0];
  const hostStatus = runtimeStatus
    ? fleetAgentStatusToEndpointHostStatus(runtimeStatus)
    : DEFAULT_ENDPOINT_HOST_STATUS;

  if (hostStatus === HostStatus.OFFLINE || hostStatus === HostStatus.INACTIVE) {
    fold.staleOrOfflineCount++;
  }

  const timestampMs = toCanonicalTimestampMs(metadata['@timestamp']);
  if (
    timestampMs !== undefined &&
    (fold.latestTimestamp === undefined || timestampMs > fold.latestTimestamp)
  ) {
    fold.latestTimestamp = timestampMs;
  }

  switch (classification) {
    case 'current':
      fold.currentCount++;
      break;
    case 'revision_lag':
      fold.revisionLagCount++;
      if (fold.revisionLagExemplars.length < exemplarLimit) {
        fold.revisionLagExemplars.push(
          toExemplar(metadata, policyInfo, classification, hostStatus, agentDoc, timestampMs)
        );
      }
      break;
    case 'identity_mismatch':
      fold.identityMismatchCount++;
      if (fold.identityMismatchExemplars.length < exemplarLimit) {
        fold.identityMismatchExemplars.push(
          toExemplar(metadata, policyInfo, classification, hostStatus, agentDoc, timestampMs)
        );
      }
      break;
    case 'unknown':
      fold.unknownCount++;
      break;
  }
};

const buildPolicyInfo = (
  agentDoc: AgentDoc,
  configuredAgentPolicy: AgentPolicy | undefined,
  configuredEndpointPolicy: PackagePolicy | undefined,
  appliedAgentPolicyId: string
): HostInfo['policy_info'] | undefined => {
  if (!configuredAgentPolicy || !configuredEndpointPolicy) {
    return undefined;
  }

  return {
    agent: {
      applied: {
        revision: agentDoc.policy_revision ?? 0,
        id: appliedAgentPolicyId,
      },
      configured: {
        revision: configuredAgentPolicy.revision,
        id: removeVersionSuffixFromPolicyId(configuredAgentPolicy.id),
      },
    },
    endpoint: {
      revision: configuredEndpointPolicy.revision,
      id: configuredEndpointPolicy.id,
    },
  };
};

const resolveAppliedAgentPolicyId = (
  reportedId: string,
  packagePolicyById: Map<string, PackagePolicy>,
  configuredAgentPolicyId: string
): string => {
  const appliedPackagePolicy = reportedId ? packagePolicyById.get(reportedId) : undefined;

  if (!appliedPackagePolicy || appliedPackagePolicy.policy_ids.length !== 1) {
    return configuredAgentPolicyId;
  }

  return removeVersionSuffixFromPolicyId(appliedPackagePolicy.policy_ids[0]);
};

const classifyEndpoint = (
  reported: HostMetadata['Endpoint']['policy']['applied'],
  current: HostInfo['policy_info'] | undefined
): PolicyApplyStateClassification => {
  if (!current || !reported.id) {
    return 'unknown';
  }

  if (
    reported.id !== current.endpoint.id ||
    current.agent.configured.id !== current.agent.applied.id
  ) {
    return 'identity_mismatch';
  }

  if (isPolicyOutOfDate(reported, current)) {
    return 'revision_lag';
  }

  return 'current';
};

const toExemplar = (
  metadata: HostMetadata,
  policyInfo: HostInfo['policy_info'],
  classification: PolicyApplyStateClassification,
  hostStatus: HostStatus,
  agentDoc: AgentDoc,
  timestampMs: number | undefined
): PolicyApplyStateExemplar => {
  const lastCheckin = resolveExemplarLastCheckin(agentDoc.last_checkin, timestampMs);

  return {
    endpointId: metadata.agent.id,
    hostName: metadata.host.hostname,
    classification,
    appliedEndpointPolicyId: metadata.Endpoint.policy.applied.id,
    appliedEndpointPolicyRevision: metadata.Endpoint.policy.applied.endpoint_policy_version,
    appliedAgentPolicyRevision: metadata.Endpoint.policy.applied.version,
    configuredEndpointPolicyId: policyInfo?.endpoint?.id,
    configuredEndpointPolicyRevision: policyInfo?.endpoint?.revision,
    configuredAgentPolicyRevision: policyInfo?.agent?.configured?.revision,
    hostStatus,
    ...(lastCheckin === undefined ? {} : { lastCheckin }),
  };
};

const resolveExemplarLastCheckin = (
  fleetCheckin: string | undefined,
  timestampMs: number | undefined
): string | undefined => {
  if (typeof fleetCheckin === 'string' && fleetCheckin.length > 0) {
    return fleetCheckin;
  }

  return timestampMs === undefined ? undefined : new Date(timestampMs).toISOString();
};
