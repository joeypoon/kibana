/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { estypes } from '@elastic/elasticsearch';
import { HostPolicyResponseActionStatus } from '../../../../../../common/endpoint/types';
import type { HostInfo, HostMetadata } from '../../../../../../common/endpoint/types';
import { isPolicyOutOfDate } from '../../../../../../common/endpoint/service/policy/apply_state';
import { METADATA_UNITED_INDEX } from '../../../../../../common/endpoint/constants';
import { prefixIndexPatternsWithCcs } from '../../../../../endpoint/utils/ccs_utils';
import {
  buildUnitedApplyStateFilter,
  UNITED_APPLY_STATE_ASSIGNMENT_FIELD,
} from './united_apply_state_filter';

export const APPLY_STATE_TUPLE_TERMS_SIZE = 1500;
export const APPLY_STATE_AGENT_TERMS_SIZE = 1500;
export const APPLY_STATE_MISSING_LONG = -1;

export const APPLY_STATE_REPORTED_PACKAGE_ID_FIELD = 'apply_state.reported_package_id';
export const APPLY_STATE_REPORTED_AGENT_REV_FIELD = 'apply_state.reported_agent_rev';
export const APPLY_STATE_REPORTED_PACKAGE_REV_FIELD = 'apply_state.reported_package_rev';
export const APPLY_STATE_APPLIED_AGENT_REV_FIELD = 'apply_state.applied_agent_rev';

export const APPLY_STATE_TUPLE_AGG_NAME = 'apply_state_tuples';
export const APPLY_STATE_AGENT_ID_AGG_NAME = 'apply_state_agent_ids';

const APPLIED_AGENT_POLICY_ID_SCRIPT = `
def source = params._source;
def base = null;
if (source != null && source.united != null && source.united.agent != null) {
  base = source.united.agent.policy_base_id;
}
if (base != null && base.toString().length() > 0) {
  emit(base.toString());
  return;
}
if (doc.containsKey('united.agent.policy_id') && doc['united.agent.policy_id'].size() > 0) {
  def policyId = doc['united.agent.policy_id'].value;
  if (policyId != null) {
    emit(policyId.toString().replaceAll(/#\\d+\\.\\d+$/, m -> ''));
    return;
  }
}
emit('');
`.trim();

const REPORTED_PACKAGE_ID_SCRIPT = `
if (doc.containsKey('united.endpoint.Endpoint.policy.applied.id') && doc['united.endpoint.Endpoint.policy.applied.id'].size() > 0) {
  def reportedId = doc['united.endpoint.Endpoint.policy.applied.id'].value;
  if (reportedId != null) {
    emit(reportedId.toString());
    return;
  }
}
emit('');
`.trim();

const PAINLESS_NORMALIZE_INTEGER_REVISION = `
long normalizeIntegerRevision(def value) {
  if (value == null) {
    return -1L;
  }
  if (value instanceof Number) {
    return ((Number) value).longValue();
  }
  if (value instanceof String) {
    def trimmed = ((String) value).trim();
    if (trimmed.length() == 0) {
      return -1L;
    }
    try {
      return Long.parseLong(trimmed);
    } catch (NumberFormatException e) {
      return -1L;
    }
  }
  return -1L;
}
`.trim();

const REPORTED_AGENT_REV_SCRIPT = `
${PAINLESS_NORMALIZE_INTEGER_REVISION}
def source = params._source;
if (source != null && source.united != null && source.united.endpoint != null && source.united.endpoint.Endpoint != null && source.united.endpoint.Endpoint.policy != null && source.united.endpoint.Endpoint.policy.applied != null && source.united.endpoint.Endpoint.policy.applied.version != null) {
  emit(normalizeIntegerRevision(source.united.endpoint.Endpoint.policy.applied.version));
} else {
  emit(-1L);
}
`.trim();

const REPORTED_PACKAGE_REV_SCRIPT = `
${PAINLESS_NORMALIZE_INTEGER_REVISION}
def source = params._source;
if (source != null && source.united != null && source.united.endpoint != null && source.united.endpoint.Endpoint != null && source.united.endpoint.Endpoint.policy != null && source.united.endpoint.Endpoint.policy.applied != null && source.united.endpoint.Endpoint.policy.applied.endpoint_policy_version != null) {
  emit(normalizeIntegerRevision(source.united.endpoint.Endpoint.policy.applied.endpoint_policy_version));
} else {
  emit(-1L);
}
`.trim();

const APPLIED_AGENT_REV_SCRIPT = `
${PAINLESS_NORMALIZE_INTEGER_REVISION}
if (doc.containsKey('united.agent.policy_revision_idx') && doc['united.agent.policy_revision_idx'].size() > 0) {
  def revision = doc['united.agent.policy_revision_idx'].value;
  if (revision != null) {
    emit(normalizeIntegerRevision(revision));
    return;
  }
}
emit(-1L);
`.trim();

export const APPLY_STATE_UNITED_RUNTIME_MAPPINGS: estypes.MappingRuntimeFields = {
  [UNITED_APPLY_STATE_ASSIGNMENT_FIELD]: {
    type: 'keyword',
    script: {
      lang: 'painless',
      source: APPLIED_AGENT_POLICY_ID_SCRIPT,
    },
  },
  [APPLY_STATE_REPORTED_PACKAGE_ID_FIELD]: {
    type: 'keyword',
    script: {
      lang: 'painless',
      source: REPORTED_PACKAGE_ID_SCRIPT,
    },
  },
  [APPLY_STATE_REPORTED_AGENT_REV_FIELD]: {
    type: 'long',
    script: {
      lang: 'painless',
      source: REPORTED_AGENT_REV_SCRIPT,
    },
  },
  [APPLY_STATE_REPORTED_PACKAGE_REV_FIELD]: {
    type: 'long',
    script: {
      lang: 'painless',
      source: REPORTED_PACKAGE_REV_SCRIPT,
    },
  },
  [APPLY_STATE_APPLIED_AGENT_REV_FIELD]: {
    type: 'long',
    script: {
      lang: 'painless',
      source: APPLIED_AGENT_REV_SCRIPT,
    },
  },
};

export interface UnitedApplyStateSearchArgs {
  agentPolicyIds: string[];
  ccsEnabled: boolean;
  cpsSpaceId?: string;
}

export function buildUnitedApplyStateSearch({
  agentPolicyIds,
  ccsEnabled,
  cpsSpaceId,
}: UnitedApplyStateSearchArgs): estypes.SearchRequest {
  return {
    index: prefixIndexPatternsWithCcs(METADATA_UNITED_INDEX, ccsEnabled && !cpsSpaceId),
    from: 0,
    size: 0,
    track_total_hits: false,
    query: buildUnitedApplyStateFilter(agentPolicyIds),
    runtime_mappings: APPLY_STATE_UNITED_RUNTIME_MAPPINGS,
    aggregations: {
      [APPLY_STATE_TUPLE_AGG_NAME]: {
        multi_terms: {
          size: APPLY_STATE_TUPLE_TERMS_SIZE,
          terms: [
            { field: UNITED_APPLY_STATE_ASSIGNMENT_FIELD },
            { field: APPLY_STATE_REPORTED_PACKAGE_ID_FIELD },
            { field: APPLY_STATE_REPORTED_AGENT_REV_FIELD },
            { field: APPLY_STATE_REPORTED_PACKAGE_REV_FIELD },
            { field: APPLY_STATE_APPLIED_AGENT_REV_FIELD },
          ],
        },
      },
      [APPLY_STATE_AGENT_ID_AGG_NAME]: {
        terms: {
          field: 'united.endpoint.agent.id',
          size: APPLY_STATE_AGENT_TERMS_SIZE,
        },
      },
    },
  };
}

export interface UnitedOutOfDateEvaluation {
  outOfDateHosts: number;
  classifiedHosts: number;
  overflowHosts: number;
  agentIds: string[];
  agentOverflow: number;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const asFiniteNumber = (value: unknown): number | undefined => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return undefined;
};

const asString = (value: unknown): string | undefined => {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  return undefined;
};

const longOrUndefined = (value: number): number | undefined =>
  value === APPLY_STATE_MISSING_LONG ? undefined : value;

const readSumOtherDocCount = (aggregation: unknown): number => {
  if (!isRecord(aggregation)) {
    return 0;
  }
  return asFiniteNumber(aggregation.sum_other_doc_count) ?? 0;
};

const readBuckets = (aggregation: unknown): unknown[] => {
  if (!isRecord(aggregation) || !Array.isArray(aggregation.buckets)) {
    return [];
  }
  return aggregation.buckets;
};

const buildReportedPolicy = (
  reportedPackageId: string,
  reportedAgentRev: number,
  reportedPackageRev: number
): HostMetadata['Endpoint']['policy']['applied'] => {
  const version = longOrUndefined(reportedAgentRev);
  const endpointPolicyVersion = longOrUndefined(reportedPackageRev);
  return {
    id: reportedPackageId,
    status: HostPolicyResponseActionStatus.success,
    name: '',
    ...(version !== undefined ? { version } : {}),
    ...(endpointPolicyVersion !== undefined
      ? { endpoint_policy_version: endpointPolicyVersion }
      : {}),
  } as HostMetadata['Endpoint']['policy']['applied'];
};

interface ParsedTupleBucket {
  appliedAgentPolicyId: string;
  reportedPackageId: string;
  reportedAgentRev: number;
  reportedPackageRev: number;
  appliedAgentRev: number;
  docCount: number;
}

const parseTupleBucket = (bucket: unknown): ParsedTupleBucket | undefined => {
  if (!isRecord(bucket) || !Array.isArray(bucket.key) || bucket.key.length !== 5) {
    return undefined;
  }

  const appliedAgentPolicyId = asString(bucket.key[0]);
  const reportedPackageId = asString(bucket.key[1]);
  const reportedAgentRev = asFiniteNumber(bucket.key[2]);
  const reportedPackageRev = asFiniteNumber(bucket.key[3]);
  const appliedAgentRev = asFiniteNumber(bucket.key[4]);
  const docCount = asFiniteNumber(bucket.doc_count);

  if (
    appliedAgentPolicyId === undefined ||
    reportedPackageId === undefined ||
    reportedAgentRev === undefined ||
    reportedPackageRev === undefined ||
    appliedAgentRev === undefined ||
    docCount === undefined
  ) {
    return undefined;
  }

  return {
    appliedAgentPolicyId,
    reportedPackageId,
    reportedAgentRev,
    reportedPackageRev,
    appliedAgentRev,
    docCount,
  };
};

const parseAgentId = (bucket: unknown): string | undefined => {
  if (!isRecord(bucket)) {
    return undefined;
  }
  const agentId = asString(bucket.key);
  return agentId !== undefined && agentId !== '' ? agentId : undefined;
};

export function evaluateUnitedOutOfDate({
  aggregations,
  packagePolicy,
  configuredByAgentPolicyId,
}: {
  aggregations: unknown;
  packagePolicy: { id: string; revision: number };
  configuredByAgentPolicyId: Readonly<Record<string, { id: string; revision: number }>>;
}): UnitedOutOfDateEvaluation {
  if (!isRecord(aggregations)) {
    return {
      outOfDateHosts: 0,
      classifiedHosts: 0,
      overflowHosts: 0,
      agentIds: [],
      agentOverflow: 0,
    };
  }

  const tupleAggregation = aggregations[APPLY_STATE_TUPLE_AGG_NAME];
  const agentAggregation = aggregations[APPLY_STATE_AGENT_ID_AGG_NAME];
  const tupleBuckets = readBuckets(tupleAggregation)
    .map(parseTupleBucket)
    .filter((bucket): bucket is ParsedTupleBucket => bucket !== undefined);

  const classifiedHosts = tupleBuckets.reduce((sum, { docCount }) => sum + docCount, 0);
  const outOfDateHosts = tupleBuckets.reduce((sum, bucket) => {
    const current: NonNullable<HostInfo['policy_info']> = {
      endpoint: { id: packagePolicy.id, revision: packagePolicy.revision },
      agent: {
        applied: {
          id: bucket.appliedAgentPolicyId,
          revision: longOrUndefined(bucket.appliedAgentRev) ?? 0,
        },
        configured: configuredByAgentPolicyId[bucket.appliedAgentPolicyId] ?? {
          id: '',
          revision: 0,
        },
      },
    };

    return isPolicyOutOfDate(
      buildReportedPolicy(
        bucket.reportedPackageId,
        bucket.reportedAgentRev,
        bucket.reportedPackageRev
      ),
      current
    )
      ? sum + bucket.docCount
      : sum;
  }, 0);

  return {
    outOfDateHosts,
    classifiedHosts,
    overflowHosts: readSumOtherDocCount(tupleAggregation),
    agentIds: readBuckets(agentAggregation)
      .map(parseAgentId)
      .filter((agentId): agentId is string => agentId !== undefined),
    agentOverflow: readSumOtherDocCount(agentAggregation),
  };
}
