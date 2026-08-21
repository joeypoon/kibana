/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SearchRequest } from '@elastic/elasticsearch/lib/api/types';
import type { ElasticsearchClient } from '@kbn/core/server';

import { policyIndexPattern } from '../../../../common/endpoint/constants';
import { INITIAL_POLICY_ID } from '../../routes/policy';
import { prefixIndexPatternsWithCcs } from '../../utils/ccs_utils';

export const LATEST_POLICY_RESPONSE_AGENT_TERMS_SIZE = 1500;

export interface LatestPolicyResponseAggregationParams {
  agentIds: readonly string[];
  termsSize: number;
  ccsEnabled: boolean;
  sourceFields: readonly string[];
  excludeInitialPolicy: boolean;
}

export interface LatestPolicyResponseAction {
  name: string;
  message: string;
  status: string;
}

export interface LatestPolicyResponseSource {
  agent?: { id?: string };
  Endpoint?: {
    policy?: {
      applied?: {
        id?: string;
        version?: number;
        endpoint_policy_version?: number;
        actions?: LatestPolicyResponseAction[];
      };
    };
  };
  host?: { os?: { name?: string } };
}

export interface LatestPolicyResponseHit {
  _id: string;
  _source?: LatestPolicyResponseSource;
}

export interface LatestPolicyResponseAggregation {
  latest_actions?: {
    buckets?: Array<{
      key?: string;
      doc_count?: number;
      latest_event?: {
        hits?: {
          hits?: Array<{
            _id?: string;
            _source?: LatestPolicyResponseSource;
          }>;
        };
      };
    }>;
    sum_other_doc_count?: number;
  };
}

export interface LatestPolicyResponseAggregationResult {
  hits: LatestPolicyResponseHit[];
  overflowAgents: number;
}

const INITIAL_POLICY_MUST_NOT = {
  term: {
    'Endpoint.policy.applied.id': INITIAL_POLICY_ID,
  },
} as const;

export const buildLatestPolicyResponseAggregation = ({
  agentIds,
  termsSize,
  ccsEnabled,
  sourceFields,
  excludeInitialPolicy,
}: LatestPolicyResponseAggregationParams): SearchRequest => ({
  allow_no_indices: true,
  ignore_unavailable: true,
  index: [prefixIndexPatternsWithCcs(policyIndexPattern, ccsEnabled)],
  query: {
    bool: {
      must: [
        {
          terms: {
            'agent.id': [...agentIds],
          },
        },
      ],
      ...(excludeInitialPolicy ? { must_not: [INITIAL_POLICY_MUST_NOT] } : {}),
    },
  },
  size: 0,
  aggs: {
    latest_actions: {
      terms: {
        field: 'agent.id',
        size: termsSize,
      },
      aggs: {
        latest_event: {
          top_hits: {
            size: 1,
            sort: [
              {
                'event.created': {
                  order: 'desc',
                },
              },
            ],
            _source: [...sourceFields],
          },
        },
      },
    },
  },
});

export const parseLatestPolicyResponseAggregation = (
  aggregations: LatestPolicyResponseAggregation | undefined
): LatestPolicyResponseAggregationResult => {
  const latestActions = aggregations?.latest_actions;
  const buckets = Array.isArray(latestActions?.buckets) ? latestActions.buckets : [];
  const overflowAgents =
    typeof latestActions?.sum_other_doc_count === 'number' ? latestActions.sum_other_doc_count : 0;

  const hits = buckets.flatMap((bucket) => {
    const latestHit = bucket?.latest_event?.hits?.hits?.[0];
    if (!latestHit || typeof latestHit._id !== 'string') {
      return [];
    }

    return [{ _id: latestHit._id, _source: latestHit._source }];
  });

  return { hits, overflowAgents };
};

export const searchLatestPolicyResponses = async (
  esClient: ElasticsearchClient,
  params: LatestPolicyResponseAggregationParams
): Promise<LatestPolicyResponseAggregationResult> => {
  if (params.agentIds.length === 0) {
    return { hits: [], overflowAgents: 0 };
  }

  const result = await esClient.search<LatestPolicyResponseSource, LatestPolicyResponseAggregation>(
    buildLatestPolicyResponseAggregation(params)
  );

  return parseLatestPolicyResponseAggregation(result.aggregations);
};
