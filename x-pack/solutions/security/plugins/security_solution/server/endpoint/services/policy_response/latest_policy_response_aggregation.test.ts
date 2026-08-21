/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient } from '@kbn/core/server';

import {
  LATEST_POLICY_RESPONSE_AGENT_TERMS_SIZE,
  buildLatestPolicyResponseAggregation,
  parseLatestPolicyResponseAggregation,
  searchLatestPolicyResponses,
  type LatestPolicyResponseAggregationParams,
} from './latest_policy_response_aggregation';

const TROUBLESHOOTING_SOURCE_FIELDS = [
  '_id',
  'agent.id',
  'host.os.name',
  'Endpoint.policy.applied.actions',
] as const;

const SOURCE_FIELDS_WITH_APPLIED_POLICY = [
  ...TROUBLESHOOTING_SOURCE_FIELDS,
  'Endpoint.policy.applied.id',
  'Endpoint.policy.applied.version',
  'Endpoint.policy.applied.endpoint_policy_version',
] as const;

const params = (
  overrides: Partial<LatestPolicyResponseAggregationParams> = {}
): LatestPolicyResponseAggregationParams => ({
  agentIds: ['a', 'b'],
  termsSize: LATEST_POLICY_RESPONSE_AGENT_TERMS_SIZE,
  ccsEnabled: false,
  sourceFields: TROUBLESHOOTING_SOURCE_FIELDS,
  excludeInitialPolicy: true,
  ...overrides,
});

const hit = (agentId: string, id: string, source: Record<string, unknown> = {}) => ({
  _id: id,
  _source: {
    agent: { id: agentId },
    ...source,
  },
});

const bucket = (
  agentId: string,
  latestHit?: { _id: string; _source?: Record<string, unknown> }
) => ({
  key: agentId,
  doc_count: 1,
  latest_event: {
    hits: {
      hits: latestHit ? [latestHit] : [],
    },
  },
});

const mockEsClient = (aggregations: unknown): ElasticsearchClient =>
  ({
    search: jest.fn().mockResolvedValue({ aggregations }),
  } as unknown as ElasticsearchClient);

describe('buildLatestPolicyResponseAggregation', () => {
  it('excludes INITIAL policy before latest selection when excludeInitialPolicy is true', () => {
    const query = buildLatestPolicyResponseAggregation(params({ excludeInitialPolicy: true }));

    expect(query.query?.bool).toEqual({
      must: [{ terms: { 'agent.id': ['a', 'b'] } }],
      must_not: [
        { term: { 'Endpoint.policy.applied.id': '00000000-0000-0000-0000-000000000000' } },
      ],
    });
  });

  it('omits INITIAL from the bool when excludeInitialPolicy is false', () => {
    const query = buildLatestPolicyResponseAggregation(params({ excludeInitialPolicy: false }));

    expect(query.query?.bool).toEqual({
      must: [{ terms: { 'agent.id': ['a', 'b'] } }],
    });
    expect(query.query?.bool?.must_not).toBeUndefined();
    expect(JSON.stringify(query.query)).not.toContain('00000000-0000-0000-0000-000000000000');
    expect(JSON.stringify(query.query)).not.toContain('Endpoint.policy.applied.id');
  });

  it('does not add a time range and sorts top_hits by event.created desc', () => {
    const query = buildLatestPolicyResponseAggregation(params());

    expect(JSON.stringify(query.query)).not.toContain('range');
    expect(query.size).toBe(0);
    expect(query.aggs?.latest_actions).toEqual(
      expect.objectContaining({
        terms: { field: 'agent.id', size: LATEST_POLICY_RESPONSE_AGENT_TERMS_SIZE },
      })
    );
    expect(
      (
        query.aggs?.latest_actions as {
          aggs: { latest_event: { top_hits: { sort: unknown } } };
        }
      ).aggs.latest_event.top_hits.sort
    ).toEqual([{ 'event.created': { order: 'desc' } }]);
  });

  it('emits empty agent.id terms when agentIds is empty', () => {
    const query = buildLatestPolicyResponseAggregation(
      params({ agentIds: [], excludeInitialPolicy: false })
    );

    expect(query.query?.bool).toEqual({
      must: [{ terms: { 'agent.id': [] } }],
    });
    expect(JSON.stringify(query.query)).not.toContain('00000000-0000-0000-0000-000000000000');
  });

  it('uses the caller-provided source fields and 1500 terms size', () => {
    const query = buildLatestPolicyResponseAggregation(
      params({
        sourceFields: SOURCE_FIELDS_WITH_APPLIED_POLICY,
        termsSize: LATEST_POLICY_RESPONSE_AGENT_TERMS_SIZE,
      })
    );

    expect(
      (
        query.aggs?.latest_actions as {
          aggs: { latest_event: { top_hits: { _source: string[] } } };
        }
      ).aggs.latest_event.top_hits._source
    ).toEqual([...SOURCE_FIELDS_WITH_APPLIED_POLICY]);
    expect((query.aggs?.latest_actions as { terms: { size: number } }).terms.size).toBe(
      LATEST_POLICY_RESPONSE_AGENT_TERMS_SIZE
    );
  });

  it('prefixes the policy-response index when ccsEnabled is true', () => {
    const query = buildLatestPolicyResponseAggregation(params({ ccsEnabled: true }));

    expect(query.index).toEqual(['metrics-endpoint.policy-*,*:metrics-endpoint.policy-*']);
  });

  it('uses the unprefixed policy-response index when ccsEnabled is false', () => {
    const query = buildLatestPolicyResponseAggregation(params({ ccsEnabled: false }));

    expect(query.index).toEqual(['metrics-endpoint.policy-*']);
  });
});

describe('parseLatestPolicyResponseAggregation', () => {
  it('returns latest hits and overflowAgents from sum_other_doc_count', () => {
    const result = parseLatestPolicyResponseAggregation({
      latest_actions: {
        sum_other_doc_count: 20,
        buckets: [
          bucket('a', hit('a', 'doc-a')),
          bucket('b', hit('b', 'doc-b', { host: { os: { name: 'Linux' } } })),
        ],
      },
    });

    expect(result).toEqual({
      overflowAgents: 20,
      hits: [
        { _id: 'doc-a', _source: { agent: { id: 'a' } } },
        {
          _id: 'doc-b',
          _source: { agent: { id: 'b' }, host: { os: { name: 'Linux' } } },
        },
      ],
    });
  });

  it('treats missing sum_other_doc_count as zero overflow', () => {
    const result = parseLatestPolicyResponseAggregation({
      latest_actions: {
        buckets: [bucket('a', hit('a', 'doc-a'))],
      },
    });

    expect(result.overflowAgents).toBe(0);
    expect(result.hits).toEqual([{ _id: 'doc-a', _source: { agent: { id: 'a' } } }]);
  });

  it('skips empty and malformed buckets instead of throwing', () => {
    const result = parseLatestPolicyResponseAggregation({
      latest_actions: {
        sum_other_doc_count: 0,
        buckets: [
          { key: 'missing-hit' },
          { key: 'empty-hits', latest_event: { hits: { hits: [] } } },
          { key: 'no-id', latest_event: { hits: { hits: [{ _source: { agent: { id: 'x' } } }] } } },
          bucket('c', hit('c', 'doc-c')),
        ],
      },
    });

    expect(result.hits).toEqual([{ _id: 'doc-c', _source: { agent: { id: 'c' } } }]);
  });

  it('returns empty hits and zero overflow when aggregations are absent', () => {
    expect(parseLatestPolicyResponseAggregation(undefined)).toEqual({
      hits: [],
      overflowAgents: 0,
    });
  });
});

describe('searchLatestPolicyResponses', () => {
  it('searches with the built query and returns parsed hits plus overflow', async () => {
    const esClient = mockEsClient({
      latest_actions: {
        sum_other_doc_count: 7,
        buckets: [bucket('a', hit('a', 'doc-a'))],
      },
    });

    const result = await searchLatestPolicyResponses(
      esClient,
      params({ excludeInitialPolicy: false, sourceFields: SOURCE_FIELDS_WITH_APPLIED_POLICY })
    );

    const query = (esClient.search as jest.Mock).mock.calls[0][0];
    expect(query.query.bool.must_not).toBeUndefined();
    expect(query.aggs.latest_actions.aggs.latest_event.top_hits._source).toEqual([
      ...SOURCE_FIELDS_WITH_APPLIED_POLICY,
    ]);
    expect(result).toEqual({
      overflowAgents: 7,
      hits: [{ _id: 'doc-a', _source: { agent: { id: 'a' } } }],
    });
  });

  it('does not search Elasticsearch when agentIds is empty', async () => {
    const esClient = mockEsClient({});

    await expect(searchLatestPolicyResponses(esClient, params({ agentIds: [] }))).resolves.toEqual({
      hits: [],
      overflowAgents: 0,
    });
    expect(esClient.search).not.toHaveBeenCalled();
  });

  it('propagates the rejection when the Elasticsearch search fails', async () => {
    const esClient = {
      search: jest.fn().mockRejectedValue(new Error('search rejected')),
    } as unknown as ElasticsearchClient;

    await expect(searchLatestPolicyResponses(esClient, params())).rejects.toThrow(
      'search rejected'
    );
  });
});
