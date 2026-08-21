/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Client as EsClient } from '@elastic/elasticsearch';
import type { ToolingLog } from '@kbn/tooling-log';
import {
  createPolicyManagementToolUsageEvaluator,
  POLICY_MANAGEMENT_GET_POLICY_TOOL_ID,
  POLICY_MANAGEMENT_ASSESS_POLICY_CHANGE_TOOL_ID,
} from './policy_management_tool_usage_evaluator';

const VALID_TRACE_ID = '0af7651916cd43dd8448eb211c80319c';

const evaluateWith = (
  evaluator: ReturnType<typeof createPolicyManagementToolUsageEvaluator>,
  {
    traceId,
    requiredTools = [POLICY_MANAGEMENT_GET_POLICY_TOOL_ID],
    forbiddenTools = [POLICY_MANAGEMENT_ASSESS_POLICY_CHANGE_TOOL_ID],
    output = { traceId },
  }: {
    traceId?: string;
    requiredTools?: readonly string[];
    forbiddenTools?: readonly string[];
    output?: Record<string, unknown>;
  }
) =>
  evaluator.evaluate({
    input: {},
    output,
    expected: {
      required_tools: requiredTools,
      forbidden_tools: forbiddenTools,
    },
    metadata: {},
  });

describe('createPolicyManagementToolUsageEvaluator', () => {
  let mockEsClient: jest.Mocked<EsClient>;
  let mockLog: jest.Mocked<ToolingLog>;
  let converse: jest.Mock;

  beforeEach(() => {
    jest.useFakeTimers();
    converse = jest.fn();
    mockEsClient = {
      esql: {
        query: jest.fn(),
      },
    } as unknown as jest.Mocked<EsClient>;

    mockLog = {
      error: jest.fn(),
      warning: jest.fn(),
      info: jest.fn(),
      debug: jest.fn(),
    } as unknown as jest.Mocked<ToolingLog>;
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  const createEvaluator = () =>
    createPolicyManagementToolUsageEvaluator({
      traceEsClient: mockEsClient,
      log: mockLog,
    });

  it('passes when all required tools are present and no forbidden tool is present', async () => {
    const evaluator = createEvaluator();

    (mockEsClient.esql.query as jest.Mock).mockResolvedValue({
      columns: [
        { name: 'total_spans', type: 'long' },
        { name: 'tool_names', type: 'keyword' },
      ],
      values: [[12, [POLICY_MANAGEMENT_GET_POLICY_TOOL_ID, 'platform.core.integration_knowledge']]],
    });

    const result = await evaluateWith(evaluator, { traceId: VALID_TRACE_ID });

    expect(result.score).toBe(1);
    expect(result.label).toBe('pass');
    expect(converse).not.toHaveBeenCalled();
    const calledQuery = (mockEsClient.esql.query as jest.Mock).mock.calls[0][0].query;
    expect(calledQuery).toContain(`trace.id == "${VALID_TRACE_ID}"`);
    expect(calledQuery).toContain('attributes.gen_ai.tool.name');
    expect(calledQuery).not.toContain('output.steps');
  });

  it('retries when a required tool becomes visible later', async () => {
    const evaluator = createEvaluator();

    (mockEsClient.esql.query as jest.Mock)
      .mockResolvedValueOnce({
        columns: [
          { name: 'total_spans', type: 'long' },
          { name: 'tool_names', type: 'keyword' },
        ],
        values: [[8, ['platform.core.integration_knowledge']]],
      })
      .mockResolvedValueOnce({
        columns: [
          { name: 'total_spans', type: 'long' },
          { name: 'tool_names', type: 'keyword' },
        ],
        values: [
          [9, [POLICY_MANAGEMENT_GET_POLICY_TOOL_ID, 'platform.core.integration_knowledge']],
        ],
      });

    const promise = evaluateWith(evaluator, { traceId: VALID_TRACE_ID });
    await jest.advanceTimersByTimeAsync(300_000);
    const result = await promise;

    expect(result.score).toBe(1);
    expect(result.label).toBe('pass');
    expect(mockEsClient.esql.query).toHaveBeenCalledTimes(2);
    expect(converse).not.toHaveBeenCalled();
  });

  it('fails as soon as the span count settles with a required tool missing', async () => {
    const evaluator = createEvaluator();

    (mockEsClient.esql.query as jest.Mock).mockResolvedValue({
      columns: [
        { name: 'total_spans', type: 'long' },
        { name: 'tool_names', type: 'keyword' },
      ],
      values: [[8, ['platform.core.integration_knowledge']]],
    });

    const promise = evaluateWith(evaluator, { traceId: VALID_TRACE_ID });
    await jest.advanceTimersByTimeAsync(300_000);
    const result = await promise;

    expect(result.score).toBe(0);
    expect(result.label).toBe('fail');
    expect(mockEsClient.esql.query).toHaveBeenCalledTimes(2);
    expect(result.label).not.toBe('potentially_incomplete');
    expect(converse).not.toHaveBeenCalled();
  });

  it('keeps retrying a missing required tool while spans are still arriving', async () => {
    const evaluator = createEvaluator();

    const spansOnly = (totalSpans: number) => ({
      columns: [
        { name: 'total_spans', type: 'long' },
        { name: 'tool_names', type: 'keyword' },
      ],
      values: [[totalSpans, ['platform.core.integration_knowledge']]],
    });

    (mockEsClient.esql.query as jest.Mock)
      .mockResolvedValueOnce(spansOnly(4))
      .mockResolvedValueOnce(spansOnly(6))
      .mockResolvedValueOnce(spansOnly(8))
      .mockResolvedValue({
        columns: [
          { name: 'total_spans', type: 'long' },
          { name: 'tool_names', type: 'keyword' },
        ],
        values: [[11, [POLICY_MANAGEMENT_GET_POLICY_TOOL_ID]]],
      });

    const promise = evaluateWith(evaluator, { traceId: VALID_TRACE_ID });
    await jest.advanceTimersByTimeAsync(300_000);
    const result = await promise;

    expect(result.score).toBe(1);
    expect(result.label).toBe('pass');
    expect(mockEsClient.esql.query).toHaveBeenCalledTimes(4);
    expect(converse).not.toHaveBeenCalled();
  });

  it('fails without throwing when a forbidden tool is present', async () => {
    const evaluator = createEvaluator();

    (mockEsClient.esql.query as jest.Mock).mockResolvedValue({
      columns: [
        { name: 'total_spans', type: 'long' },
        { name: 'tool_names', type: 'keyword' },
      ],
      values: [
        [9, [POLICY_MANAGEMENT_GET_POLICY_TOOL_ID, POLICY_MANAGEMENT_ASSESS_POLICY_CHANGE_TOOL_ID]],
      ],
    });

    const result = await evaluateWith(evaluator, { traceId: VALID_TRACE_ID });

    expect(result.score).toBe(0);
    expect(result.label).toBe('fail');
    expect(mockEsClient.esql.query).toHaveBeenCalledTimes(1);
    expect(converse).not.toHaveBeenCalled();
  });

  it('returns unavailable without throwing when no traceId is present', async () => {
    const evaluator = createEvaluator();

    const result = await evaluateWith(evaluator, { output: {} });

    expect(result.score).toBeNull();
    expect(result.label).toBe('unavailable');
    expect(mockEsClient.esql.query).not.toHaveBeenCalled();
    expect(converse).not.toHaveBeenCalled();
  });

  it('returns unavailable without throwing when no reachable tool spans are indexed', async () => {
    const evaluator = createEvaluator();

    (mockEsClient.esql.query as jest.Mock).mockResolvedValue({
      columns: [
        { name: 'total_spans', type: 'long' },
        { name: 'tool_names', type: 'keyword' },
      ],
      values: [[0, null]],
    });

    const promise = evaluateWith(evaluator, { traceId: VALID_TRACE_ID });
    await jest.advanceTimersByTimeAsync(300_000);
    const result = await promise;

    expect(result.score).toBeNull();
    expect(result.label).toBe('unavailable');
    expect(converse).not.toHaveBeenCalled();
  });

  it('returns error without throwing when the trace query fails after retries', async () => {
    const evaluator = createEvaluator();

    (mockEsClient.esql.query as jest.Mock).mockRejectedValue(new Error('esql unavailable'));

    const promise = evaluateWith(evaluator, { traceId: VALID_TRACE_ID });
    await jest.advanceTimersByTimeAsync(300_000);
    const result = await promise;

    expect(result.label).toBe('error');
    expect(result.score).toBeUndefined();
    expect(converse).not.toHaveBeenCalled();
  });

  it('does not inspect output.steps', async () => {
    const evaluator = createEvaluator();

    (mockEsClient.esql.query as jest.Mock).mockResolvedValue({
      columns: [
        { name: 'total_spans', type: 'long' },
        { name: 'tool_names', type: 'keyword' },
      ],
      values: [[4, [POLICY_MANAGEMENT_GET_POLICY_TOOL_ID]]],
    });

    await evaluateWith(evaluator, {
      traceId: VALID_TRACE_ID,
      output: {
        traceId: VALID_TRACE_ID,
        steps: [{ tool_id: POLICY_MANAGEMENT_ASSESS_POLICY_CHANGE_TOOL_ID }],
      },
    });

    const calledQuery = (mockEsClient.esql.query as jest.Mock).mock.calls[0][0].query;
    expect(calledQuery).not.toContain('steps');
    expect(calledQuery).toContain('attributes.gen_ai.tool.name');
  });
});
