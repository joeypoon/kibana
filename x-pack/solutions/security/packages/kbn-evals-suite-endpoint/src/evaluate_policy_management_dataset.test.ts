/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Client as EsClient } from '@elastic/elasticsearch';
import type { ToolingLog } from '@kbn/tooling-log';
import type {
  AgentBuilderClient,
  DefaultEvaluators,
  Evaluator,
  EvalsExecutorClient,
} from '@kbn/evals';
import {
  buildPolicyManagementEvaluators,
  createEvaluatePolicyManagementDataset,
} from './evaluate_policy_management_dataset';
import { POLICY_MANAGEMENT_TOOL_USAGE_EVALUATOR_NAME } from './policy_management_tool_usage_evaluator';

const createTraceEvaluator = (name: string): Evaluator => ({
  name,
  kind: 'CODE',
  direction: 'maximize',
  evaluate: async () => ({ score: 1 }),
});

const createMockEvaluators = (): DefaultEvaluators =>
  ({
    criteria: () => ({
      name: 'inner-criteria',
      kind: 'LLM' as const,
      evaluate: async () => ({ score: 1 }),
    }),
    traceBasedEvaluators: {
      inputTokens: createTraceEvaluator('Input Tokens'),
      outputTokens: createTraceEvaluator('Output Tokens'),
      cachedTokens: createTraceEvaluator('Cached Tokens'),
      toolCalls: createTraceEvaluator('Tool Calls'),
      latency: createTraceEvaluator('Latency'),
    },
  } as unknown as DefaultEvaluators);

describe('evaluatePolicyManagementDataset', () => {
  let mockEsClient: jest.Mocked<EsClient>;
  let mockLog: jest.Mocked<ToolingLog>;

  beforeEach(() => {
    mockEsClient = {
      esql: { query: jest.fn() },
    } as unknown as jest.Mocked<EsClient>;
    mockLog = {
      error: jest.fn(),
      warning: jest.fn(),
      info: jest.fn(),
      debug: jest.fn(),
    } as unknown as jest.Mocked<ToolingLog>;
  });

  it('attaches criteria, local tool-name usage, and trace evaluators', () => {
    const evaluators = buildPolicyManagementEvaluators({
      evaluators: createMockEvaluators(),
      traceEsClient: mockEsClient,
      log: mockLog,
    });

    const names = evaluators.map((evaluator) => evaluator.name);

    expect(names).toEqual([
      'Criteria',
      POLICY_MANAGEMENT_TOOL_USAGE_EVALUATOR_NAME,
      'Tool Calls',
      'Latency',
      'Input Tokens',
      'Output Tokens',
      'Cached Tokens',
    ]);
    expect(names).not.toContain('Skill Invoked (elastic-defend-policy-management)');
  });

  it('runs converse examples through the policy-management evaluator set', async () => {
    const runExperiment = jest.fn().mockResolvedValue(undefined);
    const converse = jest.fn().mockResolvedValue({
      message: 'answer',
      steps: [],
      traceId: 'trace-1',
    });

    const evaluatePolicyManagementDataset = createEvaluatePolicyManagementDataset({
      evaluators: createMockEvaluators(),
      executorClient: { runExperiment } as unknown as EvalsExecutorClient,
      agentBuilderClient: { converse, getConversation: jest.fn() } as unknown as AgentBuilderClient,
      traceEsClient: mockEsClient,
      log: mockLog,
    });

    await evaluatePolicyManagementDataset({
      dataset: {
        name: 'security: policy-management-os-tuning',
        description: 'unit',
        examples: [
          {
            input: {
              question:
                'Review the Elastic Defend policy named eval-agent-pm-assess. Explain the relevant event-collection settings and recommend OS-specific tuning for Windows, macOS, and Linux.',
            },
            output: {
              criteria: ['Explains the relevant settings and legal values accurately.'],
              required_tools: ['security.policy_management.get_policy'],
            },
          },
        ],
      },
    });

    expect(runExperiment).toHaveBeenCalledTimes(1);
    const [, attached] = runExperiment.mock.calls[0];
    const names = (attached as Array<{ name: string }>).map((evaluator) => evaluator.name);
    expect(names).toContain('Criteria');
    expect(names).toContain(POLICY_MANAGEMENT_TOOL_USAGE_EVALUATOR_NAME);
    expect(names).not.toContain('Skill Invoked (elastic-defend-policy-management)');
  });
});
