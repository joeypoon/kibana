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
  EvaluationDataset,
  Evaluator,
  EvalsExecutorClient,
  TaskOutput,
} from '@kbn/evals';
import { converseQuestionToTaskOutput } from './converse_task';
import { createEndpointCriteriaEvaluator, type SecurityDatasetExample } from './evaluate_dataset';
import { createPolicyManagementToolUsageEvaluator } from './policy_management_tool_usage_evaluator';

export type PolicyManagementDatasetExample = SecurityDatasetExample & {
  output: SecurityDatasetExample['output'] & {
    required_tools?: readonly string[];
    forbidden_tools?: readonly string[];
  };
};

export type EvaluatePolicyManagementDataset = (options: {
  dataset: {
    name: string;
    description: string;
    examples: PolicyManagementDatasetExample[];
  };
}) => Promise<void>;

export const buildPolicyManagementEvaluators = ({
  evaluators,
  traceEsClient,
  log,
}: {
  evaluators: DefaultEvaluators;
  traceEsClient: EsClient;
  log: ToolingLog;
}): Array<Evaluator<PolicyManagementDatasetExample, TaskOutput>> => {
  const { inputTokens, outputTokens, cachedTokens, toolCalls, latency } =
    evaluators.traceBasedEvaluators;

  return [
    createEndpointCriteriaEvaluator({ evaluators }) as Evaluator<
      PolicyManagementDatasetExample,
      TaskOutput
    >,
    createPolicyManagementToolUsageEvaluator({ traceEsClient, log }) as Evaluator<
      PolicyManagementDatasetExample,
      TaskOutput
    >,
    toolCalls as Evaluator<PolicyManagementDatasetExample, TaskOutput>,
    latency as Evaluator<PolicyManagementDatasetExample, TaskOutput>,
    inputTokens as Evaluator<PolicyManagementDatasetExample, TaskOutput>,
    outputTokens as Evaluator<PolicyManagementDatasetExample, TaskOutput>,
    cachedTokens as Evaluator<PolicyManagementDatasetExample, TaskOutput>,
  ];
};

export const createEvaluatePolicyManagementDataset = ({
  evaluators,
  executorClient,
  agentBuilderClient,
  traceEsClient,
  log,
}: {
  evaluators: DefaultEvaluators;
  executorClient: EvalsExecutorClient;
  agentBuilderClient: AgentBuilderClient;
  traceEsClient: EsClient;
  log: ToolingLog;
}): EvaluatePolicyManagementDataset => {
  return async function evaluatePolicyManagementDataset({
    dataset: { name, description, examples },
  }: {
    dataset: {
      name: string;
      description: string;
      examples: PolicyManagementDatasetExample[];
    };
  }) {
    const dataset = {
      name,
      description,
      examples,
    } satisfies EvaluationDataset<PolicyManagementDatasetExample>;

    await executorClient.runExperiment(
      {
        datasets: [dataset],
        task: async ({ input }) => converseQuestionToTaskOutput(agentBuilderClient, input.question),
      },
      buildPolicyManagementEvaluators({ evaluators, traceEsClient, log })
    );
  };
};
