/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  AgentBuilderClient,
  DefaultEvaluators,
  EvaluationDataset,
  Evaluator,
  EvalsExecutorClient,
  Example,
  TaskOutput,
} from '@kbn/evals';
import { converseQuestionToTaskOutput } from './converse_task';
import { createEndpointCriteriaEvaluator } from './evaluate_dataset';

export interface DefendPolicyManagementDatasetExample extends Example {
  input: {
    question: string;
  };
  output: {
    criteria: string[];
  };
}

export type EvaluateDefendPolicyManagementDataset = (options: {
  dataset: {
    name: string;
    description: string;
    examples: DefendPolicyManagementDatasetExample[];
  };
}) => Promise<void>;

const buildDefendPolicyManagementEvaluators = ({
  evaluators,
}: {
  evaluators: DefaultEvaluators;
}): Array<Evaluator<DefendPolicyManagementDatasetExample, TaskOutput>> => {
  const { inputTokens, outputTokens, cachedTokens, toolCalls, latency } =
    evaluators.traceBasedEvaluators;

  return [
    createEndpointCriteriaEvaluator({ evaluators }) as Evaluator<
      DefendPolicyManagementDatasetExample,
      TaskOutput
    >,
    toolCalls as Evaluator<DefendPolicyManagementDatasetExample, TaskOutput>,
    latency as Evaluator<DefendPolicyManagementDatasetExample, TaskOutput>,
    inputTokens as Evaluator<DefendPolicyManagementDatasetExample, TaskOutput>,
    outputTokens as Evaluator<DefendPolicyManagementDatasetExample, TaskOutput>,
    cachedTokens as Evaluator<DefendPolicyManagementDatasetExample, TaskOutput>,
  ];
};

export const createEvaluateDefendPolicyManagementDataset = ({
  evaluators,
  executorClient,
  agentBuilderClient,
}: {
  evaluators: DefaultEvaluators;
  executorClient: EvalsExecutorClient;
  agentBuilderClient: AgentBuilderClient;
}): EvaluateDefendPolicyManagementDataset => {
  return async function evaluateDefendPolicyManagementDataset({
    dataset: { name, description, examples },
  }: {
    dataset: {
      name: string;
      description: string;
      examples: DefendPolicyManagementDatasetExample[];
    };
  }) {
    const dataset = {
      name,
      description,
      examples,
    } satisfies EvaluationDataset<DefendPolicyManagementDatasetExample>;

    await executorClient.runExperiment(
      {
        datasets: [dataset],
        task: async ({ input }) => converseQuestionToTaskOutput(agentBuilderClient, input.question),
      },
      buildDefendPolicyManagementEvaluators({ evaluators })
    );
  };
};
