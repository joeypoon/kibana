/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EvaluationResult } from 'langsmith/evaluation';
import type { Run, Example } from 'langsmith/schemas';
import type { ActionsClientLlm } from '@kbn/langchain/server';
import { PromptTemplate } from '@langchain/core/prompts';
import { CriteriaLike, loadEvaluator } from 'langchain/evaluation';

import { getExampleDefendInsights } from './get_example';
import { getDefendInsights } from './get_run';

export interface GetCustomEvaluatorOptions {
  /**
   * Examples:
   *  - "conciseness"
   *  - "relevance"
   *  - "correctness"
   *  - "detail"
   */
  criteria: CriteriaLike;
  /**
   * The evaluation score will use this key
   */
  key: string;
  /**
   * LLm to use for evaluation
   */
  llm: ActionsClientLlm;
  /**
   * A prompt template that uses the {input}, {submission}, and {reference} variables
   */
  template: string;
}

export type CustomEvaluator = (
  rootRun: Run,
  example: Example | undefined
) => Promise<EvaluationResult>;

export const getCustomEvaluator =
  ({ criteria, key, llm, template }: GetCustomEvaluatorOptions): CustomEvaluator =>
  async (rootRun, example) => {
    const chain = await loadEvaluator('labeled_criteria', {
      criteria,
      chainOptions: {
        prompt: PromptTemplate.fromTemplate(template),
      },
      llm,
    });

    const exampleDefendInsights = getExampleDefendInsights(example);
    const runDefendInsights = getDefendInsights(rootRun);

    // NOTE: res contains a score, as well as the reasoning for the score
    const res = await chain.evaluateStrings({
      input: '', // empty for now, but this could be the events, i.e. JSON.stringify(rootRun.outputs?.anonymizedEvents, null, 2),
      prediction: JSON.stringify(runDefendInsights, null, 2),
      reference: JSON.stringify(exampleDefendInsights, null, 2),
    });

    return { key, score: res.score };
  };
