/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Document } from '@langchain/core/documents';
import type { StateGraphArgs } from '@langchain/langgraph';
import type { DateMath } from '@elastic/elasticsearch/lib/api/types';
import type { DefendInsight, DefendInsightType, Replacements } from '@kbn/elastic-assistant-common';

import type { GraphState } from '../types';
import { getDefendInsightsPrompt } from '../nodes/helpers/prompts';
import { getDefaultRefinePrompt } from '../nodes/refine/helpers/get_default_refine_prompt';
import {
  DEFAULT_MAX_GENERATION_ATTEMPTS,
  DEFAULT_MAX_HALLUCINATION_FAILURES,
  DEFAULT_MAX_REPEATED_GENERATIONS,
} from '../constants';

export interface Options {
  insightType: DefendInsightType;
  start?: string;
  end?: string;
}

export const getDefaultGraphState = ({
  insightType,
  start,
  end,
}: Options): StateGraphArgs<GraphState>['channels'] => ({
  insights: {
    value: (x: DefendInsight[] | null, y?: DefendInsight[] | null) => y ?? x,
    default: () => null,
  },
  prompt: {
    value: (x: string, y?: string) => y ?? x,
    default: () => getDefendInsightsPrompt({ type: insightType }),
  },
  anonymizedEvents: {
    value: (x: Document[], y?: Document[]) => y ?? x,
    default: () => [],
  },
  combinedGenerations: {
    value: (x: string, y?: string) => y ?? x,
    default: () => '',
  },
  combinedRefinements: {
    value: (x: string, y?: string) => y ?? x,
    default: () => '',
  },
  errors: {
    value: (x: string[], y?: string[]) => y ?? x,
    default: () => [],
  },
  generationAttempts: {
    value: (x: number, y?: number) => y ?? x,
    default: () => 0,
  },
  generations: {
    value: (x: string[], y?: string[]) => y ?? x,
    default: () => [],
  },
  hallucinationFailures: {
    value: (x: number, y?: number) => y ?? x,
    default: () => 0,
  },
  refinePrompt: {
    value: (x: string, y?: string) => y ?? x,
    default: () => getDefaultRefinePrompt(),
  },
  maxGenerationAttempts: {
    value: (x: number, y?: number) => y ?? x,
    default: () => DEFAULT_MAX_GENERATION_ATTEMPTS,
  },
  maxHallucinationFailures: {
    value: (x: number, y?: number) => y ?? x,
    default: () => DEFAULT_MAX_HALLUCINATION_FAILURES,
  },
  maxRepeatedGenerations: {
    value: (x: number, y?: number) => y ?? x,
    default: () => DEFAULT_MAX_REPEATED_GENERATIONS,
  },
  refinements: {
    value: (x: string[], y?: string[]) => y ?? x,
    default: () => [],
  },
  replacements: {
    value: (x: Replacements, y?: Replacements) => y ?? x,
    default: () => ({}),
  },
  unrefinedResults: {
    value: (x: DefendInsight[] | null, y?: DefendInsight[] | null) => y ?? x,
    default: () => null,
  },
  start: {
    value: (x?: DateMath, y?: DateMath) => y ?? x,
    default: () => start,
  },
  end: {
    value: (x?: DateMath, y?: DateMath) => y ?? x,
    default: () => end,
  },
});
