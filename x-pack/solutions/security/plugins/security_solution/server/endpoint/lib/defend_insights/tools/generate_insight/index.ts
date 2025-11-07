/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltinToolDefinition } from '@kbn/agent-builder-server/tools';
import { z } from '@kbn/zod';
import { ToolType } from '@kbn/agent-builder-common';

import { GENERATE_INSIGHT_TOOL_ID } from '../../constants';
import { createGenerateInsightGraph } from './graph';

const generateInsightSchema = z.object({
  problemDescription: z.string().describe('A brief description of the problem being addressed.'),
  endpointIds: z.array(z.string()).describe('Related endpoint IDs'),
  data: z.array(z.object({}).catchall(z.unknown())).describe('Relevant raw documents analyzed.'),
  context: z
    .array(z.object({}).catchall(z.unknown()))
    .describe('Optional additional context that may assist in generating the insight.')
    .optional(),
});

export const generateInsightToolDefinition = (): BuiltinToolDefinition<
  typeof generateInsightSchema
> => {
  return {
    id: GENERATE_INSIGHT_TOOL_ID,
    type: ToolType.builtin,
    description: `Generate and store structured Automatic Troubleshooting insights.

This tool analyzes data and creates workflow insight records that capture:
- Potential Elastic Defend configuration issues
- Troubleshooting recommendations

The insights will be stored and made available for review and action.

**When to use:**
- After completing gathering of available relevant data
- To create actionable insights for resolving Elastic Defend configuration issues`,
    schema: generateInsightSchema,
    handler: async (
      { problemDescription, endpointIds, data, context },
      { modelProvider, logger }
    ) => {
      if (!data || data.length === 0) {
        return {
          results: [],
        };
      }

      const model = await modelProvider.getDefaultModel();
      const graph = createGenerateInsightGraph({
        model,
        logger,
        problemDescription,
        endpointIds,
        data,
        context,
      });
      const outState = await graph.invoke({});

      return { results: outState.results };
    },
    tags: ['elastic_defend', 'automatic_troubleshooting'],
  };
};
