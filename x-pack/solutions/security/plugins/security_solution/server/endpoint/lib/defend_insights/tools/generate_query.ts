/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltinToolDefinition } from '@kbn/onechat-server/tools';
import { z } from '@kbn/zod';
import { ToolType } from '@kbn/onechat-common';
import { ToolResultType } from '@kbn/onechat-common/tools/tool_result';

import {
  isIndexAllowed,
  getAllowedFields,
  getDataSourceDocumentation,
} from '../data_source_metadata';
import { GENERATE_QUERY_TOOL_ID } from '../constants';
import { extractTextContent } from '@kbn/onechat-genai-utils/langchain';
import { cleanQuery } from '../helpers';

const generateQuerySchema = z.object({
  description: z
    .string()
    .describe('Natural language description of what data is needed from Elasticsearch'),
  index: z.string().describe('Target index pattern.'),
  timeRange: z
    .object({
      from: z.string().describe('Start time (ISO 8601 format or relative like "now-24h")'),
      to: z.string().describe('End time (ISO 8601 format or relative like "now")'),
    })
    .describe('Time range for the query'),
});

export const generateQueryToolDefinition = (): BuiltinToolDefinition<
  typeof generateQuerySchema
> => {
  return {
    id: GENERATE_QUERY_TOOL_ID,
    type: ToolType.builtin,
    description: `Generate an Elasticsearch DSL query for Elastic Defend configuration troubleshooting.

This tool converts natural language descriptions into validated Elasticsearch DSL queries.

**Data Sources Available:**
${getDataSourceDocumentation()}

**Important:**
- Only whitelisted indices and fields can be queried
- The generated query will be validated before being returned
- Use the execute_query tool to run the generated query

**Example Usage:**
- "Find all the latest unique file events for endpoint ID 'endpoint-123' in the last 24 hours"
- "Retrieve all the latest unique policy response in the past week for endpoint ID 'endpoint-123'"`,
    schema: generateQuerySchema,
    handler: async ({ description, index, timeRange }, { modelProvider, logger }) => {
      const targetIndex = index;

      if (!isIndexAllowed(targetIndex)) {
        return {
          results: [
            {
              type: ToolResultType.error,
              data: {
                message: `Index pattern "${targetIndex}" is not allowlisted. Available patterns: ${getDataSourceDocumentation()}`,
              },
            },
          ],
        };
      }

      const allowedFields = getAllowedFields(targetIndex);
      const fieldsList = allowedFields.map((f) => `${f.name} (${f.type})`).join(', ');

      try {
        const model = await modelProvider.getDefaultModel();

        const prompt = `You are an Elasticsearch DSL query expert. Generate a valid Elasticsearch query based on the following:

**User Request:** ${description}

**Target Index:** ${targetIndex}

**Available Fields:** ${fieldsList}

**Time Range:** from ${timeRange.from} to ${timeRange.to}


**Requirements:**
1. Generate a valid Elasticsearch DSL query (not ES|QL)
2. Only use fields from the available fields list
3. Include proper field types in your query
4. Use appropriate query types (term, match, range, bool, etc.)
5. If a time range is provided, include it in the query
6. Use aggregations when it can provide more concise data
7. Return ONLY the JSON query object, no explanation

Example query structure:
{
    allow_no_indices: true,
    query: {
      bool: {
        must: [
          {
            terms: {
              'agent.id': ['endpoint-123'],
            },
          },
          {
            range: {
              '@timestamp': {
                gte: 'now-24h',
                lte: 'now',
              },
            },
          },
        ],
      },
    },
    size: 0,
    aggs: {
      unique_process_executable: {
        terms: {
          field: 'process.executable',
          size: 1000,
        },
        aggs: {
          latest_event: {
            top_hits: {
              size: 1,
              sort: [
                {
                  '@timestamp': {
                    order: 'desc',
                  },
                },
              ],
              _source: ['_id', 'agent.id', 'process.executable'],
            },
          },
        },
      },
    },
    ignore_unavailable: true,
    index: [logs-endpoint.events.file-*],
  };
}

Generate the query now:`;

        const response = await model.chatModel.invoke(prompt);

        const queryJson = extractTextContent(response);

        const cleanedJson = queryJson
          .replace(/```json\n?/g, '')
          .replace(/```\n?/g, '')
          .trim();

        let parsedQuery;
        try {
          parsedQuery = JSON.parse(cleanedJson);
        } catch (e) {
          logger?.error(`Failed to parse generated query: ${e}`);
          return {
            results: [
              {
                type: ToolResultType.error,
                data: {
                  message: `Failed to parse generated query. LLM response: ${queryJson}`,
                },
              },
            ],
          };
        }

        const cleanedQuery = cleanQuery(parsedQuery, targetIndex);

        return {
          results: [
            {
              type: ToolResultType.query,
              data: {
                elasticsearch: cleanedQuery,
                index: targetIndex,
                description,
              },
            },
          ],
        };
      } catch (error) {
        logger?.error(`Error generating query: ${error}`);
        return {
          results: [
            {
              type: ToolResultType.error,
              data: {
                message: `Failed to generate query: ${
                  error instanceof Error ? error.message : String(error)
                }`,
              },
            },
          ],
        };
      }
    },
    tags: ['elastic_defend', 'automatic_troubleshooting'],
  };
};
