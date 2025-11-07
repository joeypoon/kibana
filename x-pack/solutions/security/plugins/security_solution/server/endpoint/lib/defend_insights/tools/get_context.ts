/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { StaticIndexSearchTool } from '@kbn/agent-builder-server/tools';
import { ToolType } from '@kbn/agent-builder-common';

import { GET_CONTEXT_TOOL_ID } from '../constants';

export const getContextToolDefinition = (): StaticIndexSearchTool => {
  return {
    id: GET_CONTEXT_TOOL_ID,
    type: ToolType.index_search,
    description: `Fetch contextual knowledge base documents relevant to troubleshooting Elastic Defend configuration issues.

This tool searches the knowledge base for information that can help with:
- Troubleshooting Elastic Defend configuration issues

Only use documents whose 'kb_resource' field value starts with 'defend_insights'.

**Example queries:**
- "How to interpret policy response failures for endpoints"`,
    configuration: {
      pattern: '.kibana-elastic-ai-assistant-knowledge-base-*',
      includeKibanaIndices: true,
    },
    tags: ['elastic_defend', 'automatic_troubleshooting'],
  };
};
