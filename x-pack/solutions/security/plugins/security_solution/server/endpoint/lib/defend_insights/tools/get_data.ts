/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { StaticIndexSearchTool } from '@kbn/agent-builder-server/tools';
import { ToolType } from '@kbn/agent-builder-common';

import { GET_DATA_TOOL_ID } from '../constants';

export const getDataToolDefinition = (): StaticIndexSearchTool => {
  return {
    id: GET_DATA_TOOL_ID,
    type: ToolType.index_search,
    description: `Fetch relevant raw data for Elastic Defend configuration troubleshooting.

Always return the _id and index fields for all documents.`,
    configuration: {
      pattern: '*endpoint*',
      includeKibanaIndices: true,
    },
    tags: ['elastic_defend', 'automatic_troubleshooting'],
  };
};
