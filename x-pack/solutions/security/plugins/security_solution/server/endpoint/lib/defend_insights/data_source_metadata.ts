/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { QueryDslFieldAndFormat } from '@elastic/elasticsearch/lib/api/types';

export interface DataSourceField {
  name: string;
  type: string;
  description: string;
}

export interface DataSourceMetadata {
  indexFilter: string;
  indexPattern: string;
  description: string;
  fields: DataSourceField[];
}

export const DEFEND_INSIGHTS_DATA_SOURCES: DataSourceMetadata[] = [
  {
    indexFilter: 'logs-endpoint.events.file-',
    indexPattern: 'logs-endpoint.events.file-{spaceId}',
    description: 'Endpoint file event activity',
    fields: [
      { name: '_id', type: 'keyword', description: 'Unique document identifier' },
      { name: 'agent.id', type: 'keyword', description: 'Endpoint agent ID' },
      { name: 'process.executable', type: 'keyword', description: 'Process executable path' },
    ],
  },
  {
    indexFilter: 'metrics-endpoint.policy-',
    indexPattern: 'metrics-endpoint.policy-{spaceId}',
    description: 'Endpoint policy responses',
    fields: [
      { name: '_id', type: 'keyword', description: 'Unique document identifier' },
      { name: 'agent.id', type: 'keyword', description: 'Endpoint agent ID' },
      { name: 'host.os.name', type: 'keyword', description: 'Operating system name' },
      {
        name: 'Endpoint.policy.applied.actions',
        type: 'nested',
        description: 'Policy actions applied to the endpoint',
      },
    ],
  },
];

export function getAllowedFields(index: string): QueryDslFieldAndFormat[] {
  const matchingSource = DEFEND_INSIGHTS_DATA_SOURCES.find((source) => {
    return index.startsWith(source.indexFilter);
  });

  return matchingSource?.fields.map((field) => ({ field: field.name })) ?? [];
}

export function getDataSourceDocumentation(): string {
  return DEFEND_INSIGHTS_DATA_SOURCES.map((source) => {
    const fieldsList = source.fields
      .map((field) => `  - ${field.name} (${field.type}): ${field.description}`)
      .join('\n');

    return `### ${source.indexPattern}\n${source.description}\n\n**Available fields:**\n${fieldsList}`;
  }).join('\n\n');
}
