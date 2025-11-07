/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export interface DataSourceField {
  name: string;
  type: string;
  description: string;
}

export interface DataSourceMetadata {
  indexFilter: string; // for startWith filtering
  indexPattern: string; // for index pattern matching
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
      // TODO is keyword correct?
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
      // is nested right?
      {
        name: 'Endpoint.policy.applied.actions',
        type: 'nested',
        description: 'Policy actions applied to the endpoint',
      },
    ],
  },
];

export function isIndexAllowed(index: string): boolean {
  return DEFEND_INSIGHTS_DATA_SOURCES.some((source) => {
    return index.startsWith(source.indexFilter);
  });
}

// probably change this
export function getAllowedFields(index: string): DataSourceField[] {
  const matchingSource = DEFEND_INSIGHTS_DATA_SOURCES.find((source) => {
    return index.startsWith(source.indexFilter);
  });

  return matchingSource?.fields ?? [];
}

export function getDataSourceDocumentation(): string {
  return DEFEND_INSIGHTS_DATA_SOURCES.map((source) => {
    const fieldsList = source.fields
      .map((field) => `  - ${field.name} (${field.type}): ${field.description}`)
      .join('\n');

    return `### ${source.indexPattern}\n${source.description}\n\n**Available fields:**\n${fieldsList}`;
  }).join('\n\n');
}
