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
  // indexFilter: string;
  indexPattern: string;
  description: string;
  // fields: DataSourceField[];
}

export const DEFEND_INSIGHTS_DATA_SOURCES: DataSourceMetadata[] = [
  {
    // indexFilter: 'logs-endpoint.events.file-',
    indexPattern: 'logs-endpoint.events.file-*',
    description: 'Endpoint file event activity',
    //   fields: [
    //     { name: '_id', type: 'keyword', description: 'Unique document identifier' },
    //     { name: 'agent.id', type: 'keyword', description: 'Endpoint agent ID' },
    //     { name: 'process.executable', type: 'keyword', description: 'Process executable path' },
    //   ],
  },
  {
    // indexFilter: 'metrics-endpoint.policy-',
    indexPattern: 'metrics-endpoint.policy-*',
    description: 'Endpoint policy responses containing warnings and errors for policy responses',
    // fields: [
    //   { name: '_id', type: 'keyword', description: 'Unique document identifier' },
    //   { name: 'agent.id', type: 'keyword', description: 'Endpoint agent ID' },
    //   { name: 'host.os.name', type: 'keyword', description: 'Operating system name' },
    //   {
    //     name: 'Endpoint.policy.applied.actions',
    //     type: 'nested',
    //     description: 'Policy actions applied to the endpoint',
    //   },
    // ],
  },
  {
    indexPattern: 'metrics-endpoint.metadata_current_*',
    description: 'Latest endpoint metadata document for each endpoint',
  },
  {
    indexPattern: '.fleet-agents*',
    description: 'Fleet agent documents containing agent and policy information',
  },
  {
    indexPattern: '.metrics-endpoint.metadata_united_*',
    description:
      'Unified endpoint metadata + fleet agent documents. Contains documents sourced from "metrics-endpoint.metadata_current_*" and ".fleet-agents*" indices. Used as the source of truth for many Elastic Defend pages in Kibana including the endpoint list page.',
  },
];

export function getDataSourceDocumentation(): string {
  return DEFEND_INSIGHTS_DATA_SOURCES.map((source) => {
    // const fieldsList = source.fields
    //   .map((field) => `  - ${field.name} (${field.type}): ${field.description}`)
    //   .join('\n');

    // return `### ${source.indexPattern}\n${source.description}\n\n**Available fields:**\n${fieldsList}`;
    return `### ${source.indexPattern}\n${source.description}`;
  }).join('\n\n');
}
