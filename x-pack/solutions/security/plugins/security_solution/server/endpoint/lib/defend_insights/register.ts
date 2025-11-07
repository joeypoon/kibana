/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger } from '@kbn/core/server';
import type { AgentBuilderPluginSetup } from '@kbn/agent-builder-plugin/server';
import type { BuiltinToolDefinition } from '@kbn/agent-builder-server/tools';
import {
  getDataToolDefinition,
  getContextToolDefinition,
  generateInsightToolDefinition,
} from './tools';
import { getAutomaticTroubleshootingAgentDefinition } from './agent';

export function registerDefendInsightsTools(
  agentBuilder: AgentBuilderPluginSetup,
  logger: Logger
): void {
  try {
    logger.info('Registering Automatic Troubleshooting tools with Agent Builder');

    const tools: BuiltinToolDefinition[] = [
      getDataToolDefinition(),
      getContextToolDefinition(),
      generateInsightToolDefinition(),
    ] as unknown as BuiltinToolDefinition[];

    tools.map((tool: BuiltinToolDefinition) => {
      try {
        agentBuilder.tools.register(tool);
      } catch (err) {
        logger.warn(`error during tool ${tool.id} registration: ${err}`);
      }
    });

    logger.info('Successfully registered 4 Automatic Troubleshooting tools');
  } catch (error) {
    logger.error(`Failed to register Automatic Troubleshooting tools: ${error}`);
    throw error;
  }
}

export function registerDefendInsightsAgent(
  agentBuilder: AgentBuilderPluginSetup,
  logger: Logger
): void {
  try {
    logger.info('Registering Automatic troubleshooting agent with Agent Builder');

    const agentDefinition = getAutomaticTroubleshootingAgentDefinition();
    try {
      agentBuilder.agents.register(agentDefinition);
    } catch (err) {
      logger.warn(`error during agent ${agentDefinition.id} registration: ${err}`);
    }

    logger.info(`Successfully registered Automatic Troubleshooting agent: ${agentDefinition.id}`);
  } catch (error) {
    logger.error(`Failed to register Automatic Troubleshooting agent: ${error}`);
    throw error;
  }
}
