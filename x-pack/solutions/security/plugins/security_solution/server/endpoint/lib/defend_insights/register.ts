/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger } from '@kbn/core/server';
import type { OnechatPluginSetup } from '@kbn/onechat-plugin/server';
import type { BuiltinToolDefinition } from '@kbn/onechat-server/tools';
import {
  executeEsqlSafeToolDefinition,
  getContextToolDefinition,
  generateInsightToolDefinition,
} from './tools';
import { getAutomaticTroubleshootingAgentDefinition } from './agent';

function registerDefendInsightsTools(onechat: OnechatPluginSetup, logger: Logger): void {
  try {
    logger.info('Registering Automatic Troubleshooting tools with OneChat');

    const tools: BuiltinToolDefinition[] = [
      executeEsqlSafeToolDefinition(),
      getContextToolDefinition(),
      generateInsightToolDefinition(),
    ] as unknown as BuiltinToolDefinition[];

    tools.map((tool: BuiltinToolDefinition) => {
      try {
        onechat.tools.register(tool);
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

function registerDefendInsightsAgent(onechat: OnechatPluginSetup, logger: Logger): void {
  try {
    logger.info('Registering Automatic troubleshooting agent with OneChat');

    const agentDefinition = getAutomaticTroubleshootingAgentDefinition();
    try {
      onechat.agents.register(agentDefinition);
    } catch (err) {
      logger.warn(`error during agent ${agentDefinition.id} registration: ${err}`);
    }

    logger.info(`Successfully registered Automatic Troubleshooting agent: ${agentDefinition.id}`);
  } catch (error) {
    logger.error(`Failed to register Automatic Troubleshooting agent: ${error}`);
    throw error;
  }
}

export function registerDefendInsights(onechat: OnechatPluginSetup, logger: Logger): void {
  registerDefendInsightsTools(onechat, logger);
  registerDefendInsightsAgent(onechat, logger);
}
