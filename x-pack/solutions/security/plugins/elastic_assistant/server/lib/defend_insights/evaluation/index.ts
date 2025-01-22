/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { LangChainTracer } from '@langchain/core/tracers/tracer_langchain';
import type { ActionsClient } from '@kbn/actions-plugin/server';
import type { Connector } from '@kbn/actions-plugin/server/application/connector/types';
import type { DefendInsightType } from '@kbn/elastic-assistant-common';
import { ElasticsearchClient } from '@kbn/core-elasticsearch-server';
import { ActionsClientLlm } from '@kbn/langchain/server';
import { getLangSmithTracer } from '@kbn/langchain/server/tracers/langsmith';
import { Logger } from '@kbn/core/server';
import { asyncForEach } from '@kbn/std';
import { PublicMethodsOf } from '@kbn/utility-types';
import { AnonymizationFieldResponse } from '@kbn/elastic-assistant-common/impl/schemas/anonymization_fields/bulk_crud_anonymization_fields_route.gen';

import type { DefendInsightsGraphMetadata } from '../../langchain/graphs';
import { getLlmType } from '../../../routes/utils';
import { DefaultDefendInsightsGraph } from '../graphs/default_defend_insights_graph';
import { runEvaluations } from './run_evaluations';
import { DEFAULT_EVAL_ANONYMIZATION_FIELDS } from './constants';

export const evaluateDefendInsights = async ({
  insightType,
  endpointIds,
  actionsClient,
  defendInsightsGraphs,
  anonymizationFields = DEFAULT_EVAL_ANONYMIZATION_FIELDS, // determines which fields are included in the events
  connectors,
  connectorTimeout,
  datasetName,
  esClient,
  evaluationId,
  evaluatorConnectorId,
  langSmithApiKey,
  langSmithProject,
  logger,
  runName,
  size,
}: {
  insightType: DefendInsightType;
  endpointIds: string[];
  actionsClient: PublicMethodsOf<ActionsClient>;
  defendInsightsGraphs: DefendInsightsGraphMetadata[];
  anonymizationFields?: AnonymizationFieldResponse[];
  connectors: Connector[];
  connectorTimeout: number;
  datasetName: string;
  esClient: ElasticsearchClient;
  evaluationId: string;
  evaluatorConnectorId: string | undefined;
  langSmithApiKey: string | undefined;
  langSmithProject: string | undefined;
  logger: Logger;
  runName: string;
  size: number;
}): Promise<void> => {
  await asyncForEach(defendInsightsGraphs, async ({ getDefaultDefendInsightsGraph }) => {
    // create a graph for every connector:
    const graphs: Array<{
      connector: Connector;
      graph: DefaultDefendInsightsGraph;
      llmType: string | undefined;
      name: string;
      traceOptions: {
        projectName: string | undefined;
        tracers: LangChainTracer[];
      };
    }> = connectors.map((connector) => {
      const llmType = getLlmType(connector.actionTypeId);

      const traceOptions = {
        projectName: langSmithProject,
        tracers: [
          ...getLangSmithTracer({
            apiKey: langSmithApiKey,
            projectName: langSmithProject,
            logger,
          }),
        ],
      };

      const llm = new ActionsClientLlm({
        actionsClient,
        connectorId: connector.id,
        llmType,
        logger,
        temperature: 0, // zero temperature for insight, because we want structured JSON output
        timeout: connectorTimeout,
        traceOptions,
      });

      const graph = getDefaultDefendInsightsGraph({
        insightType,
        endpointIds,
        anonymizationFields,
        esClient,
        llm,
        logger,
        size,
      });

      return {
        connector,
        graph,
        llmType,
        name: `${runName} - ${connector.name} - ${evaluationId} - Defend insights`,
        traceOptions,
      };
    });

    // run the evaluations for each graph:
    await runEvaluations({
      actionsClient,
      connectorTimeout,
      evaluatorConnectorId,
      datasetName,
      graphs,
      langSmithApiKey,
      logger,
    });
  });
};
