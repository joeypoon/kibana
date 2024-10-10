/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AuthenticatedUser } from '@kbn/core-security-common';
import type { DefendInsightsPostRequestBody } from '@kbn/elastic-assistant-common';

import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import { actionsMock } from '@kbn/actions-plugin/server/mocks';
import { OpenAiProviderType } from '@kbn/stack-connectors-plugin/common/openai/constants';
import { DefendInsightStatus, DefendInsightType } from '@kbn/elastic-assistant-common';

import type { DefendInsightsDataClient } from '../../ai_assistant_data_clients/defend_insights';

import { serverMock } from '../../__mocks__/server';
import { requestContextMock } from '../../__mocks__/request_context';
import { transformESSearchToDefendInsights } from '../../ai_assistant_data_clients/defend_insights/helpers';
import { getDefendInsightsSearchEsMock } from '../../__mocks__/defend_insights_schema.mock';
import { postDefendInsightsRequest } from '../../__mocks__/request';
import {
  getAssistantTool,
  getAssistantToolParams,
  updateDefendInsightStatusToRunning,
} from './helpers';
import { postDefendInsightsRoute } from './post_defend_insights';

jest.mock('./helpers');

const { clients, context } = requestContextMock.createTools();
const server: ReturnType<typeof serverMock.create> = serverMock.create();
clients.core.elasticsearch.client = elasticsearchServiceMock.createScopedClusterClient();

const mockUser = {
  username: 'my_username',
  authentication_realm: {
    type: 'my_realm_type',
    name: 'my_realm_name',
  },
} as AuthenticatedUser;
const findDefendInsightByConnectorId = jest.fn();
const mockDataClient = {
  findDefendInsightByConnectorId,
  updateDefendInsight: jest.fn(),
  createDefendInsight: jest.fn(),
  getDefendInsight: jest.fn(),
} as unknown as DefendInsightsDataClient;
const mockApiConfig = {
  connectorId: 'connector-id',
  actionTypeId: '.bedrock',
  model: 'model',
  provider: OpenAiProviderType.OpenAi,
};
const mockRequestBody: DefendInsightsPostRequestBody = {
  endpointIds: [],
  insightType: DefendInsightType.enum.incompatible_antivirus,
  subAction: 'invokeAI',
  apiConfig: mockApiConfig,
  anonymizationFields: [],
  replacements: {},
  model: 'gpt-4',
  langSmithProject: 'langSmithProject',
  langSmithApiKey: 'langSmithApiKey',
};
const mockCurrentInsight = transformESSearchToDefendInsights(getDefendInsightsSearchEsMock())[0];
const runningInsight = {
  ...mockCurrentInsight,
  status: DefendInsightStatus.enum.running,
};
describe('postDefendInsightsRoute', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    context.elasticAssistant.getCurrentUser.mockReturnValue(mockUser);
    context.elasticAssistant.getDefendInsightsDataClient.mockResolvedValue(mockDataClient);
    context.elasticAssistant.actions = actionsMock.createStart();
    postDefendInsightsRoute(server.router);
    findDefendInsightByConnectorId.mockResolvedValue(mockCurrentInsight);
    (getAssistantTool as jest.Mock).mockReturnValue({ getTool: jest.fn() });
    (getAssistantToolParams as jest.Mock).mockReturnValue({ tool: 'tool' });
    (updateDefendInsightStatusToRunning as jest.Mock).mockResolvedValue({
      currentInsight: runningInsight,
      defendInsightId: mockCurrentInsight.id,
    });
  });

  it('should handle successful request', async () => {
    const response = await server.inject(
      postDefendInsightsRequest(mockRequestBody),
      requestContextMock.convertContext(context)
    );
    expect(response.status).toEqual(200);
    expect(response.body).toEqual(runningInsight);
  });

  it('should handle missing authenticated user', async () => {
    context.elasticAssistant.getCurrentUser.mockReturnValue(null);
    const response = await server.inject(
      postDefendInsightsRequest(mockRequestBody),
      requestContextMock.convertContext(context)
    );

    expect(response.status).toEqual(401);
    expect(response.body).toEqual({
      message: 'Authenticated user not found',
      status_code: 401,
    });
  });

  it('should handle missing data client', async () => {
    context.elasticAssistant.getDefendInsightsDataClient.mockResolvedValue(null);
    const response = await server.inject(
      postDefendInsightsRequest(mockRequestBody),
      requestContextMock.convertContext(context)
    );

    expect(response.status).toEqual(500);
    expect(response.body).toEqual({
      message: 'Defend insights data client not initialized',
      status_code: 500,
    });
  });

  it('should handle assistantTool null response', async () => {
    (getAssistantTool as jest.Mock).mockReturnValue(null);
    const response = await server.inject(
      postDefendInsightsRequest(mockRequestBody),
      requestContextMock.convertContext(context)
    );
    expect(response.status).toEqual(404);
  });

  it('should handle updateDefendInsightStatusToRunning error', async () => {
    (updateDefendInsightStatusToRunning as jest.Mock).mockRejectedValue(new Error('Oh no!'));
    const response = await server.inject(
      postDefendInsightsRequest(mockRequestBody),
      requestContextMock.convertContext(context)
    );
    expect(response.status).toEqual(500);
    expect(response.body).toEqual({
      message: {
        error: 'Oh no!',
        success: false,
      },
      status_code: 500,
    });
  });
});
