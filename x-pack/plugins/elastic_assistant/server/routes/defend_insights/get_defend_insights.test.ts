/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AuthenticatedUser } from '@kbn/core-security-common';

import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';

import type { DefendInsightsDataClient } from '../../ai_assistant_data_clients/defend_insights';

import { transformESSearchToDefendInsights } from '../../ai_assistant_data_clients/defend_insights/helpers';
import { getDefendInsightsSearchEsMock } from '../../__mocks__/defend_insights_schema.mock';
import { getDefendInsightsRequest } from '../../__mocks__/request';
import { requestContextMock } from '../../__mocks__/request_context';
import { serverMock } from '../../__mocks__/server';
import { getDefendInsightStats, updateDefendInsightLastViewedAt } from './helpers';
import { getDefendInsightRoute } from './get_defend_insights';

jest.mock('./helpers');

const mockStats = {
  newConnectorResultsCount: 2,
  newInsightsCount: 4,
  statsPerConnector: [
    {
      hasViewed: false,
      status: 'failed',
      count: 0,
      connectorId: 'my-bedrock-old',
    },
    {
      hasViewed: false,
      status: 'running',
      count: 1,
      connectorId: 'my-gen-ai',
    },
    {
      hasViewed: true,
      status: 'succeeded',
      count: 1,
      connectorId: 'my-gpt4o-ai',
    },
    {
      hasViewed: true,
      status: 'canceled',
      count: 1,
      connectorId: 'my-bedrock',
    },
    {
      hasViewed: false,
      status: 'succeeded',
      count: 4,
      connectorId: 'my-gen-a2i',
    },
  ],
};
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
const mockDataClient = {
  findDefendInsightByConnectorId: jest.fn(),
  updateDefendInsight: jest.fn(),
  createDefendInsight: jest.fn(),
  getDefendInsight: jest.fn(),
} as unknown as DefendInsightsDataClient;
const mockCurrentInsight = transformESSearchToDefendInsights(getDefendInsightsSearchEsMock())[0];
describe('getDefendInsightRoute', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    context.elasticAssistant.getCurrentUser.mockReturnValue(mockUser);
    context.elasticAssistant.getDefendInsightsDataClient.mockResolvedValue(mockDataClient);

    getDefendInsightRoute(server.router);
    (updateDefendInsightLastViewedAt as jest.Mock).mockResolvedValue(mockCurrentInsight);
    (getDefendInsightStats as jest.Mock).mockResolvedValue(mockStats);
  });

  it('should handle successful request', async () => {
    const response = await server.inject(
      getDefendInsightsRequest('connector-id'),
      requestContextMock.convertContext(context)
    );
    expect(response.status).toEqual(200);
    expect(response.body).toEqual({
      data: mockCurrentInsight,
      stats: mockStats,
    });
  });

  it('should handle missing authenticated user', async () => {
    context.elasticAssistant.getCurrentUser.mockReturnValue(null);
    const response = await server.inject(
      getDefendInsightsRequest('connector-id'),
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
      getDefendInsightsRequest('connector-id'),
      requestContextMock.convertContext(context)
    );

    expect(response.status).toEqual(500);
    expect(response.body).toEqual({
      message: 'Defend insights data client not initialized',
      status_code: 500,
    });
  });

  it('should handle findDefendInsightByConnectorId null response', async () => {
    (updateDefendInsightLastViewedAt as jest.Mock).mockResolvedValue(null);
    const response = await server.inject(
      getDefendInsightsRequest('connector-id'),
      requestContextMock.convertContext(context)
    );
    expect(response.status).toEqual(200);
    expect(response.body).toEqual({
      stats: mockStats,
    });
  });

  it('should handle findDefendInsightByConnectorId error', async () => {
    (updateDefendInsightLastViewedAt as jest.Mock).mockRejectedValue(new Error('Oh no!'));
    const response = await server.inject(
      getDefendInsightsRequest('connector-id'),
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
