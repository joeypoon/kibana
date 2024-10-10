/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import moment from 'moment';

import { DefendInsightStatus, DefendInsightType } from '@kbn/elastic-assistant-common';
import { OpenAiProviderType } from '@kbn/stack-connectors-plugin/common/openai/constants';

import {
  DEFEND_INSIGHT_ERROR_EVENT,
  DEFEND_INSIGHT_SUCCESS_EVENT,
} from '../../lib/telemetry/event_based_telemetry';
import {
  getAssistantTool,
  getAssistantToolParams,
  handleToolError,
  updateDefendInsightStatusToRunning,
  updateDefendInsights,
  updateDefendInsightLastViewedAt,
  getDefendInsightStats,
} from './helpers';

describe('defend insights route helpers', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getAssistantTool', () => {
    it('should return the defend-insights tool', () => {
      const getRegisteredTools = jest.fn().mockReturnValue([{ id: 'defend-insights' }]);
      const result = getAssistantTool(getRegisteredTools, 'pluginName');
      expect(result).toEqual({ id: 'defend-insights' });
    });
  });

  describe('getAssistantToolParams', () => {
    it('should return the correct tool params', () => {
      const params = {
        endpointIds: ['endpoint-id1'],
        insightType: DefendInsightType.enum.incompatible_antivirus,
        actionsClient: {} as any,
        anonymizationFields: [],
        apiConfig: { connectorId: 'connector-id1', actionTypeId: 'action-type-id1' },
        esClient: {} as any,
        connectorTimeout: 1000,
        langChainTimeout: 1000,
        langSmithProject: 'project',
        langSmithApiKey: 'apiKey',
        logger: {} as any,
        latestReplacements: {},
        onNewReplacements: jest.fn(),
        request: {} as any,
      };
      const result = getAssistantToolParams(params);

      expect(result).toHaveProperty('endpointIds', params.endpointIds);
      expect(result).toHaveProperty('insightType', params.insightType);
      expect(result).toHaveProperty('llm');
    });
  });

  describe('handleToolError', () => {
    it('should handle tool error and update defend insight', async () => {
      const params = {
        apiConfig: {
          connectorId: 'connector-id1',
          actionTypeId: 'action-type-id1',
          model: 'model',
          provider: OpenAiProviderType.OpenAi,
        },
        defendInsightId: 'id',
        authenticatedUser: {} as any,
        dataClient: {
          getDefendInsight: jest.fn().mockResolvedValueOnce({
            status: DefendInsightStatus.enum.running,
            backingIndex: 'index',
          }),
          updateDefendInsight: jest.fn(),
        } as any,
        err: new Error('error'),
        latestReplacements: {},
        logger: { error: jest.fn() } as any,
        telemetry: { reportEvent: jest.fn() } as any,
      };
      await handleToolError(params);

      expect(params.dataClient.updateDefendInsight).toHaveBeenCalledTimes(1);
      expect(params.telemetry.reportEvent).toHaveBeenCalledWith(
        DEFEND_INSIGHT_ERROR_EVENT.eventType,
        expect.any(Object)
      );
    });
  });

  describe('updateDefendInsightStatusToRunning', () => {
    it('should update defend insight status to running', async () => {
      const params = {
        dataClient: {
          findDefendInsightByConnectorId: jest
            .fn()
            .mockResolvedValueOnce({ id: 'defend-insight-id1', backingIndex: 'backing-index' }),
          updateDefendInsight: jest.fn().mockResolvedValueOnce({ id: 'defend-insight-id1' }),
          createDefendInsight: jest.fn(),
        } as any,
        authenticatedUser: {} as any,
        apiConfig: {
          connectorId: 'connector-id1',
          actionTypeId: 'action-type-id1',
          model: 'model',
          provider: OpenAiProviderType.OpenAi,
        },
      };
      const result = await updateDefendInsightStatusToRunning(
        params.dataClient,
        params.authenticatedUser,
        params.apiConfig
      );

      expect(params.dataClient.findDefendInsightByConnectorId).toHaveBeenCalledTimes(1);
      expect(params.dataClient.findDefendInsightByConnectorId).toHaveBeenCalledWith({
        connectorId: params.apiConfig.connectorId,
        authenticatedUser: params.authenticatedUser,
      });
      expect(params.dataClient.updateDefendInsight).toHaveBeenCalledTimes(1);
      expect(params.dataClient.updateDefendInsight).toHaveBeenCalledWith({
        defendInsightUpdateProps: {
          backingIndex: 'backing-index',
          id: 'defend-insight-id1',
          status: DefendInsightStatus.enum.running,
        },
        authenticatedUser: params.authenticatedUser,
      });
      expect(result).toEqual({
        defendInsightId: 'defend-insight-id1',
        currentInsight: { id: 'defend-insight-id1' },
      });
    });

    it('should create a new defend insight if not found', async () => {
      const params = {
        dataClient: {
          findDefendInsightByConnectorId: jest.fn().mockResolvedValueOnce(null),
          updateDefendInsight: jest.fn(),
          createDefendInsight: jest.fn().mockResolvedValueOnce({ id: 'id' }),
        } as any,
        authenticatedUser: {} as any,
        apiConfig: {
          connectorId: 'connector-id1',
          actionTypeId: 'action-type-id1',
          model: 'model',
          provider: OpenAiProviderType.OpenAi,
        },
      };
      const result = await updateDefendInsightStatusToRunning(
        params.dataClient,
        params.authenticatedUser,
        params.apiConfig
      );

      expect(params.dataClient.findDefendInsightByConnectorId).toHaveBeenCalledTimes(1);
      expect(params.dataClient.findDefendInsightByConnectorId).toHaveBeenCalledWith({
        connectorId: params.apiConfig.connectorId,
        authenticatedUser: params.authenticatedUser,
      });
      expect(params.dataClient.createDefendInsight).toHaveBeenCalledTimes(1);
      expect(params.dataClient.createDefendInsight).toHaveBeenCalledWith({
        defendInsightCreate: {
          apiConfig: params.apiConfig,
          insights: [],
          status: DefendInsightStatus.enum.running,
        },
        authenticatedUser: params.authenticatedUser,
      });
      expect(result).toEqual({ defendInsightId: 'id', currentInsight: { id: 'id' } });
    });
  });

  describe('updateDefendInsights', () => {
    it('should update defend insights', async () => {
      const params = {
        apiConfig: {
          connectorId: 'connector-id1',
          actionTypeId: 'action-type-id1',
          model: 'model',
          provider: OpenAiProviderType.OpenAi,
        },
        defendInsightId: 'insight-id1',
        authenticatedUser: {} as any,
        dataClient: {
          getDefendInsight: jest.fn().mockResolvedValueOnce({
            status: DefendInsightStatus.Enum.running,
            backingIndex: 'backing-index-name',
            generationIntervals: [],
          }),
          updateDefendInsight: jest.fn(),
        } as any,
        latestReplacements: {},
        logger: { error: jest.fn() } as any,
        rawDefendInsights: '{"eventsContextCount": 5, "insights": ["insight1", "insight2"]}',
        startTime: moment(),
        telemetry: { reportEvent: jest.fn() } as any,
      };
      await updateDefendInsights(params);

      expect(params.dataClient.getDefendInsight).toHaveBeenCalledTimes(1);
      expect(params.dataClient.getDefendInsight).toHaveBeenCalledWith({
        id: params.defendInsightId,
        authenticatedUser: params.authenticatedUser,
      });
      expect(params.dataClient.updateDefendInsight).toHaveBeenCalledTimes(1);
      expect(params.dataClient.updateDefendInsight).toHaveBeenCalledWith({
        defendInsightUpdateProps: {
          eventsContextCount: 5,
          insights: ['insight1', 'insight2'],
          status: DefendInsightStatus.Enum.succeeded,
          generationIntervals: expect.arrayContaining([
            expect.objectContaining({
              date: expect.any(String),
              durationMs: expect.any(Number),
            }),
          ]),
          id: params.defendInsightId,
          replacements: params.latestReplacements,
          backingIndex: 'backing-index-name',
        },
        authenticatedUser: params.authenticatedUser,
      });
      expect(params.telemetry.reportEvent).toHaveBeenCalledWith(
        DEFEND_INSIGHT_SUCCESS_EVENT.eventType,
        expect.any(Object)
      );
    });

    it('should handle error if rawDefendInsights is null', async () => {
      const params = {
        apiConfig: {
          connectorId: 'connector-id1',
          actionTypeId: 'action-type-id1',
          model: 'model',
          provider: OpenAiProviderType.OpenAi,
        },
        defendInsightId: 'id',
        authenticatedUser: {} as any,
        dataClient: {
          getDefendInsight: jest.fn().mockResolvedValueOnce({
            status: DefendInsightStatus.enum.running,
            backingIndex: 'index',
            generationIntervals: [],
          }),
          updateDefendInsight: jest.fn(),
        } as any,
        latestReplacements: {},
        logger: { error: jest.fn() } as any,
        rawDefendInsights: null,
        startTime: moment(),
        telemetry: { reportEvent: jest.fn() } as any,
      };
      await updateDefendInsights(params);

      expect(params.logger.error).toHaveBeenCalledTimes(1);
      expect(params.telemetry.reportEvent).toHaveBeenCalledTimes(1);
      expect(params.telemetry.reportEvent).toHaveBeenCalledWith(
        DEFEND_INSIGHT_ERROR_EVENT.eventType,
        expect.any(Object)
      );
    });
  });

  describe('updateDefendInsightLastViewedAt', () => {
    it('should update lastViewedAt time', async () => {
      // ensure difference regardless of processing speed
      const startTime = new Date().getTime() - 1;
      const params = {
        connectorId: 'connector-id1',
        authenticatedUser: {} as any,
        dataClient: {
          findDefendInsightByConnectorId: jest
            .fn()
            .mockResolvedValueOnce({ id: 'defend-insight-id1', backingIndex: 'backing-index' }),
          updateDefendInsight: jest.fn().mockResolvedValueOnce({ id: 'defend-insight-id1' }),
        } as any,
      };
      const result = await updateDefendInsightLastViewedAt(params);

      expect(params.dataClient.findDefendInsightByConnectorId).toHaveBeenCalledTimes(1);
      expect(params.dataClient.findDefendInsightByConnectorId).toHaveBeenCalledWith({
        connectorId: params.connectorId,
        authenticatedUser: params.authenticatedUser,
      });
      expect(params.dataClient.updateDefendInsight).toHaveBeenCalledTimes(1);
      expect(params.dataClient.updateDefendInsight).toHaveBeenCalledWith({
        defendInsightUpdateProps: expect.objectContaining({
          id: 'defend-insight-id1',
          backingIndex: 'backing-index',
        }),
        authenticatedUser: params.authenticatedUser,
      });
      expect(
        new Date(
          params.dataClient.updateDefendInsight.mock.calls[0][0].defendInsightUpdateProps.lastViewedAt
        ).getTime()
      ).toBeGreaterThan(startTime);
      expect(result).toEqual({ id: 'defend-insight-id1' });
    });

    it('should return null if defend insight not found', async () => {
      const params = {
        connectorId: 'connectorId',
        authenticatedUser: {} as any,
        dataClient: {
          findDefendInsightByConnectorId: jest.fn().mockResolvedValueOnce(null),
          updateDefendInsight: jest.fn(),
        } as any,
      };
      const result = await updateDefendInsightLastViewedAt(params);

      expect(params.dataClient.findDefendInsightByConnectorId).toHaveBeenCalledTimes(1);
      expect(params.dataClient.findDefendInsightByConnectorId).toHaveBeenCalledWith({
        connectorId: params.connectorId,
        authenticatedUser: params.authenticatedUser,
      });
      expect(result).toBeNull();
    });
  });

  describe('getDefendInsightStats', () => {
    it('should return defend insight stats', async () => {
      const params = {
        authenticatedUser: {} as any,
        dataClient: {
          findAllDefendInsights: jest.fn().mockResolvedValueOnce([
            {
              updatedAt: '2023-01-01T00:00:00Z',
              lastViewedAt: '2023-01-01T00:00:00Z',
              insights: [{}, {}],
              status: DefendInsightStatus.enum.succeeded,
              apiConfig: { connectorId: 'connector-id1' },
            },
          ]),
        } as any,
      };

      const result = await getDefendInsightStats(params);
      expect(result).toEqual([
        {
          hasViewed: true,
          status: DefendInsightStatus.enum.succeeded,
          count: 2,
          connectorId: 'connector-id1',
        },
      ]);
    });
  });
});
