/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { UpdateRequest } from '@elastic/elasticsearch/lib/api/types';
import type { AuthenticatedUser } from '@kbn/core-security-common';
import type {
  DefendInsightCreateProps,
  DefendInsightUpdateProps,
  DefendInsightsResponse,
} from '@kbn/elastic-assistant-common';

import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import { loggerMock } from '@kbn/logging-mocks';
import { DefendInsightStatus, DefendInsightType } from '@kbn/elastic-assistant-common';

import type { AIAssistantDataClientParams } from '..';
import type { GetDefendInsightParams } from './get_defend_insight';

import { getDefendInsightsSearchEsMock } from '../../__mocks__/defend_insights_schema.mock';
import { getDefendInsight } from './get_defend_insight';
import { transformESSearchToDefendInsights } from './helpers';
import { DefendInsightsDataClient } from '.';

jest.mock('./get_defend_insight');

describe('DefendInsightsDataClient', () => {
  const mockEsClient = elasticsearchServiceMock.createElasticsearchClient();
  const mockLogger = loggerMock.create();
  const mockGetDefendInsight = jest.mocked(getDefendInsight);
  const user = {
    username: 'test_user',
    profile_uid: '1234',
    authentication_realm: {
      type: 'my_realm_type',
      name: 'my_realm_name',
    },
  } as AuthenticatedUser;
  const dataClientParams = {
    logger: mockLogger,
    currentUser: user,
    elasticsearchClientPromise: new Promise((resolve) => resolve(mockEsClient)),
    indexPatternsResourceName: 'defend-insights-index',
    kibanaVersion: '9.0.0',
    spaceId: 'space-1',
  } as AIAssistantDataClientParams;
  let dataClient: DefendInsightsDataClient;

  beforeAll(() => {
    jest.clearAllMocks();
    dataClient = new DefendInsightsDataClient(dataClientParams);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getDefendInsight', () => {
    it('should correctly get defend insight', async () => {
      const id = 'some-id';
      mockGetDefendInsight.mockResolvedValueOnce({ id } as DefendInsightsResponse);
      const response = await dataClient.getDefendInsight({ id, authenticatedUser: user });

      expect(mockGetDefendInsight).toHaveBeenCalledTimes(1);
      expect(response).not.toBeNull();
      expect(response!.id).toEqual(id);
    });
  });

  describe('createDefendInsight', () => {
    const defendInsightCreate: DefendInsightCreateProps = {
      insights: [],
      apiConfig: {
        actionTypeId: 'action-type-id',
        connectorId: 'connector-id',
        defaultSystemPromptId: 'default-prompt-id',
        model: 'model-name',
        provider: 'OpenAI',
      },
      eventsContextCount: 10,
      replacements: { key1: 'value1', key2: 'value2' },
      status: DefendInsightStatus.enum.running,
    };
    const mockArgs = {
      defendInsightCreate,
      authenticatedUser: user,
    };

    it('should create defend insight successfully', async () => {
      const id = 'created-id';
      // @ts-expect-error not full response interface
      mockEsClient.create.mockResolvedValueOnce({ _id: id });
      mockGetDefendInsight.mockResolvedValueOnce({ id } as DefendInsightsResponse);

      const response = await dataClient.createDefendInsight(mockArgs);
      expect(mockEsClient.create).toHaveBeenCalledTimes(1);
      expect(mockGetDefendInsight).toHaveBeenCalledTimes(1);
      expect(response).not.toBeNull();
      expect(response!.id).toEqual(id);
    });

    it('should throw error on elasticsearch create failure', async () => {
      mockEsClient.create.mockRejectedValueOnce(new Error('Elasticsearch error'));
      const responsePromise = dataClient.createDefendInsight(mockArgs);
      await expect(responsePromise).rejects.toThrowError('Elasticsearch error');
      expect(mockEsClient.create).toHaveBeenCalledTimes(1);
      expect(mockGetDefendInsight).not.toHaveBeenCalled();
    });
  });

  describe('findDefendInsightByConnectorId', () => {
    const mockResponse = getDefendInsightsSearchEsMock();
    const connectorId = 'connector-id';
    const mockReq = {
      connectorId,
      authenticatedUser: user,
    };

    it('should find defend insight by connector id successfully', async () => {
      mockEsClient.search.mockResolvedValueOnce(mockResponse);

      const response = await dataClient.findDefendInsightByConnectorId(mockReq);

      expect(mockEsClient.search).toHaveBeenCalledTimes(1);
      expect(response).not.toBeNull();
      expect(mockLogger.error).not.toHaveBeenCalled();
    });

    it('should return null if no defend insight found', async () => {
      mockEsClient.search.mockResolvedValueOnce({ ...mockResponse, hits: { hits: [] } });

      const response = await dataClient.findDefendInsightByConnectorId(mockReq);

      expect(mockEsClient.search).toHaveBeenCalledTimes(1);
      expect(response).toBeNull();
      expect(mockLogger.error).not.toHaveBeenCalled();
    });

    it('should throw error on elasticsearch search failure', async () => {
      mockEsClient.search.mockRejectedValueOnce(new Error('Elasticsearch error'));
      await expect(dataClient.findDefendInsightByConnectorId(mockReq)).rejects.toThrowError(
        'Elasticsearch error'
      );
      expect(mockEsClient.search).toHaveBeenCalledTimes(1);
      expect(mockLogger.error).toHaveBeenCalledTimes(1);
    });
  });

  describe('findAllDefendInsights', () => {
    const mockReq = {
      authenticatedUser: user,
    };

    it('should correctly query ES', async () => {
      const mockResponse = getDefendInsightsSearchEsMock();
      mockEsClient.search.mockResolvedValueOnce(mockResponse);
      const searchParams = {
        query: {
          bool: {
            must: [
              {
                nested: {
                  path: 'users',
                  query: {
                    bool: {
                      must: [
                        {
                          match: user.profile_uid
                            ? { 'users.id': user.profile_uid }
                            : { 'users.name': user.username },
                        },
                      ],
                    },
                  },
                },
              },
            ],
          },
        },
        size: 10000,
        _source: true,
        ignore_unavailable: true,
        index: `${dataClientParams.indexPatternsResourceName}-${dataClientParams.spaceId}`,
        seq_no_primary_term: true,
      };

      const response = await dataClient.findAllDefendInsights(mockReq);
      expect(response).not.toBeNull();
      expect(mockEsClient.search).toHaveBeenCalledTimes(1);
      expect(mockEsClient.search).toHaveBeenCalledWith(searchParams);
    });

    it('should throw error on elasticsearch search failure', async () => {
      mockEsClient.search.mockRejectedValueOnce(new Error('Elasticsearch error'));
      await expect(dataClient.findAllDefendInsights(mockReq)).rejects.toThrowError(
        'Elasticsearch error'
      );
      expect(mockEsClient.search).toHaveBeenCalledTimes(1);
      expect(mockLogger.error).toHaveBeenCalledTimes(1);
    });
  });

  describe('updateDefendInsight', () => {
    const date = new Date();
    const defendInsightUpdateProps: DefendInsightUpdateProps = {
      id: 'existing-id',
      backingIndex: 'defend-insights-index',
      status: DefendInsightStatus.enum.succeeded,
      insights: [
        {
          type: DefendInsightType.enum.incompatible_antivirus,
          group: 'windows_defender',
          events: [
            {
              id: 'event-id-1',
              endpointId: 'endpoint-id-1',
              value: '/windows/defender/scan.exe',
            },
          ],
        },
      ],
    };
    let getParams: GetDefendInsightParams;

    beforeAll(async () => {
      getParams = {
        id: defendInsightUpdateProps.id,
        esClient: await dataClientParams.elasticsearchClientPromise,
        logger: dataClientParams.logger,
        index: dataClientParams.indexPatternsResourceName,
        user: dataClientParams.currentUser,
      } as GetDefendInsightParams;
    });

    beforeEach(() => {
      const mockedGetResponse = transformESSearchToDefendInsights(
        getDefendInsightsSearchEsMock()
      )[0];
      mockedGetResponse.id = defendInsightUpdateProps.id;
      mockedGetResponse.backingIndex = defendInsightUpdateProps.backingIndex;
      mockGetDefendInsight.mockResolvedValueOnce(mockedGetResponse);
    });

    it('should update defend insight successfully', async () => {
      const mockReq = { defendInsightUpdateProps, authenticatedUser: user };
      const response = await dataClient.updateDefendInsight(mockReq);
      expect(response).not.toBeNull();
      expect(response!.id).toEqual(defendInsightUpdateProps.id);
      expect(mockEsClient.update).toHaveBeenCalledTimes(1);
      expect(mockEsClient.update).toHaveBeenCalledWith(
        expect.objectContaining({
          refresh: 'wait_for',
          index: defendInsightUpdateProps.backingIndex,
          id: defendInsightUpdateProps.id,
          doc: expect.objectContaining({
            insights: [
              {
                type: DefendInsightType.enum.incompatible_antivirus,
                group: 'windows_defender',
                events: [
                  {
                    id: 'event-id-1',
                    endpoint_id: 'endpoint-id-1',
                    value: '/windows/defender/scan.exe',
                  },
                ],
              },
            ],
            id: defendInsightUpdateProps.id,
            status: defendInsightUpdateProps.status,
          }),
        })
      );
      const updatedAtStr = (
        mockEsClient.update.mock.calls[0][0] as unknown as UpdateRequest<any, any>
      ).doc.updated_at;
      expect(new Date(updatedAtStr).getTime()).toBeGreaterThan(date.getTime());
      expect(mockGetDefendInsight).toHaveBeenCalledTimes(1);
      expect(mockGetDefendInsight).toHaveBeenCalledWith(getParams);
    });

    it('should throw error on elasticsearch update failure', async () => {
      const mockReq = { defendInsightUpdateProps, authenticatedUser: user };
      const error = new Error('Elasticsearch update error');
      mockEsClient.update.mockRejectedValueOnce(error);

      await expect(dataClient.updateDefendInsight(mockReq)).rejects.toThrowError(error);

      expect(mockEsClient.update).toHaveBeenCalledTimes(1);
      expect(mockLogger.warn).toHaveBeenCalledTimes(1);
      expect(mockLogger.warn).toHaveBeenCalledWith(
        `Error updating Defend insight: ${error} by ID: existing-id`
      );
    });
  });
});
