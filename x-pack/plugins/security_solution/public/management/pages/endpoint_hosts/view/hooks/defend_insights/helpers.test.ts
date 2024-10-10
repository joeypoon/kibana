/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { isEmpty } from 'lodash/fp';

import type { ActionConnector } from '@kbn/triggers-actions-ui-plugin/public';
import type { DefendInsightsPostRequestBody } from '@kbn/elastic-assistant-common';

import { DefendInsightType } from '@kbn/elastic-assistant-common';
import { OpenAiProviderType } from '@kbn/stack-connectors-plugin/public/common';

import { getGenAiConfig, getRequestBody } from './helpers';

jest.mock('lodash/fp', () => ({
  isEmpty: jest.fn(),
}));

describe('defend insight hooks helpers', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getGenAiConfig', () => {
    it('should return undefined if connector is preconfigured', () => {
      const connector = { isPreconfigured: true } as ActionConnector;
      const result = getGenAiConfig(connector);
      expect(result).toBeUndefined();
    });

    it('should return GenAiConfig if connector is not preconfigured', () => {
      const connector = {
        isPreconfigured: false,
        config: {
          apiProvider: OpenAiProviderType.OpenAi,
          apiUrl: 'https://api.openai.com',
          defaultModel: 'gpt-3.5-turbo',
        },
      } as unknown as ActionConnector;
      const result = getGenAiConfig(connector);
      expect(result).toEqual({
        apiProvider: OpenAiProviderType.OpenAi,
        apiUrl: 'https://api.openai.com',
        defaultModel: 'gpt-3.5-turbo',
      });
    });

    it('should return GenAiConfig with Azure API version if apiProvider is AzureAi', () => {
      const connector = {
        isPreconfigured: false,
        config: {
          apiProvider: OpenAiProviderType.AzureAi,
          apiUrl: 'https://api.azure.com?api-version=2021-06-01',
          defaultModel: 'gpt-3.5-turbo',
        },
      } as unknown as ActionConnector;
      const result = getGenAiConfig(connector);
      expect(result).toEqual({
        apiProvider: OpenAiProviderType.AzureAi,
        apiUrl: 'https://api.azure.com?api-version=2021-06-01',
        defaultModel: '2021-06-01',
      });
    });
  });

  describe('getRequestBody', () => {
    it('should return DefendInsightsPostRequestBody with provided parameters', () => {
      const params = {
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
        anonymizationFields: {
          page: 1,
          perPage: 10,
          total: 1,
          data: [
            {
              id: '1',
              field: 'field1',
            },
          ],
        },
        genAiConfig: {
          apiProvider: OpenAiProviderType.OpenAi,
          apiUrl: 'https://api.openai.com',
          defaultModel: 'gpt-3.5-turbo',
        },
        selectedConnector: {
          id: 'connector1',
          actionTypeId: 'actionType1',
        } as ActionConnector,
        traceOptions: {
          apmUrl: 'https://apm.example.com',
          langSmithProject: 'project1',
          langSmithApiKey: 'apiKey1',
        },
      };

      (isEmpty as unknown as jest.Mock).mockImplementation((value) => !value);

      const result: DefendInsightsPostRequestBody = getRequestBody(params);
      expect(result).toEqual({
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
        anonymizationFields: [
          {
            id: '1',
            field: 'field1',
          },
        ],
        langSmithProject: 'project1',
        langSmithApiKey: 'apiKey1',
        replacements: {},
        subAction: 'invokeAI',
        apiConfig: {
          connectorId: 'connector1',
          actionTypeId: 'actionType1',
          provider: OpenAiProviderType.OpenAi,
          model: 'gpt-3.5-turbo',
        },
      });
    });

    it('should return DefendInsightsPostRequestBody with undefined langSmithProject and langSmithApiKey if they are empty', () => {
      const params = {
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
        anonymizationFields: {
          page: 1,
          perPage: 10,
          total: 1,
          data: [
            {
              id: '1',
              field: 'field1',
            },
          ],
        },
        genAiConfig: {
          apiProvider: OpenAiProviderType.OpenAi,
          apiUrl: 'https://api.openai.com',
          defaultModel: 'gpt-3.5-turbo',
        },
        selectedConnector: {
          id: 'connector1',
          actionTypeId: 'actionType1',
        } as ActionConnector,
        traceOptions: {
          apmUrl: 'https://apm.example.com',
          langSmithProject: '',
          langSmithApiKey: '',
        },
      };

      (isEmpty as unknown as jest.Mock).mockImplementation((value) => !value);

      const result: DefendInsightsPostRequestBody = getRequestBody(params);
      expect(result).toEqual({
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
        anonymizationFields: [
          {
            id: '1',
            field: 'field1',
          },
        ],
        langSmithProject: undefined,
        langSmithApiKey: undefined,
        replacements: {},
        subAction: 'invokeAI',
        apiConfig: {
          connectorId: 'connector1',
          actionTypeId: 'actionType1',
          provider: OpenAiProviderType.OpenAi,
          model: 'gpt-3.5-turbo',
        },
      });
    });
  });
});
