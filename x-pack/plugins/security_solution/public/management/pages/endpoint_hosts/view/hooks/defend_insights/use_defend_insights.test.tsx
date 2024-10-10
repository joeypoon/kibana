import { renderHook, act } from '@testing-library/react-hooks';

import {
  DefendInsightType,
  DefendInsightsPostResponse,
  ELASTIC_AI_ASSISTANT_INTERNAL_API_VERSION,
} from '@kbn/elastic-assistant-common';
import { useAssistantContext, useLoadConnectors } from '@kbn/elastic-assistant';
import { useFetchAnonymizationFields } from '@kbn/elastic-assistant/impl/assistant/api/anonymization_fields/use_fetch_anonymization_fields';

import { ERROR_GENERATING_DEFEND_INSIGHTS } from '../../../../../../app/translations';
import { useKibana } from '../../../../../../common/lib/kibana';
import { useDefendInsights } from './use_defend_insights';
import { usePollDefendInsights } from './use_polling';
import { getGenAiConfig, getRequestBody } from './helpers';

jest.mock('@kbn/elastic-assistant');
jest.mock(
  '@kbn/elastic-assistant/impl/assistant/api/anonymization_fields/use_fetch_anonymization_fields'
);
jest.mock('@kbn/elastic-assistant-common', () => {
  const originalModule = jest.requireActual('@kbn/elastic-assistant-common');
  return {
    ...originalModule,
    DefendInsightsPostResponse: {
      safeParse: jest.fn(),
    },
  };
});
jest.mock('../../../../../../common/lib/kibana');
jest.mock('./use_polling');
jest.mock('./helpers');

describe('useDefendInsights', () => {
  const mockHttp = {
    fetch: jest.fn(),
  };
  const mockToasts = {
    addDanger: jest.fn(),
  };

  beforeEach(() => {
    (useKibana as jest.Mock).mockReturnValue({
      services: {
        http: mockHttp,
        notifications: { toasts: mockToasts },
      },
    });
    (useLoadConnectors as jest.Mock).mockReturnValue({ data: [{ id: 'connector1' }] });
    (useAssistantContext as jest.Mock).mockReturnValue({ traceOptions: {} });
    (useFetchAnonymizationFields as jest.Mock).mockReturnValue({ data: [] });
    (usePollDefendInsights as jest.Mock).mockReturnValue({
      data: null,
      pollApi: jest.fn(),
      status: 'idle',
      setStatus: jest.fn(),
      didInitialFetch: false,
      stats: null,
    });
    (getGenAiConfig as jest.Mock).mockReturnValue({});
    (getRequestBody as jest.Mock).mockReturnValue({
      apiConfig: { connectorId: 'connector1', actionTypeId: 'actionType1' },
    });
    (DefendInsightsPostResponse.safeParse as jest.Mock).mockReturnValue({ success: true });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should initialize with default values', () => {
    const { result } = renderHook(() =>
      useDefendInsights({
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
      })
    );

    expect(result.current).toEqual({
      eventsContextCount: null,
      approximateFutureTime: null,
      insights: [],
      didInitialFetch: false,
      failureReason: null,
      fetchDefendInsights: expect.any(Function),
      generationIntervals: [],
      isLoading: false,
      isLoadingPost: false,
      replacements: {},
      stats: null,
    });
  });

  it('should set loading state when pollStatus is running', () => {
    (usePollDefendInsights as jest.Mock).mockReturnValue({
      data: null,
      pollApi: jest.fn(),
      status: 'running',
      setStatus: jest.fn(),
      didInitialFetch: false,
      stats: null,
    });

    const { result } = renderHook(() =>
      useDefendInsights({
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
      })
    );

    expect(result.current.isLoading).toBe(true);
  });

  it('should call pollApi and reset state when connectorId changes', () => {
    const pollApiMock = jest.fn();
    const setPollStatusMock = jest.fn();

    (usePollDefendInsights as jest.Mock).mockReturnValueOnce({
      data: null,
      pollApi: pollApiMock,
      status: 'idle',
      setStatus: setPollStatusMock,
      didInitialFetch: false,
      stats: null,
    });

    const { result, rerender } = renderHook(() =>
      useDefendInsights({
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
      })
    );

    rerender();

    expect(pollApiMock).toHaveBeenCalled();
    expect(result.current.eventsContextCount).toBe(null);
    expect(result.current.failureReason).toBe(null);
    expect(result.current.replacements).toEqual({});
    expect(result.current.insights).toEqual([]);
    expect(result.current.generationIntervals).toEqual([]);
    expect(setPollStatusMock).toHaveBeenCalledWith(null);
  });

  it('should update state based on pollData', () => {
    const pollDataMock = {
      connectorId: 'connector1',
      eventsContextCount: 5,
      replacements: { key: 'value' },
      status: 'succeeded',
      insights: [{ id: 'insight1' }],
      generationIntervals: [{ start: new Date(), end: new Date() }],
    };

    (usePollDefendInsights as jest.Mock).mockReturnValue({
      data: pollDataMock,
      pollApi: jest.fn(),
      status: 'idle',
      setStatus: jest.fn(),
      didInitialFetch: false,
      stats: null,
    });

    const { result } = renderHook(() =>
      useDefendInsights({
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
      })
    );

    expect(result.current.eventsContextCount).toBe(pollDataMock.eventsContextCount);
    expect(result.current.replacements).toEqual(pollDataMock.replacements);
    expect(result.current.failureReason).toBe(null);
    expect(result.current.insights).toEqual(pollDataMock.insights);
    expect(result.current.generationIntervals).toEqual(pollDataMock.generationIntervals);
  });

  it('should handle fetchDefendInsights success', async () => {
    const { result } = renderHook(() =>
      useDefendInsights({
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
      })
    );

    await act(async () => {
      await result.current.fetchDefendInsights();
    });

    expect(mockHttp.fetch).toHaveBeenCalledWith('/internal/elastic_assistant/defend_insights', {
      body: JSON.stringify({
        apiConfig: { connectorId: 'connector1', actionTypeId: 'actionType1' },
      }),
      method: 'POST',
      version: ELASTIC_AI_ASSISTANT_INTERNAL_API_VERSION,
    });
    expect(result.current.isLoadingPost).toBe(false);
  });

  it('should handle fetchDefendInsights error', async () => {
    (mockHttp.fetch as jest.Mock).mockRejectedValueOnce(new Error('Test error'));

    const { result } = renderHook(() =>
      useDefendInsights({
        endpointIds: ['endpoint1'],
        insightType: DefendInsightType.Enum.incompatible_antivirus,
      })
    );

    await act(async () => {
      await result.current.fetchDefendInsights();
    });

    expect(result.current.isLoadingPost).toBe(false);
    expect(result.current.isLoading).toBe(false);
    expect(mockToasts.addDanger).toHaveBeenCalledWith(expect.any(Error), {
      title: ERROR_GENERATING_DEFEND_INSIGHTS,
      text: 'Test error',
    });
  });
});
