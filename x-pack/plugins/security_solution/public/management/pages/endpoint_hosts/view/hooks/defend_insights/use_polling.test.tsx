/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { renderHook, act } from '@testing-library/react-hooks';

import type { IToasts } from '@kbn/core-notifications-browser';

import { coreMock } from '@kbn/core/public/mocks';
import { DefendInsightStatus, DefendInsightsGetResponse } from '@kbn/elastic-assistant-common';

import { ERROR_GENERATING_DEFEND_INSIGHTS } from '../../../../../../app/translations';
import { usePollDefendInsights, Props } from './use_polling';

jest.mock('@kbn/elastic-assistant-common', () => {
  const originalModule = jest.requireActual('@kbn/elastic-assistant-common');
  return {
    ...originalModule,
    DefendInsightsGetResponse: {
      safeParse: jest.fn(),
    },
  };
});

describe('usePollDefendInsights', () => {
  const mockHttp = coreMock.createSetup().http;
  const mockToasts = {
    addDanger: jest.fn(),
  } as unknown as IToasts;
  const setApproximateFutureTime = jest.fn();

  const defaultProps: Props = {
    http: mockHttp,
    setApproximateFutureTime,
    toasts: mockToasts,
    connectorId: 'test-connector-id',
  };

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should initialize with default values', () => {
    const { result } = renderHook(() => usePollDefendInsights(defaultProps));

    expect(result.current).toEqual({
      didInitialFetch: false,
      status: null,
      data: null,
      stats: null,
      pollApi: expect.any(Function),
      setStatus: expect.any(Function),
    });
  });

  it('should handle response correctly', async () => {
    const responseData = {
      updatedAt: '2023-01-01T00:00:00Z',
      averageIntervalMs: 5000,
      status: DefendInsightStatus.Enum.succeeded,
      id: 'test-id',
    };

    (DefendInsightsGetResponse.safeParse as jest.Mock).mockReturnValueOnce({
      success: true,
      data: { data: responseData, stats: [] },
    });

    const { result } = renderHook(() => usePollDefendInsights(defaultProps));

    expect(result.current.didInitialFetch).toBe(false);

    await act(async () => {
      await result.current.pollApi();
    });

    expect(result.current.didInitialFetch).toBe(true);
    expect(result.current.status).toBe(DefendInsightStatus.Enum.succeeded);
    expect(result.current.data).toEqual({ ...responseData, connectorId: 'test-connector-id' });
  });

  it('should handle pollApi error', async () => {
    (mockHttp.fetch as jest.Mock).mockRejectedValueOnce(new Error('Test error'));

    const { result } = renderHook(() => usePollDefendInsights(defaultProps));

    await act(async () => {
      await result.current.pollApi();
    });

    expect(result.current.status).toBe(null);
    expect(result.current.data).toBe(null);
    expect(mockToasts.addDanger).toHaveBeenCalledWith(expect.any(Error), {
      title: ERROR_GENERATING_DEFEND_INSIGHTS,
      text: 'Test error',
    });
  });

  it('should not update state if connectorId has changed', async () => {
    const { result, rerender } = renderHook((props: Props) => usePollDefendInsights(props), {
      initialProps: defaultProps,
    });

    rerender({ ...defaultProps, connectorId: 'new-connector-id' });

    await act(async () => {
      await result.current.pollApi();
    });

    expect(result.current.didInitialFetch).toBe(false);
    expect(result.current.status).toBe(null);
    expect(result.current.data).toBe(null);
  });

  it('should set stats correctly', async () => {
    const responseData = {
      updatedAt: '2023-01-01T00:00:00Z',
      averageIntervalMs: 5000,
      status: DefendInsightStatus.Enum.succeeded,
      id: 'test-id',
    };

    const statsData = [
      { hasViewed: false, status: 'succeeded', count: 1 },
      { hasViewed: false, status: 'failed', count: 0 },
    ];

    (DefendInsightsGetResponse.safeParse as jest.Mock).mockReturnValueOnce({
      success: true,
      data: { data: responseData, stats: statsData },
    });

    const { result } = renderHook(() => usePollDefendInsights(defaultProps));

    await act(async () => {
      await result.current.pollApi();
    });

    expect(result.current.stats).toEqual({
      newDiscoveriesCount: 1,
      newConnectorResultsCount: 2,
      statsPerConnector: statsData,
    });
  });
});
