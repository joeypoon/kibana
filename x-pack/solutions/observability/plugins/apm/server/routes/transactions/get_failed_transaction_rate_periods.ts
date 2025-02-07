/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
import type { BoolQuery } from '@kbn/es-query';
import { getFailedTransactionRate } from '../../lib/transaction_groups/get_failed_transaction_rate';
import { offsetPreviousPeriodCoordinates } from '../../../common/utils/offset_previous_period_coordinate';
import type { APMEventClient } from '../../lib/helpers/create_es_client/create_apm_event_client';
import type { Coordinate } from '../../../typings/timeseries';
import type { ApmServiceTransactionDocumentType } from '../../../common/document_type';
import type { RollupInterval } from '../../../common/rollup';

export interface FailedTransactionRateResponse {
  currentPeriod: {
    timeseries: Coordinate[];
    average: number | null;
  };
  previousPeriod: {
    timeseries: Coordinate[];
    average: number | null;
  };
}

export async function getFailedTransactionRatePeriods({
  environment,
  kuery,
  filters,
  serviceName,
  transactionType,
  transactionName,
  apmEventClient,
  start,
  end,
  offset,
  documentType,
  rollupInterval,
  bucketSizeInSeconds,
}: {
  environment: string;
  kuery: string;
  filters?: BoolQuery;
  serviceName: string;
  transactionType: string;
  transactionName?: string;
  apmEventClient: APMEventClient;
  start: number;
  end: number;
  offset?: string;
  documentType: ApmServiceTransactionDocumentType;
  rollupInterval: RollupInterval;
  bucketSizeInSeconds: number;
}): Promise<FailedTransactionRateResponse> {
  const commonProps = {
    environment,
    kuery,
    filters,
    serviceName,
    transactionTypes: [transactionType],
    transactionName,
    apmEventClient,
    documentType,
    rollupInterval,
    bucketSizeInSeconds,
  };

  const currentPeriodPromise = getFailedTransactionRate({
    ...commonProps,
    start,
    end,
  });

  const previousPeriodPromise = offset
    ? getFailedTransactionRate({
        ...commonProps,
        start,
        end,
        offset,
      })
    : { timeseries: [], average: null };

  const [currentPeriod, previousPeriod] = await Promise.all([
    currentPeriodPromise,
    previousPeriodPromise,
  ]);

  const currentPeriodTimeseries = currentPeriod.timeseries;

  return {
    currentPeriod,
    previousPeriod: {
      ...previousPeriod,
      timeseries: offsetPreviousPeriodCoordinates({
        currentPeriodTimeseries,
        previousPeriodTimeseries: previousPeriod.timeseries,
      }),
    },
  };
}
