/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CloudSetup } from '@kbn/cloud-plugin/server';
import { merge } from 'lodash';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import { elasticsearchServiceMock } from '@kbn/core/server/mocks';

import type { ServerlessSecurityConfig } from '../../../config';
import type { MeteringCallbackInput } from '../../../types';
import { ProductLine, ProductTier } from '../../../../common/product';
import { METERING_TASK } from '../../constants/metering';
import { Ai4SocMeteringService } from '../metering_service';

describe('Ai4SocMeteringService', () => {
  const mockTaskId = 'test-task-id';
  const mockProjectId = 'test-project-id';

  function buildDefaultUsageRecordArgs(
    overrides: Partial<MeteringCallbackInput> = {}
  ): MeteringCallbackInput {
    return merge(
      {
        logger: loggingSystemMock.createLogger(),
        taskId: mockTaskId,
        cloudSetup: {
          serverless: {
            projectId: mockProjectId,
          },
        } as CloudSetup,
        esClient: elasticsearchServiceMock.createElasticsearchClient(),
        abortController: new AbortController(),
        lastSuccessfulReport: new Date(),
        config: {
          productTypes: [
            {
              product_line: ProductLine.aiSoc,
              product_tier: ProductTier.searchAiLake,
            },
          ],
        } as ServerlessSecurityConfig,
      },
      overrides
    );
  }

  let service: Ai4SocMeteringService;

  beforeEach(() => {
    service = new Ai4SocMeteringService();
    jest.clearAllMocks();
  });

  describe('getUsageRecords', () => {
    it('returns empty records when no ai4soc product is configured', async () => {
      const config = {
        productTypes: [
          {
            product_line: ProductLine.security,
            product_tier: ProductTier.essentials,
          },
        ],
      } as ServerlessSecurityConfig;
      const args = buildDefaultUsageRecordArgs({ config });

      const result = await service.getUsageRecords(args);

      expect(result).toEqual({ records: [] });
      expect(args.logger.error).not.toHaveBeenCalled();
    });

    it('returns empty records and logs error when project ID is missing', async () => {
      const cloudSetup: CloudSetup = null as unknown as CloudSetup;
      const args = buildDefaultUsageRecordArgs({ cloudSetup });
      const result = await service.getUsageRecords(args);

      expect(result).toEqual({ records: [] });
      expect(args.logger.error).toHaveBeenCalledWith(
        expect.stringContaining('ai4soc metering failed due to project id missing')
      );
    });

    it('returns valid metering record', async () => {
      const args = buildDefaultUsageRecordArgs();
      const result = await service.getUsageRecords(args);

      const record = result.records[0];
      expect(record).toMatchObject({
        id: expect.stringContaining(mockProjectId),
        usage: {
          type: METERING_TASK.USAGE_TYPE,
          period_seconds: METERING_TASK.SAMPLE_PERIOD_SECONDS,
          quantity: 1,
        },
        source: {
          id: mockTaskId,
          instance_group_id: mockProjectId,
          metadata: {
            tier: ProductTier.searchAiLake,
          },
        },
      });

      expect(result.shouldRunAgain).toBe(false);
      expect(args.logger.error).not.toHaveBeenCalled();
    });

    it('correctly truncates record.id timestamp to hours', async () => {
      const mockTimestamp = '2025-03-04T13:14:15.678Z';
      jest.useFakeTimers().setSystemTime(new Date(mockTimestamp));

      const result = await service.getUsageRecords(buildDefaultUsageRecordArgs());
      const record = result.records[0];
      expect(record.id).toEqual(`ai4soc-${mockProjectId}-2025-03-04T13:00:00.000Z`);
      expect(record.usage_timestamp).toEqual(mockTimestamp);
      expect(record.creation_timestamp).toEqual(mockTimestamp);

      jest.useRealTimers();
    });
  });
});
