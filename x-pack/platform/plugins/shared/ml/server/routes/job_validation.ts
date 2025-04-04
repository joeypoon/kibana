/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import Boom from '@hapi/boom';
import type { IScopedClusterClient } from '@kbn/core/server';
import type { TypeOf } from '@kbn/config-schema';
import { ML_INTERNAL_BASE_PATH } from '../../common/constants/app';
import type { AnalysisConfig, Datafeed } from '../../common/types/anomaly_detection_jobs';
import { wrapError } from '../client/error_wrapper';
import type { RouteInitialization } from '../types';
import {
  estimateBucketSpanSchema,
  modelMemoryLimitSchema,
  validateCardinalitySchema,
  validateJobSchema,
  validateDatafeedPreviewSchema,
} from './schemas/job_validation_schema';
import { estimateBucketSpanFactory } from '../models/bucket_span_estimator';
import { calculateModelMemoryLimitProvider } from '../models/calculate_model_memory_limit';
import {
  validateJob,
  validateCardinality,
  validateDatafeedPreview,
} from '../models/job_validation';
import { getAuthorizationHeader } from '../lib/request_authorization';
import type { MlClient } from '../lib/ml_client';
import type { CombinedJob } from '../../common/types/anomaly_detection_jobs';

type CalculateModelMemoryLimitPayload = TypeOf<typeof modelMemoryLimitSchema>;

/**
 * Routes for job validation
 */
export function jobValidationRoutes({ router, mlLicense, routeGuard }: RouteInitialization) {
  function calculateModelMemoryLimit(
    client: IScopedClusterClient,
    mlClient: MlClient,
    payload: CalculateModelMemoryLimitPayload
  ) {
    const {
      datafeedConfig,
      analysisConfig,
      indexPattern,
      query,
      timeFieldName,
      earliestMs,
      latestMs,
    } = payload;

    return calculateModelMemoryLimitProvider(client, mlClient)(
      analysisConfig as AnalysisConfig,
      indexPattern,
      query,
      timeFieldName,
      earliestMs,
      latestMs,
      undefined,
      datafeedConfig as Datafeed
    );
  }

  router.versioned
    .post({
      path: `${ML_INTERNAL_BASE_PATH}/validate/estimate_bucket_span`,
      access: 'internal',
      security: {
        authz: {
          requiredPrivileges: ['ml:canCreateJob'],
        },
      },
      summary: 'Estimates bucket span',
      description:
        'Estimates the minimum viable bucket span based on the characteristics of a pre-viewed subset of the data.',
    })
    .addVersion(
      {
        version: '1',
        validate: {
          request: { body: estimateBucketSpanSchema },
        },
      },

      routeGuard.fullLicenseAPIGuard(async ({ client, request, response }) => {
        try {
          let errorResp;
          const resp = await estimateBucketSpanFactory(client)(request.body)
            // this catch gets triggered when the estimation code runs without error
            // but isn't able to come up with a bucket span estimation.
            // this doesn't return a HTTP error but an object with an error message a HTTP error would be
            // too severe for this case.
            .catch((error: any) => {
              errorResp = {
                error: true,
                message: error,
              };
            });

          return response.ok({
            body: errorResp !== undefined ? errorResp : resp,
          });
        } catch (e) {
          // this catch gets triggered when an actual error gets thrown when running
          // the estimation code, for example when the request payload is malformed
          throw Boom.badRequest(e);
        }
      })
    );

  router.versioned
    .post({
      path: `${ML_INTERNAL_BASE_PATH}/validate/calculate_model_memory_limit`,
      access: 'internal',
      security: {
        authz: {
          requiredPrivileges: ['ml:canCreateJob'],
        },
      },
      summary: 'Calculates model memory limit',
      description: 'Calls _estimate_model_memory endpoint to retrieve model memory estimation.',
    })
    .addVersion(
      {
        version: '1',
        validate: {
          request: {
            body: modelMemoryLimitSchema,
          },
        },
      },
      routeGuard.fullLicenseAPIGuard(async ({ client, mlClient, request, response }) => {
        try {
          const resp = await calculateModelMemoryLimit(client, mlClient, request.body);

          return response.ok({
            body: resp,
          });
        } catch (e) {
          return response.customError(wrapError(e));
        }
      })
    );

  router.versioned
    .post({
      path: `${ML_INTERNAL_BASE_PATH}/validate/cardinality`,
      access: 'internal',
      security: {
        authz: {
          requiredPrivileges: ['ml:canCreateJob'],
        },
      },
      summary: 'Validates cardinality',
      description: 'Validates cardinality for the given job configuration.',
    })
    .addVersion(
      {
        version: '1',
        validate: {
          request: {
            body: validateCardinalitySchema,
          },
        },
      },
      routeGuard.fullLicenseAPIGuard(async ({ client, request, response }) => {
        try {
          // @ts-expect-error datafeed config is incorrect
          const resp = await validateCardinality(client, request.body);

          return response.ok({
            body: resp,
          });
        } catch (e) {
          return response.customError(wrapError(e));
        }
      })
    );

  router.versioned
    .post({
      path: `${ML_INTERNAL_BASE_PATH}/validate/job`,
      access: 'internal',
      security: {
        authz: {
          requiredPrivileges: ['ml:canCreateJob'],
        },
      },
      summary: 'Validates job',
      description: 'Validates the given job configuration.',
    })
    .addVersion(
      {
        version: '1',
        validate: {
          request: {
            body: validateJobSchema,
          },
        },
      },
      routeGuard.fullLicenseAPIGuard(async ({ client, mlClient, request, response }) => {
        try {
          const resp = await validateJob(
            client,
            mlClient,
            request.body,
            getAuthorizationHeader(request),
            mlLicense.isSecurityEnabled() === false
          );

          return response.ok({
            body: resp,
          });
        } catch (e) {
          return response.customError(wrapError(e));
        }
      })
    );

  router.versioned
    .post({
      path: `${ML_INTERNAL_BASE_PATH}/validate/datafeed_preview`,
      access: 'internal',
      security: {
        authz: {
          requiredPrivileges: ['ml:canCreateJob'],
        },
      },
      summary: 'Validates datafeed preview',
      description: 'Validates that the datafeed preview runs successfully and produces results.',
    })
    .addVersion(
      {
        version: '1',
        validate: {
          request: {
            body: validateDatafeedPreviewSchema,
          },
        },
      },
      routeGuard.fullLicenseAPIGuard(async ({ client, mlClient, request, response }) => {
        try {
          const {
            body: { job, start, end },
          } = request;

          const resp = await validateDatafeedPreview(
            mlClient,
            getAuthorizationHeader(request),
            job as CombinedJob,
            start,
            end
          );

          return response.ok({
            body: resp,
          });
        } catch (e) {
          return response.customError(wrapError(e));
        }
      })
    );
}
