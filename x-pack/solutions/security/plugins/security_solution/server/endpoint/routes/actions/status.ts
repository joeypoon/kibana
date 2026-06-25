/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RequestHandler } from '@kbn/core/server';
import type { TypeOf } from '@kbn/config-schema';
import { errorHandler } from '../error_handler';
import { stringify } from '../../utils/stringify';
import {
  ActionStatusRequestSchema,
  ActionStatusResponseSchema,
} from '../../../../common/api/endpoint';
import { ACTION_STATUS_ROUTE } from '../../../../common/endpoint/constants';
import type {
  SecuritySolutionPluginRouter,
  SecuritySolutionRequestHandlerContext,
} from '../../../types';
import type { EndpointAppContext } from '../../types';
import { getPendingActionsSummary } from '../../services';
import { withEndpointAuthz } from '../with_endpoint_authz';

/**
 * Registers routes for checking status of actions
 */
export function registerActionStatusRoutes(
  router: SecuritySolutionPluginRouter,
  endpointContext: EndpointAppContext
) {
  // Summary of action status for a given list of endpoints
  router.versioned
    .get({
      access: 'public',
      path: ACTION_STATUS_ROUTE,
      summary: 'Get response actions status',
      description: 'Get the status of response actions for the specified agent IDs.',
      security: {
        authz: {
          requiredPrivileges: ['securitySolution'],
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: ActionStatusRequestSchema,
          response: {
            200: {
              body: () => ActionStatusResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: () => ({
            operationId: 'EndpointGetActionsStatus',
            responses: {
              200: {
                content: {
                  'application/json': {
                    examples: {
                      actionStatus: {
                        summary: 'Pending response actions per agent',
                        value: {
                          data: [
                            {
                              agent_id: 'afdc366c-e2e0-4cdb-ae1d-94575bd2d8e0',
                              pending_actions: {
                                isolate: 0,
                                unisolate: 0,
                                'kill-process': 1,
                                'running-processes': 0,
                                'get-file': 0,
                                execute: 0,
                                upload: 0,
                                scan: 0,
                              },
                            },
                          ],
                        },
                      },
                    },
                  },
                },
              },
            },
          }),
        },
      },
      withEndpointAuthz(
        { all: ['canReadSecuritySolution'] },
        endpointContext.logFactory.get('hostIsolationStatus'),
        actionStatusRequestHandler(endpointContext)
      )
    );
}

export const actionStatusRequestHandler = function (
  endpointContext: EndpointAppContext
): RequestHandler<
  unknown,
  TypeOf<typeof ActionStatusRequestSchema.query>,
  unknown,
  SecuritySolutionRequestHandlerContext
> {
  const logger = endpointContext.logFactory.get('actionStatusApi');

  return async (context, req, res) => {
    logger.debug(() => `Retrieving action status for: ${stringify(req.query.agent_ids)}`);

    try {
      const spaceId = (await context.securitySolution).getSpaceId();
      const agentIDs: string[] = Array.isArray(req.query.agent_ids)
        ? [...new Set(req.query.agent_ids)]
        : [req.query.agent_ids];

      await endpointContext.service
        .getInternalFleetServices(spaceId)
        .ensureInCurrentSpace({ agentIds: agentIDs });

      const response = await getPendingActionsSummary(endpointContext.service, spaceId, agentIDs);

      return res.ok({
        body: {
          data: response,
        },
      });
    } catch (error) {
      return errorHandler(logger, res, error);
    }
  };
};
