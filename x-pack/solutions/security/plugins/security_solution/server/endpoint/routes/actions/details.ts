/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RequestHandler } from '@kbn/core/server';
import type { TypeOf } from '@kbn/config-schema';
import {
  ActionDetailsRequestSchema,
  ActionDetailsResponseSchema,
} from '../../../../common/api/endpoint';
import type {
  SecuritySolutionPluginRouter,
  SecuritySolutionRequestHandlerContext,
} from '../../../types';
import type { EndpointAppContext } from '../../types';
import { ACTION_DETAILS_ROUTE } from '../../../../common/endpoint/constants';
import { withEndpointAuthz } from '../with_endpoint_authz';
import { getActionDetailsById } from '../../services';
import { errorHandler } from '../error_handler';

/**
 * Registers the route for handling retrieval of Action Details
 * @param router
 * @param endpointContext
 */
export const registerActionDetailsRoutes = (
  router: SecuritySolutionPluginRouter,
  endpointContext: EndpointAppContext
) => {
  // Details for a given action id
  router.versioned
    .get({
      access: 'public',
      path: ACTION_DETAILS_ROUTE,
      summary: 'Get action details',
      description: 'Get the details of a response action using the action ID.',
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
          request: ActionDetailsRequestSchema,
          response: {
            200: {
              body: () => ActionDetailsResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: () => ({
            operationId: 'EndpointGetActionsDetails',
            responses: {
              200: {
                content: {
                  'application/json': {
                    examples: {
                      actionDetails: {
                        summary: 'Details of an isolate response action',
                        value: {
                          data: {
                            id: '233db9ea-6733-4849-9226-5a7039c7161d',
                            command: 'isolate',
                            agentType: 'endpoint',
                            agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
                            startedAt: '2022-08-08T15:23:37.359Z',
                            isCompleted: true,
                            completedAt: '2022-08-08T10:41:57.352Z',
                            wasSuccessful: true,
                            isExpired: false,
                            createdBy: 'elastic',
                          },
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
        { all: ['canAccessEndpointActionsLogManagement'] },
        endpointContext.logFactory.get('hostIsolationDetails'),
        getActionDetailsRequestHandler(endpointContext)
      )
    );
};

export const getActionDetailsRequestHandler = (
  endpointContext: EndpointAppContext
): RequestHandler<
  TypeOf<typeof ActionDetailsRequestSchema.params>,
  never,
  never,
  SecuritySolutionRequestHandlerContext
> => {
  return async (context, req, res) => {
    try {
      const activeSpaceId = (await context.securitySolution).getSpaceId();
      return res.ok({
        body: {
          data: await getActionDetailsById(
            endpointContext.service,
            activeSpaceId,
            req.params.action_id
          ),
        },
      });
    } catch (error) {
      return errorHandler(endpointContext.logFactory.get('EndpointActionDetails'), res, error);
    }
  };
};
