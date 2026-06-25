/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  EndpointActionListRequestSchema,
  EndpointActionListResponseSchema,
} from '../../../../common/api/endpoint';
import { BASE_ENDPOINT_ACTION_ROUTE } from '../../../../common/endpoint/constants';
import { actionListHandler } from './list_handler';

import type { SecuritySolutionPluginRouter } from '../../../types';
import type { EndpointAppContext } from '../../types';
import { withEndpointAuthz } from '../with_endpoint_authz';

/**
 * Registers the endpoint activity_log route
 */
export function registerActionListRoutes(
  router: SecuritySolutionPluginRouter,
  endpointContext: EndpointAppContext
) {
  router.versioned
    .get({
      access: 'public',
      path: BASE_ENDPOINT_ACTION_ROUTE,
      summary: 'Get response actions',
      description: 'Get a list of all response actions.',
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
          request: EndpointActionListRequestSchema,
          response: {
            200: {
              body: () => EndpointActionListResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: () => ({
            operationId: 'EndpointGetActionsList',
            responses: {
              200: {
                content: {
                  'application/json': {
                    examples: {
                      actionsList: {
                        summary: 'A list of response actions',
                        value: {
                          page: 1,
                          pageSize: 10,
                          total: 2,
                          startDate: 'now-24h/h',
                          endDate: 'now',
                          elasticAgentIds: ['afdc366c-e2e0-4cdb-ae1d-94575bd2d8e0'],
                          data: [
                            {
                              id: 'b3d6de74-36b0-4fa8-be46-c375bf1771bf',
                              agents: ['afdc366c-e2e0-4cdb-ae1d-94575bd2d8e0'],
                              command: 'running-processes',
                              agentType: 'endpoint',
                              startedAt: '2022-08-08T15:24:57.402Z',
                              isCompleted: true,
                              completedAt: '2022-08-08T09:50:47.672Z',
                              wasSuccessful: true,
                              isExpired: false,
                              createdBy: 'elastic',
                            },
                            {
                              id: '43b4098b-8752-4fbb-a7a7-6df7c74d0ee3',
                              agents: ['afdc366c-e2e0-4cdb-ae1d-94575bd2d8e0'],
                              command: 'isolate',
                              agentType: 'endpoint',
                              startedAt: '2022-08-08T15:23:37.359Z',
                              isCompleted: true,
                              completedAt: '2022-08-08T10:41:57.352Z',
                              wasSuccessful: true,
                              isExpired: false,
                              createdBy: 'elastic',
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
        { any: ['canReadActionsLogManagement', 'canAccessEndpointActionsLogManagement'] },
        endpointContext.logFactory.get('endpointActionList'),
        actionListHandler(endpointContext)
      )
    );
}
