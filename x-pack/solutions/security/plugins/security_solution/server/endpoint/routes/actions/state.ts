/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { uniq } from 'lodash/fp';
import { schema } from '@kbn/config-schema';
import type { RequestHandler } from '@kbn/core/server';
import { RESPONSE_CONSOLE_ACTION_COMMANDS_TO_REQUIRED_AUTHZ } from '../../../../common/endpoint/service/response_actions/constants';
import { ACTION_STATE_ROUTE } from '../../../../common/endpoint/constants';
import type {
  SecuritySolutionPluginRouter,
  SecuritySolutionRequestHandlerContext,
} from '../../../types';
import type { EndpointAppContext } from '../../types';
import { withEndpointAuthz } from '../with_endpoint_authz';

const ActionStateResponseSchema = schema.object(
  {
    data: schema.object(
      {
        canEncrypt: schema.maybe(
          schema.boolean({
            meta: { description: 'Whether encryption is enabled for response actions.' },
          })
        ),
      },
      { unknowns: 'allow' }
    ),
  },
  { unknowns: 'allow', meta: { id: 'ActionStateResponse' } }
);

/**
 * Registers routes for checking state of actions routes
 */
export function registerActionStateRoutes(
  router: SecuritySolutionPluginRouter,
  endpointContext: EndpointAppContext,
  canEncrypt?: boolean
) {
  const responseActionAuthzNames = uniq(
    Object.values(RESPONSE_CONSOLE_ACTION_COMMANDS_TO_REQUIRED_AUTHZ)
  );

  router.versioned
    .get({
      access: 'public',
      path: ACTION_STATE_ROUTE,
      summary: 'Get actions state',
      description: 'Get a response actions state, which reports whether encryption is enabled.',
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
          response: {
            200: {
              body: () => ActionStateResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: () => ({
            operationId: 'EndpointGetActionsState',
            responses: {
              200: {
                content: {
                  'application/json': {
                    examples: {
                      actionsState: {
                        summary: 'Response actions state with encryption enabled',
                        value: {
                          data: {
                            canEncrypt: true,
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
        {
          any: responseActionAuthzNames,
        },
        endpointContext.logFactory.get('actionState'),
        getActionStateRequestHandler(canEncrypt)
      )
    );
}

export const getActionStateRequestHandler = function (
  canEncrypt?: boolean
): RequestHandler<unknown, unknown, unknown, SecuritySolutionRequestHandlerContext> {
  return async (_, __, res) => {
    return res.ok({
      body: {
        data: { canEncrypt },
      },
    });
  };
};
