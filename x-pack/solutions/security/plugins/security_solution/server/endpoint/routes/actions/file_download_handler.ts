/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RequestHandler } from '@kbn/core/server';
import { ensureUserHasAuthzToFilesForAction } from './utils';
import type { EndpointActionFileDownloadParams } from '../../../../common/api/endpoint';
import { EndpointActionFileDownloadSchema } from '../../../../common/api/endpoint';
import type { ResponseActionsClient } from '../../services';
import {
  getResponseActionsClient,
  NormalizedExternalConnectorClient,
  getActionAgentType,
} from '../../services';
import { errorHandler } from '../error_handler';
import { ACTION_AGENT_FILE_DOWNLOAD_ROUTE } from '../../../../common/endpoint/constants';
import { withEndpointAuthz } from '../with_endpoint_authz';
import type { EndpointAppContext } from '../../types';
import type {
  SecuritySolutionPluginRouter,
  SecuritySolutionRequestHandlerContext,
} from '../../../types';

export const registerActionFileDownloadRoutes = (
  router: SecuritySolutionPluginRouter,
  endpointContext: EndpointAppContext
) => {
  const logger = endpointContext.logFactory.get('actionFileDownload');

  router.versioned
    .get({
      access: 'public',
      // NOTE:
      // Because this API is used in the browser via `href` (ex. on link to download a file),
      // we need to enable setting the version number via query params
      enableQueryVersion: true,
      path: ACTION_AGENT_FILE_DOWNLOAD_ROUTE,
      security: {
        authz: {
          requiredPrivileges: ['securitySolution'],
        },
      },
      summary: 'Download a file',
      description:
        "Download a file associated with a response action. Files are downloaded in a password-protected `.zip` archive to prevent the file from running. Use password `elastic` to open the `.zip` in a safe environment.\n> info\n> Files retrieved from third-party-protected hosts require a different password. Refer to [Third-party response actions](https://www.elastic.co/docs/solutions/security/endpoint-response-actions/third-party-response-actions) for your system's password.",
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: EndpointActionFileDownloadSchema,
        },
        options: {
          oasOperationObject: () => ({
            operationId: 'EndpointFileDownload',
            responses: {
              200: {
                description: 'A password-protected .zip archive containing the file.',
                content: {
                  'application/octet-stream': { schema: { type: 'string', format: 'binary' } },
                },
              },
            },
          }),
        },
      },
      withEndpointAuthz(
        { any: ['canWriteFileOperations', 'canWriteExecuteOperations', 'canGetRunningProcesses'] },
        logger,
        getActionFileDownloadRouteHandler(endpointContext),
        ensureUserHasAuthzToFilesForAction
      )
    );
};

export const getActionFileDownloadRouteHandler = (
  endpointContext: EndpointAppContext
): RequestHandler<
  EndpointActionFileDownloadParams,
  unknown,
  unknown,
  SecuritySolutionRequestHandlerContext
> => {
  const logger = endpointContext.logFactory.get('actionFileDownloadRoute');

  return async (context, req, res) => {
    const { action_id: actionId, file_id: fileId } = req.params;
    const coreContext = await context.core;
    const spaceId = (await context.securitySolution).getSpaceId();

    logger.debug(
      () =>
        `Retrieving file id [${fileId}] download for action [${actionId}] in spaceId [${spaceId}]`
    );

    try {
      const esClient = coreContext.elasticsearch.client.asInternalUser;
      const { agentType } = await getActionAgentType(esClient, actionId);
      const user = coreContext.security.authc.getCurrentUser();
      const casesClient = await endpointContext.service.getCasesClient(req);
      const connectorActions = (await context.actions).getActionsClient();
      const responseActionsClient: ResponseActionsClient = getResponseActionsClient(agentType, {
        esClient,
        casesClient,
        spaceId,
        endpointService: endpointContext.service,
        username: user?.username || 'unknown',
        connectorActions: new NormalizedExternalConnectorClient(connectorActions, logger),
      });

      const { stream, fileName } = await responseActionsClient.getFileDownload(actionId, fileId);

      return res.ok({
        body: stream,
        headers: {
          'content-type': 'application/octet-stream',
          'cache-control': 'max-age=31536000, immutable',
          // Note, this name can be overridden by the client if set via a "download" attribute on the HTML tag.
          'content-disposition': `attachment; filename="${fileName ?? 'download.zip'}"`,
          // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
          'x-content-type-options': 'nosniff',
        },
      });
    } catch (error) {
      return errorHandler(logger, res, error);
    }
  };
};
