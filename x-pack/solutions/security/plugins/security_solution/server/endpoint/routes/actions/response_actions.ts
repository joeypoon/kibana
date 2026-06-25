/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RequestHandler } from '@kbn/core/server';
import { MemoryDumpActionRequestSchema } from '../../../../common/api/endpoint/actions/response_actions/memory_dump';
import type {
  ResponseActionAgentType,
  ResponseActionsApiCommandNames,
} from '../../../../common/endpoint/service/response_actions/constants';
import {
  EndpointActionGetFileSchema,
  ExecuteActionRequestSchema,
  GetProcessesRouteRequestSchema,
  IsolateRouteRequestSchema,
  KillProcessRouteRequestSchema,
  type ResponseActionsRequestBody,
  ResponseActionCreateSuccessResponseSchema,
  ScanActionRequestSchema,
  SuspendProcessRouteRequestSchema,
  UnisolateRouteRequestSchema,
  UploadActionRequestSchema,
  RunScriptActionRequestSchema,
  CancelActionRequestSchema,
} from '../../../../common/api/endpoint';

import {
  CANCEL_ROUTE,
  EXECUTE_ROUTE,
  GET_FILE_ROUTE,
  GET_PROCESSES_ROUTE,
  ISOLATE_HOST_ROUTE_V2,
  KILL_PROCESS_ROUTE,
  MEMORY_DUMP_ROUTE,
  RUN_SCRIPT_ROUTE,
  SCAN_ROUTE,
  SUSPEND_PROCESS_ROUTE,
  UNISOLATE_HOST_ROUTE_V2,
  UPLOAD_ROUTE,
} from '../../../../common/endpoint/constants';
import type {
  ResponseActionParametersWithProcessData,
  ResponseActionsExecuteParameters,
  ResponseActionScanParameters,
  EndpointActionDataParameterTypes,
  ActionDetails,
  ResponseActionRunScriptParameters,
} from '../../../../common/endpoint/types';
import type {
  SecuritySolutionPluginRouter,
  SecuritySolutionRequestHandlerContext,
} from '../../../types';
import type { EndpointAppContext } from '../../types';
import { withEndpointAuthz } from '../with_endpoint_authz';
import { stringify } from '../../utils/stringify';
import { errorHandler } from '../error_handler';
import { CustomHttpRequestError } from '../../../utils/custom_http_request_error';
import type { ResponseActionsClient } from '../../services';
import { getResponseActionsClient, NormalizedExternalConnectorClient } from '../../services';
import {
  executeResponseAction,
  buildResponseActionResult,
  createCancelActionAdditionalChecks,
} from './utils';

export function registerResponseActionRoutes(
  router: SecuritySolutionPluginRouter,
  endpointContext: EndpointAppContext
) {
  const logger = endpointContext.logFactory.get('responseActionsRoutes');

  router.versioned
    .post({
      access: 'public',
      path: ISOLATE_HOST_ROUTE_V2,
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
          request: IsolateRouteRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canIsolateHost'] },
        logger,
        responseActionRequestHandler(endpointContext, 'isolate')
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: UNISOLATE_HOST_ROUTE_V2,
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
          request: UnisolateRouteRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canUnIsolateHost'] },
        logger,
        responseActionRequestHandler(endpointContext, 'unisolate')
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: KILL_PROCESS_ROUTE,
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
          request: KillProcessRouteRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canKillProcess'] },
        logger,
        responseActionRequestHandler<ResponseActionParametersWithProcessData>(
          endpointContext,
          'kill-process'
        )
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: SUSPEND_PROCESS_ROUTE,
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
          request: SuspendProcessRouteRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canSuspendProcess'] },
        logger,
        responseActionRequestHandler<ResponseActionParametersWithProcessData>(
          endpointContext,
          'suspend-process'
        )
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: GET_PROCESSES_ROUTE,
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
          request: GetProcessesRouteRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canGetRunningProcesses'] },
        logger,
        responseActionRequestHandler(endpointContext, 'running-processes')
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: GET_FILE_ROUTE,
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
          request: EndpointActionGetFileSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canWriteFileOperations'] },
        logger,
        responseActionRequestHandler(endpointContext, 'get-file')
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: EXECUTE_ROUTE,
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
          request: ExecuteActionRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canWriteExecuteOperations'] },
        logger,
        responseActionRequestHandler<ResponseActionsExecuteParameters>(endpointContext, 'execute')
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: UPLOAD_ROUTE,
      security: {
        authz: {
          requiredPrivileges: ['securitySolution'],
        },
      },
      options: {
        body: {
          accepts: ['multipart/form-data'],
          output: 'stream',
          maxBytes: endpointContext.serverConfig.maxUploadResponseActionFileBytes,
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: UploadActionRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canWriteFileOperations'] },
        logger,
        responseActionRequestHandler<ResponseActionsExecuteParameters>(endpointContext, 'upload')
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: SCAN_ROUTE,
      security: {
        authz: {
          requiredPrivileges: ['securitySolution'],
        },
      },
      summary: 'Scan a file or directory',
      description: 'Scan a specific file or directory on an endpoint for malware.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: ScanActionRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          // Carries the bits OpenAPI expresses but config-schema cannot: the curated
          // `operationId` (pinned so generated client SDKs stay stable) and request/
          // response examples. The schemas themselves come from the config-schema above.
          oasOperationObject: () => ({
            operationId: 'EndpointScanAction',
            requestBody: {
              content: {
                'application/json': {
                  examples: {
                    scanFile: {
                      summary: 'Scan a file on an endpoint',
                      value: {
                        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
                        parameters: { path: '/usr/my-file.txt' },
                        comment: 'Scan the file for malware',
                      },
                    },
                  },
                },
              },
            },
            responses: {
              200: {
                content: {
                  'application/json': {
                    examples: {
                      ScanSuccess: {
                        summary: 'Scan action successfully created',
                        value: {
                          data: {
                            id: '27ba1b42-7cc6-4e53-86ce-675c876092b2',
                            agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
                            command: 'scan',
                            agentType: 'endpoint',
                            isExpired: false,
                            isCompleted: false,
                            wasSuccessful: false,
                            status: 'pending',
                            startedAt: '2023-07-28T19:00:03.911Z',
                            createdBy: 'elastic',
                            hosts: {
                              'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
                            },
                            agentState: {
                              'ed518850-681a-4d60-bb98-e22640cae2a8': {
                                isCompleted: false,
                                wasSuccessful: false,
                              },
                            },
                            parameters: { path: '/usr/my-file.txt' },
                            outputs: {},
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
        { all: ['canWriteScanOperations'] },
        logger,
        responseActionRequestHandler<ResponseActionScanParameters>(endpointContext, 'scan')
      )
    );
  router.versioned
    .post({
      access: 'public',
      path: RUN_SCRIPT_ROUTE,
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
          request: RunScriptActionRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canWriteExecuteOperations'] },
        logger,
        responseActionRequestHandler<ResponseActionRunScriptParameters>(
          endpointContext,
          'runscript'
        )
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: CANCEL_ROUTE,
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
          request: CancelActionRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canCancelAction'] },
        logger,
        responseActionRequestHandler(endpointContext, 'cancel'),
        createCancelActionAdditionalChecks(endpointContext)
      )
    );

  router.versioned
    .post({
      access: 'public',
      path: MEMORY_DUMP_ROUTE,
      security: {
        authz: { requiredPrivileges: ['securitySolution'] },
        authc: { enabled: true },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: MemoryDumpActionRequestSchema,
        },
      },
      withEndpointAuthz(
        { all: ['canWriteExecuteOperations'] },
        logger,
        responseActionRequestHandler(endpointContext, 'memory-dump')
      )
    );
}

function responseActionRequestHandler<T extends EndpointActionDataParameterTypes>(
  endpointContext: EndpointAppContext,
  command: ResponseActionsApiCommandNames
): RequestHandler<
  unknown,
  unknown,
  ResponseActionsRequestBody,
  SecuritySolutionRequestHandlerContext
> {
  const logger = endpointContext.logFactory.get('responseActionsHandler');

  return async (context, req, res) => {
    logger.debug(() => `response action [${command}]:\n${stringify(req.body)}`);

    try {
      const experimentalFeatures = endpointContext.experimentalFeatures;

      // Note:  because our API schemas are defined as module static variables (as opposed to a
      //        `getter` function), we need to include this additional validation here, since
      //        `agent_type` is included in the schema independent of the feature flag
      if (isResponseActionDisabled(req.body.agent_type, command, experimentalFeatures)) {
        return errorHandler(
          logger,
          res,
          new CustomHttpRequestError(`[request body.agent_type]: feature is disabled`, 400)
        );
      }

      const coreContext = await context.core;
      const user = coreContext.security.authc.getCurrentUser();
      const esClient = coreContext.elasticsearch.client.asInternalUser;
      const casesClient = await endpointContext.service.getCasesClient(req);
      const connectorActions = (await context.actions).getActionsClient();
      const spaceId = (await context.securitySolution).getSpaceId();
      const responseActionsClient: ResponseActionsClient = getResponseActionsClient(
        req.body.agent_type || 'endpoint',
        {
          esClient,
          casesClient,
          spaceId,
          endpointService: endpointContext.service,
          username: user?.username || 'unknown',
          connectorActions: new NormalizedExternalConnectorClient(connectorActions, logger),
        }
      );

      const action: ActionDetails = await executeResponseAction(
        command,
        req.body,
        responseActionsClient
      );

      const result = buildResponseActionResult(command, action);
      return res.ok(result);
    } catch (err) {
      return errorHandler(logger, res, err);
    }
  };
}

function isResponseActionDisabled(
  agentType: ResponseActionAgentType | undefined,
  command: ResponseActionsApiCommandNames,
  experimentalFeatures: EndpointAppContext['experimentalFeatures']
): boolean {
  if (
    agentType === 'sentinel_one' &&
    command === 'runscript' &&
    !experimentalFeatures.responseActionsSentinelOneRunScriptEnabled
  ) {
    return true;
  }

  if (
    command === 'memory-dump' &&
    (agentType !== 'endpoint' || !experimentalFeatures.responseActionsEndpointMemoryDump)
  ) {
    return true;
  }

  return false;
}
