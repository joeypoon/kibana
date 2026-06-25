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
  ResponseActionIsolationSuccessResponseSchema,
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
import {
  scanActionOas,
  isolateActionOas,
  unisolateActionOas,
  killProcessActionOas,
  suspendProcessActionOas,
  getProcessesActionOas,
  getFileActionOas,
  executeActionOas,
  uploadActionOas,
  runScriptActionOas,
  cancelActionOas,
  memoryDumpActionOas,
} from './response_actions_oas';

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
      summary: 'Isolate an endpoint',
      description:
        "Isolate an endpoint from the network. The endpoint remains isolated until it's released.",
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: IsolateRouteRequestSchema,
          response: {
            200: {
              body: () => ResponseActionIsolationSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: isolateActionOas,
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
      summary: 'Release an isolated endpoint',
      description: 'Release an isolated endpoint, allowing it to rejoin a network.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: UnisolateRouteRequestSchema,
          response: {
            200: {
              body: () => ResponseActionIsolationSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: unisolateActionOas,
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
      summary: 'Terminate a process',
      description: 'Terminate a running process on an endpoint.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: KillProcessRouteRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: killProcessActionOas,
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
      summary: 'Suspend a process',
      description: 'Suspend a running process on an endpoint.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: SuspendProcessRouteRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: suspendProcessActionOas,
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
      summary: 'Get running processes',
      description: 'Get a list of all processes running on an endpoint.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: GetProcessesRouteRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: getProcessesActionOas,
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
      summary: 'Get a file',
      description: 'Get a file from an endpoint.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: EndpointActionGetFileSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: getFileActionOas,
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
      summary: 'Run a command',
      description: 'Run a shell command on an endpoint.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: ExecuteActionRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: executeActionOas,
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
      summary: 'Upload a file',
      description: 'Upload a file to an endpoint.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: UploadActionRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: uploadActionOas,
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
          oasOperationObject: scanActionOas,
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
      summary: 'Run a script',
      description: 'Run a script on a host. Currently supported only for some agent types.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: RunScriptActionRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: runScriptActionOas,
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
      summary: 'Cancel a response action',
      description:
        'Cancel a running or pending response action (Applies only to some agent types).',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: CancelActionRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: cancelActionOas,
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
      summary: 'Generate a memory dump from the host machine',
      description: 'Generates memory dumps on the targeted host.',
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: MemoryDumpActionRequestSchema,
          response: {
            200: {
              body: () => ResponseActionCreateSuccessResponseSchema,
              description: 'Indicates a successful call.',
            },
          },
        },
        options: {
          oasOperationObject: memoryDumpActionOas,
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
