/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { TypeOf } from '@kbn/config-schema';
import { schema } from '@kbn/config-schema';

import {
  RESPONSE_ACTION_AGENT_TYPE,
  RESPONSE_ACTION_API_COMMANDS_NAMES,
} from '../../../../endpoint/service/response_actions/constants';
import { ExecuteActionRequestSchema } from '../response_actions/execute';
import { EndpointActionGetFileSchema } from '../response_actions/get_file';
import { ScanActionRequestSchema } from '../response_actions/scan';
import { IsolateRouteRequestSchema } from '../response_actions/isolate';
import { UnisolateRouteRequestSchema } from '../response_actions/unisolate';
import { GetProcessesRouteRequestSchema } from '../response_actions/running_procs';
import { KillProcessRouteRequestSchema } from '../response_actions/kill_process';
import { SuspendProcessRouteRequestSchema } from '../response_actions/suspend_process';
import { UploadActionRequestSchema } from '../response_actions/upload';
import { RunScriptActionRequestSchema } from '../response_actions/run_script';

export const ResponseActionBodySchema = schema.oneOf([
  IsolateRouteRequestSchema.body,
  UnisolateRouteRequestSchema.body,
  GetProcessesRouteRequestSchema.body,
  KillProcessRouteRequestSchema.body,
  SuspendProcessRouteRequestSchema.body,
  EndpointActionGetFileSchema.body,
  ExecuteActionRequestSchema.body,
  UploadActionRequestSchema.body,
  ScanActionRequestSchema.body,
  RunScriptActionRequestSchema.body,
]);

export type ResponseActionsRequestBody = TypeOf<typeof ResponseActionBodySchema>;

/**
 * Details of a single response action.
 *
 * Mirrors the `ResponseActionDetails` OpenAPI component in
 * `model/schema/common.schema.yaml`, but expressed in `@kbn/config-schema` so it can serve as
 * the single source of truth: it is used for runtime (dev-mode) response validation and is
 * projected into the captured OAS by `@kbn/router-to-openapispec`.
 */
export const ResponseActionDetailsSchema = schema.object(
  {
    id: schema.maybe(schema.string({ meta: { description: 'The response action ID' } })),
    command: schema.oneOf(
      // @ts-expect-error TS2769: No overload matches this call
      RESPONSE_ACTION_API_COMMANDS_NAMES.map((command) => schema.literal(command)),
      { meta: { description: 'The command for the response action' } }
    ),
    agentType: schema.maybe(
      schema.oneOf(
        // @ts-expect-error TS2769: No overload matches this call
        RESPONSE_ACTION_AGENT_TYPE.map((agentType) => schema.literal(agentType)),
        { meta: { description: 'The type of agent the response action was sent to' } }
      )
    ),
    isExpired: schema.maybe(
      schema.boolean({ meta: { description: 'Whether the response action is expired' } })
    ),
    isCompleted: schema.maybe(
      schema.boolean({ meta: { description: 'Whether the response action is complete' } })
    ),
    wasSuccessful: schema.maybe(
      schema.boolean({ meta: { description: 'Whether the response action was successful' } })
    ),
    wasCanceled: schema.maybe(
      schema.boolean({ meta: { description: 'Whether the response action was canceled' } })
    ),
    status: schema.maybe(schema.string({ meta: { description: 'The response action status' } })),
    startedAt: schema.maybe(
      schema.string({ meta: { description: 'The response action start time' } })
    ),
    completedAt: schema.maybe(
      schema.string({ meta: { description: 'The response action completion time' } })
    ),
    createdBy: schema.maybe(
      schema.string({ meta: { description: 'The user who created the response action' } })
    ),
    agents: schema.maybe(
      schema.arrayOf(schema.string(), {
        meta: {
          description: 'The agent IDs for the hosts that the response action was sent to',
        },
      })
    ),
    parameters: schema.maybe(
      schema.object(
        {},
        {
          unknowns: 'allow',
          meta: {
            description:
              'The parameters of the response action. Content differs depending on the response action command',
          },
        }
      )
    ),
    hosts: schema.maybe(
      schema.recordOf(
        schema.string(),
        schema.object({
          name: schema.maybe(schema.string({ meta: { description: 'The host name' } })),
        }),
        {
          meta: {
            description:
              'An object containing the host names associated with the agent IDs the response action was sent to',
          },
        }
      )
    ),
    agentState: schema.maybe(
      schema.recordOf(
        schema.string(),
        schema.object({
          isCompleted: schema.maybe(schema.boolean()),
          wasSuccessful: schema.maybe(schema.boolean()),
          wasCanceled: schema.maybe(schema.boolean()),
          completedAt: schema.maybe(schema.string()),
        }),
        {
          meta: {
            description: 'The state of the response action for each agent ID that it was sent to',
          },
        }
      )
    ),
    outputs: schema.maybe(
      schema.recordOf(
        schema.string(),
        schema.object({
          type: schema.oneOf([schema.literal('json'), schema.literal('text')]),
          content: schema.oneOf([schema.object({}, { unknowns: 'allow' }), schema.string()]),
        }),
        {
          meta: {
            description:
              'The outputs of the response action for each agent ID that it was sent to. Content differs depending on the response action command and will only be present for agents that have responded to the response action',
          },
        }
      )
    ),
  },
  { meta: { id: 'ResponseActionDetails' } }
);

/**
 * The success envelope returned when a response action is created. Shared by all
 * `POST /api/endpoint/action/*` routes.
 *
 * Both this and {@link ResponseActionDetailsSchema} carry a `meta.id` so the OAS
 * converter hoists them into `components/schemas/*` and emits `$ref`s instead of
 * inlining a copy per route (mirroring the retired hand-written `$ref` structure).
 */
export const ResponseActionCreateSuccessResponseSchema = schema.object(
  {
    data: schema.maybe(ResponseActionDetailsSchema),
  },
  { meta: { id: 'ResponseActionCreateSuccessResponse' } }
);

/**
 * Success envelope for the (un)isolate routes, which additionally return a top-level
 * `action` field (a legacy duplicate of `data.id`). Shared by isolate + unisolate.
 */
export const ResponseActionIsolationSuccessResponseSchema = schema.object(
  {
    action: schema.maybe(
      schema.string({ meta: { description: 'The action ID (legacy field, same as `data.id`).' } })
    ),
    data: schema.maybe(ResponseActionDetailsSchema),
  },
  { meta: { id: 'ResponseActionIsolationSuccessResponse' } }
);
