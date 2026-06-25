/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

// TODO: fix the odd TS error
import type { TypeOf } from '@kbn/config-schema';
import { schema } from '@kbn/config-schema';
import {
  RESPONSE_ACTION_API_COMMANDS_NAMES,
  RESPONSE_ACTION_STATUS,
  RESPONSE_ACTION_TYPE,
} from '../../../../endpoint/service/response_actions/constants';
import { ENDPOINT_DEFAULT_PAGE_SIZE } from '../../../../endpoint/constants';
import { agentTypesSchema } from '../common/base';
import { ResponseActionDetailsSchema } from '../common/response_actions';

const commandsSchema = schema.oneOf(
  // @ts-expect-error TS2769: No overload matches this call
  RESPONSE_ACTION_API_COMMANDS_NAMES.map((command) => schema.literal(command))
);

const statusesSchema = {
  // @ts-expect-error TS2769: No overload matches this call
  schema: schema.oneOf(RESPONSE_ACTION_STATUS.map((status) => schema.literal(status))),
  options: { minSize: 1, maxSize: RESPONSE_ACTION_STATUS.length },
};

const actionTypesSchema = {
  // @ts-expect-error TS2769: No overload matches this call
  schema: schema.oneOf(RESPONSE_ACTION_TYPE.map((type) => schema.literal(type))),
  options: { minSize: 1, maxSize: RESPONSE_ACTION_TYPE.length },
};

export const EndpointActionListRequestSchema = {
  query: schema.object({
    agentIds: schema.maybe(
      schema.oneOf(
        [
          schema.arrayOf(schema.string({ minLength: 1, maxLength: 256 }), {
            minSize: 1,
            maxSize: 250,
          }),
          schema.string({ minLength: 1, maxLength: 256 }),
        ],
        {
          meta: {
            description: 'A list of Elastic Agent IDs to filter the response actions by.',
          },
        }
      )
    ),
    agentTypes: schema.maybe(
      schema.oneOf(
        [
          schema.arrayOf(agentTypesSchema.schema, agentTypesSchema.options),
          agentTypesSchema.schema,
        ],
        {
          meta: {
            description: 'The agent type to filter response actions by. Defaults to `endpoint`.',
          },
        }
      )
    ),
    commands: schema.maybe(
      schema.oneOf([schema.arrayOf(commandsSchema, { minSize: 1, maxSize: 50 }), commandsSchema], {
        meta: {
          description: 'A list of response action command names to filter by.',
        },
      })
    ),
    page: schema.maybe(
      schema.number({
        defaultValue: 1,
        min: 1,
        meta: { description: 'The page number to return.' },
      })
    ),
    pageSize: schema.maybe(
      schema.number({
        defaultValue: ENDPOINT_DEFAULT_PAGE_SIZE,
        min: 1,
        max: 10000,
        meta: { description: 'The number of response actions to return per page.' },
      })
    ),
    startDate: schema.maybe(
      schema.string({
        maxLength: 64,
        meta: {
          description:
            'A start date in ISO 8601 format or Date Math format (for example, `now-24h`).',
        },
      })
    ), // date ISO strings or moment date
    endDate: schema.maybe(
      schema.string({
        maxLength: 64,
        meta: {
          description: 'An end date in ISO 8601 format or Date Math format (for example, `now`).',
        },
      })
    ), // date ISO strings or moment date
    statuses: schema.maybe(
      schema.oneOf([
        schema.arrayOf(statusesSchema.schema, statusesSchema.options),
        statusesSchema.schema,
      ])
    ),
    userIds: schema.maybe(
      schema.oneOf(
        [
          schema.arrayOf(schema.string({ minLength: 1, maxLength: 256 }), {
            minSize: 1,
            maxSize: 50,
          }),
          schema.string({ minLength: 1, maxLength: 256 }),
        ],
        {
          meta: {
            description: 'A list of user IDs that submitted the response actions.',
          },
        }
      )
    ),
    withOutputs: schema.maybe(
      schema.oneOf(
        [
          schema.arrayOf(schema.string({ minLength: 1, maxLength: 256 }), {
            minSize: 1,
            maxSize: 50,
            validate: (actionIds) => {
              if (actionIds.map((v) => v.trim()).some((v) => !v.length)) {
                return 'actionIds cannot contain empty strings';
              }
            },
          }),
          schema.string({
            minLength: 1,
            maxLength: 256,
            validate: (actionId) => {
              if (!actionId.trim().length) {
                return 'actionId cannot be an empty string';
              }
            },
          }),
        ],
        {
          meta: {
            description:
              'A list of response action IDs whose outputs should be included in the response.',
          },
        }
      )
    ),
    // action types
    types: schema.maybe(
      schema.oneOf(
        [
          schema.arrayOf(actionTypesSchema.schema, actionTypesSchema.options),
          actionTypesSchema.schema,
        ],
        {
          meta: {
            description: 'A list of response action types to filter by (`automated`, `manual`).',
          },
        }
      )
    ),
  }),
};

export type EndpointActionListRequestQuery = TypeOf<typeof EndpointActionListRequestSchema.query>;

export const EndpointActionListResponseSchema = schema.object(
  {
    page: schema.maybe(schema.number({ meta: { description: 'The current page number.' } })),
    pageSize: schema.maybe(
      schema.number({ meta: { description: 'The number of items per page.' } })
    ),
    total: schema.maybe(
      schema.number({
        meta: { description: 'The total number of response actions matching the query.' },
      })
    ),
    startDate: schema.maybe(
      schema.string({ meta: { description: 'The start date filter applied to the query.' } })
    ),
    endDate: schema.maybe(
      schema.string({ meta: { description: 'The end date filter applied to the query.' } })
    ),
    elasticAgentIds: schema.maybe(
      schema.arrayOf(schema.string(), {
        meta: { description: 'The agent IDs the query was filtered by.' },
      })
    ),
    agentTypes: schema.maybe(
      schema.arrayOf(schema.string(), {
        meta: { description: 'The agent types the query was filtered by.' },
      })
    ),
    commands: schema.maybe(
      schema.arrayOf(schema.string(), {
        meta: { description: 'The commands the query was filtered by.' },
      })
    ),
    userIds: schema.maybe(
      schema.arrayOf(schema.string(), {
        meta: { description: 'The user IDs the query was filtered by.' },
      })
    ),
    statuses: schema.maybe(
      schema.arrayOf(schema.string(), {
        meta: { description: 'The statuses the query was filtered by.' },
      })
    ),
    data: schema.arrayOf(ResponseActionDetailsSchema, {
      meta: { description: 'The list of response actions.' },
    }),
  },
  { unknowns: 'allow', meta: { id: 'EndpointActionListResponse' } }
);
