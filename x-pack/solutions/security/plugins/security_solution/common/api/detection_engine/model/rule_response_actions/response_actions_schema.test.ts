/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { expectParseError, expectParseSuccess } from '@kbn/zod-helpers/v4';
import { EcsMapping, ResponseAction } from './response_actions.gen';
import {
  MAX_ECS_MAPPING_FIELD_LENGTH,
  MAX_ECS_MAPPING_PROPERTIES,
  MAX_ECS_MAPPING_VALUE_ARRAY_ITEMS,
  MAX_ECS_MAPPING_VALUE_STRING_LENGTH,
  MAX_ENDPOINT_PROCESS_CONFIG_FIELD_LENGTH,
  MAX_OSQUERY_PARAMS_QUERIES,
  MAX_OSQUERY_QUERY_ID_LENGTH,
  MAX_OSQUERY_QUERY_LENGTH,
  MAX_OSQUERY_SAVED_OBJECT_ID_LENGTH,
  MAX_OSQUERY_VERSION_OR_PLATFORM_LENGTH,
  MAX_RESPONSE_ACTION_COMMENT_LENGTH,
  MAX_RUNSCRIPT_SCRIPT_ID_LENGTH,
  MAX_RUNSCRIPT_SCRIPT_INPUT_LENGTH,
} from './schema_bounds';

const repeatChar = (length: number, char = 'a'): string => char.repeat(length);

const getBoundaryOsqueryResponseAction = (): ResponseAction => ({
  action_type_id: '.osquery',
  params: {
    query: repeatChar(MAX_OSQUERY_QUERY_LENGTH),
    pack_id: repeatChar(MAX_OSQUERY_SAVED_OBJECT_ID_LENGTH),
    saved_query_id: repeatChar(MAX_OSQUERY_SAVED_OBJECT_ID_LENGTH),
    queries: [
      {
        id: repeatChar(MAX_OSQUERY_QUERY_ID_LENGTH),
        query: repeatChar(MAX_OSQUERY_QUERY_LENGTH),
        version: repeatChar(MAX_OSQUERY_VERSION_OR_PLATFORM_LENGTH),
        platform: repeatChar(MAX_OSQUERY_VERSION_OR_PLATFORM_LENGTH),
        ecs_mapping: {
          'process.pid': {
            field: repeatChar(MAX_ECS_MAPPING_FIELD_LENGTH),
            value: Array.from({ length: MAX_ECS_MAPPING_VALUE_ARRAY_ITEMS }, () =>
              repeatChar(MAX_ECS_MAPPING_VALUE_STRING_LENGTH)
            ),
          },
        },
      },
    ],
  },
});

const getBoundaryEndpointResponseActions = (): ResponseAction[] => [
  {
    action_type_id: '.endpoint',
    params: {
      command: 'isolate',
      comment: repeatChar(MAX_RESPONSE_ACTION_COMMENT_LENGTH),
    },
  },
  {
    action_type_id: '.endpoint',
    params: {
      command: 'kill-process',
      comment: repeatChar(MAX_RESPONSE_ACTION_COMMENT_LENGTH),
      config: {
        field: repeatChar(MAX_ENDPOINT_PROCESS_CONFIG_FIELD_LENGTH),
        overwrite: false,
      },
    },
  },
  {
    action_type_id: '.endpoint',
    params: {
      command: 'runscript',
      comment: repeatChar(MAX_RESPONSE_ACTION_COMMENT_LENGTH),
      config: {
        linux: {
          scriptId: repeatChar(MAX_RUNSCRIPT_SCRIPT_ID_LENGTH),
          scriptInput: repeatChar(MAX_RUNSCRIPT_SCRIPT_INPUT_LENGTH),
        },
      },
    },
  },
];

describe('response actions schema bounds', () => {
  describe('ResponseAction', () => {
    it('accepts boundary-sized osquery and endpoint payloads', () => {
      for (const action of [
        getBoundaryOsqueryResponseAction(),
        ...getBoundaryEndpointResponseActions(),
      ]) {
        const result = ResponseAction.safeParse(action);
        expectParseSuccess(result);
      }
    });

    it('rejects osquery query text over the limit', () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.osquery',
        params: {
          query: repeatChar(MAX_OSQUERY_QUERY_LENGTH + 1),
        },
      });
      expectParseError(result);
    });

    it('rejects endpoint comments over the limit', () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.endpoint',
        params: {
          command: 'isolate',
          comment: repeatChar(MAX_RESPONSE_ACTION_COMMENT_LENGTH + 1),
        },
      });
      expectParseError(result);
    });

    it('rejects osquery queries[].id over the limit', () => {
      const action = getBoundaryOsqueryResponseAction();
      action.params.queries![0].id = repeatChar(MAX_OSQUERY_QUERY_ID_LENGTH + 1);

      const result = ResponseAction.safeParse(action);
      expectParseError(result);
    });

    it('rejects osquery queries[].platform over the limit', () => {
      const action = getBoundaryOsqueryResponseAction();
      action.params.queries![0].platform = repeatChar(MAX_OSQUERY_VERSION_OR_PLATFORM_LENGTH + 1);

      const result = ResponseAction.safeParse(action);
      expectParseError(result);
    });

    it('rejects osquery queries[].version over the limit', () => {
      const action = getBoundaryOsqueryResponseAction();
      action.params.queries![0].version = repeatChar(MAX_OSQUERY_VERSION_OR_PLATFORM_LENGTH + 1);

      const result = ResponseAction.safeParse(action);
      expectParseError(result);
    });

    it('rejects osquery pack_id over the limit', () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.osquery',
        params: {
          pack_id: repeatChar(MAX_OSQUERY_SAVED_OBJECT_ID_LENGTH + 1),
        },
      });
      expectParseError(result);
    });

    it('rejects osquery saved_query_id over the limit', () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.osquery',
        params: {
          saved_query_id: repeatChar(MAX_OSQUERY_SAVED_OBJECT_ID_LENGTH + 1),
        },
      });
      expectParseError(result);
    });

    it('rejects osquery queries[].ecs_mapping field over the limit', () => {
      const action = getBoundaryOsqueryResponseAction();
      action.params.queries![0].ecs_mapping!['process.pid'].field = repeatChar(
        MAX_ECS_MAPPING_FIELD_LENGTH + 1
      );

      const result = ResponseAction.safeParse(action);
      expectParseError(result);
    });

    it('rejects endpoint kill-process config.field over the limit', () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.endpoint',
        params: {
          command: 'kill-process',
          config: {
            field: repeatChar(MAX_ENDPOINT_PROCESS_CONFIG_FIELD_LENGTH + 1),
            overwrite: false,
          },
        },
      });
      expectParseError(result);
    });

    it('rejects endpoint runscript scriptId over the limit', () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.endpoint',
        params: {
          command: 'runscript',
          config: {
            linux: {
              scriptId: repeatChar(MAX_RUNSCRIPT_SCRIPT_ID_LENGTH + 1),
            },
          },
        },
      });
      expectParseError(result);
    });

    it('rejects endpoint runscript scriptInput over the limit', () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.endpoint',
        params: {
          command: 'runscript',
          config: {
            linux: {
              scriptId: 'script-id',
              scriptInput: repeatChar(MAX_RUNSCRIPT_SCRIPT_INPUT_LENGTH + 1),
            },
          },
        },
      });
      expectParseError(result);
    });
  });

  describe('EcsMapping', () => {
    it('accepts boundary-sized ecs mapping values', () => {
      const result = EcsMapping.safeParse({
        'process.pid': {
          field: repeatChar(MAX_ECS_MAPPING_FIELD_LENGTH),
          value: repeatChar(MAX_ECS_MAPPING_VALUE_STRING_LENGTH),
        },
      });
      expectParseSuccess(result);
    });

    it('rejects ecs mapping value strings over the limit', () => {
      const result = EcsMapping.safeParse({
        'process.pid': {
          value: repeatChar(MAX_ECS_MAPPING_VALUE_STRING_LENGTH + 1),
        },
      });
      expectParseError(result);
    });

    it('accepts ecs mapping dynamic keys because generated zod does not bound key length', () => {
      const result = EcsMapping.safeParse({
        [repeatChar(MAX_ECS_MAPPING_FIELD_LENGTH + 1)]: { value: 'static' },
      });
      expectParseSuccess(result);
    });

    it('accepts ecs mappings above maxProperties because generated zod does not enforce it', () => {
      const ecsMapping = Object.fromEntries(
        Array.from({ length: MAX_ECS_MAPPING_PROPERTIES + 1 }, (_, index) => [
          `field_${index}`,
          { value: 'static' },
        ])
      );

      const result = EcsMapping.safeParse(ecsMapping);
      expectParseSuccess(result);
    });
  });

  describe('Osquery params queries array', () => {
    it(`accepts up to ${MAX_OSQUERY_PARAMS_QUERIES} inline queries`, () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.osquery',
        params: {
          queries: Array.from({ length: MAX_OSQUERY_PARAMS_QUERIES }, (_, index) => ({
            id: `query-${index}`,
            query: 'select 1;',
          })),
        },
      });
      expectParseSuccess(result);
    });

    it(`rejects more than ${MAX_OSQUERY_PARAMS_QUERIES} inline queries`, () => {
      const result = ResponseAction.safeParse({
        action_type_id: '.osquery',
        params: {
          queries: Array.from({ length: MAX_OSQUERY_PARAMS_QUERIES + 1 }, (_, index) => ({
            id: `query-${index}`,
            query: 'select 1;',
          })),
        },
      });
      expectParseError(result);
    });
  });
});
