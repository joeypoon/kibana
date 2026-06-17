/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';

export const MAX_ECS_MAPPING_FIELD_LENGTH = 256;
export const MAX_ECS_MAPPING_RESPONSE_KEYS = 1000;
export const MAX_ECS_MAPPING_STRING_VALUE = 1024;
export const MAX_ECS_MAPPING_VALUE_ARRAY = 1000;
export const MAX_OSQUERY_PACK_QUERIES = 1000;
export const MAX_OSQUERY_PACK_QUERY_KEY_LENGTH = 256;
export const MAX_OSQUERY_POLICY_ID_LENGTH = 1024;
export const MAX_OSQUERY_SHARDS_OR_POLICIES = 10_000;
export const MAX_RRULE_LENGTH = 2048;
export const MAX_RRULE_DATE_OR_SPLAY_LENGTH = 64;

// `ecs_mapping` is stored in two shapes: HTTP record form and the canonical
// array form produced by `convertECSMappingToArray`. Forward-compat schemas
// accept both so on-disk documents continue to validate after bounds are added.

const validateRecordMaxKeys = (value: Record<string, unknown>, maxKeys: number): string | void => {
  if (Object.keys(value).length > maxKeys) {
    return `record must not exceed ${maxKeys} keys`;
  }
};

const boundedRecordOf = (
  keyType: Parameters<typeof schema.recordOf>[0],
  valueType: Parameters<typeof schema.recordOf>[1],
  maxKeys: number,
  options: Parameters<typeof schema.recordOf>[2] = {}
) =>
  schema.recordOf(keyType, valueType, {
    ...options,
    validate: (value) => validateRecordMaxKeys(value, maxKeys),
  });

const ecsMappingItemSchema = schema.object(
  {
    field: schema.maybe(schema.string({ maxLength: MAX_ECS_MAPPING_FIELD_LENGTH })),
    value: schema.maybe(
      schema.oneOf([
        schema.string({ maxLength: MAX_ECS_MAPPING_STRING_VALUE }),
        schema.arrayOf(schema.string({ maxLength: MAX_ECS_MAPPING_STRING_VALUE }), {
          maxSize: MAX_ECS_MAPPING_VALUE_ARRAY,
        }),
      ])
    ),
  },
  { unknowns: 'allow' }
);

const ecsMappingArrayItemSchema = schema.object({
  key: schema.string({ maxLength: MAX_ECS_MAPPING_FIELD_LENGTH }),
  value: ecsMappingItemSchema,
});

/** Pack-query ECS mapping — accepts record and canonical array forms. */
export const packEcsMappingSchema = schema.oneOf([
  boundedRecordOf(
    schema.string({ maxLength: MAX_ECS_MAPPING_FIELD_LENGTH }),
    ecsMappingItemSchema,
    MAX_ECS_MAPPING_RESPONSE_KEYS
  ),
  schema.arrayOf(ecsMappingArrayItemSchema, { maxSize: MAX_ECS_MAPPING_RESPONSE_KEYS }),
]);

/**
 * Saved-query ECS mapping — accepts record and canonical array forms written
 * via `convertECSMappingToArray`.
 */
export const savedQueryEcsMappingSchema = schema.oneOf([
  boundedRecordOf(
    schema.string({ maxLength: MAX_ECS_MAPPING_FIELD_LENGTH }),
    ecsMappingItemSchema,
    MAX_ECS_MAPPING_RESPONSE_KEYS
  ),
  schema.arrayOf(ecsMappingArrayItemSchema, { maxSize: MAX_ECS_MAPPING_RESPONSE_KEYS }),
]);

export const policyIdsSchema = schema.arrayOf(
  schema.string({ maxLength: MAX_OSQUERY_POLICY_ID_LENGTH }),
  { maxSize: MAX_OSQUERY_SHARDS_OR_POLICIES }
);

const shardItemSchema = schema.object({
  key: schema.string({ maxLength: MAX_OSQUERY_POLICY_ID_LENGTH }),
  value: schema.number(),
});

export const shardsSchema = schema.oneOf([
  boundedRecordOf(
    schema.string({ maxLength: MAX_OSQUERY_POLICY_ID_LENGTH }),
    schema.number(),
    MAX_OSQUERY_SHARDS_OR_POLICIES
  ),
  schema.arrayOf(shardItemSchema, { maxSize: MAX_OSQUERY_SHARDS_OR_POLICIES }),
]);

export const boundedPackQueriesSchema = (packQuerySchema: Parameters<typeof schema.arrayOf>[0]) =>
  schema.oneOf([
    boundedRecordOf(
      schema.string({ maxLength: MAX_OSQUERY_PACK_QUERY_KEY_LENGTH }),
      packQuerySchema,
      MAX_OSQUERY_PACK_QUERIES
    ),
    schema.arrayOf(packQuerySchema, { maxSize: MAX_OSQUERY_PACK_QUERIES }),
  ]);
