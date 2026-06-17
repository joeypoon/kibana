/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import {
  boundedPackQueriesSchema,
  MAX_RRULE_DATE_OR_SPLAY_LENGTH,
  MAX_RRULE_LENGTH,
  packEcsMappingSchema,
  policyIdsSchema,
  savedQueryEcsMappingSchema,
  shardsSchema,
} from './config_schema_bounds';

const savedQuerySchemaV1 = schema.object({
  id: schema.string(),
  description: schema.maybe(schema.string()),
  query: schema.maybe(schema.string()),
  created_at: schema.maybe(schema.string()),
  created_by: schema.maybe(schema.nullable(schema.string())),
  platform: schema.maybe(schema.string()),
  version: schema.maybe(schema.oneOf([schema.string(), schema.number()])),
  updated_at: schema.maybe(schema.string()),
  updated_by: schema.maybe(schema.nullable(schema.string())),
  interval: schema.maybe(schema.oneOf([schema.string(), schema.number()])),
  timeout: schema.maybe(schema.number()),
  snapshot: schema.maybe(schema.boolean()),
  removed: schema.maybe(schema.boolean()),
  prebuilt: schema.maybe(schema.boolean()),
  ecs_mapping: schema.maybe(savedQueryEcsMappingSchema),
});

export const savedQuerySchemaV2 = savedQuerySchemaV1.extends({
  created_by_profile_uid: schema.maybe(schema.nullable(schema.string())),
  updated_by_profile_uid: schema.maybe(schema.nullable(schema.string())),
});

// `unknowns: 'allow'` is load-bearing — do not tighten. The per-query RRULE
// overrides (`schedule_type`, `rrule_schedule`) flow through this schema
// without an explicit `queries.properties` mapping addition because the pack
// SO's `queries` field is `dynamic: false` and this schema accepts unknown
// keys at read time. Tightening to `forbid` silently breaks flag-on customers
// with per-query RRULE overrides. See `design.md` D35.
const packQuerySchema = schema.object(
  {
    id: schema.maybe(schema.string()),
    query: schema.maybe(schema.string()),
    interval: schema.maybe(schema.oneOf([schema.string(), schema.number()])),
    timeout: schema.maybe(schema.number()),
    platform: schema.maybe(schema.string()),
    version: schema.maybe(schema.string()),
    ecs_mapping: schema.maybe(packEcsMappingSchema),
    snapshot: schema.maybe(schema.boolean()),
    removed: schema.maybe(schema.boolean()),
  },
  { unknowns: 'allow' }
);

const packSchemaV1 = schema.object({
  name: schema.maybe(schema.string()),
  description: schema.maybe(schema.string()),
  queries: schema.maybe(boundedPackQueriesSchema(packQuerySchema)),
  // Pack-asset version (prebuilt-pack version number). Name is taken — a future
  // V4 / D29 "min osquery version" field MUST use a different name (e.g.
  // `min_osquery_version`) to avoid type collision with this number field.
  version: schema.maybe(schema.number()),
  enabled: schema.maybe(schema.boolean()),
  created_at: schema.maybe(schema.string()),
  created_by: schema.maybe(schema.nullable(schema.string())),
  updated_at: schema.maybe(schema.string()),
  updated_by: schema.maybe(schema.nullable(schema.string())),
  policy_ids: schema.maybe(policyIdsSchema),
  shards: schema.maybe(shardsSchema),
});

export const packSchemaV2 = packSchemaV1.extends({
  created_by_profile_uid: schema.maybe(schema.nullable(schema.string())),
  updated_by_profile_uid: schema.maybe(schema.nullable(schema.string())),
});

const rruleScheduleConfigSchema = schema.object(
  {
    rrule: schema.string({ maxLength: MAX_RRULE_LENGTH }),
    start_date: schema.string({ maxLength: MAX_RRULE_DATE_OR_SPLAY_LENGTH }),
    end_date: schema.maybe(schema.string({ maxLength: MAX_RRULE_DATE_OR_SPLAY_LENGTH })),
    splay: schema.maybe(schema.string({ maxLength: MAX_RRULE_DATE_OR_SPLAY_LENGTH })),
    timeout: schema.maybe(schema.number()),
  },
  { unknowns: 'allow' }
);

export const packSchemaV3 = packSchemaV2.extends({
  // Nullable so update routes can clear the prior-mode pack-level field on a
  // schedule_type transition (D14) — the SO mapping accepts null and the
  // discriminated read/find responses then drop the slot entirely.
  schedule_type: schema.maybe(
    schema.nullable(schema.oneOf([schema.literal('interval'), schema.literal('rrule')]))
  ),
  interval: schema.maybe(schema.nullable(schema.number())),
  rrule_schedule: schema.maybe(schema.nullable(rruleScheduleConfigSchema)),
});
