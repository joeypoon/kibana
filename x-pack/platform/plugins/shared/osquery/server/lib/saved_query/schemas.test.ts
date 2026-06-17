/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  MAX_ECS_MAPPING_FIELD_LENGTH,
  MAX_ECS_MAPPING_RESPONSE_KEYS,
  MAX_ECS_MAPPING_STRING_VALUE,
  MAX_ECS_MAPPING_VALUE_ARRAY,
  MAX_OSQUERY_PACK_QUERIES,
  MAX_OSQUERY_PACK_QUERY_KEY_LENGTH,
  MAX_OSQUERY_POLICY_ID_LENGTH,
  MAX_OSQUERY_SHARDS_OR_POLICIES,
  MAX_RRULE_DATE_OR_SPLAY_LENGTH,
  MAX_RRULE_LENGTH,
} from './config_schema_bounds';
import { packSchemaV3, savedQuerySchemaV2 } from './schemas';

const policyId = 'a'.repeat(MAX_OSQUERY_POLICY_ID_LENGTH);
const overlongPolicyId = 'a'.repeat(MAX_OSQUERY_POLICY_ID_LENGTH + 1);

const packQuery = {
  query: 'select 1',
};

describe('packSchemaV3 bounds', () => {
  it('accepts policy_ids at the upper bound', () => {
    expect(
      packSchemaV3.validate({
        policy_ids: Array.from({ length: MAX_OSQUERY_SHARDS_OR_POLICIES }, (_, index) =>
          String(index)
        ),
      })
    ).toBeDefined();
  });

  it('rejects policy_ids above the upper bound', () => {
    expect(() =>
      packSchemaV3.validate({
        policy_ids: Array.from({ length: MAX_OSQUERY_SHARDS_OR_POLICIES + 1 }, () => policyId),
      })
    ).toThrow(/cannot be greater than \[10000\]/);
  });

  it('rejects overlong policy_ids items', () => {
    expect(() =>
      packSchemaV3.validate({
        policy_ids: [overlongPolicyId],
      })
    ).toThrow(/must have a maximum length of/);
  });

  it('accepts shards record branch at the upper bound', () => {
    const shards = Object.fromEntries(
      Array.from({ length: MAX_OSQUERY_SHARDS_OR_POLICIES }, (_, index) => [String(index), 50])
    );

    expect(packSchemaV3.validate({ shards })).toEqual({ shards });
  });

  it('rejects shards record branch above the upper bound', () => {
    const shards = Object.fromEntries(
      Array.from({ length: MAX_OSQUERY_SHARDS_OR_POLICIES + 1 }, (_, index) => [String(index), 50])
    );

    expect(() => packSchemaV3.validate({ shards })).toThrow(/must not exceed 10000 keys/);
  });

  it('rejects overlong shard record keys', () => {
    expect(() =>
      packSchemaV3.validate({
        shards: { [overlongPolicyId]: 50 },
      })
    ).toThrow(/must have a maximum length of/);
  });

  it('accepts shards array branch at the upper bound', () => {
    const shards = Array.from({ length: MAX_OSQUERY_SHARDS_OR_POLICIES }, (_, index) => ({
      key: String(index),
      value: 50,
    }));

    expect(packSchemaV3.validate({ shards })).toEqual({ shards });
  });

  it('rejects shards array branch above the upper bound', () => {
    const shards = Array.from({ length: MAX_OSQUERY_SHARDS_OR_POLICIES + 1 }, (_, index) => ({
      key: String(index),
      value: 50,
    }));

    expect(() => packSchemaV3.validate({ shards })).toThrow(/cannot be greater than \[10000\]/);
  });

  it('accepts queries array branch at the existing 1000 cap', () => {
    const queries = Array.from({ length: MAX_OSQUERY_PACK_QUERIES }, (_, index) => ({
      id: String(index),
      ...packQuery,
    }));

    expect(packSchemaV3.validate({ queries })).toEqual({ queries });
  });

  it('rejects queries array branch above 1000 items', () => {
    const queries = Array.from({ length: MAX_OSQUERY_PACK_QUERIES + 1 }, (_, index) => ({
      id: String(index),
      ...packQuery,
    }));

    expect(() => packSchemaV3.validate({ queries })).toThrow(/cannot be greater than \[1000\]/);
  });

  it('rejects queries record branch above 1000 keys', () => {
    const queries = Object.fromEntries(
      Array.from({ length: MAX_OSQUERY_PACK_QUERIES + 1 }, (_, index) => [String(index), packQuery])
    );

    expect(() => packSchemaV3.validate({ queries })).toThrow(/must not exceed 1000 keys/);
  });

  it('rejects overlong queries record keys', () => {
    const overlongQueryKey = 'a'.repeat(MAX_OSQUERY_PACK_QUERY_KEY_LENGTH + 1);

    expect(() =>
      packSchemaV3.validate({
        queries: { [overlongQueryKey]: packQuery },
      })
    ).toThrow(/must have a maximum length of/);
  });

  it('accepts per-query ecs_mapping array branch at 1000 items', () => {
    const ecsMappingArray = Array.from({ length: MAX_ECS_MAPPING_RESPONSE_KEYS }, (_, index) => ({
      key: `field_${index}`,
      value: { value: 'static' },
    }));

    expect(
      packSchemaV3.validate({
        queries: [{ ...packQuery, ecs_mapping: ecsMappingArray }],
      })
    ).toBeDefined();
  });

  it('rejects per-query ecs_mapping array branch above 1000 items', () => {
    const ecsMappingArray = Array.from(
      { length: MAX_ECS_MAPPING_RESPONSE_KEYS + 1 },
      (_, index) => ({
        key: `field_${index}`,
        value: { value: 'static' },
      })
    );

    expect(() =>
      packSchemaV3.validate({
        queries: [{ ...packQuery, ecs_mapping: ecsMappingArray }],
      })
    ).toThrow(/cannot be greater than \[1000\]/);
  });

  it('preserves unknown per-query RRULE fields via unknowns allow', () => {
    expect(
      packSchemaV3.validate({
        queries: {
          q1: {
            ...packQuery,
            schedule_type: 'rrule',
            rrule_schedule: { rrule: 'FREQ=DAILY', start_date: '2024-01-01T00:00:00Z' },
          },
        },
      })
    ).toEqual({
      queries: {
        q1: {
          ...packQuery,
          schedule_type: 'rrule',
          rrule_schedule: { rrule: 'FREQ=DAILY', start_date: '2024-01-01T00:00:00Z' },
        },
      },
    });
  });

  it('rejects rrule_schedule.rrule above the HTTP API limit', () => {
    expect(() =>
      packSchemaV3.validate({
        rrule_schedule: {
          rrule: 'a'.repeat(MAX_RRULE_LENGTH + 1),
          start_date: '2024-01-01T00:00:00Z',
        },
      })
    ).toThrow(/must have a maximum length of/);
  });

  it('rejects rrule_schedule date and splay strings above the HTTP API limit', () => {
    const overlongDateOrSplay = 'a'.repeat(MAX_RRULE_DATE_OR_SPLAY_LENGTH + 1);

    for (const fieldName of ['start_date', 'end_date', 'splay']) {
      expect(() =>
        packSchemaV3.validate({
          rrule_schedule: {
            rrule: 'FREQ=DAILY',
            start_date: fieldName === 'start_date' ? overlongDateOrSplay : '2024-01-01T00:00:00Z',
            end_date: fieldName === 'end_date' ? overlongDateOrSplay : undefined,
            splay: fieldName === 'splay' ? overlongDateOrSplay : undefined,
          },
        })
      ).toThrow(/must have a maximum length of/);
    }
  });
});

describe('saved query saved-object schema bounds', () => {
  it('accepts ecs_mapping record branch at 1000 keys', () => {
    const ecsMappingRecord = Object.fromEntries(
      Array.from({ length: MAX_ECS_MAPPING_RESPONSE_KEYS }, (_, index) => [
        `field_${index}`,
        { value: 'static' },
      ])
    );

    expect(savedQuerySchemaV2.validate({ id: 'sq1', ecs_mapping: ecsMappingRecord })).toEqual({
      id: 'sq1',
      ecs_mapping: ecsMappingRecord,
    });
  });

  it('accepts ecs_mapping array branch at 1000 items', () => {
    const ecsMappingArray = Array.from({ length: MAX_ECS_MAPPING_RESPONSE_KEYS }, (_, index) => ({
      key: `field_${index}`,
      value: { value: 'static' },
    }));

    expect(savedQuerySchemaV2.validate({ id: 'sq1', ecs_mapping: ecsMappingArray })).toEqual({
      id: 'sq1',
      ecs_mapping: ecsMappingArray,
    });
  });

  it('rejects ecs_mapping record branch above 1000 keys', () => {
    const ecsMappingRecord = Object.fromEntries(
      Array.from({ length: MAX_ECS_MAPPING_RESPONSE_KEYS + 1 }, (_, index) => [
        `field_${index}`,
        { value: 'static' },
      ])
    );

    expect(() => savedQuerySchemaV2.validate({ id: 'sq1', ecs_mapping: ecsMappingRecord })).toThrow(
      /must not exceed 1000 keys/
    );
  });

  it('rejects ecs_mapping value strings above 1024 characters', () => {
    expect(() =>
      savedQuerySchemaV2.validate({
        id: 'sq1',
        ecs_mapping: {
          host: { value: 'a'.repeat(MAX_ECS_MAPPING_STRING_VALUE + 1) },
        },
      })
    ).toThrow(/must have a maximum length of/);
  });

  it('rejects ecs_mapping value arrays above 1000 items', () => {
    expect(() =>
      savedQuerySchemaV2.validate({
        id: 'sq1',
        ecs_mapping: {
          host: {
            value: Array.from({ length: MAX_ECS_MAPPING_VALUE_ARRAY + 1 }, () => 'x'),
          },
        },
      })
    ).toThrow(/cannot be greater than \[1000\]/);
  });

  it('rejects ecs_mapping record keys above 256 characters', () => {
    expect(() =>
      savedQuerySchemaV2.validate({
        id: 'sq1',
        ecs_mapping: {
          ['a'.repeat(MAX_ECS_MAPPING_FIELD_LENGTH + 1)]: { value: 'static' },
        },
      })
    ).toThrow(/must have a maximum length of/);
  });

  it('rejects ecs_mapping array branch keys above 256 characters', () => {
    expect(() =>
      savedQuerySchemaV2.validate({
        id: 'sq1',
        ecs_mapping: [
          {
            key: 'a'.repeat(MAX_ECS_MAPPING_FIELD_LENGTH + 1),
            value: { value: 'static' },
          },
        ],
      })
    ).toThrow(/must have a maximum length of/);
  });

  it('rejects ecs_mapping field values above 256 characters', () => {
    expect(() =>
      savedQuerySchemaV2.validate({
        id: 'sq1',
        ecs_mapping: {
          host: {
            field: 'a'.repeat(MAX_ECS_MAPPING_FIELD_LENGTH + 1),
          },
        },
      })
    ).toThrow(/must have a maximum length of/);
  });
});
