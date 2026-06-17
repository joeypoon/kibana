/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import {
  MAX_DATE_STRING_LENGTH,
  MAX_FIELD_NAME_LENGTH,
  MAX_FILTER_STRING_LENGTH,
  MAX_ID_LENGTH,
  MAX_INDEX_PATTERN_LENGTH,
  MAX_RESOLVER_ENTITY_ID_LENGTH,
} from './schema_bounds_constants';

/**
 * Used to validate GET requests for a complete resolver tree.
 */
export const validateTree = {
  body: schema.object({
    /**
     * If the ancestry field is specified this field will be ignored
     *
     * If the ancestry field is specified we have a much more performant way of retrieving levels so let's not limit
     * the number of levels that come back in that scenario. We could still limit it, but what we'd likely have to do
     * is get all the levels back like we normally do with the ancestry array, bucket them together by level, and then
     * remove the levels that exceeded the requested number which seems kind of wasteful.
     */
    descendantLevels: schema.number({ defaultValue: 20, min: 0, max: 1000 }),
    descendants: schema.number({ defaultValue: 1000, min: 0, max: 10000 }),
    // if the ancestry array isn't specified allowing 200 might be too high
    ancestors: schema.number({ defaultValue: 200, min: 0, max: 10000 }),
    timeRange: schema.maybe(
      schema.object({
        from: schema.string({ maxLength: MAX_DATE_STRING_LENGTH }),
        to: schema.string({ maxLength: MAX_DATE_STRING_LENGTH }),
      })
    ),
    agentId: schema.maybe(schema.string({ minLength: 1, maxLength: MAX_ID_LENGTH })),
    schema: schema.object({
      // the ancestry field is optional
      ancestry: schema.maybe(
        schema.string({ minLength: 1, maxLength: MAX_RESOLVER_ENTITY_ID_LENGTH })
      ),
      // the agentId field is introduced because agent.id will stop being included in entity_id
      agentId: schema.maybe(schema.string({ minLength: 1, maxLength: MAX_ID_LENGTH })),
      id: schema.string({ minLength: 1, maxLength: MAX_RESOLVER_ENTITY_ID_LENGTH }),
      name: schema.maybe(schema.string({ minLength: 1, maxLength: MAX_FIELD_NAME_LENGTH })),
      parent: schema.string({ minLength: 1, maxLength: MAX_RESOLVER_ENTITY_ID_LENGTH }),
    }),
    // only allowing strings and numbers for node IDs because Elasticsearch only allows those types for collapsing:
    // https://www.elastic.co/guide/en/elasticsearch/reference/current/collapse-search-results.html
    // We use collapsing in our Elasticsearch queries for the tree api
    nodes: schema.arrayOf(
      schema.oneOf([
        schema.string({ minLength: 1, maxLength: MAX_RESOLVER_ENTITY_ID_LENGTH }),
        schema.number(),
      ]),
      {
        minSize: 1,
        maxSize: 65536,
      }
    ),
    indexPatterns: schema.arrayOf(schema.string({ maxLength: MAX_INDEX_PATTERN_LENGTH }), {
      minSize: 1,
      maxSize: 100,
    }),
    includeHits: schema.boolean({ defaultValue: false }),
  }),
};

/**
 * Used to validate POST requests for `/resolver/events` api.
 */
export const validateEvents = {
  query: schema.object({
    // keeping the max as 10k because the limit in ES for a single query is also 10k
    limit: schema.number({ defaultValue: 1000, min: 1, max: 10000 }),
    afterEvent: schema.maybe(
      schema.string({ minLength: 1, maxLength: MAX_RESOLVER_ENTITY_ID_LENGTH })
    ),
  }),
  body: schema.object({
    timeRange: schema.maybe(
      schema.object({
        from: schema.string({ maxLength: MAX_DATE_STRING_LENGTH }),
        to: schema.string({ maxLength: MAX_DATE_STRING_LENGTH }),
      })
    ),
    indexPatterns: schema.arrayOf(schema.string({ maxLength: MAX_INDEX_PATTERN_LENGTH }), {
      maxSize: 100,
    }),
    filter: schema.maybe(schema.string({ maxLength: MAX_FILTER_STRING_LENGTH })),
    entityType: schema.maybe(schema.string({ minLength: 1, maxLength: MAX_FIELD_NAME_LENGTH })),
    eventID: schema.maybe(
      schema.string({ minLength: 1, maxLength: MAX_RESOLVER_ENTITY_ID_LENGTH })
    ),
    agentId: schema.maybe(schema.string({ minLength: 1, maxLength: MAX_ID_LENGTH })),
  }),
};

/**
 * Used to validate GET requests for 'entities'
 */
export const validateEntities = {
  query: schema.object({
    /**
     * Return the process entities related to the document w/ the matching `_id`.
     */
    _id: schema.string({ minLength: 1, maxLength: MAX_RESOLVER_ENTITY_ID_LENGTH }),
    /**
     * Indices to search in.
     */
    indices: schema.oneOf([
      schema.arrayOf(schema.string({ maxLength: MAX_INDEX_PATTERN_LENGTH }), { maxSize: 100 }),
      schema.string({ maxLength: MAX_INDEX_PATTERN_LENGTH }),
    ]),
  }),
};
