/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  MAX_DATE_STRING_LENGTH,
  MAX_FILTER_STRING_LENGTH,
  MAX_INDEX_PATTERN_LENGTH,
  MAX_RESOLVER_ENTITY_ID_LENGTH,
} from './schema_bounds_constants';
import { validateEntities, validateEvents, validateTree } from './resolver';

describe('endpoint resolver schemas', () => {
  const validTreeBody = {
    schema: {
      id: 'entity-id',
      parent: 'parent-id',
    },
    nodes: ['node-1'],
    indexPatterns: ['logs-endpoint.events.*'],
  };

  describe('validateTree', () => {
    it('should accept a valid tree request body', () => {
      expect(() => validateTree.body.validate(validTreeBody)).not.toThrow();
    });

    it('should reject schema id longer than max length', () => {
      expect(() =>
        validateTree.body.validate({
          ...validTreeBody,
          schema: {
            ...validTreeBody.schema,
            id: 'x'.repeat(MAX_RESOLVER_ENTITY_ID_LENGTH + 1),
          },
        })
      ).toThrow();
    });

    it('should accept schema id at max length', () => {
      expect(() =>
        validateTree.body.validate({
          ...validTreeBody,
          schema: {
            ...validTreeBody.schema,
            id: 'x'.repeat(MAX_RESOLVER_ENTITY_ID_LENGTH),
          },
        })
      ).not.toThrow();
    });

    it('should reject index pattern longer than max length', () => {
      expect(() =>
        validateTree.body.validate({
          ...validTreeBody,
          indexPatterns: ['x'.repeat(MAX_INDEX_PATTERN_LENGTH + 1)],
        })
      ).toThrow();
    });

    it('should accept index pattern at max length', () => {
      expect(() =>
        validateTree.body.validate({
          ...validTreeBody,
          indexPatterns: ['x'.repeat(MAX_INDEX_PATTERN_LENGTH)],
        })
      ).not.toThrow();
    });

    it('should reject time range strings longer than max length', () => {
      expect(() =>
        validateTree.body.validate({
          ...validTreeBody,
          timeRange: {
            from: 'x'.repeat(MAX_DATE_STRING_LENGTH + 1),
            to: 'now',
          },
        })
      ).toThrow();
    });

    it('should accept time range strings at max length', () => {
      expect(() =>
        validateTree.body.validate({
          ...validTreeBody,
          timeRange: {
            from: 'x'.repeat(MAX_DATE_STRING_LENGTH),
            to: 'y'.repeat(MAX_DATE_STRING_LENGTH),
          },
        })
      ).not.toThrow();
    });
  });

  describe('validateEvents', () => {
    it('should reject afterEvent longer than max length', () => {
      expect(() =>
        validateEvents.query.validate({
          afterEvent: 'x'.repeat(MAX_RESOLVER_ENTITY_ID_LENGTH + 1),
        })
      ).toThrow();
    });

    it('should accept afterEvent at max length', () => {
      expect(() =>
        validateEvents.query.validate({
          afterEvent: 'x'.repeat(MAX_RESOLVER_ENTITY_ID_LENGTH),
        })
      ).not.toThrow();
    });

    it('should reject filter longer than max length', () => {
      expect(() =>
        validateEvents.body.validate({
          indexPatterns: ['logs-endpoint.events.*'],
          filter: 'x'.repeat(MAX_FILTER_STRING_LENGTH + 1),
        })
      ).toThrow();
    });

    it('should accept filter at max length', () => {
      expect(() =>
        validateEvents.body.validate({
          indexPatterns: ['logs-endpoint.events.*'],
          filter: 'x'.repeat(MAX_FILTER_STRING_LENGTH),
        })
      ).not.toThrow();
    });
  });

  describe('validateEntities', () => {
    it('should reject _id longer than max length', () => {
      expect(() =>
        validateEntities.query.validate({
          _id: 'x'.repeat(MAX_RESOLVER_ENTITY_ID_LENGTH + 1),
          indices: 'logs-endpoint.events.*',
        })
      ).toThrow();
    });

    it('should accept _id at max length', () => {
      expect(() =>
        validateEntities.query.validate({
          _id: 'x'.repeat(MAX_RESOLVER_ENTITY_ID_LENGTH),
          indices: 'logs-endpoint.events.*',
        })
      ).not.toThrow();
    });

    it('should reject indices string longer than max length', () => {
      expect(() =>
        validateEntities.query.validate({
          _id: 'doc-id',
          indices: 'x'.repeat(MAX_INDEX_PATTERN_LENGTH + 1),
        })
      ).toThrow();
    });

    it('should accept indices string at max length', () => {
      expect(() =>
        validateEntities.query.validate({
          _id: 'doc-id',
          indices: 'x'.repeat(MAX_INDEX_PATTERN_LENGTH),
        })
      ).not.toThrow();
    });
  });
});
