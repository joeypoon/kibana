/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';

import { EndpointSuggestionsSchema } from './get_suggestions';
import {
  MAX_FIELD_META_KEYS,
  MAX_FIELD_NAME_LENGTH,
  MAX_SUGGESTION_QUERY_LENGTH,
} from '../../../endpoint/schema/schema_bounds_constants';

describe('EndpointSuggestionsSchema', () => {
  const validateBody = (body: Record<string, unknown>) =>
    schema
      .object(EndpointSuggestionsSchema)
      .validate({ body, params: { suggestion_type: 'endpoints' } });

  it('accepts valid bounded input', () => {
    expect(() =>
      validateBody({
        field: 'host.name',
        query: 'host',
        fieldMeta: { type: 'string' },
      })
    ).not.toThrow();
  });

  it('accepts realistic field.toSpec()-shaped fieldMeta', () => {
    expect(() =>
      validateBody({
        field: 'host.name',
        query: 'host',
        fieldMeta: {
          name: 'host.name',
          type: 'string',
          esTypes: ['keyword'],
          searchable: true,
          aggregatable: true,
          readFromDocValues: true,
          format: { id: 'string' },
        },
      })
    ).not.toThrow();
  });

  it('rejects field longer than 256 characters', () => {
    expect(() =>
      validateBody({
        field: 'a'.repeat(MAX_FIELD_NAME_LENGTH + 1),
        query: 'host',
      })
    ).toThrow();
  });

  it('rejects query longer than 1024 characters', () => {
    expect(() =>
      validateBody({
        field: 'host.name',
        query: 'a'.repeat(MAX_SUGGESTION_QUERY_LENGTH + 1),
      })
    ).toThrow();
  });

  it('rejects fieldMeta with more than 50 keys', () => {
    const fieldMeta = Object.fromEntries(
      Array.from({ length: MAX_FIELD_META_KEYS + 1 }, (_, index) => [`key-${index}`, 'value'])
    );

    expect(() =>
      validateBody({
        field: 'host.name',
        query: 'host',
        fieldMeta,
      })
    ).toThrow();
  });

  it('accepts bounded filters entries', () => {
    expect(() =>
      validateBody({
        field: 'host.name',
        query: 'host',
        filters: [{ term: { 'test.field': 'test-value' } }],
      })
    ).not.toThrow();
  });

  it('rejects filters with more than 50 keys in an entry', () => {
    const filters = [
      Object.fromEntries(
        Array.from({ length: MAX_FIELD_META_KEYS + 1 }, (_, index) => [`key-${index}`, 'value'])
      ),
    ];

    expect(() =>
      validateBody({
        field: 'host.name',
        query: 'host',
        filters,
      })
    ).toThrow();
  });

  it('rejects filters with more than 50 entries', () => {
    const filters = Array.from({ length: 51 }, () => ({
      term: { 'test.field': 'test-value' },
    }));

    expect(() =>
      validateBody({
        field: 'host.name',
        query: 'host',
        filters,
      })
    ).toThrow();
  });

  it('rejects nested filter arrays above the item cap', () => {
    const filters = [
      {
        terms: {
          'test.field': Array.from({ length: 51 }, () => 'value'),
        },
      },
    ];

    expect(() =>
      validateBody({
        field: 'host.name',
        query: 'host',
        filters,
      })
    ).toThrow();
  });
});
