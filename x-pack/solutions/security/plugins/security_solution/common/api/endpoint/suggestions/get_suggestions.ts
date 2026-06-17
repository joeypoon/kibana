/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { TypeOf } from '@kbn/config-schema';
import { schema } from '@kbn/config-schema';
import type { FieldSpec } from '@kbn/data-views-plugin/common';
import {
  MAX_FIELD_META_KEYS,
  MAX_FIELD_NAME_LENGTH,
  MAX_LONG_TEXT_LENGTH,
  MAX_SUGGESTION_FILTER_ARRAY_ITEMS,
  MAX_SUGGESTION_QUERY_LENGTH,
} from '../../../endpoint/schema/schema_bounds_constants';

const validateBoundedRecordKeys = (
  record: Record<string, unknown>,
  label: string,
  maxKeys: number
) => {
  if (Object.keys(record).length > maxKeys) {
    return `${label} cannot have more than ${maxKeys} keys`;
  }
};

const validateBoundedNestedObjectShape = (
  value: unknown,
  label: string,
  maxKeys: number
): string | void => {
  if (value === null || typeof value !== 'object') {
    return undefined;
  }

  if (Array.isArray(value)) {
    if (value.length > MAX_SUGGESTION_FILTER_ARRAY_ITEMS) {
      return `${label} array must not exceed ${MAX_SUGGESTION_FILTER_ARRAY_ITEMS} items`;
    }

    for (const item of value) {
      const itemError = validateBoundedNestedObjectShape(item, label, maxKeys);
      if (itemError) {
        return itemError;
      }
    }

    return undefined;
  }

  const record = value as Record<string, unknown>;
  const keyError = validateBoundedRecordKeys(record, label, maxKeys);
  if (keyError) {
    return keyError;
  }

  for (const [key, child] of Object.entries(record)) {
    if (key.length > MAX_FIELD_NAME_LENGTH) {
      return `${label} key must not exceed ${MAX_FIELD_NAME_LENGTH} characters`;
    }

    if (typeof child === 'string' && child.length > MAX_LONG_TEXT_LENGTH) {
      return `${label} string value must not exceed ${MAX_LONG_TEXT_LENGTH} characters`;
    }

    if (Array.isArray(child)) {
      if (child.length > MAX_SUGGESTION_FILTER_ARRAY_ITEMS) {
        return `${label} array value must not exceed ${MAX_SUGGESTION_FILTER_ARRAY_ITEMS} items`;
      }

      for (const item of child) {
        const arrayItemError = validateBoundedNestedObjectShape(item, label, maxKeys);
        if (arrayItemError) {
          return arrayItemError;
        }
      }
    }

    if (typeof child === 'object' && child !== null) {
      const nestedError = validateBoundedNestedObjectShape(child, label, maxKeys);
      if (nestedError) {
        return nestedError;
      }
    }
  }
};

const validateBoundedFilterShape = (value: unknown): string | void =>
  validateBoundedNestedObjectShape(value, 'filter', MAX_FIELD_META_KEYS);

const validateBoundedFieldMetaShape = (value: unknown): string | void =>
  validateBoundedNestedObjectShape(value, 'fieldMeta', MAX_FIELD_META_KEYS);

const boundedFieldMetaSchema = schema.object(
  {},
  {
    unknowns: 'allow',
    validate: (value) => validateBoundedFieldMetaShape(value),
  }
);

const boundedFilterSchema = schema.object(
  {},
  {
    unknowns: 'allow',
    validate: (value) => validateBoundedFilterShape(value),
  }
);

export const EndpointSuggestionsSchema = {
  body: schema.object({
    field: schema.string({ maxLength: MAX_FIELD_NAME_LENGTH }),
    query: schema.string({ maxLength: MAX_SUGGESTION_QUERY_LENGTH }),
    filters: schema.maybe(
      schema.arrayOf(boundedFilterSchema, {
        maxSize: MAX_SUGGESTION_FILTER_ARRAY_ITEMS,
      })
    ),
    fieldMeta: schema.maybe(boundedFieldMetaSchema),
  }),
  params: schema.object({
    suggestion_type: schema.oneOf([
      schema.literal('eventFilters'),
      schema.literal('endpoints'),
      schema.literal('endpointExceptions'),
      schema.literal('trustedApps'),
      schema.literal('trustedDevices'),
    ]),
  }),
};

type EndpointSuggestionsBodyValidated = TypeOf<typeof EndpointSuggestionsSchema.body>;

export type EndpointSuggestionsBody = Omit<EndpointSuggestionsBodyValidated, 'fieldMeta'> & {
  fieldMeta?: FieldSpec;
};
export type EndpointSuggestionsParams = TypeOf<typeof EndpointSuggestionsSchema.params>;
