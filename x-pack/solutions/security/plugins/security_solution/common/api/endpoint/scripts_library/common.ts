/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import { SCRIPT_TAGS } from '../../../endpoint/service/script_library/constants';
import {
  MAX_FILE_PATH_LENGTH,
  MAX_LONG_TEXT_LENGTH,
  MAX_NAME_LENGTH,
  MAX_SCRIPT_TAG_LENGTH,
} from '../../../endpoint/schema/schema_bounds_constants';
import { validateNoDuplicateValues, validateNonEmptyString } from '../schema_utils';
import { SUPPORTED_HOST_OS_TYPE } from '../../../endpoint/constants';

export const ScriptNameSchema = schema.string({
  minLength: 1,
  maxLength: MAX_NAME_LENGTH,
  validate: validateNonEmptyString,
});
export const ScriptFileSchema = schema.stream();
export const ScriptFileTypeSchema = schema.oneOf([
  schema.literal('archive'),
  schema.literal('script'),
]);
export const ScriptRequiresInputSchema = schema.boolean({ defaultValue: false });
export const ScriptPlatformSchema = schema.arrayOf(
  // @ts-expect-error TS2769: No overload matches this call. (due to now `oneOf()` type is defined)
  schema.oneOf(SUPPORTED_HOST_OS_TYPE.map((osType) => schema.literal(osType))),
  { minSize: 1, maxSize: 3, validate: validateNoDuplicateValues }
);

export const ScriptPathToExecutableSchema = schema.string({
  minLength: 1,
  maxLength: MAX_FILE_PATH_LENGTH,
  validate: validateNonEmptyString,
});

export const ScriptDescriptionSchema = schema.string({ maxLength: MAX_LONG_TEXT_LENGTH });
export const ScriptInstructionsSchema = schema.string({ maxLength: MAX_LONG_TEXT_LENGTH });
export const ScriptExampleSchema = schema.string({ maxLength: MAX_LONG_TEXT_LENGTH });

export const getScriptsTagSchema = (type: 'patch' | 'post') =>
  // @ts-expect-error TS2769: No overload matches this call. (due to how `oneOf()` type is defined)
  schema.arrayOf(schema.oneOf(Object.keys(SCRIPT_TAGS).map((osType) => schema.literal(osType))), {
    minSize: type === 'patch' ? 0 : 1,
    maxSize: Object.keys(SCRIPT_TAGS).length,
    validate: (tags) => {
      const duplicateError = validateNoDuplicateValues(tags);
      if (duplicateError) {
        return duplicateError;
      }

      if (tags.some((tag) => tag.length > MAX_SCRIPT_TAG_LENGTH)) {
        return `[tags]: string length must be less than or equal to ${MAX_SCRIPT_TAG_LENGTH}`;
      }
    },
  });
