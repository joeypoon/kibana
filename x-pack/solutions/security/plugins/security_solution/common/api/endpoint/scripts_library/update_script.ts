/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema, type TypeOf } from '@kbn/config-schema';
import {
  ScriptDescriptionSchema,
  ScriptExampleSchema,
  ScriptFileSchema,
  ScriptFileTypeSchema,
  ScriptInstructionsSchema,
  ScriptNameSchema,
  ScriptPathToExecutableSchema,
  ScriptPlatformSchema,
  ScriptRequiresInputSchema,
  getScriptsTagSchema,
} from './common';
import type { DeepMutable } from '../../../endpoint/types';
import { MAX_ID_LENGTH } from '../../../endpoint/schema/schema_bounds_constants';
import { validateNonEmptyString } from '../schema_utils';

export const PatchUpdateScriptRequestSchema = {
  body: schema.object(
    {
      name: schema.maybe(ScriptNameSchema),
      platform: schema.maybe(ScriptPlatformSchema),
      file: schema.maybe(ScriptFileSchema),
      fileType: schema.maybe(ScriptFileTypeSchema),
      requiresInput: schema.maybe(ScriptRequiresInputSchema),
      description: schema.maybe(ScriptDescriptionSchema),
      instructions: schema.maybe(ScriptInstructionsSchema),
      example: schema.maybe(ScriptExampleSchema),
      pathToExecutable: schema.conditional(
        schema.siblingRef('fileType'),
        'archive',
        ScriptPathToExecutableSchema,
        schema.never()
      ),
      tags: schema.maybe(getScriptsTagSchema('patch')),
      version: schema.maybe(
        schema.string({
          minLength: 1,
          maxLength: MAX_ID_LENGTH,
          validate: validateNonEmptyString,
        })
      ),
    },
    {
      validate: ({ version, ...updates }) => {
        if (Object.keys(updates).length === 0) {
          return 'At least one field must be defined for update';
        }
      },
    }
  ),
  params: schema.object({
    script_id: schema.string({
      minLength: 1,
      maxLength: MAX_ID_LENGTH,
      validate: validateNonEmptyString,
    }),
  }),
};

export type PatchUpdateRequestParams = DeepMutable<
  TypeOf<typeof PatchUpdateScriptRequestSchema.params>
>;
export type PatchUpdateRequestBody = DeepMutable<
  TypeOf<typeof PatchUpdateScriptRequestSchema.body>
>;
