/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import { MAX_ID_LENGTH } from '../../../../endpoint/schema/schema_bounds_constants';

export const ActionStatusRequestSchema = {
  query: schema.object({
    agent_ids: schema.oneOf([
      schema.arrayOf(schema.string({ minLength: 1, maxLength: MAX_ID_LENGTH }), {
        minSize: 1,
        maxSize: 50,
      }),
      schema.string({ minLength: 1, maxLength: MAX_ID_LENGTH }),
    ]),
  }),
};
