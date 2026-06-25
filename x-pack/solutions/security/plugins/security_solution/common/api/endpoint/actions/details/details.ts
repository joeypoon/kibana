/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import { ResponseActionDetailsSchema } from '../common/response_actions';

export const ActionDetailsRequestSchema = {
  params: schema.object({
    action_id: schema.string({
      minLength: 1,
      maxLength: 256,
      meta: { description: 'The ID of the response action to retrieve.' },
    }),
  }),
};

export const ActionDetailsResponseSchema = schema.object(
  { data: schema.maybe(ResponseActionDetailsSchema) },
  { unknowns: 'allow', meta: { id: 'ActionDetailsResponse' } }
);
