/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { TypeOf } from '@kbn/config-schema';
import { schema } from '@kbn/config-schema';
import { MAX_ALERT_IDS, MAX_DATE_STRING_LENGTH, MAX_ID_LENGTH } from './schema_bounds_constants';

export const AutomatedActionListRequestSchema = {
  query: schema.object({
    alertIds: schema.arrayOf(schema.string({ minLength: 1, maxLength: MAX_ID_LENGTH }), {
      minSize: 1,
      maxSize: MAX_ALERT_IDS,
      validate: (alertIds) => {
        if (alertIds.map((v) => v.trim()).some((v) => !v.length)) {
          return 'alertIds cannot contain empty strings';
        }
      },
    }),
  }),
};

export type EndpointAutomatedActionListRequestQuery = TypeOf<
  typeof AutomatedActionListRequestSchema.query
>;

export const AutomatedActionResponseRequestSchema = {
  query: schema.object({
    expiration: schema.string({ maxLength: MAX_DATE_STRING_LENGTH }),
    actionId: schema.string({ maxLength: MAX_ID_LENGTH }),
    agent: schema.object({
      id: schema.oneOf([
        schema.string({ maxLength: MAX_ID_LENGTH }),
        schema.arrayOf(schema.string({ maxLength: MAX_ID_LENGTH }), { maxSize: 50 }),
      ]),
    }),
  }),
};

export type EndpointAutomatedActionResponseRequestQuery = TypeOf<
  typeof AutomatedActionResponseRequestSchema.query
>;
