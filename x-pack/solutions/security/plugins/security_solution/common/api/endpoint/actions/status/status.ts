/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';

export const ActionStatusRequestSchema = {
  query: schema.object({
    agent_ids: schema.oneOf(
      [
        schema.arrayOf(schema.string({ minLength: 1, maxLength: 256 }), {
          minSize: 1,
          maxSize: 50,
        }),
        schema.string({ minLength: 1, maxLength: 256 }),
      ],
      { meta: { description: 'A list of agent IDs to get the action status for.' } }
    ),
  }),
};

export const ActionStatusResponseSchema = schema.object(
  {
    data: schema.arrayOf(
      schema.object(
        {
          agent_id: schema.string({ meta: { description: 'The agent ID.' } }),
          pending_actions: schema.recordOf(schema.string(), schema.number(), {
            meta: {
              description:
                'A map of pending response-action command names to their pending counts.',
            },
          }),
        },
        { unknowns: 'allow' }
      ),
      { meta: { description: 'One pending-actions summary entry per requested agent.' } }
    ),
  },
  { unknowns: 'allow', meta: { id: 'ActionStatusResponse' } }
);
