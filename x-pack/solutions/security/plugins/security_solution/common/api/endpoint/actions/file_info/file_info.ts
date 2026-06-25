/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { TypeOf } from '@kbn/config-schema';
import { schema } from '@kbn/config-schema';

/** Schema that validates the file info API */
export const EndpointActionFileInfoSchema = {
  params: schema.object({
    action_id: schema.string({
      minLength: 1,
      maxLength: 256,
      meta: { description: 'The ID of the response action that generated the file.' },
    }),
    file_id: schema.string({
      minLength: 1,
      maxLength: 256,
      meta: {
        description: `The file identifier is constructed in one of two ways:
- For Elastic Defend agents (\`agentType\` of \`endpoint\`): combine the \`action_id\` and \`agent_id\` values using a dot (\`.\`) separator:
\`{file_id}\` = \`{action_id}.{agent_id}\`
- For all other agent types: the \`file_id\` is the \`agent_id\` for which the response action was sent to.`,
      },
    }),
  }),
};

export type EndpointActionFileInfoParams = TypeOf<typeof EndpointActionFileInfoSchema.params>;

export const ActionFileInfoResponseSchema = schema.object(
  {
    data: schema.maybe(
      schema.object(
        {
          actionId: schema.maybe(
            schema.string({ meta: { description: 'The response action ID.' } })
          ),
          agentId: schema.maybe(
            schema.string({ meta: { description: 'The agent ID that generated the file.' } })
          ),
          id: schema.maybe(schema.string({ meta: { description: 'The file identifier.' } })),
          agentType: schema.maybe(
            schema.string({
              meta: { description: 'The type of agent that generated the file.' },
            })
          ),
          status: schema.maybe(schema.string({ meta: { description: 'The file upload status.' } })),
          created: schema.maybe(
            schema.string({
              meta: { description: 'The date and time the file was created.' },
            })
          ),
          name: schema.maybe(schema.string({ meta: { description: 'The file name.' } })),
          size: schema.maybe(schema.number({ meta: { description: 'The file size in bytes.' } })),
          mimeType: schema.maybe(
            schema.string({ meta: { description: 'The MIME type of the file.' } })
          ),
        },
        { unknowns: 'allow' }
      )
    ),
  },
  { unknowns: 'allow', meta: { id: 'ActionFileInfoResponse' } }
);
