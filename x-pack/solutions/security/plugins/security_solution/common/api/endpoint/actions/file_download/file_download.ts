/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import type { TypeOf } from '@kbn/config-schema';

/** Schema that validates the file download API */
export const EndpointActionFileDownloadSchema = {
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

export type EndpointActionFileDownloadParams = TypeOf<
  typeof EndpointActionFileDownloadSchema.params
>;
