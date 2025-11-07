/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod';
import { DefendInsightType } from '@kbn/elastic-assistant-common';

import { PROMPTS } from './prompts';

export function getDefendInsightsOutputSchema({ type }: { type: DefendInsightType }) {
  switch (type) {
    case DefendInsightType.Enum.incompatible_antivirus:
      const antivirus_prompts = PROMPTS.INCOMPATIBLE_ANTIVIRUS;
      return z.object({
        insights: z.array(
          z.object({
            group: z.string().describe(antivirus_prompts.GROUP),
            events: z
              .object({
                id: z.string().describe(antivirus_prompts.EVENTS_ID),
                endpointId: z.string().describe(antivirus_prompts.EVENTS_ENDPOINT_ID),
                value: z.string().describe(antivirus_prompts.EVENTS_VALUE),
              })
              .array()
              .describe(antivirus_prompts.EVENTS),
          })
        ),
      });
    case DefendInsightType.Enum.policy_response_failure:
      const policy_response_prompts = PROMPTS.POLICY_RESPONSE_FAILURE;
      return z.object({
        insights: z.array(
          z.object({
            group: z.string().describe(policy_response_prompts.GROUP),
            events: z
              .object({
                id: z.string().describe(policy_response_prompts.EVENTS_ID),
                endpointId: z.string().describe(policy_response_prompts.EVENTS_ENDPOINT_ID),
                value: z.string().describe(policy_response_prompts.EVENTS_VALUE),
              })
              .array()
              .describe(policy_response_prompts.EVENTS),
            remediation: z
              .object({
                message: z.string().describe(policy_response_prompts.REMEDIATION_MESSAGE ?? ''),
                link: z.string().describe(policy_response_prompts.REMEDIATION_LINK ?? ''),
              })
              .describe(policy_response_prompts.REMEDIATION ?? ''),
          })
        ),
      });
    default:
      const custom_prompts = PROMPTS.CUSTOM;
      return z.object({
        insights: z.array(
          z.object({
            group: z.string().describe(custom_prompts.GROUP),
            events: z
              .object({
                id: z.string().describe(custom_prompts.EVENTS_ID),
                endpointId: z.string().describe(custom_prompts.EVENTS_ENDPOINT_ID),
                value: z.string().describe(custom_prompts.EVENTS_VALUE),
              })
              .array()
              .describe(custom_prompts.EVENTS),
            remediation: z
              .object({
                message: z.string().describe(custom_prompts.REMEDIATION_MESSAGE ?? ''),
              })
              .describe(custom_prompts.REMEDIATION ?? ''),
          })
        ),
      });
  }
}
