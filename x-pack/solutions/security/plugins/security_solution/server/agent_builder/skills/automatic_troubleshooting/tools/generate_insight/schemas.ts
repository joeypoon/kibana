/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';

import {
  MAX_ID_LENGTH,
  MAX_INSIGHTS_ARRAY_SIZE,
  MAX_LONG_TEXT_LENGTH,
  MAX_URL_LENGTH,
} from '../../../../../../common/endpoint/schema/schema_bounds_constants';
import { WorkflowInsightType } from '../../../../../../common/endpoint/types/workflow_insights';
import { PROMPTS } from './prompts';

const boundedDefendInsightGroupSchema = () => z.string().min(1).max(MAX_LONG_TEXT_LENGTH);

const boundedDefendInsightEventsSchema = ({
  eventsId,
  eventsEndpointId,
  eventsValue,
}: {
  eventsId: string;
  eventsEndpointId: string;
  eventsValue: string;
}) =>
  z
    .array(
      z.object({
        id: z.string().min(1).max(MAX_ID_LENGTH).describe(eventsId),
        endpointId: z.string().min(1).max(MAX_ID_LENGTH).describe(eventsEndpointId),
        value: z.string().min(1).max(MAX_LONG_TEXT_LENGTH).describe(eventsValue),
      })
    )
    .max(MAX_INSIGHTS_ARRAY_SIZE);

const boundedDefendInsightRemediationSchema = () =>
  z.object({
    message: z.string().min(1).max(MAX_LONG_TEXT_LENGTH),
    link: z.string().min(1).max(MAX_URL_LENGTH),
  });

export function getDefendInsightsOutputSchema({ type }: { type: WorkflowInsightType }) {
  switch (type) {
    case WorkflowInsightType.enum.incompatible_antivirus:
      const antivirusPrompts = PROMPTS.INCOMPATIBLE_ANTIVIRUS;
      return z.object({
        insights: z
          .array(
            z.object({
              group: boundedDefendInsightGroupSchema().describe(antivirusPrompts.GROUP),
              events: boundedDefendInsightEventsSchema({
                eventsId: antivirusPrompts.EVENTS_ID,
                eventsEndpointId: antivirusPrompts.EVENTS_ENDPOINT_ID,
                eventsValue: antivirusPrompts.EVENTS_VALUE,
              }).describe(antivirusPrompts.EVENTS),
            })
          )
          .max(MAX_INSIGHTS_ARRAY_SIZE),
      });
    case WorkflowInsightType.enum.policy_response_failure:
      const policyResponsePrompts = PROMPTS.POLICY_RESPONSE_FAILURE;
      return z.object({
        insights: z
          .array(
            z.object({
              group: boundedDefendInsightGroupSchema().describe(policyResponsePrompts.GROUP),
              events: boundedDefendInsightEventsSchema({
                eventsId: policyResponsePrompts.EVENTS_ID,
                eventsEndpointId: policyResponsePrompts.EVENTS_ENDPOINT_ID,
                eventsValue: policyResponsePrompts.EVENTS_VALUE,
              }).describe(policyResponsePrompts.EVENTS),
              remediation: boundedDefendInsightRemediationSchema().describe(
                policyResponsePrompts.REMEDIATION ?? ''
              ),
            })
          )
          .max(MAX_INSIGHTS_ARRAY_SIZE),
      });
    default:
      const customPrompts = PROMPTS.CUSTOM;
      return z.object({
        insights: z
          .array(
            z.object({
              group: boundedDefendInsightGroupSchema().describe(customPrompts.GROUP),
              events: boundedDefendInsightEventsSchema({
                eventsId: customPrompts.EVENTS_ID,
                eventsEndpointId: customPrompts.EVENTS_ENDPOINT_ID,
                eventsValue: customPrompts.EVENTS_VALUE,
              }).describe(customPrompts.EVENTS),
              remediation: boundedDefendInsightRemediationSchema()
                .pick({ message: true })
                .describe(customPrompts.REMEDIATION ?? ''),
            })
          )
          .max(MAX_INSIGHTS_ARRAY_SIZE),
      });
  }
}
