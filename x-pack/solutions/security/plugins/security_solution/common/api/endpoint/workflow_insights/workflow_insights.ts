/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema, type TypeOf, type Type } from '@kbn/config-schema';

import {
  WORKFLOW_INSIGHT_TYPE_VALUES,
  WORKFLOW_INSIGHT_CATEGORY_VALUES,
  WORKFLOW_INSIGHT_SOURCE_TYPE_VALUES,
  WORKFLOW_INSIGHT_TARGET_TYPE_VALUES,
  WORKFLOW_INSIGHT_ACTION_TYPE_VALUES,
} from '../../../endpoint/types/workflow_insights';
import type { WorkflowInsightType } from '../../../endpoint/types/workflow_insights';
import {
  MAX_DATE_STRING_LENGTH,
  MAX_DESCRIPTION_LENGTH,
  MAX_FIELD_NAME_LENGTH,
  MAX_ID_LENGTH,
  MAX_LONG_TEXT_LENGTH,
  MAX_METADATA_NOTES_KEYS,
  MAX_NAME_LENGTH,
  MAX_SCRIPT_TAG_LENGTH,
  MAX_URL_LENGTH,
  MAX_USERNAME_LENGTH,
  MAX_WORKFLOW_INSIGHTS_PAGE_SIZE,
} from '../../../endpoint/schema/schema_bounds_constants';

const boundedNonEmptyString = (field: string, maxLength: number) =>
  schema.string({
    minLength: 1,
    maxLength,
    validate: (value) => {
      if (value.trim() === '') {
        return `${field} cannot be an empty string`;
      }
    },
  });

const arrayWithNonEmptyString = (
  field: string,
  options: { maxSize: number },
  maxLength: number = MAX_ID_LENGTH
) => schema.arrayOf(boundedNonEmptyString(field, maxLength), options);

const boundedDateString = () => schema.string({ maxLength: MAX_DATE_STRING_LENGTH });

const boundedNotesRecord = () =>
  schema.recordOf(
    schema.string({ maxLength: MAX_USERNAME_LENGTH }),
    schema.string({ maxLength: MAX_USERNAME_LENGTH }),
    {
      validate: (record) => {
        if (Object.keys(record).length > MAX_METADATA_NOTES_KEYS) {
          return `notes cannot have more than ${MAX_METADATA_NOTES_KEYS} keys`;
        }
      },
    }
  );

const workflowInsightExceptionListEntrySchema = schema.object(
  {
    field: schema.maybe(schema.string({ maxLength: MAX_FIELD_NAME_LENGTH })),
    operator: schema.maybe(schema.string({ maxLength: MAX_NAME_LENGTH })),
    type: schema.maybe(schema.string({ maxLength: MAX_NAME_LENGTH })),
    value: schema.maybe(
      schema.oneOf([
        schema.string({ maxLength: MAX_LONG_TEXT_LENGTH }),
        schema.arrayOf(schema.string({ maxLength: MAX_LONG_TEXT_LENGTH }), { maxSize: 2000 }),
      ])
    ),
  },
  { unknowns: 'ignore' }
);

const schemaOneOfValues = (values: readonly string[]) =>
  schema.oneOf(values.map((v) => schema.literal(v)) as [Type<string>]);

const insightTypeOneOf = schemaOneOfValues(WORKFLOW_INSIGHT_TYPE_VALUES);
const categoryOneOf = schemaOneOfValues(WORKFLOW_INSIGHT_CATEGORY_VALUES);
const sourceTypeOneOf = schemaOneOfValues(WORKFLOW_INSIGHT_SOURCE_TYPE_VALUES);
const targetTypeOneOf = schemaOneOfValues(WORKFLOW_INSIGHT_TARGET_TYPE_VALUES);
const actionTypeOneOf = schemaOneOfValues(WORKFLOW_INSIGHT_ACTION_TYPE_VALUES);

export const UpdateWorkflowInsightRequestSchema = {
  params: schema.object({
    insightId: boundedNonEmptyString('insightId', MAX_ID_LENGTH),
  }),
  body: schema.object({
    '@timestamp': schema.maybe(boundedDateString()),
    message: schema.maybe(schema.string({ maxLength: MAX_LONG_TEXT_LENGTH })),
    category: schema.maybe(categoryOneOf),
    type: schema.maybe(insightTypeOneOf),
    source: schema.maybe(
      schema.object({
        type: schema.maybe(sourceTypeOneOf),
        id: schema.maybe(boundedNonEmptyString('source.id', MAX_ID_LENGTH)),
        data_range_start: schema.maybe(boundedDateString()),
        data_range_end: schema.maybe(boundedDateString()),
      })
    ),
    target: schema.maybe(
      schema.object({
        type: schema.maybe(targetTypeOneOf),
        ids: schema.maybe(arrayWithNonEmptyString('target.id', { maxSize: 50 })),
      })
    ),
    action: schema.maybe(
      schema.object({
        type: schema.maybe(actionTypeOneOf),
        timestamp: schema.maybe(boundedDateString()),
      })
    ),
    value: schema.maybe(schema.string({ maxLength: MAX_LONG_TEXT_LENGTH })),
    remediation: schema.maybe(
      schema.object({
        exception_list_items: schema.maybe(
          schema.arrayOf(
            schema.object({
              list_id: schema.maybe(boundedNonEmptyString('list_id', MAX_ID_LENGTH)),
              name: schema.maybe(schema.string({ maxLength: MAX_NAME_LENGTH })),
              description: schema.maybe(schema.string({ maxLength: MAX_DESCRIPTION_LENGTH })),
              entries: schema.maybe(
                schema.arrayOf(workflowInsightExceptionListEntrySchema, { maxSize: 250 })
              ),
              tags: schema.maybe(arrayWithNonEmptyString('tag', { maxSize: 50 }, MAX_NAME_LENGTH)),
              os_types: schema.maybe(
                arrayWithNonEmptyString('os_type', { maxSize: 20 }, MAX_SCRIPT_TAG_LENGTH)
              ),
            }),
            { maxSize: 100 }
          )
        ),
        descriptive: schema.maybe(schema.string({ maxLength: MAX_LONG_TEXT_LENGTH })),
        link: schema.maybe(schema.string({ maxLength: MAX_URL_LENGTH })),
      })
    ),
    metadata: schema.maybe(
      schema.object({
        notes: schema.maybe(boundedNotesRecord()),
        message_variables: schema.maybe(
          arrayWithNonEmptyString('message_variable', { maxSize: 50 }, MAX_NAME_LENGTH)
        ),
      })
    ),
  }),
};

export const GetWorkflowInsightsRequestSchema = {
  query: schema.object({
    size: schema.maybe(schema.number({ min: 0, max: MAX_WORKFLOW_INSIGHTS_PAGE_SIZE })),
    from: schema.maybe(schema.number({ min: 0 })),
    ids: schema.maybe(arrayWithNonEmptyString('ids', { maxSize: 50 })),
    categories: schema.maybe(schema.arrayOf(categoryOneOf, { maxSize: 20 })),
    types: schema.maybe(schema.arrayOf(insightTypeOneOf, { maxSize: 20 })),
    sourceTypes: schema.maybe(schema.arrayOf(sourceTypeOneOf, { maxSize: 20 })),
    sourceIds: schema.maybe(arrayWithNonEmptyString('sourceId', { maxSize: 50 })),
    targetTypes: schema.maybe(schema.arrayOf(targetTypeOneOf, { maxSize: 20 })),
    targetIds: schema.maybe(arrayWithNonEmptyString('targetId', { maxSize: 50 })),
    actionTypes: schema.maybe(schema.arrayOf(actionTypeOneOf, { maxSize: 20 })),
  }),
};

export const CreateWorkflowInsightRequestSchema = {
  body: schema.object({
    insightTypes: schema.arrayOf(insightTypeOneOf, { maxSize: 10 }),
    endpointIds: arrayWithNonEmptyString('endpointId', { maxSize: 50 }),
    connectorId: schema.maybe(boundedNonEmptyString('connectorId', MAX_ID_LENGTH)),
  }),
};

export const GetPendingInsightsRequestSchema = {
  query: schema.object({
    insightTypes: schema.maybe(schema.arrayOf(insightTypeOneOf, { maxSize: 10 })),
    endpointIds: schema.maybe(arrayWithNonEmptyString('endpointId', { maxSize: 50 })),
  }),
};

export type GetWorkflowInsightsRequestQueryParams = TypeOf<
  typeof GetWorkflowInsightsRequestSchema.query
>;

export type UpdateWorkflowInsightsRequestParams = TypeOf<
  typeof UpdateWorkflowInsightRequestSchema.params
>;
export type UpdateWorkflowInsightsRequestBody = TypeOf<
  typeof UpdateWorkflowInsightRequestSchema.body
>;

export interface CreateWorkflowInsightRequestBody {
  insightTypes: WorkflowInsightType[];
  endpointIds: string[];
  connectorId?: string;
}

export type GetPendingInsightsRequestQueryParams = TypeOf<
  typeof GetPendingInsightsRequestSchema.query
>;

export interface GetPendingWorkflowInsightsResponse {
  pending: Array<{
    executionId: string;
    status: string;
    conversationId?: string;
    insightType?: string;
    endpointId?: string;
    '@timestamp': string;
    failureReason?: string;
  }>;
}

export interface CreateWorkflowInsightResponse {
  executions: Array<{
    executionId: string;
    conversationId?: string;
    insightType: string;
    endpointId?: string;
    '@timestamp'?: string;
  }>;
  failures?: Array<{
    insightType: string;
    endpointId: string;
    error: string;
  }>;
}
