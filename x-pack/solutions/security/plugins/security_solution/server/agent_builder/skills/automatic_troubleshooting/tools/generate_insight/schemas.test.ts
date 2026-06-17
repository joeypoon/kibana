/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { expectParseError, expectParseSuccess } from '@kbn/zod-helpers/v4';

import {
  MAX_ID_LENGTH,
  MAX_INSIGHTS_ARRAY_SIZE,
  MAX_LONG_TEXT_LENGTH,
  MAX_URL_LENGTH,
} from '../../../../../../common/endpoint/schema/schema_bounds_constants';
import { WorkflowInsightType } from '../../../../../../common/endpoint/types/workflow_insights';
import { getDefendInsightsOutputSchema } from './schemas';

const repeatChar = (length: number, char = 'a'): string => char.repeat(length);

const getBoundaryEvent = () => ({
  id: repeatChar(MAX_ID_LENGTH),
  endpointId: repeatChar(MAX_ID_LENGTH),
  value: repeatChar(MAX_LONG_TEXT_LENGTH),
});

const getBoundaryInsightForType = (type: WorkflowInsightType) => {
  const insight = {
    group: repeatChar(MAX_LONG_TEXT_LENGTH),
    events: Array.from({ length: MAX_INSIGHTS_ARRAY_SIZE }, () => getBoundaryEvent()),
  };

  if (type === WorkflowInsightType.enum.policy_response_failure) {
    return {
      ...insight,
      remediation: {
        message: repeatChar(MAX_LONG_TEXT_LENGTH),
        link: repeatChar(MAX_URL_LENGTH),
      },
    };
  }

  if (type === WorkflowInsightType.enum.custom) {
    return {
      ...insight,
      remediation: {
        message: repeatChar(MAX_LONG_TEXT_LENGTH),
      },
    };
  }

  return insight;
};

const insightTypes = [
  WorkflowInsightType.enum.incompatible_antivirus,
  WorkflowInsightType.enum.policy_response_failure,
  WorkflowInsightType.enum.custom,
] as const;

describe('getDefendInsightsOutputSchema bounds', () => {
  describe.each(insightTypes)('%s', (type) => {
    const schema = getDefendInsightsOutputSchema({ type });

    it('accepts insights array at the upper bound', () => {
      const result = schema.safeParse({
        insights: Array.from({ length: MAX_INSIGHTS_ARRAY_SIZE }, () =>
          getBoundaryInsightForType(type)
        ),
      });
      expectParseSuccess(result);
    });

    it('rejects insights array above the upper bound', () => {
      const result = schema.safeParse({
        insights: Array.from({ length: MAX_INSIGHTS_ARRAY_SIZE + 1 }, () =>
          getBoundaryInsightForType(type)
        ),
      });
      expectParseError(result);
    });

    it('accepts nested events array at the upper bound', () => {
      const result = schema.safeParse({
        insights: [getBoundaryInsightForType(type)],
      });
      expectParseSuccess(result);
    });

    it('rejects nested events array above the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.events = Array.from({ length: MAX_INSIGHTS_ARRAY_SIZE + 1 }, () => ({
        id: 'event-id',
        endpointId: 'endpoint-id',
        value: 'event value',
      }));

      const result = schema.safeParse({ insights: [insight] });
      expectParseError(result);
    });

    it('accepts group text at the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.group = repeatChar(MAX_LONG_TEXT_LENGTH);

      const result = schema.safeParse({ insights: [insight] });
      expectParseSuccess(result);
    });

    it('rejects group text above the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.group = repeatChar(MAX_LONG_TEXT_LENGTH + 1);

      const result = schema.safeParse({ insights: [insight] });
      expectParseError(result);
    });

    it('accepts event id at the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.events[0].id = repeatChar(MAX_ID_LENGTH);

      const result = schema.safeParse({ insights: [insight] });
      expectParseSuccess(result);
    });

    it('rejects event id above the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.events[0].id = repeatChar(MAX_ID_LENGTH + 1);

      const result = schema.safeParse({ insights: [insight] });
      expectParseError(result);
    });

    it('accepts event endpointId at the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.events[0].endpointId = repeatChar(MAX_ID_LENGTH);

      const result = schema.safeParse({ insights: [insight] });
      expectParseSuccess(result);
    });

    it('rejects event endpointId above the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.events[0].endpointId = repeatChar(MAX_ID_LENGTH + 1);

      const result = schema.safeParse({ insights: [insight] });
      expectParseError(result);
    });

    it('accepts event value at the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.events[0].value = repeatChar(MAX_LONG_TEXT_LENGTH);

      const result = schema.safeParse({ insights: [insight] });
      expectParseSuccess(result);
    });

    it('rejects event value above the upper bound', () => {
      const insight = getBoundaryInsightForType(type);
      insight.events[0].value = repeatChar(MAX_LONG_TEXT_LENGTH + 1);

      const result = schema.safeParse({ insights: [insight] });
      expectParseError(result);
    });
  });

  describe('policy_response_failure remediation', () => {
    const schema = getDefendInsightsOutputSchema({
      type: WorkflowInsightType.enum.policy_response_failure,
    });

    it('accepts remediation message and link at the upper bound', () => {
      const result = schema.safeParse({
        insights: [
          {
            group: 'test group',
            events: [{ id: 'e1', endpointId: 'ep1', value: 'event value' }],
            remediation: {
              message: repeatChar(MAX_LONG_TEXT_LENGTH),
              link: repeatChar(MAX_URL_LENGTH),
            },
          },
        ],
      });
      expectParseSuccess(result);
    });

    it('rejects remediation message above the upper bound', () => {
      const result = schema.safeParse({
        insights: [
          {
            group: 'test group',
            events: [{ id: 'e1', endpointId: 'ep1', value: 'event value' }],
            remediation: {
              message: repeatChar(MAX_LONG_TEXT_LENGTH + 1),
              link: 'https://example.com',
            },
          },
        ],
      });
      expectParseError(result);
    });

    it('rejects remediation link above the upper bound', () => {
      const result = schema.safeParse({
        insights: [
          {
            group: 'test group',
            events: [{ id: 'e1', endpointId: 'ep1', value: 'event value' }],
            remediation: {
              message: 'fix it',
              link: repeatChar(MAX_URL_LENGTH + 1),
            },
          },
        ],
      });
      expectParseError(result);
    });

    it('requires remediation link', () => {
      const result = schema.safeParse({
        insights: [
          {
            group: 'test group',
            events: [{ id: 'e1', endpointId: 'ep1', value: 'event value' }],
            remediation: {
              message: 'fix it',
            },
          },
        ],
      });
      expectParseError(result);
    });
  });

  describe('custom remediation', () => {
    const schema = getDefendInsightsOutputSchema({ type: WorkflowInsightType.enum.custom });

    it('accepts remediation message at the upper bound', () => {
      const result = schema.safeParse({
        insights: [
          {
            group: 'test group',
            events: [{ id: 'e1', endpointId: 'ep1', value: 'event value' }],
            remediation: {
              message: repeatChar(MAX_LONG_TEXT_LENGTH),
            },
          },
        ],
      });
      expectParseSuccess(result);
    });

    it('rejects remediation message above the upper bound', () => {
      const result = schema.safeParse({
        insights: [
          {
            group: 'test group',
            events: [{ id: 'e1', endpointId: 'ep1', value: 'event value' }],
            remediation: {
              message: repeatChar(MAX_LONG_TEXT_LENGTH + 1),
            },
          },
        ],
      });
      expectParseError(result);
    });
  });
});
