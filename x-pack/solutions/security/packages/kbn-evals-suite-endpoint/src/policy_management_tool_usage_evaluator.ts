/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Client as EsClient } from '@elastic/elasticsearch';
import { createTraceBasedEvaluator, type Evaluator } from '@kbn/evals';
import type { ToolingLog } from '@kbn/tooling-log';

export const POLICY_MANAGEMENT_GET_POLICY_TOOL_ID = 'security.policy_management.get_policy';
export const POLICY_MANAGEMENT_GET_POLICY_FIELD_REFERENCE_TOOL_ID =
  'security.policy_management.get_policy_field_reference';
export const POLICY_MANAGEMENT_LIST_POLICIES_TOOL_ID = 'security.policy_management.list_policies';
export const POLICY_MANAGEMENT_COMPARE_POLICIES_TOOL_ID =
  'security.policy_management.compare_policies';
export const POLICY_MANAGEMENT_ASSESS_POLICY_CHANGE_TOOL_ID =
  'security.policy_management.assess_policy_change';
export const POLICY_MANAGEMENT_GET_POLICY_APPLY_STATE_TOOL_ID =
  'security.policy_management.get_policy_apply_state';

export const POLICY_MANAGEMENT_TOOL_USAGE_EVALUATOR_NAME = 'Policy Management Tool Usage';

export interface PolicyManagementToolUsageExpected {
  required_tools?: readonly string[];
  forbidden_tools?: readonly string[];
}

const asToolNames = (value: unknown): string[] => {
  if (typeof value === 'string' && value.length > 0) {
    return [value];
  }
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === 'string' && item.length > 0);
};

const toPassFailLabel = (score: number): 'pass' | 'fail' => (score === 1 ? 'pass' : 'fail');

export function createPolicyManagementToolUsageEvaluator({
  traceEsClient,
  log,
}: {
  traceEsClient: EsClient;
  log: ToolingLog;
}): Evaluator {
  return {
    name: POLICY_MANAGEMENT_TOOL_USAGE_EVALUATOR_NAME,
    kind: 'CODE',
    direction: 'maximize',
    evaluate: async (args) => {
      const expected = args.expected as PolicyManagementToolUsageExpected | undefined;
      const requiredTools = expected?.required_tools ?? [];
      const forbiddenTools = expected?.forbidden_tools ?? [];
      const requiredSet = new Set(requiredTools);
      const forbiddenSet = new Set(forbiddenTools);
      let previousTotalSpans: number | undefined;
      let shouldRetryForMissingRequiredTool = false;

      const inner = createTraceBasedEvaluator({
        traceEsClient,
        log,
        config: {
          name: POLICY_MANAGEMENT_TOOL_USAGE_EVALUATOR_NAME,
          direction: 'maximize',
          buildQuery: (traceId) => `FROM traces-*
| WHERE trace.id == "${traceId}"
| STATS
  total_spans = COUNT(*),
  tool_names = VALUES(attributes.gen_ai.tool.name)`,
          extractResult: (response) => {
            const totalSpansIndex = response.columns.findIndex(
              (column) => column.name === 'total_spans'
            );
            const toolNamesIndex = response.columns.findIndex(
              (column) => column.name === 'tool_names'
            );

            if (totalSpansIndex === -1 || toolNamesIndex === -1) {
              log.warning('Expected columns not found in policy-management tool-usage trace query');
              return null;
            }

            const row = response.values[0];
            const totalSpans = row?.[totalSpansIndex] as number | undefined;
            const toolNames = asToolNames(row?.[toolNamesIndex]);

            if (!totalSpans || toolNames.length === 0) {
              return null;
            }

            const observed = new Set(toolNames);
            const requiredMissing = [...requiredSet].some((toolId) => !observed.has(toolId));
            const forbiddenFound = [...forbiddenSet].some((toolId) => observed.has(toolId));

            const stillPropagating =
              previousTotalSpans === undefined || totalSpans > previousTotalSpans;
            previousTotalSpans = totalSpans;
            shouldRetryForMissingRequiredTool =
              requiredMissing && !forbiddenFound && stillPropagating;

            return requiredMissing || forbiddenFound ? 0 : 1;
          },
          isResultValid: (result) => result !== null && !shouldRetryForMissingRequiredTool,
        },
      });

      const result = await inner.evaluate(args);

      if (result.score === 0 || result.score === 1) {
        return {
          ...result,
          label: toPassFailLabel(result.score),
        };
      }

      if (result.label === 'error') {
        return result;
      }

      return {
        score: null,
        label: 'unavailable',
        explanation:
          result.explanation ??
          `No reachable tool spans for ${POLICY_MANAGEMENT_TOOL_USAGE_EVALUATOR_NAME}`,
        metadata: result.metadata,
      };
    },
  };
}
