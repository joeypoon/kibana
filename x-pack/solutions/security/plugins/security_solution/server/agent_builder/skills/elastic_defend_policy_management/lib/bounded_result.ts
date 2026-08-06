/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { estimateTokens } from '@kbn/agent-builder-genai-utils/tools/utils/token_count';

export const TOOL_RESULT_TOKEN_BUDGET = 20_000;

export const TOOL_RESULT_TOKEN_SAFETY_FACTOR = 0.75;
export const RESULT_TOKEN_BUDGET = Math.floor(
  TOOL_RESULT_TOKEN_BUDGET * TOOL_RESULT_TOKEN_SAFETY_FACTOR
);

export const MAX_INVENTORY_DESCRIPTION_CHARS = 512;
export const MAX_POLICY_DESCRIPTION_CHARS = 1_024;
export const MAX_SETTING_STRING_CHARS = 1_024;
export const MAX_DOCUMENTATION_CHARS = 768;
export const MAX_ASSESS_STRING_CHARS = 128;
export const MAX_ASSESS_DOCUMENTATION_CHARS = 192;
export const MAX_EXEMPLAR_STRING_CHARS = 256;

const WRAPPED_RESULT_ID_PLACEHOLDER = 'XXXXXX';

export const estimateResultTokens = (payload: unknown): number =>
  JSON.stringify(payload) === undefined ? 0 : estimateTokens(payload);

export const estimateWrappedHandlerTokens = (data: unknown): number =>
  estimateResultTokens({
    results: [
      {
        tool_result_id: WRAPPED_RESULT_ID_PLACEHOLDER,
        type: 'other',
        data,
      },
    ],
  });

interface BoundedList<TItem> {
  readonly items: readonly TItem[];
  readonly returned: number;
  readonly total: number;
  readonly truncated: boolean;
  readonly truncationNotice?: string;
}

interface BoundListOptions<TItem> {
  readonly items: readonly TItem[];
  readonly maxItems: number;
  readonly tokenBudget?: number;
  readonly envelopeTokens?: number;
  readonly continuation: string;
  readonly itemLabel: string;
}

export const boundList = <TItem>({
  items,
  maxItems,
  tokenBudget = RESULT_TOKEN_BUDGET,
  envelopeTokens = 0,
  continuation,
  itemLabel,
}: BoundListOptions<TItem>): BoundedList<TItem> => {
  const trueTotal = items.length;
  const itemTokenBudget = Math.max(tokenBudget - envelopeTokens, 0);
  const admitted: TItem[] = [];
  let usedTokens = 0;

  for (const item of items) {
    if (admitted.length >= maxItems) {
      break;
    }

    const itemTokens = estimateResultTokens(item);

    if (usedTokens + itemTokens > itemTokenBudget) {
      break;
    }

    admitted.push(item);
    usedTokens += itemTokens;
  }

  const returned = admitted.length;
  const truncated = returned < trueTotal;

  return {
    items: admitted,
    returned,
    total: trueTotal,
    truncated,
    ...(truncated
      ? {
          truncationNotice: buildTruncationNotice({
            returned,
            total: trueTotal,
            itemLabel,
            continuation,
          }),
        }
      : {}),
  };
};

interface TruncationNoticeOptions {
  readonly returned: number;
  readonly total: number;
  readonly itemLabel: string;
  readonly continuation: string;
}

export const buildTruncationNotice = ({
  returned,
  total,
  itemLabel,
  continuation,
}: TruncationNoticeOptions): string =>
  returned === 0
    ? `Showing 0 of ${total} ${itemLabel}. ${total} exist and were left out because even the first item exceeded the per-response size limit after long string fields were truncated — this is not an empty estate. ${continuation}`
    : `Showing ${returned} of ${total} ${itemLabel}. ${
        total - returned
      } were left out of this result to stay within the per-response size limit — they are not absent from your deployment. ${continuation}`;

export const isWithinPlatformBudget = (data: unknown): boolean =>
  estimateWrappedHandlerTokens(data) <= TOOL_RESULT_TOKEN_BUDGET;

export const isWithinResultBudget = (payload: unknown): boolean =>
  estimateResultTokens(payload) <= RESULT_TOKEN_BUDGET;

interface ResultBudgetNoticeOptions {
  readonly estimatedTokens: number;
}

export const buildResultBudgetNotice = ({ estimatedTokens }: ResultBudgetNoticeOptions): string =>
  `This result is larger than the ${TOOL_RESULT_TOKEN_BUDGET}-token platform size this skill bounds itself to (estimated ${estimatedTokens} wrapped tokens). Every list above is already trimmed and states its own total: rely on those totals, never on how many items you can see. Nothing was removed to produce this notice.`;

export const truncateBoundedString = (value: string, maxChars: number): string => {
  if (value.length <= maxChars) {
    return value;
  }

  const marker = `…[truncated; original ${value.length} chars]`;
  if (maxChars <= marker.length) {
    return marker.slice(0, Math.max(maxChars, 0));
  }

  return `${value.slice(0, maxChars - marker.length)}${marker}`;
};

export const truncateBoundedValue = (value: unknown, maxChars: number): unknown =>
  typeof value === 'string' ? truncateBoundedString(value, maxChars) : value;
