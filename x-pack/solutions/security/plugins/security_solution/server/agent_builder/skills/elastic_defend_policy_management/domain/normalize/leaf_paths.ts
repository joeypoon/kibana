/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export const collectPolicyLeafPaths = (
  value: unknown,
  prefix = '',
  accumulator: Map<string, unknown> = new Map()
): Map<string, unknown> => {
  if (!isPlainRecord(value)) {
    if (prefix !== '') {
      accumulator.set(prefix, value);
    }

    return accumulator;
  }

  for (const [key, nested] of Object.entries(value)) {
    collectPolicyLeafPaths(nested, prefix === '' ? key : `${prefix}.${key}`, accumulator);
  }

  return accumulator;
};
