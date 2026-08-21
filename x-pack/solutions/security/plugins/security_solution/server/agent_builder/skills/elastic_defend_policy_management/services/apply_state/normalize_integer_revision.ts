/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

const INTEGER_STRING_PATTERN = /^[+-]?\d+$/;

export const normalizeIntegerRevision = (value: unknown): number | undefined => {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      return undefined;
    }

    return value;
  }

  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();
  if (!INTEGER_STRING_PATTERN.test(trimmed)) {
    return undefined;
  }

  return Number.parseInt(trimmed, 10);
};
