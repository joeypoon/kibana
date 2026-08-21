/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { normalizeIntegerRevision } from './normalize_integer_revision';

describe('normalizeIntegerRevision', () => {
  it.each([
    ['integer number', 3, 3],
    ['zero', 0, 0],
    ['negative integer', -1, -1],
    ['integer string', '3', 3],
    ['trimmed integer string', ' 3 ', 3],
    ['plus-signed integer string', '+3', 3],
    ['negative integer string', '-1', -1],
    ['leading-zero integer string', '03', 3],
  ])('accepts %s', (_label, value, expected) => {
    expect(normalizeIntegerRevision(value)).toBe(expected);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['empty string', ''],
    ['whitespace', '  '],
    ['float string', '2.0'],
    ['fractional string', '2.5'],
    ['scientific string', '1e2'],
    ['invalid string', 'abc'],
    ['boolean true', true],
    ['boolean false', false],
    ['object', { revision: 3 }],
    ['array', [3]],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['non-integer number', 2.5],
  ])('rejects %s', (_label, value) => {
    expect(normalizeIntegerRevision(value)).toBeUndefined();
  });
});
