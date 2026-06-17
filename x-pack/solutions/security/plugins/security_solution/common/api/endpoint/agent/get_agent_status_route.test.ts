/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { EndpointAgentStatusRequestSchema } from './get_agent_status_route';
import { MAX_ID_LENGTH } from '../../../endpoint/schema/schema_bounds_constants';

describe('Agent status api route schema', () => {
  it('should optionally accept `agentType`', () => {
    expect(() =>
      EndpointAgentStatusRequestSchema.query.validate({
        agentIds: '1',
      })
    ).not.toThrow();
  });

  it('should error if unknown `agentType` is used', () => {
    expect(() =>
      EndpointAgentStatusRequestSchema.query.validate({
        agentIds: '1',
        agentType: 'foo',
      })
    ).toThrow(/\[agentType]: types that failed validation/);
  });

  it.each([
    ['string with spaces only', { agentIds: '  ' }],
    ['empty string', { agentIds: '' }],
    ['array with empty strings', { agentIds: [' ', ''] }],
    ['agentIds not defined', {}],
    ['agentIds is empty array', { agentIds: [] }],
    [
      'more than 50 agentIds',
      { agentIds: Array.from({ length: 51 }, () => Math.random().toString(32)) },
    ],
  ])('should error if %s are used for `agentIds`', (_, validateOptions) => {
    expect(() => EndpointAgentStatusRequestSchema.query.validate(validateOptions)).toThrow(
      /\[agentIds]:/
    );
  });

  it.each([
    ['single string value', 'one'],
    ['array of strings', ['one', 'two']],
  ])('should accept %s of `agentIds`', (_, agentIdsValue) => {
    expect(() =>
      EndpointAgentStatusRequestSchema.query.validate({
        agentIds: agentIdsValue,
      })
    ).not.toThrow();
  });

  it('should error if an `agentIds` value exceeds the max length', () => {
    expect(() =>
      EndpointAgentStatusRequestSchema.query.validate({
        agentIds: 'a'.repeat(MAX_ID_LENGTH + 1),
      })
    ).toThrow(/\[agentIds]:/);
  });

  it('should accept `agentIds` at exactly max length', () => {
    expect(() =>
      EndpointAgentStatusRequestSchema.query.validate({
        agentIds: 'a'.repeat(MAX_ID_LENGTH),
      })
    ).not.toThrow();
  });
});
