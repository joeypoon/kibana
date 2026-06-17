/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { GetPolicyResponseSchema } from '../../api/endpoint/policy/policy_response';
import { MAX_ID_LENGTH } from './schema_bounds_constants';

// NOTE: Even though schemas are kept in common/api/endpoint - we keep tests here, because common/api should import from outside
describe('endpoint policy response schema', () => {
  describe('GetPolicyResponseSchema', () => {
    const query = GetPolicyResponseSchema.query;
    const maxId = 'a'.repeat(MAX_ID_LENGTH);
    const overMaxId = 'a'.repeat(MAX_ID_LENGTH + 1);

    it('should accept agentId at max length', () => {
      expect(() => query.validate({ agentId: maxId })).not.toThrow();
    });

    it('should reject agentId over max length', () => {
      expect(() => query.validate({ agentId: overMaxId })).toThrow();
    });
  });
});
