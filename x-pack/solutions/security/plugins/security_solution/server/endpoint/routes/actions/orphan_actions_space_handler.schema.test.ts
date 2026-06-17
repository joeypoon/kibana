/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';

import { UpdateOrphanActionsSpaceSchema } from './orphan_actions_space_handler';
import { MAX_SPACE_ID_LENGTH } from '../../../../common/endpoint/schema/schema_bounds_constants';

describe('UpdateOrphanActionsSpaceSchema', () => {
  const validateBody = (body: Record<string, unknown>) =>
    schema.object(UpdateOrphanActionsSpaceSchema).validate({ body });

  it('accepts a valid space id', () => {
    expect(() => validateBody({ spaceId: 'default' })).not.toThrow();
  });

  it('rejects space ids longer than 1024 characters', () => {
    expect(() => validateBody({ spaceId: 'a'.repeat(MAX_SPACE_ID_LENGTH + 1) })).toThrow();
  });
});
