/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  CreateUpdateProtectionUpdatesNoteSchema,
  GetProtectionUpdatesNoteSchema,
} from '../../api/endpoint/protection_updates_note/protection_updates_note';
import { MAX_ID_LENGTH, MAX_NOTE_LENGTH } from './schema_bounds_constants';

// NOTE: Even though schemas are kept in common/api/endpoint - we keep tests here, because common/api should import from outside
describe('endpoint protection updates note schema', () => {
  const maxId = 'a'.repeat(MAX_ID_LENGTH);
  const overMaxId = 'a'.repeat(MAX_ID_LENGTH + 1);
  const maxNote = 'n'.repeat(MAX_NOTE_LENGTH);
  const overMaxNote = 'n'.repeat(MAX_NOTE_LENGTH + 1);

  describe('GetProtectionUpdatesNoteSchema', () => {
    it('should accept package_policy_id at max length', () => {
      expect(() =>
        GetProtectionUpdatesNoteSchema.params.validate({ package_policy_id: maxId })
      ).not.toThrow();
    });

    it('should reject package_policy_id over max length', () => {
      expect(() =>
        GetProtectionUpdatesNoteSchema.params.validate({ package_policy_id: overMaxId })
      ).toThrow();
    });
  });

  describe('CreateUpdateProtectionUpdatesNoteSchema', () => {
    it('should accept package_policy_id at max length', () => {
      expect(() =>
        CreateUpdateProtectionUpdatesNoteSchema.params.validate({ package_policy_id: maxId })
      ).not.toThrow();
    });

    it('should reject package_policy_id over max length', () => {
      expect(() =>
        CreateUpdateProtectionUpdatesNoteSchema.params.validate({ package_policy_id: overMaxId })
      ).toThrow();
    });

    it('should accept note at max length', () => {
      expect(() =>
        CreateUpdateProtectionUpdatesNoteSchema.body.validate({ note: maxNote })
      ).not.toThrow();
    });

    it('should reject note over max length', () => {
      expect(() =>
        CreateUpdateProtectionUpdatesNoteSchema.body.validate({ note: overMaxNote })
      ).toThrow();
    });
  });
});
