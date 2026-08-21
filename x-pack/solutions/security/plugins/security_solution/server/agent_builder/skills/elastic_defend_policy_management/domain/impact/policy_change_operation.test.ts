/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ProtectionModes } from '../../../../../../common/endpoint/types';
import {
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  POLICY_CHANGE_SCHEMA_MESSAGE,
  PolicyChangePreparationError,
  assessPolicyChangeParamsSchema,
  parseAssessPolicyChangeParams,
  policyChangeOperationSchema,
} from './policy_change_operation';

describe('policy change operation schema', () => {
  it('accepts each public operation variant', () => {
    expect(
      policyChangeOperationSchema.parse({
        op: 'set_protection_enabled',
        protection: 'malware',
        enabled: true,
      })
    ).toEqual({
      op: 'set_protection_enabled',
      protection: 'malware',
      enabled: true,
    });
    expect(
      policyChangeOperationSchema.parse({
        op: 'set_protection_level',
        protection: 'ransomware',
        mode: ProtectionModes.detect,
      })
    ).toEqual({
      op: 'set_protection_level',
      protection: 'ransomware',
      mode: ProtectionModes.detect,
    });
    expect(
      policyChangeOperationSchema.parse({
        op: 'set_field',
        path: 'windows.malware.mode',
        value: { nested: true },
      })
    ).toEqual({
      op: 'set_field',
      path: 'windows.malware.mode',
      value: { nested: true },
    });
  });

  it('forwards raw set_field values including non-boolean JSON types', () => {
    for (const value of [0, '', null, [], {}, 'prevent']) {
      expect(
        policyChangeOperationSchema.parse({
          op: 'set_field',
          path: 'linux.events.session_data',
          value,
        })
      ).toEqual({
        op: 'set_field',
        path: 'linux.events.session_data',
        value,
      });
    }
  });

  it('rejects unknown ops, extra keys, and unbounded identifiers', () => {
    expect(() =>
      policyChangeOperationSchema.parse({
        op: 'apply_change',
        path: 'windows.malware.mode',
        value: true,
      })
    ).toThrow();
    expect(() =>
      policyChangeOperationSchema.parse({
        op: 'set_field',
        path: 'windows.malware.mode',
        value: true,
        extra: true,
      })
    ).toThrow();
    expect(() =>
      assessPolicyChangeParamsSchema.parse({
        idOrName: '',
        changes: [{ op: 'set_field', path: 'windows.malware.mode', value: true }],
      })
    ).toThrow();
    expect(() =>
      assessPolicyChangeParamsSchema.parse({
        idOrName: 'p',
        changes: [],
      })
    ).toThrow();
    expect(() =>
      assessPolicyChangeParamsSchema.parse({
        idOrName: 'p',
        changes: Array.from({ length: 51 }, () => ({
          op: 'set_field',
          path: 'windows.malware.mode',
          value: true,
        })),
      })
    ).toThrow();
  });

  it('parses a bounded request and uses a stable invalid_input code', () => {
    expect(
      parseAssessPolicyChangeParams({
        idOrName: ' policy-1 ',
        changes: [{ op: 'set_field', path: 'windows.malware.mode', value: 1 }],
      })
    ).toEqual({
      idOrName: 'policy-1',
      changes: [{ op: 'set_field', path: 'windows.malware.mode', value: 1 }],
    });

    try {
      parseAssessPolicyChangeParams({ idOrName: 'p' });
      throw new Error('expected parse to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyChangePreparationError);
      expect((error as PolicyChangePreparationError).code).toBe(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input
      );
      expect((error as PolicyChangePreparationError).message).toBe(POLICY_CHANGE_SCHEMA_MESSAGE);
    }
  });

});
