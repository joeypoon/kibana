/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { normalize } from '../normalize';
import { diffPolicyConfig } from './diff_policy_config';

describe('diffPolicyConfig', () => {
  it('emits a leaf row when popup enabled differs', () => {
    const left = policyFactory();
    const right = policyFactory();
    right.windows.popup.malware.enabled = !left.windows.popup.malware.enabled;

    expect(diffPolicyConfig(normalize(left), normalize(right))).toEqual([
      {
        path: 'windows.popup.malware.enabled',
        from: left.windows.popup.malware.enabled,
        to: right.windows.popup.malware.enabled,
      },
    ]);
  });

  it('emits one row when a key exists on only one side', () => {
    const left = policyFactory();
    const right = policyFactory();
    right.linux.advanced = { ...(right.linux.advanced ?? {}), extra: 'only-right' };

    expect(diffPolicyConfig(normalize(left), normalize(right))).toEqual([
      {
        path: 'linux.advanced.extra',
        from: undefined,
        to: 'only-right',
      },
    ]);
  });

  it('emits a left-only row when a key exists only on the left side', () => {
    const left = policyFactory();
    left.linux.advanced = { ...(left.linux.advanced ?? {}), extra: 'only-left' };
    const right = policyFactory();

    expect(diffPolicyConfig(normalize(left), normalize(right))).toEqual([
      {
        path: 'linux.advanced.extra',
        from: 'only-left',
        to: undefined,
      },
    ]);
  });
});
