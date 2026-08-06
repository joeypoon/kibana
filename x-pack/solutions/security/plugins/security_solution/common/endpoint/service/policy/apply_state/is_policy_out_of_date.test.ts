/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { HostInfo, HostMetadata } from '../../../types';
import { HostPolicyResponseActionStatus } from '../../../types';
import { isPolicyOutOfDate } from './is_policy_out_of_date';

type AppliedPolicy = HostMetadata['Endpoint']['policy']['applied'];
type CurrentPolicyInfo = NonNullable<HostInfo['policy_info']>;

const appliedPolicy = (overrides: Partial<AppliedPolicy> = {}): AppliedPolicy => ({
  id: 'endpoint-policy-1',
  status: HostPolicyResponseActionStatus.success,
  name: 'test policy',
  endpoint_policy_version: 3,
  version: 7,
  ...overrides,
});

const currentPolicyInfo = (overrides: Partial<CurrentPolicyInfo> = {}): CurrentPolicyInfo => ({
  agent: {
    configured: { id: 'agent-policy-1', revision: 7 },
    applied: { id: 'agent-policy-1', revision: 7 },
  },
  endpoint: { id: 'endpoint-policy-1', revision: 3 },
  ...overrides,
});

describe('isPolicyOutOfDate', () => {
  it('returns false when reported ids and revisions match the current ones', () => {
    expect(isPolicyOutOfDate(appliedPolicy(), currentPolicyInfo())).toBe(false);
  });

  it('returns false when reported revisions are ahead of the current ones', () => {
    expect(
      isPolicyOutOfDate(
        appliedPolicy({ version: 8, endpoint_policy_version: 4 }),
        currentPolicyInfo()
      )
    ).toBe(false);
  });

  it('returns false when the current policy info is missing', () => {
    expect(isPolicyOutOfDate(appliedPolicy(), undefined)).toBe(false);
  });

  it('returns false when the reported policy id is missing', () => {
    expect(isPolicyOutOfDate(appliedPolicy({ id: '' }), currentPolicyInfo())).toBe(false);
  });

  it('returns true when the endpoint package policy was reassigned', () => {
    expect(
      isPolicyOutOfDate(appliedPolicy({ id: 'endpoint-policy-other' }), currentPolicyInfo())
    ).toBe(true);
  });

  it('returns true when the agent policy was reassigned but not yet applied', () => {
    expect(
      isPolicyOutOfDate(
        appliedPolicy(),
        currentPolicyInfo({
          agent: {
            configured: { id: 'agent-policy-2', revision: 7 },
            applied: { id: 'agent-policy-1', revision: 7 },
          },
        })
      )
    ).toBe(true);
  });

  it('returns true when the reported agent version lags the applied agent revision', () => {
    expect(
      isPolicyOutOfDate(
        appliedPolicy({ version: 6 }),
        currentPolicyInfo({
          agent: {
            configured: { id: 'agent-policy-1', revision: 6 },
            applied: { id: 'agent-policy-1', revision: 7 },
          },
        })
      )
    ).toBe(true);
  });

  it('returns true when the reported agent version lags the configured agent revision', () => {
    expect(
      isPolicyOutOfDate(
        appliedPolicy({ version: 6 }),
        currentPolicyInfo({
          agent: {
            configured: { id: 'agent-policy-1', revision: 7 },
            applied: { id: 'agent-policy-1', revision: 6 },
          },
        })
      )
    ).toBe(true);
  });

  it('returns true when the reported endpoint revision lags the current endpoint revision', () => {
    expect(
      isPolicyOutOfDate(
        appliedPolicy({ endpoint_policy_version: 2 }),
        currentPolicyInfo({ endpoint: { id: 'endpoint-policy-1', revision: 3 } })
      )
    ).toBe(true);
  });
});
