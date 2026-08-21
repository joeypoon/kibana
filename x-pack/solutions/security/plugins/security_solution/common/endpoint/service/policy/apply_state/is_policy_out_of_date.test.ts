/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { HostPolicyResponseActionStatus } from '../../../types';
import type { HostInfo, HostMetadata } from '../../../types';
import { isPolicyOutOfDate } from './is_policy_out_of_date';

type Reported = HostMetadata['Endpoint']['policy']['applied'];
type Current = NonNullable<HostInfo['policy_info']>;

const createReported = (overrides: Partial<Reported> = {}): Reported => ({
  id: 'endpoint-policy-id',
  status: HostPolicyResponseActionStatus.success,
  name: 'policy',
  endpoint_policy_version: 3,
  version: 5,
  ...overrides,
});

const createCurrent = ({
  endpointId = 'endpoint-policy-id',
  endpointRevision = 3,
  configuredId = 'agent-policy-id',
  configuredRevision = 5,
  appliedId = 'agent-policy-id',
  appliedRevision = 5,
}: {
  endpointId?: string;
  endpointRevision?: number;
  configuredId?: string;
  configuredRevision?: number;
  appliedId?: string;
  appliedRevision?: number;
} = {}): Current => ({
  agent: {
    configured: { id: configuredId, revision: configuredRevision },
    applied: { id: appliedId, revision: appliedRevision },
  },
  endpoint: { id: endpointId, revision: endpointRevision },
});

const createReportedWithOmittedRevision = (
  field: 'version' | 'endpoint_policy_version'
): Reported => {
  const { [field]: _omitted, ...rest } = createReported();
  return rest as unknown as Reported;
};

describe('isPolicyOutOfDate', () => {
  it.each([
    {
      name: 'missing current policy info',
      reported: createReported(),
      current: undefined,
      expected: false,
    },
    {
      name: 'missing reported id',
      reported: createReported({ id: '' }),
      current: createCurrent(),
      expected: false,
    },
    {
      name: 'all clauses hold',
      reported: createReported(),
      current: createCurrent(),
      expected: false,
    },
    {
      name: 'reported id does not match endpoint id',
      reported: createReported(),
      current: createCurrent({ endpointId: 'other-endpoint-policy-id' }),
      expected: true,
    },
    {
      name: 'configured agent policy id does not match applied id',
      reported: createReported(),
      current: createCurrent({ configuredId: 'other-agent-policy-id' }),
      expected: true,
    },
    {
      name: 'reported version is less than applied agent revision',
      reported: createReported({ version: 4 }),
      current: createCurrent({ appliedRevision: 5, configuredRevision: 4 }),
      expected: true,
    },
    {
      name: 'reported version is less than configured agent revision',
      reported: createReported({ version: 4 }),
      current: createCurrent({ configuredRevision: 5, appliedRevision: 4 }),
      expected: true,
    },
    {
      name: 'reported endpoint policy version is less than endpoint revision',
      reported: createReported({ endpoint_policy_version: 2 }),
      current: createCurrent({ endpointRevision: 3 }),
      expected: true,
    },
    {
      name: 'reported revisions equal current revisions',
      reported: createReported({ version: 5, endpoint_policy_version: 3 }),
      current: createCurrent({ appliedRevision: 5, configuredRevision: 5, endpointRevision: 3 }),
      expected: false,
    },
    {
      name: 'reported revisions are greater than current revisions',
      reported: createReported({ version: 7, endpoint_policy_version: 4 }),
      current: createCurrent({ appliedRevision: 5, configuredRevision: 5, endpointRevision: 3 }),
      expected: false,
    },
    {
      name: 'missing reported version with present id',
      reported: createReportedWithOmittedRevision('version'),
      current: createCurrent(),
      expected: true,
    },
    {
      name: 'missing reported endpoint policy version with present id',
      reported: createReportedWithOmittedRevision('endpoint_policy_version'),
      current: createCurrent(),
      expected: true,
    },
  ])('returns $expected when $name', ({ reported, current, expected }) => {
    expect(isPolicyOutOfDate(reported, current)).toBe(expected);
  });
});
