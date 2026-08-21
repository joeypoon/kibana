/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  buildUnitedApplyStateFilter,
  UNITED_APPLY_STATE_ASSIGNMENT_FIELD,
} from './united_apply_state_filter';

describe('buildUnitedApplyStateFilter', () => {
  const ignoredAgentIds = [
    '00000000-0000-0000-0000-000000000000',
    '11111111-1111-1111-1111-111111111111',
  ];

  it('returns match_none when agentPolicyIds is empty', () => {
    expect(buildUnitedApplyStateFilter([])).toEqual({ match_none: {} });
  });

  it('admits exact assignment ids on the runtime membership field', () => {
    expect(buildUnitedApplyStateFilter(['base'])).toEqual({
      bool: {
        must_not: { terms: { 'agent.id': ignoredAgentIds } },
        filter: [
          { exists: { field: 'united.endpoint.agent.id' } },
          { exists: { field: 'united.agent.agent.id' } },
          { term: { 'united.agent.active': { value: true } } },
          { terms: { [UNITED_APPLY_STATE_ASSIGNMENT_FIELD]: ['base'] } },
        ],
      },
    });
  });

  it('deduplicates assignment ids and does not emit suffix wildcards', () => {
    const result = buildUnitedApplyStateFilter(['base', 'other', 'base']);
    const serialized = JSON.stringify(result);

    expect(result).toEqual({
      bool: {
        must_not: { terms: { 'agent.id': ignoredAgentIds } },
        filter: [
          { exists: { field: 'united.endpoint.agent.id' } },
          { exists: { field: 'united.agent.agent.id' } },
          { term: { 'united.agent.active': { value: true } } },
          { terms: { [UNITED_APPLY_STATE_ASSIGNMENT_FIELD]: ['base', 'other'] } },
        ],
      },
    });
    expect(serialized).not.toContain('#*');
    expect(serialized).not.toContain('wildcard');
  });

  it('uses the runtime assignment field so suffix and _source base membership stay query-side', () => {
    const serialized = JSON.stringify(buildUnitedApplyStateFilter(['base']));

    expect(serialized).toContain(UNITED_APPLY_STATE_ASSIGNMENT_FIELD);
    expect(serialized).not.toContain('united.agent.policy_id');
    expect(serialized).not.toContain('united.agent.policy_base_id');
    expect(serialized).not.toContain('applied.id');
  });

  it('does not include other-policy assignment ids', () => {
    const serialized = JSON.stringify(buildUnitedApplyStateFilter(['base']));

    expect(serialized).toContain('"base"');
    expect(serialized).not.toContain('other');
  });

  it('keeps the root agent.id ignore list and does not query .fleet-agents', () => {
    const serialized = JSON.stringify(buildUnitedApplyStateFilter(['base']));

    expect(serialized).toContain('00000000-0000-0000-0000-000000000000');
    expect(serialized).toContain('11111111-1111-1111-1111-111111111111');
    expect(serialized).not.toContain('.fleet-agents');
    expect(serialized).not.toContain('united.agent.namespaces');
  });
});
