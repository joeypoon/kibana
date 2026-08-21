/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { uniq } from 'lodash';
import type { QueryDslQueryContainer } from '@elastic/elasticsearch/lib/api/types';

const IGNORED_ELASTIC_AGENT_IDS = [
  '00000000-0000-0000-0000-000000000000',
  '11111111-1111-1111-1111-111111111111',
];

export const UNITED_APPLY_STATE_ASSIGNMENT_FIELD = 'apply_state.applied_agent_policy_id';

export function buildUnitedApplyStateFilter(agentPolicyIds: string[]): QueryDslQueryContainer {
  const uniqueAgentPolicyIds = uniq(agentPolicyIds);
  if (uniqueAgentPolicyIds.length === 0) {
    return { match_none: {} };
  }

  return {
    bool: {
      must_not: { terms: { 'agent.id': IGNORED_ELASTIC_AGENT_IDS } },
      filter: [
        { exists: { field: 'united.endpoint.agent.id' } },
        { exists: { field: 'united.agent.agent.id' } },
        { term: { 'united.agent.active': { value: true } } },
        { terms: { [UNITED_APPLY_STATE_ASSIGNMENT_FIELD]: uniqueAgentPolicyIds } },
      ],
    },
  };
}
