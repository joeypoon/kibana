/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import type { KibanaRequest, StartServicesAccessor } from '@kbn/core/server';
import { z } from '@kbn/zod/v4';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import type { HasAtLeast } from '../services/access_context';
import type { ApplyStateDto } from '../services/read_apply_state';
import { readApplyState } from '../services/read_apply_state';
import { createPolicyTool } from './create_policy_tool';
import { presentBoundedIdentityStrings, presentWithinGuardedBudget } from './trim_policy_result';

export const GET_POLICY_APPLY_STATE_TOOL_ID = 'security.policy_management.get_policy_apply_state';

const IDENTIFIER_MAX_LENGTH = 256;
const GET_POLICY_APPLY_STATE_MAX_RESULT_TOKENS = 8_000;

export const getPolicyApplyStateSchema = z.object({
  idOrName: z
    .string()
    .trim()
    .min(1)
    .max(IDENTIFIER_MAX_LENGTH)
    .describe(
      'Saved-object id or exact endpoint policy name in the current space (1–256 characters after trim).'
    ),
});

type PresentedApplyStatePolicy = ApplyStateDto['policy'] &
  Partial<Record<'id_string_truncated' | 'name_string_truncated', true>>;

const presentApplyStatePolicy = (policy: ApplyStateDto['policy']): PresentedApplyStatePolicy => {
  const presented = presentBoundedIdentityStrings({
    id: policy.id,
    name: policy.name,
    description: '',
    revision: policy.revision,
    version: '',
  });

  return {
    id: presented.id,
    name: presented.name,
    revision: presented.revision,
    ...(presented.id_string_truncated === true ? { id_string_truncated: true as const } : {}),
    ...(presented.name_string_truncated === true ? { name_string_truncated: true as const } : {}),
  };
};

const presentApplyState = (dto: ApplyStateDto) => {
  const presented = {
    ...dto,
    policy: presentApplyStatePolicy(dto.policy),
  };

  return presentWithinGuardedBudget(
    () => presented,
    GET_POLICY_APPLY_STATE_MAX_RESULT_TOKENS,
    () => presented
  );
};

export const createGetPolicyApplyStateTool = ({
  endpointAppContextService,
  getStartServices,
}: {
  endpointAppContextService: EndpointAppContextService;
  getStartServices: StartServicesAccessor;
}): BuiltinSkillBoundedTool<typeof getPolicyApplyStateSchema> =>
  createPolicyTool({
    endpointAppContextService,
    getStartServices,
    id: GET_POLICY_APPLY_STATE_TOOL_ID,
    description:
      'Get assigned-versus-applied lag: known out-of-date host counts and current policy-response failure counts for one Elastic Defend ' +
      'endpoint policy by saved-object id or exact name in the current space. Out-of-date counts are readable ' +
      "united endpoint hosts whose canonical assignment id matches this policy's current agent-policy ids on the " +
      'request-scoped CPS/CCS surface. Failure counts are latest policy responses at the current package revision. ' +
      'Classified or assignment-matched hosts are not enrolled-agent usage evidence and cannot answer used or unused. ' +
      'Overflow fields are unclassified truncation and must not be added or treated as out-of-date or failing hosts. ' +
      'Does not write policies.',
    schema: getPolicyApplyStateSchema,
    level: 'estate_read',
    maxResultTokens: GET_POLICY_APPLY_STATE_MAX_RESULT_TOKENS,
    run: async (
      { idOrName }: z.infer<typeof getPolicyApplyStateSchema>,
      access: HasAtLeast<'estate_read'>,
      core: { request: KibanaRequest }
    ) => {
      const dto = await readApplyState(
        access,
        endpointAppContextService,
        { idOrName },
        core.request
      );
      return presentApplyState(dto);
    },
  });
