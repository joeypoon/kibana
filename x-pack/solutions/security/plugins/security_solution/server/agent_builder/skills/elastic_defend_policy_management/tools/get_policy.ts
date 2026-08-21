/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import { z } from '@kbn/zod/v4';
import type { StartServicesAccessor } from '@kbn/core/server';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import type { HasAtLeast } from '../services/access_context';
import type { PolicyIdentity } from '../services/read_policy';
import { getEndpointPolicy } from '../services/read_policy';
import { createPolicyTool } from './create_policy_tool';
import {
  parentTrimMetadata,
  presentBoundedIdentityStrings,
  presentWithinGuardedBudget,
  toPresentationHash,
  trimPolicyResultWithMeta,
} from './trim_policy_result';

export const GET_POLICY_TOOL_ID = 'security.policy_management.get_policy';

const IDENTIFIER_MAX_LENGTH = 256;
const GET_POLICY_MAX_RESULT_TOKENS = 12_000;

export const getPolicySchema = z.object({
  idOrName: z
    .string()
    .trim()
    .min(1)
    .max(IDENTIFIER_MAX_LENGTH)
    .describe(
      'Saved-object id or exact endpoint policy name in the current space (1–256 characters after trim).'
    ),
});

const presentGetPolicy = (
  policy: PolicyIdentity,
  normalizedConfig: unknown,
  serviceHash: string
): Record<string, unknown> => {
  const identity = presentBoundedIdentityStrings(policy);
  const normalizedHash = toPresentationHash(serviceHash);

  return presentWithinGuardedBudget(
    (limits) => {
      const trimmed = trimPolicyResultWithMeta(normalizedConfig, limits);
      return {
        policy: identity,
        normalizedHash,
        config: trimmed.value,
        ...parentTrimMetadata(trimmed.value, trimmed.metadata),
      };
    },
    GET_POLICY_MAX_RESULT_TOKENS,
    () => ({
      policy: identity,
      normalizedHash,
    })
  );
};

export const createGetPolicyTool = ({
  endpointAppContextService,
  getStartServices,
}: {
  endpointAppContextService: EndpointAppContextService;
  getStartServices: StartServicesAccessor;
}): BuiltinSkillBoundedTool<typeof getPolicySchema> =>
  createPolicyTool({
    endpointAppContextService,
    getStartServices,
    id: GET_POLICY_TOOL_ID,
    description:
      'Get one Elastic Defend endpoint policy by saved-object id or exact name in the current space. ' +
      'Returns complete identity, a full-config normalized hash, and a structurally bounded presented config. ' +
      'Does not count endpoints or write policies.',
    schema: getPolicySchema,
    level: 'policy_read',
    maxResultTokens: GET_POLICY_MAX_RESULT_TOKENS,
    run: async (
      { idOrName }: z.infer<typeof getPolicySchema>,
      access: HasAtLeast<'policy_read'>
    ) => {
      const { policy, normalizedConfig, normalizedHash } = await getEndpointPolicy(access, {
        idOrName,
      });

      return presentGetPolicy(policy, normalizedConfig, normalizedHash);
    },
  });
