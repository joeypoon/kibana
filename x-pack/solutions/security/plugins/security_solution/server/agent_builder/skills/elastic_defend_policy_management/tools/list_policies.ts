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
import { createPolicyAccessContext } from '../services/access_context';
import type { ClassifiedPolicyUsage } from '../services/classify_policy_usage';
import { classifyPolicyUsage } from '../services/classify_policy_usage';
import { countEndpoints } from '../services/count_endpoints';
import { PolicyAuthorizationError } from '../services/policy_errors';
import type { ListPoliciesDto, ListPolicyItem } from '../services/read_estate';
import { listEndpointPolicies } from '../services/read_estate';
import { createPolicyTool } from './create_policy_tool';
import { omitTrailingToFit, toPresentationHash } from './trim_policy_result';

export const LIST_POLICIES_TOOL_ID = 'security.policy_management.list_policies';

const LIST_PAGE_MIN = 1;
const LIST_PAGE_MAX = 10_000;
const LIST_PER_PAGE_MIN = 1;
const LIST_PER_PAGE_MAX = 50;
const LIST_PER_PAGE_DEFAULT = 20;
const LIST_STRING_CAP = 512;
const LIST_POLICIES_MAX_RESULT_TOKENS = 8_000;
const LIST_USAGE_FANOUT_MAX = 20;

export const listPoliciesSchema = z.object({
  page: z
    .number()
    .int()
    .min(LIST_PAGE_MIN)
    .max(LIST_PAGE_MAX)
    .default(LIST_PAGE_MIN)
    .describe(
      '1-based page of endpoint package policies in the current space (1–10000, default 1).'
    ),
  perPage: z
    .number()
    .int()
    .min(LIST_PER_PAGE_MIN)
    .max(LIST_PER_PAGE_MAX)
    .default(LIST_PER_PAGE_DEFAULT)
    .describe(
      'Page size (1–50, default 20). Usage and enrolled-agent counts are returned only in usage mode under endpoint-list read.'
    ),
  includeUsage: z
    .boolean()
    .default(false)
    .describe(
      'When true, return per-policy enrolled-agent-backed usage classification. Requires endpoint-list read.'
    ),
});

const capPresentedString = (value: string): { text: string; truncated: boolean } => {
  if (value.length <= LIST_STRING_CAP) {
    return { text: value, truncated: false };
  }

  return { text: value.slice(0, LIST_STRING_CAP), truncated: true };
};

type ListedPolicyItem = ListPolicyItem & {
  usage?: ClassifiedPolicyUsage;
};

type ListedPolicies = Omit<ListPoliciesDto, 'items'> & {
  items: readonly ListedPolicyItem[];
  usage_truncated?: true;
  usage_unavailable?: 'requires_endpoint_list_read';
};

type PresentedListPolicies = ListedPolicies & {
  items_total?: number;
  items_truncated?: true;
};

const presentListPolicyItem = (item: ListedPolicyItem): ListedPolicyItem => {
  const name = capPresentedString(item.name);
  const description = capPresentedString(item.description);

  return {
    ...item,
    name: name.text,
    description: description.text,
    normalizedHash: toPresentationHash(item.normalizedHash),
    ...(name.truncated || item.name_string_truncated ? { name_string_truncated: true } : {}),
    ...(description.truncated || item.description_string_truncated
      ? { description_string_truncated: true }
      : {}),
  };
};

const presentListPolicies = (dto: ListedPolicies): PresentedListPolicies => {
  const presentedItems = dto.items.map(presentListPolicyItem);

  return omitTrailingToFit(
    (keep): PresentedListPolicies => ({
      ...dto,
      items: presentedItems.slice(0, keep),
      ...(keep < presentedItems.length
        ? { items_total: presentedItems.length, items_truncated: true as const }
        : {}),
    }),
    presentedItems.length,
    LIST_POLICIES_MAX_RESULT_TOKENS
  );
};

const attachUsage = async (
  items: readonly ListPolicyItem[],
  estateAccess: HasAtLeast<'estate_read'>
): Promise<Pick<ListedPolicies, 'items' | 'usage_truncated'>> => {
  const usageTruncated = items.length > LIST_USAGE_FANOUT_MAX;
  const classifiedHead = await Promise.all(
    items.slice(0, LIST_USAGE_FANOUT_MAX).map(async (item): Promise<ListedPolicyItem> => {
      try {
        const count = await countEndpoints(estateAccess, { policyId: item.id });
        return { ...item, usage: classifyPolicyUsage(count) };
      } catch {
        return {
          ...item,
          usage: { classification: 'undetermined', reason: 'count_unavailable' },
        };
      }
    })
  );

  const undeterminedTail = items.slice(LIST_USAGE_FANOUT_MAX).map(
    (item): ListedPolicyItem => ({
      ...item,
      usage: { classification: 'undetermined', reason: 'usage_truncated' },
    })
  );

  return {
    items: [...classifiedHead, ...undeterminedTail],
    ...(usageTruncated ? { usage_truncated: true as const } : {}),
  };
};

export const createListPoliciesTool = ({
  endpointAppContextService,
  getStartServices,
}: {
  endpointAppContextService: EndpointAppContextService;
  getStartServices: StartServicesAccessor;
}): BuiltinSkillBoundedTool<typeof listPoliciesSchema> =>
  createPolicyTool({
    endpointAppContextService,
    getStartServices,
    id: LIST_POLICIES_TOOL_ID,
    description:
      'List Elastic Defend endpoint policies in the current space as a bounded page of identity, ' +
      'normalized hash, and compact posture. Usage and enrolled-agent counts are returned only in usage mode under endpoint-list read. Does not write policies.',
    schema: listPoliciesSchema,
    level: 'policy_read',
    maxResultTokens: LIST_POLICIES_MAX_RESULT_TOKENS,
    run: async (
      { page, perPage, includeUsage }: z.infer<typeof listPoliciesSchema>,
      access: HasAtLeast<'policy_read'>,
      core: { request: KibanaRequest }
    ) => {
      const dto = await listEndpointPolicies(access, { page, perPage });

      if (!includeUsage) {
        return presentListPolicies(dto);
      }

      let estateAccess: HasAtLeast<'estate_read'>;
      try {
        estateAccess = await createPolicyAccessContext(
          endpointAppContextService,
          { request: core.request, spaceId: access.spaceId },
          'estate_read',
          getStartServices
        );
      } catch (error) {
        if (error instanceof PolicyAuthorizationError) {
          const deniedItems = dto.items.map(
            (item): ListedPolicyItem => ({
              ...item,
              usage: { classification: 'undetermined', reason: 'requires_endpoint_list_read' },
            })
          );
          return {
            ...presentListPolicies({ ...dto, items: deniedItems }),
            usage_unavailable: 'requires_endpoint_list_read',
          };
        }
        throw error;
      }

      const withUsage = await attachUsage(dto.items, estateAccess);
      return presentListPolicies({
        ...dto,
        ...withUsage,
      });
    },
  });
