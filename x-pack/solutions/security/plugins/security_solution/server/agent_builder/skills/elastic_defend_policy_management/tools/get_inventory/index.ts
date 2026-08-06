/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType } from '@kbn/agent-builder-common/tools';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import { normalizePolicySearch, readDefendPolicyInventory } from '../../services/policy_read';
import type { PolicyInventoryIdentity } from '../../services/policy_read';
import {
  boundList,
  MAX_INVENTORY_DESCRIPTION_CHARS,
  truncateBoundedString,
} from '../../lib/bounded_result';
import type { DefendPolicyManagementSkillDeps } from '../../deps';
import { resolvePolicyServices } from '../../deps';
import { INTERACTIVE_ESTATE_WORK_LIMIT } from '../work_limit';
import { resolvePolicyFieldRegistry } from '../../lib/policy_registry_cache';
import {
  CONFIGURED_NOT_APPLIED_STATEMENT,
  UNTRUSTED_FIELD_DATA_STATEMENT,
  toScopeDisclosurePayload,
  toolDenial,
  toolException,
  toolSuccess,
} from '../../lib/tool_results';
import { policySearchInput, POLICY_SEARCH_CONTRACT } from '../schemas';

export const GET_DEFEND_POLICY_INVENTORY_TOOL_ID = 'security.get_defend_policy_inventory';

const MAX_INVENTORY_ITEMS = 100;

const INVENTORY_ENVELOPE_TOKENS = 1_000;

const getDefendPolicyInventorySchema = z
  .object({
    search: policySearchInput
      .optional()
      .describe(
        `Optional filter narrowing the listing to Elastic Defend policies whose names match. ${POLICY_SEARCH_CONTRACT}`
      ),
  })
  .strict();

interface InventoryRow {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly revision: number;
  readonly version?: string;
  readonly package_version: string;
  readonly agent_policy_ids: readonly string[];
  readonly updated_at: string;
  readonly updated_by: string;
}

const toInventoryRow = ({
  identity,
  name,
  description,
  packageVersion,
  policyIds,
  provenance,
}: PolicyInventoryIdentity): InventoryRow => ({
  id: identity.id,
  name,
  ...(description === undefined
    ? {}
    : { description: truncateBoundedString(description, MAX_INVENTORY_DESCRIPTION_CHARS) }),
  revision: identity.revision,
  ...(identity.version === undefined ? {} : { version: identity.version }),
  package_version: packageVersion,
  agent_policy_ids: [...policyIds],
  updated_at: provenance.updatedAt,
  updated_by: provenance.updatedBy,
});

const FILTERED_ZERO_NOTE =
  '`search` is a literal, case-sensitive substring filter — not a regular expression and not a ' +
  'glob — so a wildcard-shaped filter matches (almost) nothing. If you expected policies here, ' +
  'omit `search` to list every accessible policy.';

const FILTERED_SCOPE_NOTE =
  'This listing is scoped to policies whose names match the filter. Omit `search` to list every ' +
  'policy the user can access.';

export const createGetDefendPolicyInventoryTool = (
  deps: DefendPolicyManagementSkillDeps
): BuiltinSkillBoundedTool<typeof getDefendPolicyInventorySchema> => ({
  id: GET_DEFEND_POLICY_INVENTORY_TOOL_ID,
  type: ToolType.builtin,
  description:
    'List the Elastic Defend (endpoint protection) policies the user can access, with names, ' +
    'revisions, package versions, and agent-policy assignments. Use for "what Defend policies do I ' +
    'have", counts, and finding a policy id by name. The optional `search` is a LITERAL, ' +
    'CASE-SENSITIVE name substring filter — not regex, not glob — and omitting it covers the whole ' +
    'accessible estate. Returns a bounded listing, the number of ' +
    'policies the traversal observed, and a scope disclosure that states any incompleteness and ' +
    'how to obtain the rest. Read-only. Returns CONFIGURED policy, and cannot ' +
    "confirm what endpoints are currently running. For one policy's full settings use " +
    '`security.get_defend_policy`.',
  schema: getDefendPolicyInventorySchema,
  handler: async ({ search }, { request }) => {
    const policySearch = normalizePolicySearch(search);

    try {
      const resolved = await resolvePolicyServices({ deps, request });
      if (!resolved.ok) {
        return toolDenial(resolved.denial);
      }

      const services = resolved.value;
      const outcome = await readDefendPolicyInventory({
        packagePolicyService: services.packagePolicyService,
        privilegeBasis: services.privilegeBasis,
        getSoClient: services.getSoClient,
        spaceId: services.spaceId,
        ...(policySearch === undefined ? {} : { search: policySearch }),
        resolveRegistry: (packageVersion) =>
          resolvePolicyFieldRegistry(packageVersion, { referenceVersion: deps.kibanaVersion }),
        logger: deps.logger,
        maxPoliciesTraversed: INTERACTIVE_ESTATE_WORK_LIMIT,
      });

      if (!outcome.ok) {
        return toolDenial(outcome.denial);
      }

      const { items, scope, accounting } = outcome.value;
      const rows = items.map(toInventoryRow);

      const bounded = boundList({
        items: rows,
        maxItems: MAX_INVENTORY_ITEMS,
        envelopeTokens: INVENTORY_ENVELOPE_TOKENS,
        itemLabel: 'Elastic Defend policies',
        continuation: 'Narrow the listing with `search` to see the omitted policies.',
      });

      const { listingComplete, continuation, completenessNote } = describeCompleteness({
        traversalComplete: accounting.complete,
        partial: scope.partial !== undefined,
        trimmed: bounded.truncated,
        search: policySearch,
      });

      return toolSuccess(
        {
          message: buildInventoryMessage({
            returned: bounded.returned,
            total: scope.total,
            listingComplete,
            traversalComplete: accounting.complete,
            truncationNotice: bounded.truncationNotice,
            completenessNote,
            search: policySearch,
          }),
          policies: bounded.items,
          total: scope.total,
          returned: bounded.returned,
          truncated: bounded.truncated,
          ...(bounded.truncationNotice === undefined
            ? {}
            : { truncation_notice: bounded.truncationNotice }),
          listing_complete: listingComplete,
          continuation,
          work_limit: INTERACTIVE_ESTATE_WORK_LIMIT,
          scope_disclosure: toScopeDisclosurePayload(scope),
          configured_not_applied: CONFIGURED_NOT_APPLIED_STATEMENT,
          untrusted_field_data: UNTRUSTED_FIELD_DATA_STATEMENT,
        },
        { logger: deps.logger, toolId: GET_DEFEND_POLICY_INVENTORY_TOOL_ID }
      );
    } catch (error) {
      return toolException(error, {
        logger: deps.logger,
        toolId: GET_DEFEND_POLICY_INVENTORY_TOOL_ID,
        operation: 'listing Elastic Defend policies',
      });
    }
  },
});

interface CompletenessInputs {
  readonly traversalComplete: boolean;
  readonly partial: boolean;
  readonly trimmed: boolean;
  readonly search?: string;
}

interface ListingCompleteness {
  readonly listingComplete: boolean;
  readonly continuation: string;
  readonly completenessNote?: string;
}

const describeCompleteness = ({
  traversalComplete,
  partial,
  trimmed,
  search,
}: CompletenessInputs): ListingCompleteness => {
  if (trimmed) {
    return {
      listingComplete: false,
      continuation:
        'Some policies were left out to fit the response size limit, so this listing is INCOMPLETE. ' +
        'Narrow the listing with `search` to see them.',
      completenessNote:
        'This listing is INCOMPLETE: it was trimmed to fit the response size limit — narrow the ' +
        'listing with `search` before stating a per-policy breakdown as complete.',
    };
  }

  if (!traversalComplete || partial) {
    return {
      listingComplete: false,
      continuation:
        'The listing did not cover every accessible policy; the scope disclosure states the reason ' +
        'and the way to obtain the rest.',
      completenessNote:
        'This listing is INCOMPLETE — see the scope disclosure before stating a per-policy ' +
        'breakdown as complete.',
    };
  }

  return search === undefined
    ? {
        listingComplete: true,
        continuation: 'Every policy you can access has been returned.',
      }
    : {
        listingComplete: true,
        continuation:
          'Every policy MATCHING the name filter has been returned — policies whose names do not ' +
          'contain the filter terms are NOT covered. Omit `search` to list every policy the user ' +
          'can access.',
      };
};

interface InventoryMessageOptions {
  readonly returned: number;
  readonly total: number;
  readonly listingComplete: boolean;
  readonly traversalComplete: boolean;
  readonly truncationNotice?: string;
  readonly completenessNote?: string;
  readonly search?: string;
}

const buildInventoryMessage = ({
  returned,
  total,
  listingComplete,
  traversalComplete,
  truncationNotice,
  completenessNote,
  search,
}: InventoryMessageOptions): string => {
  const filter = search === undefined ? '' : ` matching the name filter ${JSON.stringify(search)}`;
  const filteredScopeNote =
    search !== undefined && !listingComplete ? FILTERED_SCOPE_NOTE : undefined;

  if (total === 0) {
    const zero = traversalComplete
      ? `No Elastic Defend policies you can access${filter}.`
      : `The listing examined no Elastic Defend policies${filter} before stopping; the accessible set may not be empty.`;
    const filteredZeroNote =
      traversalComplete && search !== undefined ? FILTERED_ZERO_NOTE : undefined;

    return [zero, filteredZeroNote, completenessNote]
      .filter((part): part is string => part !== undefined)
      .join(' ');
  }

  const scope = traversalComplete
    ? `${total} Elastic Defend ${total === 1 ? 'policy' : 'policies'} you can access${filter}.`
    : `The listing examined ${total} Elastic Defend ${
        total === 1 ? 'policy' : 'policies'
      }${filter} before stopping, so it is INCOMPLETE.`;

  const count =
    returned === total && listingComplete
      ? search === undefined
        ? `Returning all ${returned}.`
        : `Returning all ${returned} matching the filter.`
      : `Returning ${returned} of them.`;

  return [scope, count, truncationNotice, completenessNote, filteredScopeNote]
    .filter((part): part is string => part !== undefined)
    .join(' ');
};
