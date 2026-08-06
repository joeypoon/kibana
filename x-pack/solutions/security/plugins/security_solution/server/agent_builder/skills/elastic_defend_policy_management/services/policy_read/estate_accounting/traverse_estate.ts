/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger, SavedObjectsClientContract } from '@kbn/core/server';
import { SavedObjectsErrorHelpers } from '@kbn/core/server';
import type { PackagePolicyClient } from '@kbn/fleet-plugin/server';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import type { EstateAccounting, PartialResultReason } from '../../../domain/read/types';

export const DEFAULT_MAX_POLICIES_TRAVERSED = 20_000;

export interface TraverseEstateOptions<TAggregate> {
  readonly packagePolicyService: Pick<PackagePolicyClient, 'fetchAllItems'>;
  readonly soClient: SavedObjectsClientContract;
  readonly spaceId: string;
  readonly kuery?: string;
  readonly logger: Logger;
  readonly maxPoliciesTraversed?: number;
  readonly visit: (policy: PackagePolicy) => void;
  readonly finalize: () => TAggregate;
}

export interface TraverseEstateResult<TAggregate> {
  readonly aggregate: TAggregate;
  readonly accounting: EstateAccounting;
}

const classifyInterruption = (error: unknown): PartialResultReason =>
  SavedObjectsErrorHelpers.isNotAuthorizedError(error as Error) ||
  SavedObjectsErrorHelpers.isForbiddenError(error as Error)
    ? 'missing_privilege'
    : 'upstream_failure';

export const traverseEstate = async <TAggregate>({
  packagePolicyService,
  soClient,
  spaceId,
  kuery,
  logger,
  maxPoliciesTraversed = DEFAULT_MAX_POLICIES_TRAVERSED,
  visit,
  finalize,
}: TraverseEstateOptions<TAggregate>): Promise<TraverseEstateResult<TAggregate>> => {
  let policiesTraversed = 0;
  let pagesFetched = 0;
  let complete = true;
  let incompleteReason: PartialResultReason | undefined;

  try {
    const iterator = await packagePolicyService.fetchAllItems(soClient, {
      spaceIds: [spaceId],
      kuery,
    });

    for await (const page of iterator) {
      if (page.length > 0) {
        pagesFetched += 1;

        for (const policy of page) {
          if (policiesTraversed >= maxPoliciesTraversed) {
            complete = false;
            incompleteReason = 'result_limit_reached';
            break;
          }

          visit(policy);
          policiesTraversed += 1;
        }

        if (!complete) {
          break;
        }
      }
    }
  } catch (error) {
    complete = false;
    incompleteReason = classifyInterruption(error);

    logger.warn(
      `traverseEstate(): traversal interrupted after ${policiesTraversed} policy(ies) across ${pagesFetched} page(s): ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }

  return {
    aggregate: finalize(),
    accounting: {
      policiesTraversed,
      pagesFetched,
      complete,
      ...(incompleteReason === undefined ? {} : { incompleteReason }),
    },
  };
};
