/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SavedObjectsErrorHelpers } from '@kbn/core/server';
import { PackagePolicyNotFoundError } from '@kbn/fleet-plugin/server/errors';
import { EndpointError } from '../../../../../../common/endpoint/errors';
import type { RegistryVersionUnknown } from '../../domain/field_registry/types';
import { DefendPolicyInputNotFoundError } from './defend_policy_management_input_not_found_error';

export { DefendPolicyInputNotFoundError };

export class PolicyRegistryVersionUnknownError extends EndpointError {
  constructor(public readonly detail: RegistryVersionUnknown) {
    super(
      `No Elastic Defend policy field registry is available for package version [${
        detail.requestedVersion
      }]${
        detail.nearestKnownVersion
          ? `; the nearest known version is [${detail.nearestKnownVersion}]`
          : ''
      }.`
    );
  }
}

export const isPolicyNotFoundError = (error: unknown): boolean =>
  error instanceof PackagePolicyNotFoundError ||
  error instanceof DefendPolicyInputNotFoundError ||
  (error instanceof Error && SavedObjectsErrorHelpers.isNotFoundError(error));
