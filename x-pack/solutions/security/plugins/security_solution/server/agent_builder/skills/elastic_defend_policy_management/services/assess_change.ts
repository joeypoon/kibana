/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ProductFeatureSecurityKey } from '@kbn/security-solution-features/keys';
import type { PolicyConfig } from '../../../../../common/endpoint/types';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import type { PolicyDiffEntry } from '../domain/diff';
import * as fieldRegistry from '../domain/field_registry';
import {
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  PolicyChangePreparationError,
  assertParameterBounds,
  buildEligibilityContext,
  computePathEligibility,
  nonWritablePathMessage,
  parseAssessPolicyChangeParams,
  prepareChangeSet,
} from '../domain/impact';
import type {
  EligibilityContext,
  ExplicitPolicyChange,
  PolicyChangeFact,
  PolicyChangeOperation,
  PolicyChangeSideEffect,
} from '../domain/impact';
import type { HasAtLeast } from './access_context';
import type { EndpointCountResult } from './count_endpoints';
import { countEndpoints } from './count_endpoints';
import { getEndpointPolicy } from './read_policy';

export interface AssessPolicyChangeDto {
  readonly policy: {
    readonly id: string;
    readonly name: string;
    readonly revision: number;
    readonly version: string;
  };
  readonly spaceId: string;
  readonly requestedOperations: readonly PolicyChangeOperation[];
  readonly requestedImpact: readonly PolicyChangeFact[];
  readonly expandedChanges: readonly PolicyChangeFact[];
  readonly normalizedDiff: readonly PolicyDiffEntry[];
  readonly sideEffects: readonly PolicyChangeSideEffect[];
  readonly blastRadius: EndpointCountResult;
}

export const toEligibilityContext = (
  endpointAppContextService: EndpointAppContextService,
  proposedConfig: PolicyConfig
): EligibilityContext => {
  const licenseService = endpointAppContextService.getLicenseService();
  const productFeatures = endpointAppContextService.getProductFeaturesService();
  const { experimentalFeatures } = endpointAppContextService;

  return buildEligibilityContext({
    proposedConfig,
    licenseInformation: licenseService.getLicenseInformation(),
    endpointPolicyProtections: productFeatures.isEnabled(
      ProductFeatureSecurityKey.endpointPolicyProtections
    ),
    endpointTrustedDevices: productFeatures.isEnabled(
      ProductFeatureSecurityKey.endpointTrustedDevices
    ),
    trustedDevicesExperimental: experimentalFeatures.trustedDevices,
    endpointProtectionUpdates: productFeatures.isEnabled(
      ProductFeatureSecurityKey.endpointProtectionUpdates
    ),
    serverless: endpointAppContextService.isServerless(),
  });
};

const toPolicyChangeFact = (
  change: ExplicitPolicyChange,
  eligibilityContext: EligibilityContext
): PolicyChangeFact => {
  const entry = fieldRegistry.getFieldRegistryEntry(change.path);
  if (entry === undefined) {
    throw new PolicyChangePreparationError(
      POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
      nonWritablePathMessage(change.path)
    );
  }

  return {
    path: change.path,
    from: change.from,
    to: change.to,
    origin: change.origin,
    registry: {
      path: entry.path,
      os: entry.os,
      kind: entry.kind,
      tier: entry.tier,
      documentation: entry.documentation,
      license: entry.license,
      minVersion: entry.minVersion,
      maxVersion: entry.maxVersion,
      source: entry.source,
      userEditable: entry.userEditable,
      productFeatureGate: entry.productFeatureGate,
    },
    eligibility: computePathEligibility(change.path, eligibilityContext),
  };
};

export const assessChange = async (
  access: HasAtLeast<'estate_read'>,
  endpointAppContextService: EndpointAppContextService,
  rawParams: unknown
): Promise<AssessPolicyChangeDto> => {
  assertParameterBounds(rawParams);
  const { idOrName } = parseAssessPolicyChangeParams(rawParams);
  const resolved = await getEndpointPolicy(access, { idOrName });
  const prepared = prepareChangeSet(rawParams, resolved.storedConfig);
  const eligibilityContext = toEligibilityContext(
    endpointAppContextService,
    prepared.proposedConfig
  );
  const blastRadius = await countEndpoints(access, { policyId: resolved.policy.id });
  const expandedChanges = prepared.explicitChanges.map((change) =>
    toPolicyChangeFact(change, eligibilityContext)
  );

  return {
    policy: {
      id: resolved.policy.id,
      name: resolved.policy.name,
      revision: resolved.policy.revision,
      version: resolved.policy.version,
    },
    spaceId: access.spaceId,
    requestedOperations: prepared.operations,
    requestedImpact: expandedChanges.filter((change) => change.origin.kind === 'direct'),
    expandedChanges,
    normalizedDiff: prepared.normalizedDiff,
    sideEffects: prepared.sideEffects,
    blastRadius,
  };
};
