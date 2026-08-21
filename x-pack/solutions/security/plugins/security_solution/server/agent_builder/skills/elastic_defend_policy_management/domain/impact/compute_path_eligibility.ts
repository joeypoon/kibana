/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { get, isEqual } from 'lodash';
import moment from 'moment';
import { getControlledArtifactCutoffDate } from '../../../../../../common/endpoint/utils/controlled_artifact_rollout';
import type { EligibilityContext, PathEligibility } from './policy_change_operation';

const ineligible = (reason: string): PathEligibility => ({
  eligible: false,
  reason,
});

const isLicenseUnconstrainedPath = (path: string): boolean =>
  path.endsWith('.device_control.usb_storage') ||
  path.endsWith('.behavior_protection.reputation_service');

const licenseReason = (
  path: string,
  context: EligibilityContext,
  proposedValue: unknown
): string => {
  if (isEqual(proposedValue, get(context.platinumStripped, path))) {
    return 'license_below_platinum';
  }
  if (isEqual(proposedValue, get(context.enterpriseStripped, path))) {
    return 'license_below_enterprise';
  }
  return 'license_insufficient';
};

const globalManifestVersionReason = (proposedValue: unknown): string | undefined => {
  if (typeof proposedValue !== 'string') {
    return 'global_manifest_version_invalid_format';
  }

  const parsedDate = moment.utc(proposedValue, 'YYYY-MM-DD', true);
  if (!parsedDate.isValid()) {
    return 'global_manifest_version_invalid_format';
  }

  const maxAllowedDate = getControlledArtifactCutoffDate();
  if (parsedDate.startOf('day').isBefore(maxAllowedDate.clone().startOf('day'))) {
    return 'global_manifest_version_too_old';
  }

  const minAllowedDate = moment.utc().subtract(1, 'day');
  if (parsedDate.isAfter(minAllowedDate)) {
    return 'global_manifest_version_in_future';
  }

  return undefined;
};

export const computePathEligibility = (
  path: string,
  context: EligibilityContext
): PathEligibility => {
  const proposedValue = get(context.proposedConfig, path);

  if (
    !context.serverless &&
    !isLicenseUnconstrainedPath(path) &&
    !isEqual(proposedValue, get(context.licenseStripped, path))
  ) {
    return ineligible(licenseReason(path, context, proposedValue));
  }

  if (path === 'global_manifest_version' && proposedValue !== 'latest') {
    if (!context.endpointProtectionUpdates) {
      return ineligible('endpoint_protection_updates_disabled');
    }

    const manifestVersionReason = globalManifestVersionReason(proposedValue);
    if (manifestVersionReason !== undefined) {
      return ineligible(manifestVersionReason);
    }
  }

  if (!isEqual(proposedValue, get(context.protectionsStripped, path))) {
    return ineligible('endpoint_policy_protections_disabled');
  }

  if (!isEqual(proposedValue, get(context.deviceControlStripped, path))) {
    return ineligible(context.deviceControlReason);
  }

  return { eligible: true };
};
