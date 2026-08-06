/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cloneDeep } from 'lodash';
import { ProductFeatureSecurityKey } from '@kbn/security-solution-features/keys';

import type { ExperimentalFeatures } from '../../../../../../common';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { ProtectionModes } from '../../../../../../common/endpoint/types';
import {
  ensureOnlyEventCollectionIsAllowed,
  isPolicySetToEventCollectionOnly,
  removeDeviceControl,
} from '../../../../../../common/endpoint/models/policy_config_helpers';
import { updateAntivirusRegistrationEnabled } from '../../../../../../common/endpoint/utils/update_antivirus_registration_enabled';
import type { ProductFeaturesService } from '../../../../../lib/product_features_service';

export interface PreviewFleetUpdateRewritesArgs {
  readonly proposedConfig: PolicyConfig;
  readonly productFeaturesService: Pick<ProductFeaturesService, 'isEnabled'>;
  readonly experimentalFeatures: ExperimentalFeatures;
}

export interface FleetUpdateRewritePreview {
  readonly validationConfig: PolicyConfig;
  readonly persistedConfig: PolicyConfig;
}

const restoreFalsyMacRansomwareMode = (policy: PolicyConfig): void => {
  if (policy.mac?.ransomware && !policy.mac.ransomware.mode) {
    policy.mac.ransomware.mode = ProtectionModes.off;
  }
};

export const previewFleetUpdateRewrites = ({
  proposedConfig,
  productFeaturesService,
  experimentalFeatures,
}: PreviewFleetUpdateRewritesArgs): FleetUpdateRewritePreview => {
  const working = cloneDeep(proposedConfig);
  restoreFalsyMacRansomwareMode(working);

  let persisted: PolicyConfig = working;

  const eventsOnlyPolicy = isPolicySetToEventCollectionOnly(working);
  if (
    !productFeaturesService.isEnabled(ProductFeatureSecurityKey.endpointPolicyProtections) &&
    !eventsOnlyPolicy.isOnlyCollectingEvents
  ) {
    persisted = ensureOnlyEventCollectionIsAllowed(working);
  }

  if (
    !productFeaturesService.isEnabled(ProductFeatureSecurityKey.endpointTrustedDevices) ||
    !experimentalFeatures.trustedDevices
  ) {
    persisted = removeDeviceControl(working);
  }

  const antivirusTarget = cloneDeep(working);
  updateAntivirusRegistrationEnabled(antivirusTarget);

  if (persisted === working) {
    persisted = antivirusTarget;
  }

  return {
    validationConfig: working,
    persistedConfig: persisted,
  };
};
