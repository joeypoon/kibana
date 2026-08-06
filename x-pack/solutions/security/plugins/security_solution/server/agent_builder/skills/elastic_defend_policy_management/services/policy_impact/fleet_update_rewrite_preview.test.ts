/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cloneDeep } from 'lodash';
import {
  ALL_PRODUCT_FEATURE_KEYS,
  ProductFeatureSecurityKey,
} from '@kbn/security-solution-features/keys';

import { allowedExperimentalValues } from '../../../../../../common';
import type { ExperimentalFeatures } from '../../../../../../common';
import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import * as PolicyConfigHelpers from '../../../../../../common/endpoint/models/policy_config_helpers';
import {
  ensureOnlyEventCollectionIsAllowed,
  removeDeviceControl,
} from '../../../../../../common/endpoint/models/policy_config_helpers';
import { ProtectionModes } from '../../../../../../common/endpoint/types';
import { createProductFeaturesServiceMock } from '../../../../../lib/product_features_service/mocks';
import { previewFleetUpdateRewrites } from './fleet_update_rewrite_preview';

const experimentalFeatures = (
  overrides: Partial<ExperimentalFeatures> = {}
): ExperimentalFeatures => ({
  ...allowedExperimentalValues,
  ...overrides,
});

const productFeatures = (
  disabled: readonly ProductFeatureSecurityKey[] = []
): ReturnType<typeof createProductFeaturesServiceMock> =>
  createProductFeaturesServiceMock(
    ALL_PRODUCT_FEATURE_KEYS.filter((key) => !disabled.includes(key as ProductFeatureSecurityKey))
  );

const deepFreeze = (value: unknown): void => {
  if (typeof value !== 'object' || value === null) {
    return;
  }

  Object.freeze(value);

  for (const nested of Object.values(value)) {
    deepFreeze(nested);
  }
};

describe('previewFleetUpdateRewrites', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('leaves the source proposed config immutable, including through antivirus mutation', () => {
    const proposedConfig = policyFactory();
    proposedConfig.windows.malware.mode = ProtectionModes.detect;
    const sourceBefore = cloneDeep(proposedConfig);
    deepFreeze(proposedConfig);

    const preview = previewFleetUpdateRewrites({
      proposedConfig,
      productFeaturesService: productFeatures(),
      experimentalFeatures: experimentalFeatures(),
    });

    expect(proposedConfig).toEqual(sourceBefore);
    expect(preview.persistedConfig).not.toBe(proposedConfig);
    expect(preview.validationConfig).not.toBe(proposedConfig);
    expect(preview.persistedConfig.windows.antivirus_registration.enabled).toBe(false);
    expect(proposedConfig.windows.antivirus_registration.enabled).toBe(true);
  });

  it('restores falsy mac ransomware before gates so an events-only policy is not rewritten', () => {
    const proposedConfig = ensureOnlyEventCollectionIsAllowed(policyFactory());
    delete (proposedConfig.mac.ransomware as { mode?: ProtectionModes }).mode;

    const ensureSpy = jest.spyOn(PolicyConfigHelpers, 'ensureOnlyEventCollectionIsAllowed');

    const preview = previewFleetUpdateRewrites({
      proposedConfig,
      productFeaturesService: productFeatures([
        ProductFeatureSecurityKey.endpointPolicyProtections,
      ]),
      experimentalFeatures: experimentalFeatures(),
    });

    expect(proposedConfig.mac.ransomware.mode).toBeUndefined();
    expect(preview.validationConfig.mac.ransomware.mode).toBe(ProtectionModes.off);
    expect(ensureSpy).not.toHaveBeenCalled();
  });

  it('applies antivirus registration to persisted config when neither gate reassigns', () => {
    const proposedConfig = policyFactory();
    proposedConfig.windows.malware.mode = ProtectionModes.detect;

    const preview = previewFleetUpdateRewrites({
      proposedConfig,
      productFeaturesService: productFeatures(),
      experimentalFeatures: experimentalFeatures({ trustedDevices: true }),
    });

    expect(preview.persistedConfig.windows.malware.mode).toBe(ProtectionModes.detect);
    expect(preview.persistedConfig.windows.antivirus_registration.enabled).toBe(false);
    expect(preview.validationConfig.windows.antivirus_registration.enabled).toBe(true);
  });

  it('does not apply antivirus mutation to a device-control reassignment', () => {
    const proposedConfig = policyFactory();
    proposedConfig.windows.malware.mode = ProtectionModes.detect;

    const preview = previewFleetUpdateRewrites({
      proposedConfig,
      productFeaturesService: productFeatures(),
      experimentalFeatures: experimentalFeatures({ trustedDevices: false }),
    });

    expect(preview.persistedConfig.windows.malware.mode).toBe(ProtectionModes.detect);
    expect(preview.persistedConfig.windows.antivirus_registration.enabled).toBe(true);
    expect(preview.persistedConfig.windows).not.toHaveProperty('device_control');
    expect(preview.persistedConfig.mac).not.toHaveProperty('device_control');
  });

  it('assigns the protection-gate helper return value and leaves device_control present', () => {
    const proposedConfig = policyFactory();

    const preview = previewFleetUpdateRewrites({
      proposedConfig,
      productFeaturesService: productFeatures([
        ProductFeatureSecurityKey.endpointPolicyProtections,
      ]),
      experimentalFeatures: experimentalFeatures({ trustedDevices: true }),
    });

    expect(preview.persistedConfig.windows.malware.mode).toBe(ProtectionModes.off);
    expect(preview.persistedConfig.windows.device_control).toBeDefined();
    expect(preview.persistedConfig.windows.antivirus_registration.enabled).toBe(false);
    expect(preview.validationConfig.windows.malware.mode).toBe(ProtectionModes.prevent);
  });

  it('removes device control when trustedDevices experimental state is off', () => {
    const proposedConfig = policyFactory();

    const preview = previewFleetUpdateRewrites({
      proposedConfig,
      productFeaturesService: productFeatures(),
      experimentalFeatures: experimentalFeatures({ trustedDevices: false }),
    });

    expect(preview.persistedConfig.windows.malware.mode).toBe(ProtectionModes.prevent);
    expect(preview.persistedConfig.windows).not.toHaveProperty('device_control');
    expect(preview.validationConfig.windows.device_control).toBeDefined();
  });

  it('dual gates persist removeDeviceControl(working), not sequential events-only composition', () => {
    const proposedConfig = policyFactory();
    const ensureSpy = jest.spyOn(PolicyConfigHelpers, 'ensureOnlyEventCollectionIsAllowed');
    const removeSpy = jest.spyOn(PolicyConfigHelpers, 'removeDeviceControl');

    const preview = previewFleetUpdateRewrites({
      proposedConfig,
      productFeaturesService: productFeatures([
        ProductFeatureSecurityKey.endpointPolicyProtections,
        ProductFeatureSecurityKey.endpointTrustedDevices,
      ]),
      experimentalFeatures: experimentalFeatures({ trustedDevices: true }),
    });

    expect(ensureSpy).toHaveBeenCalledTimes(1);
    expect(removeSpy).toHaveBeenCalledTimes(1);
    expect(removeSpy.mock.calls[0][0]).toBe(ensureSpy.mock.calls[0][0]);
    expect(preview.persistedConfig.windows.malware.mode).toBe(ProtectionModes.prevent);
    expect(preview.persistedConfig.windows).not.toHaveProperty('device_control');
    expect(preview.persistedConfig.windows.antivirus_registration.enabled).toBe(true);

    const sequential = removeDeviceControl(
      ensureOnlyEventCollectionIsAllowed(cloneDeep(proposedConfig))
    );
    expect(sequential.windows.malware.mode).toBe(ProtectionModes.off);
    expect(preview.persistedConfig.windows.malware.mode).not.toBe(sequential.windows.malware.mode);
  });
});
