/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { Subject } from 'rxjs';
import type { ILicense } from '@kbn/licensing-types';
import { licenseMock } from '@kbn/licensing-plugin/common/licensing.mock';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import { ALL_PRODUCT_FEATURE_KEYS } from '@kbn/security-solution-features/keys';
import type { NewPackagePolicyInput } from '@kbn/fleet-plugin/common';

import { LicenseService } from '../../../../../../common/license';
import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { DeviceControlAccessLevel, ProtectionModes } from '../../../../../../common/endpoint/types';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { createProductFeaturesServiceMock } from '../../../../../lib/product_features_service/mocks';
import type { ProductFeaturesService } from '../../../../../lib/product_features_service';
import { composePolicyValidators } from './compose_validators';

const buildInputs = (config: PolicyConfig): NewPackagePolicyInput[] => [
  { type: 'system', enabled: true, streams: [] },
  {
    type: 'endpoint',
    enabled: true,
    streams: [],
    config: {
      artifact_manifest: { value: { artifacts: {}, manifest_version: '1', schema_version: 'v1' } },
      policy: { value: config },
    },
  },
];

describe('composePolicyValidators', () => {
  const logger = loggingSystemMock.createLogger();
  const Platinum = licenseMock.createLicense({
    license: { type: 'platinum', mode: 'platinum', uid: 'uid' },
  });
  const Gold = licenseMock.createLicense({ license: { type: 'gold', mode: 'gold', uid: 'uid' } });
  const Enterprise = licenseMock.createLicense({ license: { type: 'enterprise', uid: 'uid' } });

  let licenseEmitter: Subject<ILicense>;
  let licenseService: LicenseService;
  let productFeaturesService: ProductFeaturesService;

  beforeEach(() => {
    licenseEmitter = new Subject();
    licenseService = new LicenseService();
    licenseService.start(licenseEmitter);
    licenseEmitter.next(Enterprise);
    productFeaturesService = createProductFeaturesServiceMock();
  });

  afterEach(() => {
    licenseService.stop();
  });

  it('reports all three validators as passing for a default policy', () => {
    const proposedConfig = policyFactory();

    expect(
      composePolicyValidators({
        proposedConfig,
        inputs: buildInputs(proposedConfig),
        licenseService,
        productFeaturesService,
        logger,
      })
    ).toEqual([
      { validator: 'package_policy', passed: true },
      { validator: 'license', passed: true },
      { validator: 'product_features', passed: true },
    ]);
  });

  it('surfaces the package-policy validator message verbatim', () => {
    const proposedConfig = policyFactory();
    proposedConfig.global_manifest_version = 'not-a-date';

    const outcomes = composePolicyValidators({
      proposedConfig,
      inputs: buildInputs(policyFactory()),
      licenseService,
      productFeaturesService,
      logger,
    });

    const packagePolicy = outcomes.find(({ validator }) => validator === 'package_policy');

    expect(packagePolicy).toEqual({
      validator: 'package_policy',
      passed: false,
      message: 'Invalid date format. Use "latest" or "YYYY-MM-DD" format. UTC time.',
    });
  });

  it('surfaces the license validator message verbatim and does not suppress the others', () => {
    licenseEmitter.next(Gold);

    const proposedConfig = policyFactory();
    proposedConfig.windows.device_control = {
      enabled: true,
      usb_storage: DeviceControlAccessLevel.deny_all,
    };

    const outcomes = composePolicyValidators({
      proposedConfig,
      inputs: buildInputs(policyFactory()),
      licenseService,
      productFeaturesService,
      logger,
    });

    expect(outcomes.find(({ validator }) => validator === 'license')).toEqual({
      validator: 'license',
      passed: false,
      message: 'Gold license does not support this action. Please upgrade your license.',
    });

    expect(outcomes).toHaveLength(3);
    expect(outcomes.map(({ validator }) => validator)).toEqual([
      'package_policy',
      'license',
      'product_features',
    ]);
  });

  it('surfaces the product-features validator message verbatim', () => {
    productFeaturesService = createProductFeaturesServiceMock(
      ALL_PRODUCT_FEATURE_KEYS.filter((key) => key !== 'endpoint_protection_updates')
    );

    const proposedConfig = policyFactory();
    proposedConfig.global_manifest_version = '2024-01-01';

    const outcomes = composePolicyValidators({
      proposedConfig,
      inputs: buildInputs(policyFactory()),
      licenseService,
      productFeaturesService,
      logger,
    });

    expect(outcomes.find(({ validator }) => validator === 'product_features')).toEqual({
      validator: 'product_features',
      passed: false,
      message: 'To modify protection updates, you must add Endpoint Complete to your project.',
    });
  });

  it('validates the PROPOSED config rather than the stored one', () => {
    licenseEmitter.next(Platinum);

    const storedConfig = policyFactory();
    const proposedConfig = policyFactory();
    proposedConfig.windows.device_control = {
      enabled: true,
      usb_storage: DeviceControlAccessLevel.deny_all,
    };

    const outcomes = composePolicyValidators({
      proposedConfig,
      inputs: buildInputs(storedConfig),
      licenseService,
      productFeaturesService,
      logger,
    });

    expect(outcomes.find(({ validator }) => validator === 'license')?.passed).toBe(false);
  });

  it('selects the endpoint input by type, not by position', () => {
    const proposedConfig = policyFactory();
    proposedConfig.windows.device_control = {
      enabled: true,
      usb_storage: DeviceControlAccessLevel.audit,
    };
    proposedConfig.windows.popup.device_control = { enabled: true, message: 'blocked' };

    const outcomes = composePolicyValidators({
      proposedConfig,
      inputs: buildInputs(policyFactory()),
      licenseService,
      productFeaturesService,
      logger,
    });

    expect(outcomes.find(({ validator }) => validator === 'package_policy')).toEqual({
      validator: 'package_policy',
      passed: false,
      message:
        'Device Control user notifications are only supported when USB storage access level is set to deny_all. Current Windows access level is "audit". Please either set the access level to deny_all or disable user notifications.',
    });
  });

  it('does not mutate the inputs it was given', () => {
    const storedConfig = policyFactory();
    const inputs = buildInputs(storedConfig);
    const inputsSnapshot = JSON.stringify(inputs);

    const proposedConfig = policyFactory();
    proposedConfig.windows.malware.mode = ProtectionModes.off;

    composePolicyValidators({
      proposedConfig,
      inputs,
      licenseService,
      productFeaturesService,
      logger,
    });

    expect(JSON.stringify(inputs)).toEqual(inputsSnapshot);
  });
});
