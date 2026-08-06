/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger } from '@kbn/core/server';
import type { NewPackagePolicyInput } from '@kbn/fleet-plugin/common';

import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import type { PolicyValidatorOutcome } from '../../domain/impact/types';
import type { LicenseService } from '../../../../../../common/license';
import type { ProductFeaturesService } from '../../../../../lib/product_features_service';
import { validateEndpointPackagePolicy } from '../../../../../fleet_integration/handlers/validate_endpoint_package_policy';
import { validatePolicyAgainstLicense } from '../../../../../fleet_integration/handlers/validate_policy_against_license';
import { validatePolicyAgainstProductFeatures } from '../../../../../fleet_integration/handlers/validate_policy_against_product_features';

export interface ComposeValidatorsArgs {
  readonly proposedConfig: PolicyConfig;
  readonly inputs: readonly NewPackagePolicyInput[];
  readonly licenseService: LicenseService;
  readonly productFeaturesService: ProductFeaturesService;
  readonly logger: Logger;
}

const ENDPOINT_INPUT_TYPE = 'endpoint';

export const composePolicyValidators = ({
  proposedConfig,
  inputs,
  licenseService,
  productFeaturesService,
  logger,
}: ComposeValidatorsArgs): PolicyValidatorOutcome[] => {
  const proposedInputs: NewPackagePolicyInput[] = inputs.map((input) =>
    input.type === ENDPOINT_INPUT_TYPE
      ? {
          ...input,
          config: {
            ...input.config,
            policy: { ...input.config?.policy, value: proposedConfig },
          },
        }
      : input
  );

  return [
    runValidator('package_policy', () => validateEndpointPackagePolicy(proposedInputs, 'update')),
    runValidator('license', () =>
      validatePolicyAgainstLicense(proposedConfig, licenseService, logger)
    ),
    runValidator('product_features', () =>
      validatePolicyAgainstProductFeatures(proposedInputs, productFeaturesService)
    ),
  ];
};

const runValidator = (
  validator: PolicyValidatorOutcome['validator'],
  validate: () => void
): PolicyValidatorOutcome => {
  try {
    validate();

    return { validator, passed: true };
  } catch (error) {
    return {
      validator,
      passed: false,
      message: error instanceof Error ? error.message : String(error),
    };
  }
};
