/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger } from '@kbn/core/server';
import type { NewPackagePolicyInput } from '@kbn/fleet-plugin/common';

import type { ExperimentalFeatures } from '../../../../../../common';
import type {
  PolicyChangeAssessment,
  PolicyChangeProposal,
  PolicyChangeRejection,
} from '../../domain/impact/types';
import type { PolicyFieldRegistry } from '../../domain/field_registry/types';
import type { AssignmentEvidence, PolicySnapshot } from '../../domain/read/types';
import { buildImpactFieldLookup } from '../../domain/impact/field_lookup';
import { applyChangeProposal } from '../../domain/impact/apply_proposal';
import { unionPersistPreviewDiffs } from '../../domain/impact/diff_proposal';
import { labelChangeEvidence } from '../../domain/impact/label_evidence';
import type { LicenseService } from '../../../../../../common/license';
import type { ProductFeaturesService } from '../../../../../lib/product_features_service';
import { composePolicyValidators } from './compose_validators';
import { previewFleetUpdateRewrites } from './fleet_update_rewrite_preview';

export interface AssessPolicyChangeArgs {
  readonly proposal: PolicyChangeProposal;
  readonly snapshot: PolicySnapshot;
  readonly registry: PolicyFieldRegistry;
  readonly inputs: readonly NewPackagePolicyInput[];
  readonly population: AssignmentEvidence;
  readonly licenseService: LicenseService;
  readonly productFeaturesService: ProductFeaturesService;
  readonly experimentalFeatures: ExperimentalFeatures;
  readonly logger: Logger;
}

export type AssessPolicyChangeResult =
  | { readonly assessment: PolicyChangeAssessment }
  | { readonly rejection: PolicyChangeRejection };

export const assessPolicyChange = ({
  proposal,
  snapshot,
  registry,
  inputs,
  population,
  licenseService,
  productFeaturesService,
  experimentalFeatures,
  logger,
}: AssessPolicyChangeArgs): AssessPolicyChangeResult => {
  const lookup = buildImpactFieldLookup(registry);
  const applied = applyChangeProposal({ proposal, snapshot, lookup });

  if ('rejection' in applied) {
    return { rejection: applied.rejection };
  }

  const proposedConfig = applied.config;
  const { validationConfig, persistedConfig } = previewFleetUpdateRewrites({
    proposedConfig,
    productFeaturesService,
    experimentalFeatures,
  });

  const validatorOutcomes = composePolicyValidators({
    proposedConfig: validationConfig,
    inputs,
    licenseService,
    productFeaturesService,
    logger,
  });

  const diffs = unionPersistPreviewDiffs({
    before: snapshot.config,
    proposed: proposedConfig,
    persisted: persistedConfig,
    proposal,
    lookup,
    packageVersion: snapshot.packageVersion,
  });

  const { verifiedConfigurationEffects, likelyPopulationEffects, unknowns } = labelChangeEvidence({
    identity: snapshot.identity,
    diffs,
    validatorOutcomes,
    population,
  });

  return {
    assessment: {
      proposal,
      assessedIdentity: snapshot.identity,
      diffs,
      validatorOutcomes,
      verifiedConfigurationEffects,
      likelyPopulationEffects,
      unknowns,
      applied: false,
    },
  };
};
