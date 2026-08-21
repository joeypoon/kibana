/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { diffPolicyConfig } from '../diff';
import * as fieldRegistry from '../field_registry';
import { normalize } from '../normalize';
import { expandChangeSet } from './expand_change_set';
import { assertParameterBounds } from './parameter_bounds';
import type {
  PreparedPolicyChangeAssessment,
  PolicyChangeSideEffect,
} from './policy_change_operation';
import {
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  PolicyChangePreparationError,
  nonWritablePathMessage,
  parseAssessPolicyChangeParams,
} from './policy_change_operation';
import { validateSetFieldValue } from './validate_set_field_value';

const toDerivedSideEffect = (path: string, from: unknown, to: unknown): PolicyChangeSideEffect => {
  const entry = fieldRegistry.getFieldRegistryEntry(path);
  if (entry === undefined) {
    throw new PolicyChangePreparationError(
      POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
      nonWritablePathMessage(path)
    );
  }

  return {
    path,
    from,
    to,
    reason: 'derived_field_update',
    registry: {
      path: entry.path,
      os: entry.os,
      kind: entry.kind,
      tier: entry.tier,
      source: entry.source,
    },
  };
};

export const prepareChangeSet = (
  rawParams: unknown,
  currentConfig: PolicyConfig
): PreparedPolicyChangeAssessment => {
  assertParameterBounds(rawParams);
  const params = parseAssessPolicyChangeParams(rawParams);

  for (const operation of params.changes) {
    if (operation.op === 'set_field') {
      validateSetFieldValue(operation.path, operation.value);
    }
  }

  const prepared = expandChangeSet(params.changes, currentConfig);
  const normalizedDiff = diffPolicyConfig(
    normalize(currentConfig),
    normalize(prepared.proposedConfig)
  );
  const sideEffects = normalizedDiff
    .filter((entry) => fieldRegistry.isDerivedPath(entry.path))
    .map((entry) => toDerivedSideEffect(entry.path, entry.from, entry.to));

  return {
    ...prepared,
    normalizedDiff,
    sideEffects,
  };
};
