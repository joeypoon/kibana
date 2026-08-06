/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyConfig, PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import type {
  PolicyFieldRecord,
  PolicyFieldRegistry,
  PolicyFieldValueType,
} from '../field_registry/types';
import {
  COMPARABLE_APPLICABILITY,
  evaluateFieldApplicability,
} from '../field_registry/applicability';
import type { UnrecoverableDefault } from './default_variants';
import { getUnrecoverableDefaults } from './default_variants';
import { buildPolicyFieldIndex, POLICY_OPERATING_SYSTEMS } from './field_index';
import { collectPolicyLeafPaths } from './leaf_paths';
import { classifyPopupMessage } from './popup_message';
import type { AnnotatedPolicyField, ExplicitVsDefault, StoredIndeterminateReason } from './types';

export const storedValueMatchesDefault = (
  type: PolicyFieldValueType,
  value: unknown,
  shippedDefault: unknown
): boolean => {
  if (value === shippedDefault) {
    return true;
  }

  if (typeof value !== 'string') {
    return false;
  }

  if (type === 'number' && typeof shippedDefault === 'number') {
    const parsed = Number(value);

    return Number.isFinite(parsed) && String(parsed) === value && parsed === shippedDefault;
  }

  if (type === 'boolean' && typeof shippedDefault === 'boolean') {
    return shippedDefault ? value === 'true' : value === 'false';
  }

  return false;
};

interface AnnotateExplicitVsDefaultArgs {
  readonly config: PolicyConfig;
  readonly registry: PolicyFieldRegistry;
  readonly packageVersion: string;
}

const decideState = (
  field: PolicyFieldRecord,
  value: unknown,
  unrecoverable: UnrecoverableDefault | undefined
): {
  state: ExplicitVsDefault;
  indeterminateReason?: string;
  indeterminateReasonCode?: StoredIndeterminateReason;
} => {
  const { keyPath, license, type, default: defaultValue, defaultSource } = field;

  const candidates = unrecoverable?.candidates;

  if (
    candidates !== undefined &&
    !candidates.some((candidate) => storedValueMatchesDefault(type, value, candidate))
  ) {
    return { state: 'explicit' };
  }

  if (license !== undefined) {
    return {
      state: 'indeterminate',
      indeterminateReasonCode: 'license_gated_default_unrecoverable',
      indeterminateReason:
        `Field requires a minimum license of '${license}', and the stored policy does not ` +
        `record the license tier in effect when it was created, so the correct default ` +
        `variant for '${keyPath}' is unrecoverable.`,
    };
  }

  if (unrecoverable !== undefined) {
    return {
      state: 'indeterminate',
      indeterminateReasonCode: 'creation_input_unrecoverable',
      indeterminateReason:
        `The shipped default for '${keyPath}' depends on ${unrecoverable.input}, which the ` +
        `stored policy does not record. The stored value matches one of the shipped defaults ` +
        `(${candidates?.map((candidate) => JSON.stringify(candidate)).join(' or ')}), so it ` +
        `cannot be told apart from a policy left at its default.`,
    };
  }

  if (defaultSource === 'unknown') {
    return {
      state: 'indeterminate',
      indeterminateReasonCode: 'no_recoverable_default',
      indeterminateReason:
        `No default value for '${keyPath}' is recoverable from any in-repo source ` +
        `(defaultSource is 'unknown'), so the stored value cannot be compared against one.`,
    };
  }

  if (defaultValue === undefined) {
    return {
      state: 'indeterminate',
      indeterminateReasonCode: 'registry_default_missing',
      indeterminateReason:
        `The registry reports defaultSource '${defaultSource}' for '${keyPath}' but carries ` +
        `no default value, so the stored value cannot be compared against one.`,
    };
  }

  const popupState = classifyPopupMessage(keyPath, value);

  if (popupState !== undefined) {
    return { state: popupState === 'default' ? 'default' : 'explicit' };
  }

  return { state: storedValueMatchesDefault(type, value, defaultValue) ? 'default' : 'explicit' };
};

export const annotateExplicitVsDefault = ({
  config,
  registry,
  packageVersion,
}: AnnotateExplicitVsDefaultArgs): AnnotatedPolicyField[] => {
  const index = buildPolicyFieldIndex(registry);
  const unrecoverable = getUnrecoverableDefaults();
  const annotated: AnnotatedPolicyField[] = [];

  const annotate = (
    field: PolicyFieldRecord,
    value: unknown,
    unrecoverableDefault: UnrecoverableDefault | undefined,
    os?: PolicyOperatingSystem
  ): void => {
    if (COMPARABLE_APPLICABILITY[evaluateFieldApplicability(field, packageVersion)] !== true) {
      return;
    }

    const { state, indeterminateReason, indeterminateReasonCode } = decideState(
      field,
      value,
      unrecoverableDefault
    );

    annotated.push({
      keyPath: field.keyPath,
      ...(os === undefined ? {} : { os }),
      value,
      defaultValue: field.default,
      state,
      ...(indeterminateReason === undefined ? {} : { indeterminateReason }),
      ...(indeterminateReasonCode === undefined ? {} : { indeterminateReasonCode }),
    });
  };

  for (const os of POLICY_OPERATING_SYSTEMS) {
    const known = index.byOs.get(os);

    if (known !== undefined && known.size > 0) {
      const unrecoverableForOs = unrecoverable.byOs.get(os);

      for (const [keyPath, value] of collectPolicyLeafPaths(config[os])) {
        const field = known.get(keyPath);

        if (field !== undefined) {
          annotate(field, value, unrecoverableForOs?.get(keyPath), os);
        }
      }
    }
  }

  for (const [keyPath, value] of collectPolicyLeafPaths({
    global_manifest_version: config.global_manifest_version,
    global_telemetry_enabled: config.global_telemetry_enabled,
  })) {
    const field = index.root.get(keyPath);

    if (field !== undefined) {
      annotate(field, value, unrecoverable.root.get(keyPath));
    }
  }

  return annotated;
};
