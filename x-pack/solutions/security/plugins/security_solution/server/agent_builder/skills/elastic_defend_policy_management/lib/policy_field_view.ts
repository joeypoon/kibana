/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyConfig, PolicyOperatingSystem } from '../../../../../common/endpoint/types';
import type {
  PolicyFieldApplicability,
  PolicyFieldRecord,
  PolicyFieldRegistry,
} from '../domain/field_registry/types';
import { evaluateFieldApplicability } from '../domain/field_registry/applicability';
import type {
  AnnotatedPolicyField,
  ExplicitVsDefault,
  StoredIndeterminateReason,
} from '../domain/normalize/types';
import { annotateExplicitVsDefault } from '../domain/normalize/annotate_explicit_vs_default';
import { collectPolicyLeafPaths } from '../domain/normalize/leaf_paths';
import { isExcludedKeyPath } from '../domain/normalize/exclusions';
import { POLICY_OPERATING_SYSTEMS } from '../domain/normalize/field_index';

type UnstoredIndeterminateReason =
  | 'license_gated_default_unrecoverable'
  /** The registry records no usable default for this field. */
  | 'no_recoverable_default'
  /** A non-advanced key the stored policy omits: the feature may not be present at all. */
  | 'feature_may_be_absent';

export type IndeterminateReasonCode = UnstoredIndeterminateReason | StoredIndeterminateReason;

interface RecognizedPolicyFieldReport {
  readonly unrecognized?: false;
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
  readonly value: unknown;
  readonly defaultValue?: unknown;
  readonly state: ExplicitVsDefault;
  readonly indeterminateReason?: string;
  readonly indeterminateReasonCode?: IndeterminateReasonCode;
  readonly stored: boolean;
  readonly applicability: PolicyFieldApplicability;
  readonly category: PolicyFieldRecord['category'];
  readonly type: PolicyFieldRecord['type'];
  readonly enumValues?: PolicyFieldRecord['enumValues'];
  readonly documentation?: PolicyFieldRecord['documentation'];
}

interface UnrecognizedPolicyFieldReport {
  readonly unrecognized: true;
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
  readonly value: unknown;
  readonly state: 'explicit';
  readonly stored: true;
  readonly applicability: 'unknown';
  readonly defaultValue?: never;
  readonly indeterminateReason?: never;
  readonly indeterminateReasonCode?: never;
  readonly category?: never;
  readonly type?: never;
  readonly enumValues?: never;
  readonly documentation?: never;
}

export type PolicyFieldReport = RecognizedPolicyFieldReport | UnrecognizedPolicyFieldReport;

interface UnstoredVerdict {
  readonly state: ExplicitVsDefault;
  readonly indeterminateReason?: string;
  readonly indeterminateReasonCode?: UnstoredIndeterminateReason;
}

const describeUnstoredField = (field: PolicyFieldRecord): UnstoredVerdict => {
  const { keyPath, category, license, default: defaultValue, defaultSource } = field;

  if (category !== 'advanced') {
    return {
      state: 'indeterminate',
      indeterminateReasonCode: 'feature_may_be_absent',
      indeterminateReason:
        `'${keyPath}' is advertised by the Elastic Defend policy schema but is absent from this ` +
        `policy's stored configuration. For a '${category}' setting that does not necessarily mean ` +
        `it is at its default: the feature may have been removed from the policy by the license ` +
        `tier or a feature flag. The effective value cannot be stated from configuration alone.`,
    };
  }

  if (license !== undefined) {
    return {
      state: 'indeterminate',
      indeterminateReasonCode: 'license_gated_default_unrecoverable',
      indeterminateReason:
        `'${keyPath}' is not set on this policy, so its shipped default applies — but the field ` +
        `requires a minimum license of '${license}' and the stored policy does not record the ` +
        `license tier in effect when it was created, so the correct default variant is unrecoverable.`,
    };
  }

  if (defaultSource === 'unknown' || defaultValue === undefined) {
    return {
      state: 'indeterminate',
      indeterminateReasonCode: 'no_recoverable_default',
      indeterminateReason:
        `'${keyPath}' is not set on this policy, so its shipped default applies — but no default ` +
        `value for it is recoverable from any in-repo source, so the effective value cannot be stated.`,
    };
  }

  return { state: 'default' };
};

interface BuildPolicyFieldReportsOptions {
  readonly config: PolicyConfig;
  readonly registry: PolicyFieldRegistry;
  readonly packageVersion: string;
}

const STATE_ORDER: Record<ExplicitVsDefault, number> = {
  explicit: 0,
  indeterminate: 1,
  default: 2,
};

export const buildPolicyFieldReports = ({
  config,
  registry,
  packageVersion,
}: BuildPolicyFieldReportsOptions): readonly PolicyFieldReport[] => {
  const annotatedByKey = new Map<string, AnnotatedPolicyField>();

  for (const annotated of annotateExplicitVsDefault({ config, registry, packageVersion })) {
    annotatedByKey.set(`${annotated.os ?? 'root'}|${annotated.keyPath}`, annotated);
  }

  const storedLeaves = new Map<string, unknown>();

  for (const os of POLICY_OPERATING_SYSTEMS) {
    for (const [keyPath, value] of collectPolicyLeafPaths(config[os])) {
      storedLeaves.set(`${os}|${keyPath}`, value);
    }
  }

  for (const [keyPath, value] of collectPolicyLeafPaths({
    global_manifest_version: config.global_manifest_version,
    global_telemetry_enabled: config.global_telemetry_enabled,
  })) {
    storedLeaves.set(`root|${keyPath}`, value);
  }

  const reports: PolicyFieldReport[] = [];
  const registryKeyPaths = new Set<string>();

  const addReport = (field: PolicyFieldRecord, os?: PolicyOperatingSystem): void => {
    const key = `${os ?? 'root'}|${field.keyPath}`;
    const isStored = storedLeaves.has(key);
    const observed = storedLeaves.get(key);

    storedLeaves.delete(key);

    const annotated = annotatedByKey.get(key);
    const applicability = evaluateFieldApplicability(field, packageVersion);
    const shared = {
      keyPath: field.keyPath,
      ...(os === undefined ? {} : { os }),
      applicability,
      category: field.category,
      type: field.type,
      ...(field.enumValues === undefined ? {} : { enumValues: field.enumValues }),
      ...(field.documentation === undefined ? {} : { documentation: field.documentation }),
    };

    if (annotated !== undefined) {
      reports.push({
        ...shared,
        value: annotated.value,
        ...(annotated.defaultValue === undefined ? {} : { defaultValue: annotated.defaultValue }),
        state: annotated.state,
        ...(annotated.indeterminateReason === undefined
          ? {}
          : { indeterminateReason: annotated.indeterminateReason }),
        ...(annotated.indeterminateReasonCode === undefined
          ? {}
          : { indeterminateReasonCode: annotated.indeterminateReasonCode }),
        stored: true,
      });

      return;
    }

    if (isStored) {
      const hasRecoverableDefault =
        field.license === undefined &&
        field.defaultSource !== 'unknown' &&
        field.default !== undefined;

      reports.push({
        ...shared,
        value: observed,
        ...(field.default === undefined ? {} : { defaultValue: field.default }),
        ...(hasRecoverableDefault
          ? { state: observed === field.default ? 'default' : 'explicit' }
          : {
              state: 'indeterminate',
              indeterminateReasonCode: 'no_recoverable_default',
              indeterminateReason:
                `'${field.keyPath}' is set on this policy, but no default value for it is ` +
                `recoverable from any in-repo source, so whether the stored value was deliberately ` +
                `chosen or is the shipped default cannot be stated.`,
            }),
        stored: true,
      });

      return;
    }

    const { state, indeterminateReason, indeterminateReasonCode } = describeUnstoredField(field);

    reports.push({
      ...shared,
      value: state === 'default' ? field.default : undefined,
      ...(field.default === undefined ? {} : { defaultValue: field.default }),
      state,
      ...(indeterminateReason === undefined ? {} : { indeterminateReason }),
      ...(indeterminateReasonCode === undefined ? {} : { indeterminateReasonCode }),
      stored: false,
    });
  };

  for (const field of registry.fields) {
    registryKeyPaths.add(field.keyPath);

    if (field.configurable) {
      if (field.os.length === 0) {
        addReport(field);
      } else {
        for (const os of field.os) {
          addReport(field, os);
        }
      }
    }
  }

  for (const [key, value] of storedLeaves) {
    const separator = key.indexOf('|');
    const scope = key.slice(0, separator);
    const keyPath = key.slice(separator + 1);

    if (!isExcludedKeyPath(keyPath) && !registryKeyPaths.has(keyPath)) {
      reports.push({
        unrecognized: true,
        keyPath,
        ...(scope === 'root' ? {} : { os: scope as PolicyOperatingSystem }),
        value,
        state: 'explicit',
        stored: true,
        applicability: 'unknown',
      });
    }
  }

  return reports.sort((left, right) => {
    const byState = STATE_ORDER[left.state] - STATE_ORDER[right.state];

    if (byState !== 0) {
      return byState;
    }

    const byOs = (left.os ?? '').localeCompare(right.os ?? '');

    return byOs !== 0 ? byOs : left.keyPath.localeCompare(right.keyPath);
  });
};

export interface PolicyFieldSummary {
  readonly total: number;
  readonly explicit: number;
  readonly default: number;
  readonly indeterminate: number;
  readonly notStored: number;
  readonly applicable: number;
  readonly versionUnavailable: number;
  readonly unsupported: number;
  readonly unrecognized: number;
}

export const summarizePolicyFields = (
  reports: readonly PolicyFieldReport[]
): PolicyFieldSummary => {
  let explicit = 0;
  let byDefault = 0;
  let indeterminate = 0;
  let notStored = 0;
  let applicable = 0;
  let versionUnavailable = 0;
  let unsupported = 0;
  let unrecognized = 0;

  for (const { state, stored, applicability, unrecognized: isUnrecognized } of reports) {
    if (state === 'explicit') explicit += 1;
    else if (state === 'default') byDefault += 1;
    else indeterminate += 1;

    if (!stored) notStored += 1;

    if (applicability === 'applicable') applicable += 1;
    else if (applicability === 'version_unavailable') versionUnavailable += 1;
    else if (applicability === 'unsupported') unsupported += 1;

    if (isUnrecognized === true) unrecognized += 1;
  }

  return {
    total: reports.length,
    explicit,
    default: byDefault,
    indeterminate,
    notStored,
    applicable,
    versionUnavailable,
    unsupported,
    unrecognized,
  };
};

export type PolicyDetailSettingsFilter = 'stored' | 'all' | 'explicit_only';

export const selectPolicyFieldReports = ({
  reports,
  settingsFilter,
  keyPaths,
  category,
}: {
  readonly reports: readonly PolicyFieldReport[];
  readonly settingsFilter: PolicyDetailSettingsFilter;
  readonly keyPaths?: readonly string[];
  readonly category?: PolicyFieldRecord['category'];
}): readonly PolicyFieldReport[] => {
  const selectionRequested = keyPaths !== undefined || category !== undefined;
  const requestedKeyPaths = keyPaths === undefined ? undefined : new Set(keyPaths);

  return reports.filter((report) => {
    if (requestedKeyPaths !== undefined && !requestedKeyPaths.has(report.keyPath)) {
      return false;
    }

    if (category !== undefined && report.category !== category) {
      return false;
    }

    if (settingsFilter === 'explicit_only') {
      return report.state === 'explicit';
    }

    if (settingsFilter === 'stored') {
      return report.stored || selectionRequested;
    }

    return true;
  });
};
