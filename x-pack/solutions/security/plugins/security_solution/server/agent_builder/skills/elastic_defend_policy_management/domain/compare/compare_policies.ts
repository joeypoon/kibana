/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import type { PolicyFieldRegistry } from '../field_registry/types';
import { buildPolicyFieldIndex, POLICY_OPERATING_SYSTEMS } from '../normalize/field_index';
import type { NormalizedPolicyConfig } from '../normalize/types';
import { areStoredValuesEqual } from './hash_policy_config';
import type { PolicyComparison, PolicyFieldDifference } from './types';

export interface ComparablePolicy {
  readonly id: string;
  readonly packageVersion: string;
  readonly configNormalized: NormalizedPolicyConfig;
}

interface ComparePoliciesArgs {
  readonly left: ComparablePolicy;
  readonly right: ComparablePolicy;
  readonly registry: PolicyFieldRegistry;
}

const sortedStoredKnownKeyPaths = (
  leftBranch: Readonly<Record<string, unknown>>,
  rightBranch: Readonly<Record<string, unknown>>
): string[] =>
  [...new Set([...Object.keys(leftBranch), ...Object.keys(rightBranch)])].sort(
    (leftPath, rightPath) => leftPath.localeCompare(rightPath)
  );

const recordStoredLeaf = ({
  differences,
  notComparable,
  keyPath,
  os,
  leftBranch,
  rightBranch,
  unrecognized,
}: {
  readonly differences: PolicyFieldDifference[];
  readonly notComparable: PolicyFieldDifference[];
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
  readonly leftBranch: Readonly<Record<string, unknown>>;
  readonly rightBranch: Readonly<Record<string, unknown>>;
  readonly unrecognized?: true;
}): void => {
  const leftHas = Object.hasOwn(leftBranch, keyPath);
  const rightHas = Object.hasOwn(rightBranch, keyPath);

  if (!leftHas && !rightHas) {
    return;
  }

  const difference: PolicyFieldDifference = {
    keyPath,
    ...(os === undefined ? {} : { os }),
    leftPresent: leftHas,
    rightPresent: rightHas,
    left: leftBranch[keyPath],
    right: rightBranch[keyPath],
    ...(unrecognized === undefined ? {} : { unrecognized }),
  };

  if (!leftHas || !rightHas) {
    notComparable.push(difference);
    return;
  }

  if (!areStoredValuesEqual(difference.left, difference.right)) {
    differences.push(difference);
  }
};

export const comparePolicies = ({
  left,
  right,
  registry,
}: ComparePoliciesArgs): PolicyComparison => {
  const index = buildPolicyFieldIndex(registry);
  const differences: PolicyFieldDifference[] = [];
  const notComparable: PolicyFieldDifference[] = [];

  for (const os of POLICY_OPERATING_SYSTEMS) {
    const known = index.byOs.get(os);
    const leftBranch = left.configNormalized.perOs[os];
    const rightBranch = right.configNormalized.perOs[os];

    for (const keyPath of sortedStoredKnownKeyPaths(leftBranch, rightBranch)) {
      if (known?.has(keyPath) === true) {
        recordStoredLeaf({
          differences,
          notComparable,
          keyPath,
          os,
          leftBranch,
          rightBranch,
        });
      }
    }

    const leftUnrecognized = left.configNormalized.unrecognizedPerOs[os];
    const rightUnrecognized = right.configNormalized.unrecognizedPerOs[os];

    for (const keyPath of new Set([
      ...Object.keys(leftUnrecognized),
      ...Object.keys(rightUnrecognized),
    ])) {
      recordStoredLeaf({
        differences,
        notComparable,
        keyPath,
        os,
        leftBranch: leftUnrecognized,
        rightBranch: rightUnrecognized,
        unrecognized: true,
      });
    }
  }

  const { globalTelemetryEnabled: leftTelemetry, globalManifestVersion: leftPin } =
    left.configNormalized;
  const { globalTelemetryEnabled: rightTelemetry, globalManifestVersion: rightPin } =
    right.configNormalized;

  if (!areStoredValuesEqual(leftTelemetry, rightTelemetry)) {
    differences.push({
      keyPath: 'global_telemetry_enabled',
      leftPresent: true,
      rightPresent: true,
      left: leftTelemetry,
      right: rightTelemetry,
    });
  }

  return {
    leftId: left.id,
    rightId: right.id,
    configIdentical: differences.length === 0 && notComparable.length === 0,
    protectionUpdatesPinDiffers: leftPin !== rightPin,
    leftGlobalManifestVersion: leftPin,
    rightGlobalManifestVersion: rightPin,
    differences,
    notComparable,
  };
};
