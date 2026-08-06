/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import semverCoerce from 'semver/functions/coerce';

import type {
  PolicyFieldApplicability,
  PolicyFieldRecord,
  PolicyFieldRegistry,
  RegistryVersionUnknown,
} from './types';

type BoundPrecision = 1 | 2 | 3;

interface PartialBound {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly precision: BoundPrecision;
}

export const COMPARABLE_APPLICABILITY: Readonly<Partial<Record<PolicyFieldApplicability, true>>> = {
  applicable: true,
  unknown: true,
};

const parsePartialBound = (bound: string): PartialBound | null => {
  const trimmed = bound.trim();

  if (trimmed.length === 0) {
    return null;
  }

  const coerced = semverCoerce(trimmed);

  if (coerced === null) {
    return null;
  }

  const declaredSegments = trimmed.split('.').length;
  const precision: BoundPrecision = declaredSegments >= 3 ? 3 : declaredSegments === 2 ? 2 : 1;

  const { major, minor, patch } = coerced;

  return { major, minor, patch, precision };
};

export const compareVersionToPartialBound = (
  packageVersion: string,
  bound: string
): number | null => {
  const parsedBound = parsePartialBound(bound);
  const parsedVersion = semverCoerce(packageVersion.trim());

  if (parsedBound === null || parsedVersion === null) {
    return null;
  }

  if (parsedVersion.major !== parsedBound.major) {
    return parsedVersion.major - parsedBound.major;
  }

  if (parsedBound.precision === 1) {
    return 0;
  }

  if (parsedVersion.minor !== parsedBound.minor) {
    return parsedVersion.minor - parsedBound.minor;
  }

  if (parsedBound.precision === 2) {
    return 0;
  }

  return parsedVersion.patch - parsedBound.patch;
};

export const evaluateFieldApplicability = (
  field: PolicyFieldRecord,
  packageVersion: string
): PolicyFieldApplicability => {
  const { firstSupportedVersion, lastSupportedVersion } = field;

  if (firstSupportedVersion === undefined && lastSupportedVersion === undefined) {
    return 'unknown';
  }

  if (lastSupportedVersion !== undefined) {
    const comparison = compareVersionToPartialBound(packageVersion, lastSupportedVersion);

    if (comparison === null) {
      return 'unknown';
    }

    if (comparison > 0) {
      return 'unsupported';
    }
  }

  if (firstSupportedVersion !== undefined) {
    const comparison = compareVersionToPartialBound(packageVersion, firstSupportedVersion);

    if (comparison === null) {
      return 'unknown';
    }

    if (comparison < 0) {
      return 'version_unavailable';
    }
  }

  return 'applicable';
};

const versionSortKey = (packageVersion: string): number | null => {
  const coerced = semverCoerce(packageVersion.trim());

  if (coerced === null) {
    return null;
  }

  const { major, minor, patch } = coerced;

  return major * 1_000_000 + minor * 1_000 + patch;
};

export const resolveRegistryForVersion = (
  registries: readonly PolicyFieldRegistry[],
  requestedVersion: string
): PolicyFieldRegistry | RegistryVersionUnknown => {
  const exactMatch = registries.find(({ packageVersion }) => packageVersion === requestedVersion);

  if (exactMatch !== undefined) {
    return exactMatch;
  }

  const requestedKey = versionSortKey(requestedVersion);

  if (requestedKey === null) {
    return { status: 'registry_version_unknown', requestedVersion };
  }

  const coercedMatch = registries.find(
    ({ packageVersion }) => versionSortKey(packageVersion) === requestedKey
  );

  if (coercedMatch !== undefined) {
    return coercedMatch;
  }

  let nearestKnownVersion: string | undefined;
  let nearestDistance = Number.POSITIVE_INFINITY;
  let nearestKey = Number.POSITIVE_INFINITY;

  for (const { packageVersion } of registries) {
    const candidateKey = versionSortKey(packageVersion);

    if (candidateKey !== null) {
      const distance = Math.abs(candidateKey - requestedKey);

      if (
        distance < nearestDistance ||
        (distance === nearestDistance && candidateKey < nearestKey)
      ) {
        nearestDistance = distance;
        nearestKey = candidateKey;
        nearestKnownVersion = packageVersion;
      }
    }
  }

  return nearestKnownVersion === undefined
    ? { status: 'registry_version_unknown', requestedVersion }
    : { status: 'registry_version_unknown', requestedVersion, nearestKnownVersion };
};
