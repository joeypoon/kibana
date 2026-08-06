/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';

import {
  COMPARABLE_APPLICABILITY,
  compareVersionToPartialBound,
  evaluateFieldApplicability,
  resolveRegistryForVersion,
} from './applicability';
import type { PolicyFieldRecord, PolicyFieldRegistry } from './types';

const fieldWithWindow = (
  window: Pick<PolicyFieldRecord, 'firstSupportedVersion' | 'lastSupportedVersion'>
): PolicyFieldRecord => ({
  keyPath: 'advanced.agent.connection_delay',
  os: [PolicyOperatingSystem.linux],
  category: 'advanced',
  type: 'number',
  default: 60,
  defaultSource: 'advanced_schema_documentation',
  configurable: true,
  ...window,
});

describe('COMPARABLE_APPLICABILITY', () => {
  it('includes applicable and unbounded registry fields without admitting unsupported fields', () => {
    expect(COMPARABLE_APPLICABILITY).toEqual({ applicable: true, unknown: true });
    expect(COMPARABLE_APPLICABILITY.unsupported).toBeUndefined();
    expect(COMPARABLE_APPLICABILITY.version_unavailable).toBeUndefined();
  });
});

describe('evaluateFieldApplicability', () => {
  it('returns applicable when the version sits inside an open-ended window', () => {
    expect(
      evaluateFieldApplicability(fieldWithWindow({ firstSupportedVersion: '7.9' }), '8.15.1')
    ).toBe('applicable');
  });

  it('returns applicable when the version equals the inclusive lower bound', () => {
    expect(
      evaluateFieldApplicability(fieldWithWindow({ firstSupportedVersion: '8.15' }), '8.15.0')
    ).toBe('applicable');
  });

  it('returns version_unavailable when the version predates the lower bound', () => {
    expect(
      evaluateFieldApplicability(fieldWithWindow({ firstSupportedVersion: '8.18' }), '8.15.1')
    ).toBe('version_unavailable');
  });

  it('returns version_unavailable across a major boundary', () => {
    expect(
      evaluateFieldApplicability(fieldWithWindow({ firstSupportedVersion: '9.1' }), '8.19.4')
    ).toBe('version_unavailable');
  });

  it('returns unsupported when the version is past the upper bound', () => {
    expect(
      evaluateFieldApplicability(
        fieldWithWindow({ firstSupportedVersion: '7.9', lastSupportedVersion: '8.10' }),
        '8.11.0'
      )
    ).toBe('unsupported');
  });

  it('treats a two-segment upper bound as covering the whole minor series', () => {
    expect(
      evaluateFieldApplicability(
        fieldWithWindow({ firstSupportedVersion: '7.9', lastSupportedVersion: '8.10' }),
        '8.10.2'
      )
    ).toBe('applicable');
  });

  it('honours a three-segment upper bound at patch precision', () => {
    const field = fieldWithWindow({
      firstSupportedVersion: '7.9',
      lastSupportedVersion: '8.10.1',
    });

    expect(evaluateFieldApplicability(field, '8.10.1')).toBe('applicable');
    expect(evaluateFieldApplicability(field, '8.10.2')).toBe('unsupported');
  });

  it('treats a single-segment bound as covering the whole major series', () => {
    const field = fieldWithWindow({ firstSupportedVersion: '8', lastSupportedVersion: '8' });

    expect(evaluateFieldApplicability(field, '8.19.4')).toBe('applicable');
    expect(evaluateFieldApplicability(field, '9.0.0')).toBe('unsupported');
    expect(evaluateFieldApplicability(field, '7.17.0')).toBe('version_unavailable');
  });

  it('returns unknown when the field declares no window at all', () => {
    expect(evaluateFieldApplicability(fieldWithWindow({}), '8.15.1')).toBe('unknown');
  });

  it('returns unknown when the package version cannot be coerced', () => {
    expect(
      evaluateFieldApplicability(fieldWithWindow({ firstSupportedVersion: '7.9' }), 'not-a-version')
    ).toBe('unknown');
  });

  it('returns unknown when a bound cannot be coerced', () => {
    expect(
      evaluateFieldApplicability(fieldWithWindow({ firstSupportedVersion: 'latest' }), '8.15.1')
    ).toBe('unknown');
  });

  it('returns unknown for a blank bound rather than treating it as unbounded', () => {
    expect(
      evaluateFieldApplicability(fieldWithWindow({ firstSupportedVersion: '   ' }), '8.15.1')
    ).toBe('unknown');
  });

  it('discards a prerelease tag on the bound as well as on the version', () => {
    expect(compareVersionToPartialBound('9.6.0', '9.6.0-SNAPSHOT')).toBe(0);
    expect(
      evaluateFieldApplicability(
        fieldWithWindow({ firstSupportedVersion: '9.6.0-SNAPSHOT' }),
        '9.6.0'
      )
    ).toBe('applicable');
  });

  it('coerces prerelease package versions rather than refusing them', () => {
    expect(
      evaluateFieldApplicability(
        fieldWithWindow({ firstSupportedVersion: '8.14' }),
        '8.15.1-prerelease.1'
      )
    ).toBe('applicable');
  });

  it('treats a prerelease of the gating minor as applicable, discarding the tag', () => {
    expect(
      evaluateFieldApplicability(
        fieldWithWindow({ firstSupportedVersion: '9.6' }),
        '9.6.0-prerelease.0'
      )
    ).toBe('applicable');
    expect(
      evaluateFieldApplicability(
        fieldWithWindow({ firstSupportedVersion: '9.6' }),
        '9.6.0-prerelease.0'
      )
    ).not.toBe('version_unavailable');
  });

  it('discards the prerelease tag at patch precision too', () => {
    expect(
      evaluateFieldApplicability(
        fieldWithWindow({ firstSupportedVersion: '9.6.0' }),
        '9.6.0-prerelease.0'
      )
    ).toBe('applicable');
  });

  it('prefers unsupported over version_unavailable for an inverted window', () => {
    expect(
      evaluateFieldApplicability(
        fieldWithWindow({ firstSupportedVersion: '9.0', lastSupportedVersion: '8.10' }),
        '8.15.1'
      )
    ).toBe('unsupported');
  });
});

describe('resolveRegistryForVersion', () => {
  const registryFor = (packageVersion: string): PolicyFieldRegistry => ({
    packageVersion,
    fields: [],
  });

  const registries = [registryFor('8.14.0'), registryFor('8.15.1'), registryFor('9.0.0')];

  it('returns the exact registry when one matches', () => {
    expect(resolveRegistryForVersion(registries, '8.15.1')).toBe(registries[1]);
  });

  it('matches a version that differs only in formatting', () => {
    expect(resolveRegistryForVersion(registries, 'v8.15.1')).toBe(registries[1]);
  });

  it('refuses to substitute a neighbouring version and discloses the nearest known one', () => {
    expect(resolveRegistryForVersion(registries, '8.16.0')).toEqual({
      status: 'registry_version_unknown',
      requestedVersion: '8.16.0',
      nearestKnownVersion: '8.15.1',
    });
  });

  it('reports the nearest known version below when the request is older than everything', () => {
    expect(resolveRegistryForVersion(registries, '7.17.0')).toEqual({
      status: 'registry_version_unknown',
      requestedVersion: '7.17.0',
      nearestKnownVersion: '8.14.0',
    });
  });

  it('breaks a distance tie toward the lower version regardless of array order', () => {
    const low = registryFor('8.14.0');
    const high = registryFor('8.16.0');

    expect(resolveRegistryForVersion([low, high], '8.15.0')).toEqual({
      status: 'registry_version_unknown',
      requestedVersion: '8.15.0',
      nearestKnownVersion: '8.14.0',
    });
    expect(resolveRegistryForVersion([high, low], '8.15.0')).toEqual({
      status: 'registry_version_unknown',
      requestedVersion: '8.15.0',
      nearestKnownVersion: '8.14.0',
    });
  });

  it('omits a nearest version when the request cannot be placed on the version line', () => {
    expect(resolveRegistryForVersion(registries, 'unreleased')).toEqual({
      status: 'registry_version_unknown',
      requestedVersion: 'unreleased',
    });
  });

  it('omits a nearest version when there are no registries', () => {
    expect(resolveRegistryForVersion([], '8.15.1')).toEqual({
      status: 'registry_version_unknown',
      requestedVersion: '8.15.1',
    });
  });
});
