/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { getFlattenedObject } from '@kbn/std';
import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { getPolicyProtectionsReference } from '../../../../../../common/endpoint/models/policy_config_helpers';
import { AdvancedPolicySchema } from '../../../../../../common/endpoint/service/policy/advanced_policy_schema';
import { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import {
  getFieldRegistry,
  getFieldRegistryEntry,
  getOsLessRemainderEntries,
  getProtectionKeyPathEntries,
  isExcludedPath,
  isWritablePath,
  type FieldRegistryEntry,
} from '.';

const POLICY_OPERATING_SYSTEMS = new Set<string>(Object.values(PolicyOperatingSystem));

describe('field registry integrity', () => {
  const registry = getFieldRegistry();
  const factoryLeaves = getFlattenedObject(policyFactory());

  it('resolves every factory and schema path uniquely', () => {
    const paths = registry.map((entry) => entry.path);
    expect(new Set(paths).size).toBe(registry.length);

    for (const path of Object.keys(factoryLeaves)) {
      expect(getFieldRegistryEntry(path)?.path).toBe(path);
    }

    for (const { key } of AdvancedPolicySchema) {
      const entry = getFieldRegistryEntry(key);
      expect(entry?.path).toBe(key);
      const [osSegment] = key.split('.');
      expect(osSegment !== undefined && POLICY_OPERATING_SYSTEMS.has(osSegment)).toBe(true);
    }
  });

  it('gives every factory-sourced entry a defaultValue', () => {
    for (const entry of registry) {
      if (entry.source === 'factory' || entry.source === 'both') {
        expect(entry.defaultValue).toBeDefined();
      }
    }
  });

  it('requires every protection expansion to exist as Tier 1', () => {
    for (const { keyPath, osList } of getPolicyProtectionsReference()) {
      const expanded = getProtectionKeyPathEntries(keyPath);
      expect(expanded).toHaveLength(osList.length);

      for (const os of osList) {
        const entry = getFieldRegistryEntry(`${os}.${keyPath}`);
        expect(entry).toBeDefined();
        expect(entry?.tier).toBe(1);
        expect(entry?.kind).toBe('protection');
      }
    }
  });

  it('assigns only Tier 1 or Tier 2', () => {
    for (const entry of registry) {
      expect(entry.tier === 1 || entry.tier === 2).toBe(true);
    }
  });

  it('meets settable tier floors without snapshotting inventory', () => {
    const settableTier1 = registry.filter(
      (entry) => entry.tier === 1 && !entry.excludeFromComparison
    );
    const settableTier2 = registry.filter(
      (entry) => entry.tier === 2 && !entry.excludeFromComparison
    );

    expect(settableTier1.length).toBeGreaterThanOrEqual(72);
    expect(settableTier2.length).toBeGreaterThanOrEqual(268);
  });

  it('excludes every factory popup message path from comparison', () => {
    const popupMessagePaths = Object.keys(factoryLeaves).filter(
      (path) => isExcludedPath(path) && path.includes('.popup.')
    );

    expect(popupMessagePaths.length).toBeGreaterThan(0);
    for (const path of popupMessagePaths) {
      const entry = getFieldRegistryEntry(path);
      expect(entry).toBeDefined();
      expect(entry?.excludeFromComparison).toBe(true);
    }
  });

  it('applies structural userEditable and isWritablePath samples', () => {
    const requireEntry = (path: string): FieldRegistryEntry => {
      const entry = getFieldRegistryEntry(path);
      if (entry === undefined) {
        throw new Error(`expected registry entry for ${path}`);
      }
      return entry;
    };

    expect(isWritablePath(requireEntry('windows.logging.file'))).toBe(false);

    expect(isWritablePath(requireEntry('global_manifest_version'))).toBe(true);
    expect(requireEntry('global_manifest_version').productFeatureGate).toBe(
      'endpointProtectionUpdates'
    );
    expect(requireEntry('windows.malware.mode').productFeatureGate).toBeUndefined();

    expect(isWritablePath(requireEntry('windows.ransomware.supported'))).toBe(false);

    const derivedAv = requireEntry('windows.antivirus_registration.enabled');
    expect(derivedAv.isDerived).toBe(true);
    expect(isWritablePath(derivedAv)).toBe(false);

    expect(isWritablePath(requireEntry('mac.ransomware.mode'))).toBe(true);

    expect(isWritablePath(requireEntry('windows.popup.malware.message'))).toBe(false);
    expect(isWritablePath(requireEntry('windows.malware.mode'))).toBe(true);
  });

  it('groups OS-less remainders by the complete remainder after one supported OS segment', () => {
    for (const entry of registry) {
      const [osSegment, ...rest] = entry.path.split('.');
      if (osSegment !== undefined && rest.length > 0 && POLICY_OPERATING_SYSTEMS.has(osSegment)) {
        const remainder = rest.join('.');
        const grouped = getOsLessRemainderEntries(remainder);
        expect(grouped.some((member) => member.path === entry.path)).toBe(true);

        for (const member of grouped) {
          const [memberOs, ...memberRest] = member.path.split('.');
          expect(memberOs !== undefined && POLICY_OPERATING_SYSTEMS.has(memberOs)).toBe(true);
          expect(memberRest.join('.')).toBe(remainder);
          expect(member.path).toBe(`${memberOs}.${remainder}`);
        }
      }
    }

    expect(
      getOsLessRemainderEntries('logging.file')
        .map((entry) => entry.path)
        .sort()
    ).toEqual(['linux.logging.file', 'mac.logging.file', 'windows.logging.file']);
    expect(getOsLessRemainderEntries('linux.ransomware.mode')).toEqual([]);
    expect(getOsLessRemainderEntries('windows.turbo_mode')).toEqual([]);
  });
});
