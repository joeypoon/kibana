/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { getFlattenedObject } from '@kbn/std';
import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { AdvancedPolicySchema } from '../../../../../../common/endpoint/service/policy/advanced_policy_schema';
import { ProtectionModes } from '../../../../../../common/endpoint/types';
import {
  getFieldRegistry,
  getFieldRegistryEntry,
  getOsLessRemainderEntries,
  getProtectionKeyPathEntries,
  isWritablePath,
  type FieldRegistryEntry,
} from '.';

type ValueConstraintField = 'valueType' | 'allowedValues';
type HasValueConstraintField = ValueConstraintField & keyof FieldRegistryEntry;
const _valueConstraintFieldsAbsent: [HasValueConstraintField] extends [never] ? true : never = true;
void _valueConstraintFieldsAbsent;

describe('deriveFieldRegistry', () => {
  it('merges mac.ransomware.mode as Tier 1 from both sources', () => {
    const entry = getFieldRegistryEntry('mac.ransomware.mode');

    expect(entry).toEqual(
      expect.objectContaining({
        path: 'mac.ransomware.mode',
        os: ['mac'],
        kind: 'protection',
        tier: 1,
        source: 'both',
        defaultValue: ProtectionModes.off,
        license: 'platinum',
        minVersion: '9.4',
        userEditable: true,
        isDerived: false,
        excludeFromComparison: false,
      })
    );
    expect(entry?.documentation).toContain('Enable ransomware protection for macOS');
    expect(entry).toBeDefined();
    if (entry === undefined) {
      throw new Error('expected mac.ransomware.mode in the derived registry');
    }
    expect(isWritablePath(entry)).toBe(true);
  });

  it('keeps factory defaultValue and schema documentation on capture_env_vars conflicts', () => {
    const mac = getFieldRegistryEntry('mac.advanced.capture_env_vars');
    const linux = getFieldRegistryEntry('linux.advanced.capture_env_vars');
    const factoryLeaves = getFlattenedObject(policyFactory());

    expect(mac).toEqual(
      expect.objectContaining({
        source: 'both',
        tier: 2,
        kind: 'advanced',
        defaultValue: factoryLeaves['mac.advanced.capture_env_vars'],
      })
    );
    expect(linux).toEqual(
      expect.objectContaining({
        source: 'both',
        tier: 2,
        kind: 'advanced',
        defaultValue: factoryLeaves['linux.advanced.capture_env_vars'],
      })
    );
    expect(mac?.defaultValue).toBeDefined();
    expect(linux?.defaultValue).toBeDefined();
    const macSchemaRow = AdvancedPolicySchema.find(
      (row) => row.key === 'mac.advanced.capture_env_vars'
    );
    const linuxSchemaRow = AdvancedPolicySchema.find(
      (row) => row.key === 'linux.advanced.capture_env_vars'
    );
    expect(macSchemaRow).toBeDefined();
    expect(linuxSchemaRow).toBeDefined();
    expect(mac?.documentation).toBe(macSchemaRow?.documentation);
    expect(linux?.documentation).toBe(linuxSchemaRow?.documentation);
  });

  it('classifies path-shape kinds and stamps protection expansions', () => {
    expect(getFieldRegistryEntry('linux.events.dns')).toEqual(
      expect.objectContaining({
        kind: 'event',
        tier: 1,
        source: 'factory',
        defaultValue: true,
        userEditable: true,
      })
    );
    expect(getFieldRegistryEntry('windows.popup.malware.enabled')).toEqual(
      expect.objectContaining({
        kind: 'popup',
        tier: 1,
        excludeFromComparison: false,
        userEditable: true,
      })
    );
    expect(getFieldRegistryEntry('windows.popup.malware.message')).toEqual(
      expect.objectContaining({
        kind: 'popup',
        tier: 1,
        excludeFromComparison: true,
        userEditable: true,
      })
    );
    expect(getFieldRegistryEntry('windows.logging.file')).toEqual(
      expect.objectContaining({
        kind: 'logging',
        tier: 1,
        userEditable: false,
      })
    );
    expect(getFieldRegistryEntry('meta.billable')).toEqual(
      expect.objectContaining({
        kind: 'meta',
        excludeFromComparison: true,
        userEditable: false,
      })
    );
    expect(getFieldRegistryEntry('linux.advanced.agent.connection_delay')).toEqual(
      expect.objectContaining({
        kind: 'advanced',
        tier: 2,
        source: 'advanced_schema',
      })
    );
    expect(getFieldRegistryEntry('windows.device_control.enabled')).toEqual(
      expect.objectContaining({
        kind: 'other',
        tier: 1,
        userEditable: true,
      })
    );
    expect(getFieldRegistryEntry('windows.antivirus_registration.enabled')).toEqual(
      expect.objectContaining({
        kind: 'protection',
        isDerived: true,
        userEditable: false,
      })
    );
  });

  it('derives userEditable from the UI section map and path-shape exceptions', () => {
    expect(getFieldRegistryEntry('windows.logging.file')?.userEditable).toBe(false);
    expect(getFieldRegistryEntry('global_telemetry_enabled')?.userEditable).toBe(false);
    expect(getFieldRegistryEntry('global_manifest_version')?.userEditable).toBe(true);
    expect(getFieldRegistryEntry('global_manifest_version')?.productFeatureGate).toBe(
      'endpointProtectionUpdates'
    );
    expect(getFieldRegistryEntry('windows.logging.file')?.productFeatureGate).toBeUndefined();
    expect(getFieldRegistryEntry('windows.ransomware.supported')?.userEditable).toBe(false);
    expect(getFieldRegistryEntry('windows.antivirus_registration.enabled')?.userEditable).toBe(
      false
    );
    expect(getFieldRegistryEntry('mac.ransomware.mode')?.userEditable).toBe(true);
  });

  it('looks up exact paths, protection keyPaths, and complete OS-less remainders without prefix search', () => {
    expect(getFieldRegistryEntry('linux.events.dns')?.path).toBe('linux.events.dns');
    expect(getFieldRegistryEntry('events.dns')).toBeUndefined();
    expect(getFieldRegistryEntry('linux.ransomware.mode')).toBeUndefined();

    const malware = getProtectionKeyPathEntries('malware.mode');
    expect(malware).toHaveLength(3);
    expect(malware.map((entry) => entry.path).sort()).toEqual([
      'linux.malware.mode',
      'mac.malware.mode',
      'windows.malware.mode',
    ]);
    expect(malware.every((entry) => entry.kind === 'protection')).toBe(true);

    expect(getProtectionKeyPathEntries('events.dns')).toEqual([]);
    expect(getProtectionKeyPathEntries('behavior_protection.reputation_service')).toEqual([]);
    expect(getProtectionKeyPathEntries('ransomware.mode').map((entry) => entry.path)).toEqual([
      'windows.ransomware.mode',
      'mac.ransomware.mode',
    ]);

    const reputation = getOsLessRemainderEntries('behavior_protection.reputation_service');
    expect(reputation.map((entry) => entry.path).sort()).toEqual([
      'linux.behavior_protection.reputation_service',
      'mac.behavior_protection.reputation_service',
      'windows.behavior_protection.reputation_service',
    ]);
    expect(reputation.every((entry) => entry.documentation === undefined)).toBe(true);

    expect(
      getOsLessRemainderEntries('logging.file')
        .map((entry) => entry.path)
        .sort()
    ).toEqual(['linux.logging.file', 'mac.logging.file', 'windows.logging.file']);
    expect(
      getOsLessRemainderEntries('logging.file').some((entry) => entry.path.includes('.advanced.'))
    ).toBe(false);
    expect(getOsLessRemainderEntries('linux.ransomware.mode')).toEqual([]);
    expect(getOsLessRemainderEntries('windows.turbo_mode')).toEqual([]);
  });

  it('returns a deterministic unique registry', () => {
    const first = getFieldRegistry();
    const second = getFieldRegistry();
    const paths = first.map((entry) => entry.path);

    expect(first).toBe(second);
    expect(new Set(paths).size).toBe(first.length);
    expect(paths).toEqual([...paths].sort((left, right) => left.localeCompare(right)));
  });
});
