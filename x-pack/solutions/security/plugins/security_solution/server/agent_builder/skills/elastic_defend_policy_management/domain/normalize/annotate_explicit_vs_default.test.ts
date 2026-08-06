/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { set } from '@kbn/safer-lodash-set';

import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import { buildPolicyFieldRegistry } from '../field_registry/generate_field_registry';
import {
  annotateExplicitVsDefault,
  storedValueMatchesDefault,
} from './annotate_explicit_vs_default';
import type { AnnotatedPolicyField } from './types';

const PACKAGE_VERSION = '9.4.0';
const registry = buildPolicyFieldRegistry({ packageVersion: PACKAGE_VERSION });

const annotate = (config = policyFactory()): AnnotatedPolicyField[] =>
  annotateExplicitVsDefault({ config, registry, packageVersion: PACKAGE_VERSION });

const find = (
  annotated: readonly AnnotatedPolicyField[],
  keyPath: string,
  os?: PolicyOperatingSystem
): AnnotatedPolicyField | undefined =>
  annotated.find((field) => field.keyPath === keyPath && field.os === os);

describe('annotateExplicitVsDefault', () => {
  it('annotates the factory policy without asserting anything as explicit that was not authored', () => {
    const annotated = annotate();

    expect(annotated.length).toBeGreaterThan(0);
    expect(annotated.every(({ state }) => state !== 'explicit')).toBe(true);
  });

  it('marks a changed non-gated leaf as explicit', () => {
    const config = policyFactory();
    set(config, 'windows.events.dns', false);

    const dns = find(annotate(config), 'events.dns', PolicyOperatingSystem.windows);

    expect(dns).toMatchObject({ state: 'explicit', value: false, defaultValue: true });
  });

  it('marks an untouched non-gated leaf as default', () => {
    const events = find(annotate(), 'events.dns', PolicyOperatingSystem.windows);

    expect(events).toMatchObject({ state: 'default', value: true });
    expect(events?.indeterminateReason).toBeUndefined();
  });

  describe('indeterminate', () => {
    it('marks a license-gated advanced field indeterminate with a reason naming the license', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.alerts.rollback.self_healing.enabled', true);

      const rollback = find(
        annotate(config),
        'advanced.alerts.rollback.self_healing.enabled',
        PolicyOperatingSystem.windows
      );

      expect(rollback?.state).toBe('indeterminate');
      expect(rollback?.indeterminateReason).toBeTruthy();
      expect(rollback?.indeterminateReason).toContain('platinum');
    });

    it('marks a license-gated field indeterminate even when it holds the documented default', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.alerts.rollback.self_healing.enabled', false);

      const rollback = find(
        annotate(config),
        'advanced.alerts.rollback.self_healing.enabled',
        PolicyOperatingSystem.windows
      );

      expect(rollback).toMatchObject({ value: false, defaultValue: false, state: 'indeterminate' });
      expect(rollback?.indeterminateReason).toBeTruthy();
    });

    it('does not annotate an advanced key the policy does not carry', () => {
      expect(
        find(
          annotate(),
          'advanced.alerts.rollback.self_healing.enabled',
          PolicyOperatingSystem.windows
        )
      ).toBeUndefined();
    });

    it('marks license-tier-dependent protection leaves indeterminate', () => {
      const annotated = annotate();

      for (const keyPath of ['memory_protection.supported', 'behavior_protection.supported']) {
        const field = find(annotated, keyPath, PolicyOperatingSystem.windows);

        expect(field?.state).toBe('indeterminate');
        expect(field?.indeterminateReason).toContain('license tier');
      }
    });

    it('marks reputation_service indeterminate because its default follows the cloud flag', () => {
      const reputation = find(
        annotate(),
        'behavior_protection.reputation_service',
        PolicyOperatingSystem.linux
      );

      expect(reputation?.state).toBe('indeterminate');
      expect(reputation?.indeterminateReason).toContain('Elastic Cloud');
    });

    it('marks global_telemetry_enabled indeterminate because its default follows the opt-in', () => {
      const telemetry = find(annotate(), 'global_telemetry_enabled');

      expect(telemetry?.state).toBe('indeterminate');
      expect(telemetry?.indeterminateReason).toContain('telemetry opt-in');
    });

    it('always supplies a non-empty reason wherever it reports indeterminate', () => {
      const indeterminate = annotate().filter(({ state }) => state === 'indeterminate');

      expect(indeterminate.length).toBeGreaterThan(0);
      expect(
        indeterminate.every(({ indeterminateReason }) => (indeterminateReason ?? '').length > 0)
      ).toBe(true);
    });

    it('never reports a reason on a determinate field', () => {
      const determinate = annotate().filter(({ state }) => state !== 'indeterminate');

      expect(determinate.length).toBeGreaterThan(0);
      expect(
        determinate.every(({ indeterminateReason }) => indeterminateReason === undefined)
      ).toBe(true);
    });

    it('supplies a machine-readable code alongside every reason', () => {
      const indeterminate = annotate().filter(({ state }) => state === 'indeterminate');

      expect(indeterminate.length).toBeGreaterThan(0);
      expect(
        indeterminate
          .filter(({ indeterminateReasonCode }) => indeterminateReasonCode === undefined)
          .map(({ os, keyPath }) => `${os ?? 'root'}|${keyPath}`)
      ).toEqual([]);
    });

    it('codes the license and creation-input branches distinguishably', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.alerts.rollback.self_healing.enabled', true);

      const annotated = annotate(config);

      expect(
        find(
          annotated,
          'advanced.alerts.rollback.self_healing.enabled',
          PolicyOperatingSystem.windows
        )
      ).toMatchObject({ indeterminateReasonCode: 'license_gated_default_unrecoverable' });
      expect(find(annotated, 'global_telemetry_enabled')).toMatchObject({
        indeterminateReasonCode: 'creation_input_unrecoverable',
      });
    });

    it('never reports a code on a determinate field', () => {
      const determinate = annotate().filter(({ state }) => state !== 'indeterminate');

      expect(determinate.length).toBeGreaterThan(0);
      expect(
        determinate.every(({ indeterminateReasonCode }) => indeterminateReasonCode === undefined)
      ).toBe(true);
    });

    it('reports a value matching NO shipped default variant as explicit, not indeterminate', () => {
      const config = policyFactory();

      set(config, 'windows.ransomware.mode', 'detect');

      expect(
        find(annotate(config), 'ransomware.mode', PolicyOperatingSystem.windows)
      ).toMatchObject({ state: 'explicit' });
    });

    it('still reports indeterminate when the value matches one of the variant defaults', () => {
      const config = policyFactory();

      for (const ambiguous of ['prevent', 'off'] as const) {
        set(config, 'windows.ransomware.mode', ambiguous);

        expect(
          find(annotate(config), 'ransomware.mode', PolicyOperatingSystem.windows)
        ).toMatchObject({
          state: 'indeterminate',
          indeterminateReasonCode: 'creation_input_unrecoverable',
        });
      }
    });

    it('names the candidate defaults in the reason so the ambiguity is auditable', () => {
      const config = policyFactory();

      set(config, 'windows.ransomware.mode', 'prevent');

      const reason =
        find(annotate(config), 'ransomware.mode', PolicyOperatingSystem.windows)
          ?.indeterminateReason ?? '';

      expect(reason).toContain('"prevent"');
      expect(reason).toContain('"off"');
    });

    it('keeps a license-gated boolean indeterminate when both booleans are shipped defaults', () => {
      const config = policyFactory();

      for (const ambiguous of [true, false]) {
        set(config, 'windows.device_control.enabled', ambiguous);

        expect(
          find(annotate(config), 'device_control.enabled', PolicyOperatingSystem.windows)
        ).toMatchObject({ state: 'indeterminate' });
      }
    });
  });

  describe('stored advanced strings against natively typed defaults', () => {
    it('reports the numeric default typed as a string as default', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.agent.connection_delay', '60');

      expect(
        find(annotate(config), 'advanced.agent.connection_delay', PolicyOperatingSystem.windows)
      ).toMatchObject({ state: 'default', value: '60' });
    });

    it('still reports the numeric default stored natively as default', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.agent.connection_delay', 60);

      expect(
        find(annotate(config), 'advanced.agent.connection_delay', PolicyOperatingSystem.windows)
      ).toMatchObject({ state: 'default', value: 60 });
    });

    it('reports a genuinely different number as explicit however it is stored', () => {
      for (const changed of ['90', 90]) {
        const config = policyFactory();
        set(config, 'windows.advanced.agent.connection_delay', changed);

        expect(
          find(annotate(config), 'advanced.agent.connection_delay', PolicyOperatingSystem.windows)
        ).toMatchObject({ state: 'explicit' });
      }
    });

    it('reports the boolean defaults typed as strings as default', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.malware.quarantine', 'true');
      set(config, 'windows.advanced.events.ancestry_in_all_events', 'false');

      const annotated = annotate(config);

      expect(
        find(annotated, 'advanced.malware.quarantine', PolicyOperatingSystem.windows)
      ).toMatchObject({ state: 'default', value: 'true', defaultValue: true });
      expect(
        find(annotated, 'advanced.events.ancestry_in_all_events', PolicyOperatingSystem.windows)
      ).toMatchObject({ state: 'default', value: 'false', defaultValue: false });
    });

    it('reports the inverted boolean as explicit', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.malware.quarantine', 'false');

      expect(
        find(annotate(config), 'advanced.malware.quarantine', PolicyOperatingSystem.windows)
      ).toMatchObject({ state: 'explicit' });
    });

    it('never launders an ambiguous or invalid string into default', () => {
      for (const suspect of ['60abc', '', '   ', ' 60', '060', '0x3c', '6e1', 'sixty']) {
        const config = policyFactory();
        set(config, 'windows.advanced.agent.connection_delay', suspect);

        expect(
          find(annotate(config), 'advanced.agent.connection_delay', PolicyOperatingSystem.windows)
        ).toMatchObject({ state: 'explicit', value: suspect });
      }
    });

    it('does not accept a truthy-looking string for a boolean default', () => {
      for (const suspect of ['1', 'yes', 'TRUE', 'on']) {
        const config = policyFactory();
        set(config, 'windows.advanced.malware.quarantine', suspect);

        expect(
          find(annotate(config), 'advanced.malware.quarantine', PolicyOperatingSystem.windows)
        ).toMatchObject({ state: 'explicit', value: suspect });
      }
    });

    it('does not read a numeric string as a match for an enum or string default', () => {
      expect(storedValueMatchesDefault('enum', '1', 1)).toBe(false);
      expect(storedValueMatchesDefault('string', 'true', true)).toBe(false);
      expect(storedValueMatchesDefault('unknown', '60', 60)).toBe(false);
    });

    it('refuses non-finite strings that would otherwise round-trip', () => {
      expect(storedValueMatchesDefault('number', 'NaN', Number.NaN)).toBe(false);
      expect(storedValueMatchesDefault('number', 'Infinity', Number.POSITIVE_INFINITY)).toBe(false);
    });

    it('applies the same equality rule to the candidate-set check', () => {
      const config = policyFactory();

      for (const ambiguous of ['true', 'false']) {
        set(config, 'windows.device_control.enabled', ambiguous);

        expect(
          find(annotate(config), 'device_control.enabled', PolicyOperatingSystem.windows)
        ).toMatchObject({ state: 'indeterminate' });
      }
    });

    it('still reports a candidate-set miss as explicit when the string is not canonical', () => {
      const config = policyFactory();
      set(config, 'windows.device_control.enabled', '1');

      expect(
        find(annotate(config), 'device_control.enabled', PolicyOperatingSystem.windows)
      ).toMatchObject({ state: 'explicit' });
    });
  });

  describe('popup messages', () => {
    it('reports the shipped default message as default rather than explicit', () => {
      const malware = find(annotate(), 'popup.malware.message', PolicyOperatingSystem.linux);

      expect(malware?.state).toBe('default');
    });

    it('reports operator-written text as explicit', () => {
      const config = policyFactory();
      set(config, 'linux.popup.malware.message', 'Call the SOC');

      const malware = find(annotate(config), 'popup.malware.message', PolicyOperatingSystem.linux);

      expect(malware?.state).toBe('explicit');
    });
  });

  describe('exclusions and scoping', () => {
    it('never annotates a meta.* leaf', () => {
      expect(annotate().some(({ keyPath }) => keyPath.startsWith('meta'))).toBe(false);
    });

    it('never annotates logging.file', () => {
      expect(annotate().some(({ keyPath }) => keyPath === 'logging.file')).toBe(false);
    });

    it('never annotates a windows-only field against mac or linux', () => {
      const offOs = annotate().filter(
        ({ keyPath, os }) =>
          keyPath.startsWith('antivirus_registration.') && os !== PolicyOperatingSystem.windows
      );

      expect(offOs).toEqual([]);
    });

    it('omits os for policy-root fields and sets it for OS-scoped fields', () => {
      const annotated = annotate();

      expect(find(annotated, 'global_manifest_version')?.os).toBeUndefined();
      expect(find(annotated, 'malware.mode', PolicyOperatingSystem.mac)?.os).toBe(
        PolicyOperatingSystem.mac
      );
    });

    it('skips fields whose support window excludes the policy package version', () => {
      const old = annotateExplicitVsDefault({
        config: policyFactory(),
        registry: buildPolicyFieldRegistry({ packageVersion: '8.0.0' }),
        packageVersion: '8.0.0',
      });

      expect(find(old, 'ransomware.mode', PolicyOperatingSystem.mac)).toBeUndefined();
      expect(find(annotate(), 'ransomware.mode', PolicyOperatingSystem.mac)).toBeDefined();
    });
  });

  it('does not mutate the policy it annotates', () => {
    const config = policyFactory();
    set(config, 'mac.malware.mode', ProtectionModes.detect);
    const snapshot = JSON.stringify(config);

    annotate(config);

    expect(JSON.stringify(config)).toBe(snapshot);
  });
});
