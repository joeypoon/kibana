/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cloneDeep } from 'lodash';
import { set } from '@kbn/safer-lodash-set';

import {
  policyFactory,
  DefaultPolicyDeviceNotificationMessage,
  DefaultPolicyNotificationMessage,
  DefaultPolicyRuleNotificationMessage,
} from '../../../../../../common/endpoint/models/policy_config';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import { buildPolicyFieldRegistry } from '../field_registry/generate_field_registry';
import { normalizePolicyConfig } from './normalize_policy_config';

const PACKAGE_VERSION = '9.4.0';
const registry = buildPolicyFieldRegistry({ packageVersion: PACKAGE_VERSION });

describe('normalizePolicyConfig', () => {
  it('carries the protection-updates pin as its own dimension, never inside perOs', () => {
    const config = policyFactory();
    config.global_manifest_version = '2024-01-01';

    const normalized = normalizePolicyConfig(config, registry);

    expect(normalized.globalManifestVersion).toBe('2024-01-01');

    for (const os of Object.values(PolicyOperatingSystem)) {
      expect(normalized.perOs[os]).not.toHaveProperty('global_manifest_version');
    }
  });

  it('carries global_telemetry_enabled as a top-level field', () => {
    const normalized = normalizePolicyConfig(
      policyFactory({ isGlobalTelemetryEnabled: true }),
      registry
    );

    expect(normalized.globalTelemetryEnabled).toBe(true);
  });

  describe('exclusions', () => {
    it('excludes every meta.* leaf', () => {
      const normalized = normalizePolicyConfig(
        policyFactory({ license: 'platinum', clusterName: 'prod', cloud: true }),
        registry
      );

      const allKeyPaths = Object.values(PolicyOperatingSystem).flatMap((os) =>
        Object.keys(normalized.perOs[os])
      );

      expect(allKeyPaths.filter((keyPath) => keyPath.startsWith('meta'))).toEqual([]);
      expect(JSON.stringify(normalized)).not.toContain('cluster_name');
    });

    it('excludes logging.file', () => {
      const config = policyFactory();
      set(config, 'windows.logging.file', 'debug');

      expect(Object.keys(normalizePolicyConfig(config, registry).perOs.windows)).not.toContain(
        'logging.file'
      );
    });

    it('carries a key the registry does not know about into unrecognizedPerOs, never dropping it', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.not_a_real_shipped_key', 'whatever');

      const { perOs, unrecognizedPerOs } = normalizePolicyConfig(config, registry);

      expect(Object.keys(perOs.windows)).not.toContain('advanced.not_a_real_shipped_key');
      expect(unrecognizedPerOs.windows).toEqual({
        'advanced.not_a_real_shipped_key': 'whatever',
      });
    });

    it('keeps excluded leaves out of unrecognizedPerOs, not merely out of perOs', () => {
      const config = policyFactory();
      set(config, 'windows.logging.file', 'debug');
      set(config, 'windows.artifact_manifest.value', { artifacts: { 'endpoint-blah': 'abc' } });

      const { unrecognizedPerOs } = normalizePolicyConfig(config, registry);

      expect(Object.keys(unrecognizedPerOs.windows)).not.toContain('logging.file');
      expect(
        Object.keys(unrecognizedPerOs.windows).filter((keyPath) =>
          keyPath.startsWith('artifact_manifest')
        )
      ).toEqual([]);
    });
  });

  describe('registry-unknown leaves', () => {
    it('reports every OS branch, so a consumer never has to guard an absent one', () => {
      const { unrecognizedPerOs } = normalizePolicyConfig(policyFactory(), registry);

      expect(unrecognizedPerOs).toEqual({ windows: {}, mac: {}, linux: {} });
    });

    it('never lets one keyPath land in both perOs and unrecognizedPerOs for an OS', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.brand_new_key', 'x');
      set(config, 'linux.advanced.another_new_key', 'y');

      const { perOs, unrecognizedPerOs } = normalizePolicyConfig(config, registry);

      for (const os of Object.values(PolicyOperatingSystem)) {
        const recognized = new Set(Object.keys(perOs[os]));

        expect(
          Object.keys(unrecognizedPerOs[os]).filter((keyPath) => recognized.has(keyPath))
        ).toEqual([]);
      }
    });

    it('scopes an unknown key to the OS branch that carries it', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.brand_new_key', 'x');

      const { unrecognizedPerOs } = normalizePolicyConfig(config, registry);

      expect(unrecognizedPerOs.windows).toEqual({ 'advanced.brand_new_key': 'x' });
      expect(unrecognizedPerOs.mac).toEqual({});
      expect(unrecognizedPerOs.linux).toEqual({});
    });

    it('does not treat a registry-known field on the wrong OS as unrecognised', () => {
      const config = policyFactory();
      set(config, 'linux.antivirus_registration.enabled', true);

      const { unrecognizedPerOs } = normalizePolicyConfig(config, registry);

      expect(Object.keys(unrecognizedPerOs.linux)).not.toContain('antivirus_registration.enabled');
    });
  });

  describe('per-OS scoping', () => {
    const keyPathsOf = (os: PolicyOperatingSystem, config = policyFactory()): string[] =>
      Object.keys(normalizePolicyConfig(config, registry).perOs[os]);

    it('keeps windows-only fields out of the mac and linux branches', () => {
      const windowsOnly = [
        'antivirus_registration.enabled',
        'antivirus_registration.mode',
        'attack_surface_reduction.credential_hardening.enabled',
      ];

      expect(keyPathsOf(PolicyOperatingSystem.windows)).toEqual(
        expect.arrayContaining(windowsOnly)
      );

      for (const os of [PolicyOperatingSystem.mac, PolicyOperatingSystem.linux]) {
        expect(keyPathsOf(os)).toEqual(expect.not.arrayContaining(windowsOnly));
      }
    });

    it('keeps device_control out of the linux branch', () => {
      expect(keyPathsOf(PolicyOperatingSystem.windows)).toContain('device_control.enabled');
      expect(keyPathsOf(PolicyOperatingSystem.mac)).toContain('device_control.enabled');
      expect(keyPathsOf(PolicyOperatingSystem.linux)).not.toContain('device_control.enabled');
    });

    it('keeps linux-only event fields out of windows and mac', () => {
      expect(keyPathsOf(PolicyOperatingSystem.linux)).toEqual(
        expect.arrayContaining(['events.session_data', 'events.tty_io'])
      );
      expect(keyPathsOf(PolicyOperatingSystem.windows)).not.toContain('events.session_data');
      expect(keyPathsOf(PolicyOperatingSystem.mac)).not.toContain('events.tty_io');
    });

    it('does not leak a windows-only value into another OS even when the key is set there', () => {
      const config = policyFactory();
      set(config, 'linux.antivirus_registration.enabled', true);

      expect(keyPathsOf(PolicyOperatingSystem.linux, config)).not.toContain(
        'antivirus_registration.enabled'
      );
    });
  });

  describe('popup message classification', () => {
    it('classifies an empty message as default', () => {
      const normalized = normalizePolicyConfig(policyFactory(), registry);

      expect(normalized.perOs.windows['popup.malware.message']).toBe('default');
      expect(normalized.perOs.linux['popup.memory_protection.message']).toBe('default');
    });

    it('classifies the shipped default message carried verbatim as default', () => {
      const config = policyFactory();
      set(config, 'windows.popup.malware.message', DefaultPolicyNotificationMessage);
      set(config, 'mac.popup.ransomware.message', DefaultPolicyNotificationMessage);
      set(config, 'linux.popup.memory_protection.message', DefaultPolicyRuleNotificationMessage);
      set(
        config,
        'windows.popup.behavior_protection.message',
        DefaultPolicyRuleNotificationMessage
      );
      set(config, 'windows.popup.device_control.message', DefaultPolicyDeviceNotificationMessage);

      const normalized = normalizePolicyConfig(config, registry);

      expect(normalized.perOs.windows['popup.malware.message']).toBe('default');
      expect(normalized.perOs.mac['popup.ransomware.message']).toBe('default');
      expect(normalized.perOs.linux['popup.memory_protection.message']).toBe('default');
      expect(normalized.perOs.windows['popup.behavior_protection.message']).toBe('default');
      expect(normalized.perOs.windows['popup.device_control.message']).toBe('default');
    });

    it('classifies operator-written text as customized', () => {
      const config = policyFactory();
      set(config, 'windows.popup.malware.message', 'Contact the SOC at ext. 4400');

      const normalized = normalizePolicyConfig(config, registry);

      expect(normalized.perOs.windows['popup.malware.message']).toBe('customized');
    });

    it('never carries the raw message text into the normalized form', () => {
      const config = policyFactory();
      set(config, 'windows.popup.malware.message', 'Contact the SOC at ext. 4400');

      expect(JSON.stringify(normalizePolicyConfig(config, registry))).not.toContain('ext. 4400');
    });

    it('does not confuse the rule default with the filename default', () => {
      const config = policyFactory();
      set(config, 'windows.popup.malware.message', DefaultPolicyRuleNotificationMessage);

      const normalized = normalizePolicyConfig(config, registry);

      expect(normalized.perOs.windows['popup.malware.message']).toBe('customized');
    });

    it('classifies popup.*.enabled as a normal boolean, not a message state', () => {
      const config = policyFactory();
      set(config, 'windows.popup.malware.enabled', false);

      const normalized = normalizePolicyConfig(config, registry);

      expect(normalized.perOs.windows['popup.malware.enabled']).toBe(false);
    });
  });

  describe('key insertion order', () => {
    it('produces deep-equal output for the same policy written in a different key order', () => {
      const config = policyFactory();

      const reordered = cloneDeep(config);
      const { mode, blocklist, on_write_scan: onWriteScan } = config.windows.malware;
      reordered.windows.malware = { on_write_scan: onWriteScan, blocklist, mode };

      expect(normalizePolicyConfig(reordered, registry)).toEqual(
        normalizePolicyConfig(config, registry)
      );
    });
  });

  it('is a pure function of its inputs', () => {
    const config = policyFactory();
    const snapshot = cloneDeep(config);

    normalizePolicyConfig(config, registry);

    expect(config).toEqual(snapshot);
  });

  it('reflects a real protection change', () => {
    const config = policyFactory();
    set(config, 'windows.malware.mode', ProtectionModes.detect);

    const normalized = normalizePolicyConfig(config, registry);

    expect(normalized.perOs.windows['malware.mode']).toBe(ProtectionModes.detect);
  });
});
