/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cloneDeep } from 'lodash';
import { set } from '@kbn/safer-lodash-set';

import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import { buildPolicyFieldRegistry } from '../field_registry/generate_field_registry';
import { normalizePolicyConfig } from '../normalize/normalize_policy_config';
import type { ComparablePolicy } from './compare_policies';
import { comparePolicies } from './compare_policies';
import { hashPolicyConfig } from './hash_policy_config';

const PACKAGE_VERSION = '9.4.0';
const registry = buildPolicyFieldRegistry({ packageVersion: PACKAGE_VERSION });

const asComparable = (
  id: string,
  config: PolicyConfig,
  packageVersion = PACKAGE_VERSION
): ComparablePolicy => ({
  id,
  packageVersion,
  configNormalized: normalizePolicyConfig(config, registry),
});

const compare = (
  left: PolicyConfig,
  right: PolicyConfig,
  versions: { left?: string; right?: string } = {}
) =>
  comparePolicies({
    left: asComparable('left', left, versions.left),
    right: asComparable('right', right, versions.right),
    registry,
  });

const keyPathsOf = (differences: ReadonlyArray<{ keyPath: string }>): string[] =>
  differences.map(({ keyPath }) => keyPath);

describe('comparePolicies', () => {
  it('reports identical policies as configIdentical with no differences', () => {
    const comparison = compare(policyFactory(), policyFactory());

    expect(comparison).toMatchObject({
      leftId: 'left',
      rightId: 'right',
      configIdentical: true,
      protectionUpdatesPinDiffers: false,
      differences: [],
    });
  });

  it('reports a single changed leaf with both values and its OS', () => {
    const right = policyFactory();
    set(right, 'windows.malware.mode', ProtectionModes.detect);

    const { differences, configIdentical } = compare(policyFactory(), right);

    expect(configIdentical).toBe(false);
    expect(differences).toEqual([
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        leftPresent: true,
        rightPresent: true,
        left: ProtectionModes.prevent,
        right: ProtectionModes.detect,
      },
    ]);
  });

  describe('ordering-only differences never appear as drift', () => {
    it('reports no difference when a branch is rebuilt with reversed key order', () => {
      const left = policyFactory();
      const right = cloneDeep(left);
      const { mode, blocklist, on_write_scan: onWriteScan } = left.windows.malware;
      right.windows.malware = { on_write_scan: onWriteScan, blocklist, mode };
      const {
        dns,
        file,
        network,
        process: proc,
        session_data: session,
        tty_io: tty,
      } = left.linux.events;
      right.linux.events = {
        tty_io: tty,
        session_data: session,
        process: proc,
        network,
        file,
        dns,
      };

      expect(compare(left, right)).toMatchObject({ configIdentical: true, differences: [] });
    });
  });

  describe('platform-specific fields never surface as another OS difference', () => {
    it('reports a windows-only change only against windows', () => {
      const right = policyFactory();
      set(right, 'windows.antivirus_registration.enabled', false);
      set(right, 'windows.attack_surface_reduction.credential_hardening.enabled', false);

      const { differences } = compare(policyFactory(), right);

      expect(differences).toHaveLength(2);
      expect(differences.every(({ os }) => os === PolicyOperatingSystem.windows)).toBe(true);
    });

    it('never reports a windows-only field against mac or linux even when set there', () => {
      const right = policyFactory();
      set(right, 'linux.antivirus_registration.enabled', false);
      set(right, 'mac.attack_surface_reduction.credential_hardening.enabled', false);

      const { differences, notComparable } = compare(policyFactory(), right);

      expect(differences).toEqual([]);
      expect(notComparable).toEqual([]);
    });

    it('never reports device_control against linux', () => {
      const right = policyFactory();
      set(right, 'windows.device_control.enabled', false);
      set(right, 'linux.device_control.enabled', false);

      const { differences } = compare(policyFactory(), right);

      expect(differences).toEqual([
        {
          keyPath: 'device_control.enabled',
          os: PolicyOperatingSystem.windows,
          leftPresent: true,
          rightPresent: true,
          left: true,
          right: false,
        },
      ]);
    });
  });

  describe('the protection-updates pin is its own dimension', () => {
    it('reports pin-only differences as identical configuration with a differing pin', () => {
      const left = policyFactory();
      const right = policyFactory();
      right.global_manifest_version = '2024-06-01';

      const comparison = compare(left, right);

      expect(comparison.configIdentical).toBe(true);
      expect(comparison.protectionUpdatesPinDiffers).toBe(true);
      expect(comparison.leftGlobalManifestVersion).toBe('latest');
      expect(comparison.rightGlobalManifestVersion).toBe('2024-06-01');
      expect(keyPathsOf(comparison.differences)).not.toContain('global_manifest_version');
      expect(keyPathsOf(comparison.notComparable)).not.toContain('global_manifest_version');
      expect(comparison.differences).toEqual([]);
    });

    it('reports both the pin and real drift when both are present', () => {
      const right = policyFactory();
      right.global_manifest_version = '2024-06-01';
      set(right, 'mac.malware.blocklist', false);

      const comparison = compare(policyFactory(), right);

      expect(comparison.protectionUpdatesPinDiffers).toBe(true);
      expect(comparison.configIdentical).toBe(false);
      expect(keyPathsOf(comparison.differences)).toEqual(['malware.blocklist']);
    });

    it('populates both pin fields even when the pins agree', () => {
      const comparison = compare(policyFactory(), policyFactory());

      expect(comparison.leftGlobalManifestVersion).toBe('latest');
      expect(comparison.rightGlobalManifestVersion).toBe('latest');
      expect(comparison.protectionUpdatesPinDiffers).toBe(false);
    });
  });

  describe('version scoping', () => {
    it('reports a stored protection difference across package versions as a difference, not identical', () => {
      const right = policyFactory();
      set(right, 'mac.ransomware.mode', ProtectionModes.prevent);

      const comparison = compare(policyFactory(), right, { left: '8.0.0' });

      expect(comparison.configIdentical).toBe(false);
      expect(comparison.notComparable).toEqual([]);
      expect(comparison.differences).toEqual([
        {
          keyPath: 'ransomware.mode',
          os: PolicyOperatingSystem.mac,
          leftPresent: true,
          rightPresent: true,
          left: ProtectionModes.off,
          right: ProtectionModes.prevent,
        },
      ]);
    });

    it('reports the same field as real drift when both versions support it', () => {
      const right = policyFactory();
      set(right, 'mac.ransomware.mode', ProtectionModes.prevent);

      const { differences, notComparable } = compare(policyFactory(), right);

      expect(keyPathsOf(differences)).toContain('ransomware.mode');
      expect(notComparable).toEqual([]);
    });

    it('never places a field in both differences and notComparable', () => {
      const right = policyFactory();
      set(right, 'mac.ransomware.mode', ProtectionModes.prevent);
      set(right, 'windows.malware.mode', ProtectionModes.off);

      const { differences, notComparable } = compare(policyFactory(), right, { left: '8.0.0' });

      const overlap = keyPathsOf(differences).filter((keyPath) =>
        keyPathsOf(notComparable).includes(keyPath)
      );

      expect(overlap).toEqual([]);
    });

    it('does not emit unstored version-window fields as notComparable', () => {
      const comparison = compare(policyFactory(), policyFactory(), {
        left: '8.0.0',
        right: '9.4.0',
      });

      expect(comparison).toMatchObject({
        configIdentical: true,
        differences: [],
        notComparable: [],
      });
    });

    it('reports a stored advanced setting as a windows difference', () => {
      const left = policyFactory();
      const right = policyFactory();
      set(left, 'windows.advanced.artifacts.global.interval', 3600);
      set(right, 'windows.advanced.artifacts.global.interval', 7200);

      const { differences, configIdentical, notComparable } = compare(left, right);

      expect(configIdentical).toBe(false);
      expect(notComparable).toEqual([]);
      expect(differences).toEqual([
        {
          keyPath: 'advanced.artifacts.global.interval',
          os: PolicyOperatingSystem.windows,
          leftPresent: true,
          rightPresent: true,
          left: 3600,
          right: 7200,
        },
      ]);
    });

    it('reports a stored advanced setting across package versions as a difference', () => {
      const left = policyFactory();
      const right = policyFactory();
      set(left, 'windows.advanced.artifacts.global.proxy_url', 'https://left.example');
      set(right, 'windows.advanced.artifacts.global.proxy_url', 'https://right.example');

      const { differences, configIdentical, notComparable } = compare(left, right, {
        left: '8.0.0',
      });

      expect(configIdentical).toBe(false);
      expect(notComparable).toEqual([]);
      expect(differences).toEqual([
        {
          keyPath: 'advanced.artifacts.global.proxy_url',
          os: PolicyOperatingSystem.windows,
          leftPresent: true,
          rightPresent: true,
          left: 'https://left.example',
          right: 'https://right.example',
        },
      ]);
    });
  });

  describe('array-valued stored leaves agree with duplicate hashing', () => {
    const ARRAY_PATH = 'linux.advanced.capture_env_vars';
    const LEFT_ARRAY = ['HOME', 'PATH'];
    const RIGHT_ARRAY = ['PATH', 'HOME'];

    it('reports identical configuration when array contents match, matching the config hash', () => {
      const left = policyFactory();
      const right = policyFactory();
      set(left, ARRAY_PATH, [...LEFT_ARRAY]);
      set(right, ARRAY_PATH, [...LEFT_ARRAY]);

      const comparison = compare(left, right);

      expect(comparison.configIdentical).toBe(true);
      expect(comparison.differences).toEqual([]);
      expect(comparison.notComparable).toEqual([]);
      expect(hashPolicyConfig(asComparable('left', left).configNormalized)).toBe(
        hashPolicyConfig(asComparable('right', right).configNormalized)
      );
    });

    it('reports a difference when array contents differ, matching a config hash mismatch', () => {
      const left = policyFactory();
      const right = policyFactory();
      set(left, ARRAY_PATH, [...LEFT_ARRAY]);
      set(right, ARRAY_PATH, [...RIGHT_ARRAY]);

      const comparison = compare(left, right);

      expect(comparison.configIdentical).toBe(false);
      expect(comparison.notComparable).toEqual([]);
      expect(comparison.differences).toEqual([
        {
          keyPath: 'advanced.capture_env_vars',
          os: PolicyOperatingSystem.linux,
          leftPresent: true,
          rightPresent: true,
          left: LEFT_ARRAY,
          right: RIGHT_ARRAY,
        },
      ]);
      expect(hashPolicyConfig(asComparable('left', left).configNormalized)).not.toBe(
        hashPolicyConfig(asComparable('right', right).configNormalized)
      );
    });
  });

  describe('popup messages', () => {
    it('reports a customization as a state change, not as raw text', () => {
      const right = policyFactory();
      set(right, 'windows.popup.malware.message', 'Call the SOC at ext. 4400');

      const { differences } = compare(policyFactory(), right);

      expect(differences).toEqual([
        {
          keyPath: 'popup.malware.message',
          os: PolicyOperatingSystem.windows,
          leftPresent: true,
          rightPresent: true,
          left: 'default',
          right: 'customized',
        },
      ]);
    });

    it('reports no drift between an empty message and the shipped default text', () => {
      const right = policyFactory();
      set(right, 'windows.popup.malware.message', 'Elastic Security {action} {filename}');

      expect(compare(policyFactory(), right)).toMatchObject({
        configIdentical: true,
        differences: [],
      });
    });

    it('reports no drift between two differently-worded customizations', () => {
      const left = policyFactory();
      const right = policyFactory();
      set(left, 'windows.popup.malware.message', 'Call the SOC');
      set(right, 'windows.popup.malware.message', 'Ring the on-call');

      expect(compare(left, right)).toMatchObject({ configIdentical: true, differences: [] });
    });
  });

  describe('excluded surfaces never appear as drift', () => {
    it('ignores meta.* differences', () => {
      expect(
        compare(policyFactory({ license: 'platinum', clusterName: 'a' }), policyFactory())
      ).toMatchObject({ configIdentical: true, differences: [] });
    });

    it('ignores logging.file differences', () => {
      const right = policyFactory();
      set(right, 'linux.logging.file', 'debug');

      expect(compare(policyFactory(), right)).toMatchObject({
        configIdentical: true,
        differences: [],
      });
    });
  });

  it('reports global_telemetry_enabled as a policy-root difference with no os', () => {
    const { differences } = compare(
      policyFactory({ isGlobalTelemetryEnabled: false }),
      policyFactory({ isGlobalTelemetryEnabled: true })
    );

    expect(differences).toEqual([
      {
        keyPath: 'global_telemetry_enabled',
        leftPresent: true,
        rightPresent: true,
        left: false,
        right: true,
      },
    ]);
  });

  it('reports a leaf present on one side only as notComparable, not as identical', () => {
    const right = policyFactory();
    delete right.windows.device_control;

    const comparison = compare(policyFactory(), right);
    const serializedNotComparable = JSON.parse(JSON.stringify(comparison.notComparable));

    expect(comparison.configIdentical).toBe(false);
    expect(keyPathsOf(comparison.differences)).not.toContain('device_control.enabled');
    expect(serializedNotComparable).toEqual(
      expect.arrayContaining([
        {
          keyPath: 'device_control.enabled',
          os: PolicyOperatingSystem.windows,
          leftPresent: true,
          rightPresent: false,
          left: true,
        },
      ])
    );
  });

  describe('registry-unknown stored leaves', () => {
    it('reports a value change on an unknown leaf as an unrecognized difference', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.some_new_9_7_key', 'aggressive');
      const right = policyFactory();
      set(right, 'windows.advanced.some_new_9_7_key', 'off');

      const { differences, configIdentical, notComparable } = compare(left, right);

      expect(configIdentical).toBe(false);
      expect(notComparable).toEqual([]);
      expect(differences).toEqual([
        {
          keyPath: 'advanced.some_new_9_7_key',
          os: PolicyOperatingSystem.windows,
          leftPresent: true,
          rightPresent: true,
          left: 'aggressive',
          right: 'off',
          unrecognized: true,
        },
      ]);
    });

    it('reports an unknown leaf present on one side only as notComparable', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.some_new_9_7_key', 'aggressive');

      const { differences, configIdentical, notComparable } = compare(left, policyFactory());

      expect(configIdentical).toBe(false);
      expect(differences).toEqual([]);
      expect(notComparable).toEqual([
        {
          keyPath: 'advanced.some_new_9_7_key',
          os: PolicyOperatingSystem.windows,
          leftPresent: true,
          rightPresent: false,
          left: 'aggressive',
          right: undefined,
          unrecognized: true,
        },
      ]);
    });

    it('reports identical policies that share the same unknown leaf as configIdentical', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.some_new_9_7_key', 'aggressive');
      const right = policyFactory();
      set(right, 'windows.advanced.some_new_9_7_key', 'aggressive');

      expect(compare(left, right)).toMatchObject({
        configIdentical: true,
        differences: [],
        notComparable: [],
      });
    });

    it('scopes an unknown leaf present on only one OS as notComparable on that OS', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.some_new_9_7_key', 'on');
      const right = policyFactory();
      set(right, 'linux.advanced.some_new_9_7_key', 'on');

      const { differences, configIdentical, notComparable } = compare(left, right);

      expect(configIdentical).toBe(false);
      expect(differences).toEqual([]);
      expect(notComparable).toEqual([
        {
          keyPath: 'advanced.some_new_9_7_key',
          os: PolicyOperatingSystem.windows,
          leftPresent: true,
          rightPresent: false,
          left: 'on',
          right: undefined,
          unrecognized: true,
        },
        {
          keyPath: 'advanced.some_new_9_7_key',
          os: PolicyOperatingSystem.linux,
          leftPresent: false,
          rightPresent: true,
          left: undefined,
          right: 'on',
          unrecognized: true,
        },
      ]);
    });

    it('still treats two policies as identical when shared unknown leaves were written in a different order', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.new_key_a', 'one');
      set(left, 'windows.advanced.new_key_b', 2);
      const right = policyFactory();
      set(right, 'windows.advanced.new_key_b', 2);
      set(right, 'windows.advanced.new_key_a', 'one');

      expect(compare(left, right)).toMatchObject({
        configIdentical: true,
        differences: [],
      });
    });

    it('still reports a known leaf change when an unknown leaf also differs', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.some_new_9_7_key', 'aggressive');
      const right = policyFactory();
      set(right, 'windows.advanced.some_new_9_7_key', 'off');
      set(right, 'windows.malware.mode', ProtectionModes.detect);

      const { differences, configIdentical } = compare(left, right);

      expect(configIdentical).toBe(false);
      expect(keyPathsOf(differences)).toEqual(['malware.mode', 'advanced.some_new_9_7_key']);
      expect(differences.find(({ keyPath }) => keyPath === 'advanced.some_new_9_7_key')).toEqual({
        keyPath: 'advanced.some_new_9_7_key',
        os: PolicyOperatingSystem.windows,
        leftPresent: true,
        rightPresent: true,
        left: 'aggressive',
        right: 'off',
        unrecognized: true,
      });
    });
  });
});
