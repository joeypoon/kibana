/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cloneDeep } from 'lodash';
import { set } from '@kbn/safer-lodash-set';

import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import { buildPolicyFieldRegistry } from '../field_registry/generate_field_registry';
import { normalizePolicyConfig } from '../normalize/normalize_policy_config';
import type { NormalizedPolicyConfig } from '../normalize/types';
import { areStoredValuesEqual, hashPolicyConfig } from './hash_policy_config';

const PACKAGE_VERSION = '9.4.0';
const registry = buildPolicyFieldRegistry({ packageVersion: PACKAGE_VERSION });

const hashOf = (config = policyFactory()): string =>
  hashPolicyConfig(normalizePolicyConfig(config, registry));

describe('hashPolicyConfig', () => {
  it('is stable for the same configuration', () => {
    expect(hashOf()).toBe(hashOf());
  });

  it('returns a hex sha256 digest', () => {
    expect(hashOf()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes when a real protection leaf changes', () => {
    const config = policyFactory();
    set(config, 'windows.malware.mode', ProtectionModes.detect);

    expect(hashOf(config)).not.toBe(hashOf());
  });

  it('changes when global_telemetry_enabled changes', () => {
    expect(hashOf(policyFactory({ isGlobalTelemetryEnabled: true }))).not.toBe(
      hashOf(policyFactory({ isGlobalTelemetryEnabled: false }))
    );
  });

  describe('stability across key insertion order', () => {
    it('is unchanged when a policy branch is rebuilt with reversed key order', () => {
      const config = policyFactory();
      const reordered = cloneDeep(config);
      const { mode, blocklist, on_write_scan: onWriteScan } = config.windows.malware;
      reordered.windows.malware = { on_write_scan: onWriteScan, blocklist, mode };

      expect(hashOf(reordered)).toBe(hashOf(config));
    });

    it('is unchanged when the normalized object itself is rebuilt key-reversed', () => {
      const config = policyFactory();
      set(config, 'windows.advanced.some_unknown_key', 'a');
      set(config, 'windows.advanced.another_unknown_key', 'b');

      const normalized = normalizePolicyConfig(config, registry);
      const reversedBranch = (branch: Readonly<Record<string, unknown>>): Record<string, unknown> =>
        Object.fromEntries(Object.entries(branch).reverse());

      const reversed: NormalizedPolicyConfig = {
        perOs: {
          [PolicyOperatingSystem.linux]: reversedBranch(normalized.perOs.linux),
          [PolicyOperatingSystem.mac]: reversedBranch(normalized.perOs.mac),
          [PolicyOperatingSystem.windows]: reversedBranch(normalized.perOs.windows),
        },
        unrecognizedPerOs: {
          [PolicyOperatingSystem.linux]: reversedBranch(normalized.unrecognizedPerOs.linux),
          [PolicyOperatingSystem.mac]: reversedBranch(normalized.unrecognizedPerOs.mac),
          [PolicyOperatingSystem.windows]: reversedBranch(normalized.unrecognizedPerOs.windows),
        },
        globalTelemetryEnabled: normalized.globalTelemetryEnabled,
        globalManifestVersion: normalized.globalManifestVersion,
      };

      expect(hashPolicyConfig(reversed)).toBe(hashPolicyConfig(normalized));
    });
  });

  describe('a setting this build does not recognise cannot produce a false equality', () => {
    it('hashes differently for two policies differing ONLY at an unknown advanced key', () => {
      const aggressive = policyFactory();
      set(aggressive, 'windows.advanced.some_new_9_7_key', 'aggressive');

      const off = policyFactory();
      set(off, 'windows.advanced.some_new_9_7_key', 'off');

      expect(hashOf(aggressive)).not.toBe(hashOf(off));
    });

    it('hashes differently when only one policy carries the unknown key at all', () => {
      const withKey = policyFactory();
      set(withKey, 'windows.advanced.some_new_9_7_key', 'aggressive');

      expect(hashOf(withKey)).not.toBe(hashOf(policyFactory()));
    });

    it('distinguishes the OS branch an unknown key was set on', () => {
      const onWindows = policyFactory();
      set(onWindows, 'windows.advanced.some_new_9_7_key', 'on');

      const onLinux = policyFactory();
      set(onLinux, 'linux.advanced.some_new_9_7_key', 'on');

      expect(hashOf(onWindows)).not.toBe(hashOf(onLinux));
    });

    it('still hashes EQUAL for two policies carrying the same unknown key with the same value', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.some_new_9_7_key', 'aggressive');

      const right = policyFactory();
      set(right, 'windows.advanced.some_new_9_7_key', 'aggressive');

      expect(hashOf(left)).toBe(hashOf(right));
    });

    it('still hashes equal across several shared unknown keys written in a different order', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.new_key_a', 'one');
      set(left, 'windows.advanced.new_key_b', 2);
      set(left, 'linux.advanced.new_key_c', true);

      const right = policyFactory();
      set(right, 'linux.advanced.new_key_c', true);
      set(right, 'windows.advanced.new_key_b', 2);
      set(right, 'windows.advanced.new_key_a', 'one');

      expect(hashOf(left)).toBe(hashOf(right));
    });

    it('does not let a registry-known field on the wrong OS branch change the hash', () => {
      const config = policyFactory();
      set(config, 'linux.antivirus_registration.enabled', true);

      expect(hashOf(config)).toBe(hashOf());
    });
  });

  describe('the protection-updates pin is outside the hash', () => {
    it('hashes equal for two configs differing ONLY in global_manifest_version', () => {
      const latest = policyFactory();
      const pinned = policyFactory();
      pinned.global_manifest_version = '2024-06-01';

      expect(latest.global_manifest_version).not.toBe(pinned.global_manifest_version);
      expect(hashOf(pinned)).toBe(hashOf(latest));
    });

    it('hashes equal across three distinct pins', () => {
      const pins = ['latest', '2024-01-01', '2025-12-31'];

      const hashes = new Set(
        pins.map((pin) => {
          const config = policyFactory();
          config.global_manifest_version = pin;

          return hashOf(config);
        })
      );

      expect(hashes.size).toBe(1);
    });
  });

  describe('excluded surfaces cannot reach the digest', () => {
    it('ignores every meta.* field', () => {
      expect(
        hashOf(
          policyFactory({
            license: 'platinum',
            licenseUuid: 'uuid-a',
            clusterUuid: 'cluster-a',
            clusterName: 'prod',
            serverless: true,
          })
        )
      ).toBe(hashOf(policyFactory()));
    });

    it('ignores logging.file', () => {
      const config = policyFactory();
      set(config, 'windows.logging.file', 'debug');
      set(config, 'linux.logging.file', 'error');

      expect(hashOf(config)).toBe(hashOf());
    });

    it('ignores an artifact_manifest sibling placed on the config', () => {
      const config = policyFactory();
      set(config, 'windows.artifact_manifest.value', { artifacts: { 'endpoint-blah': 'abc123' } });

      expect(hashOf(config)).toBe(hashOf());
    });

    it('ignores policy_ids however it is attached', () => {
      const config = policyFactory();
      set(config, 'policy_ids', ['agent-policy-1', 'agent-policy-2']);

      expect(hashOf(config)).toBe(hashOf());
    });
  });

  it('is insensitive to prototype identity, so a reconstructed object agrees', () => {
    const normalized = normalizePolicyConfig(policyFactory(), registry);

    expect(hashPolicyConfig(JSON.parse(JSON.stringify(normalized)))).toBe(
      hashPolicyConfig(normalized)
    );
  });

  describe('array-valued stored leaves share structural equality with comparison', () => {
    it('hashes equal for two policies whose array-valued advanced setting differs only by array identity', () => {
      const left = policyFactory();
      const right = policyFactory();
      set(left, 'linux.advanced.capture_env_vars', ['HOME', 'PATH']);
      set(right, 'linux.advanced.capture_env_vars', ['HOME', 'PATH']);

      expect(hashOf(left)).toBe(hashOf(right));
      expect(areStoredValuesEqual(['HOME', 'PATH'], ['HOME', 'PATH'])).toBe(true);
    });

    it('hashes differently when the array-valued advanced setting contents differ', () => {
      const left = policyFactory();
      const right = policyFactory();
      set(left, 'linux.advanced.capture_env_vars', ['HOME', 'PATH']);
      set(right, 'linux.advanced.capture_env_vars', ['PATH', 'HOME']);

      expect(hashOf(left)).not.toBe(hashOf(right));
      expect(areStoredValuesEqual(['HOME', 'PATH'], ['PATH', 'HOME'])).toBe(false);
    });
  });
});
