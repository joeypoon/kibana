/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';

import { AdvancedPolicySchema } from '../../../../../../common/endpoint/service/policy/field_registry/advanced_policy_schema';
import { buildPolicyFieldRegistry, collectFactoryLeaves } from './generate_field_registry';
import { parseDocumentedDefault } from './parse_documented_default';
import type { PolicyFieldRecord } from './types';

const PACKAGE_VERSION = '8.15.1';

const walkLeaves = (value: unknown, prefix: string, into: Set<string>): void => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    if (value !== undefined) {
      into.add(prefix);
    }

    return;
  }

  for (const [segment, child] of Object.entries(value as Record<string, unknown>)) {
    walkLeaves(child, prefix === '' ? segment : `${prefix}.${segment}`, into);
  }
};

const factoryLeafPaths = (): Set<string> => {
  const paths = new Set<string>();
  walkLeaves(policyFactory(), '', paths);

  return paths;
};

const registry = buildPolicyFieldRegistry({ packageVersion: PACKAGE_VERSION });
const { osLeaves } = collectFactoryLeaves();

const identity = ({ keyPath, os }: PolicyFieldRecord): string => `${os.join(',')}|${keyPath}`;

describe('buildPolicyFieldRegistry', () => {
  it('stamps the requested package version', () => {
    expect(registry.packageVersion).toBe(PACKAGE_VERSION);
  });

  it('emits no duplicate (keyPath, os) records', () => {
    const seen = new Set(registry.fields.map(identity));

    expect(seen.size).toBe(registry.fields.length);
  });

  describe('default provenance', () => {
    it('gives every record a defaultSource', () => {
      for (const field of registry.fields) {
        expect(field.defaultSource).toBeDefined();
      }
    });

    it('only omits a default when the source is unknown', () => {
      for (const field of registry.fields) {
        if (field.default === undefined) {
          expect(field.defaultSource).toBe('unknown');
        }
      }
    });

    it('always carries a value when the source is not unknown', () => {
      for (const field of registry.fields) {
        if (field.defaultSource !== 'unknown') {
          expect(field.default).not.toBeUndefined();
        }
      }
    });

    it('falls back to policyFactory for linux and mac capture_env_vars', () => {
      for (const os of [PolicyOperatingSystem.linux, PolicyOperatingSystem.mac] as const) {
        const field = registry.fields.find(
          (candidate) => candidate.keyPath === 'advanced.capture_env_vars' && candidate.os[0] === os
        );

        expect(field).toMatchObject({
          defaultSource: 'policy_factory',
          default: osLeaves.get(os)?.get('advanced.capture_env_vars'),
          type: 'string',
        });
      }
    });

    it('does not invent defaults for other Default: none. advanced keys', () => {
      const documentedNone = AdvancedPolicySchema.filter(({ documentation }) => {
        const parsed = parseDocumentedDefault({ documentation });

        return parsed.status === 'unparseable' && parsed.reason === 'value_absent';
      });
      const factoryFallbackKeys = new Set([
        'linux.advanced.capture_env_vars',
        'mac.advanced.capture_env_vars',
      ]);
      const invented: string[] = [];

      for (const { key } of documentedNone) {
        if (!factoryFallbackKeys.has(key)) {
          const [os, ...remainder] = key.split('.');
          const field = registry.fields.find(
            (candidate) => candidate.keyPath === remainder.join('.') && candidate.os[0] === os
          );

          if (
            field === undefined ||
            field.defaultSource !== 'unknown' ||
            field.default !== undefined
          ) {
            invented.push(key);
          }
        }
      }

      expect(documentedNone.length).toBeGreaterThan(factoryFallbackKeys.size);
      expect(invented).toEqual([]);
    });

    it('resolves a version-conditional default to the branch matching the package version', () => {
      const forOlder = buildPolicyFieldRegistry({ packageVersion: '8.14.0' }).fields.find(
        (field) =>
          field.keyPath === 'advanced.events.process_ancestry_length' &&
          field.os[0] === PolicyOperatingSystem.windows
      );
      const forNewer = registry.fields.find(
        (field) =>
          field.keyPath === 'advanced.events.process_ancestry_length' &&
          field.os[0] === PolicyOperatingSystem.windows
      );

      expect(forOlder).toMatchObject({
        default: 20,
        type: 'number',
        defaultSource: 'advanced_schema_documentation',
      });
      expect(forNewer).toMatchObject({
        default: 5,
        type: 'number',
        defaultSource: 'advanced_schema_documentation',
      });
    });

    it('keeps the declared type even when a conditional default cannot be resolved', () => {
      const uncomparable = buildPolicyFieldRegistry({ packageVersion: 'latest' }).fields.find(
        (field) =>
          field.keyPath === 'advanced.events.process_ancestry_length' &&
          field.os[0] === PolicyOperatingSystem.windows
      );

      expect(uncomparable).toMatchObject({ defaultSource: 'unknown', type: 'number' });
      expect(uncomparable?.default).toBeUndefined();
    });
  });

  describe('the advanced surface', () => {
    it('represents every AdvancedPolicySchema key exactly once', () => {
      const occurrencesByKey = new Map<string, number>();

      for (const field of registry.fields) {
        const qualified = field.os.length === 0 ? field.keyPath : `${field.os[0]}.${field.keyPath}`;
        occurrencesByKey.set(qualified, (occurrencesByKey.get(qualified) ?? 0) + 1);
      }

      const missing: string[] = [];
      const duplicated: string[] = [];

      for (const { key } of AdvancedPolicySchema) {
        const occurrences = occurrencesByKey.get(key) ?? 0;

        if (occurrences === 0) {
          missing.push(key);
        } else if (occurrences > 1) {
          duplicated.push(key);
        }
      }

      expect(missing).toEqual([]);
      expect(duplicated).toEqual([]);

      const schemaSourced = registry.fields.filter(
        ({ firstSupportedVersion }) => firstSupportedVersion !== undefined
      );

      expect(schemaSourced).toHaveLength(AdvancedPolicySchema.length);
    });

    it('accounts for the one schema key that is not in the advanced namespace', () => {
      const nonAdvanced = AdvancedPolicySchema.filter(
        ({ key }) => key.split('.')[1] !== 'advanced'
      );

      expect(nonAdvanced.map(({ key }) => key)).toEqual(['mac.ransomware.mode']);

      const advancedCategoryCount = registry.fields.filter(
        ({ category }) => category === 'advanced'
      ).length;

      expect(advancedCategoryCount).toBe(AdvancedPolicySchema.length - nonAdvanced.length);
    });

    it('strips the OS segment into `os` and leaves a branch-relative keyPath', () => {
      const connectionDelay = registry.fields.find(
        (field) =>
          field.keyPath === 'advanced.agent.connection_delay' &&
          field.os[0] === PolicyOperatingSystem.linux
      );

      expect(connectionDelay).toMatchObject({
        keyPath: 'advanced.agent.connection_delay',
        os: [PolicyOperatingSystem.linux],
        category: 'advanced',
        type: 'number',
        default: 60,
        defaultSource: 'advanced_schema_documentation',
        firstSupportedVersion: '7.9',
        configurable: true,
      });
      expect(connectionDelay?.documentation).toContain('agent connectivity');
    });

    it('carries the shipped license tier through', () => {
      const selfHealing = registry.fields.find(
        (field) =>
          field.keyPath === 'advanced.alerts.rollback.self_healing.enabled' &&
          field.os[0] === PolicyOperatingSystem.windows
      );

      expect(selfHealing?.license).toBe('platinum');
    });

    it('gives every advanced record a first supported version and marks it configurable', () => {
      for (const field of registry.fields.filter(({ category }) => category === 'advanced')) {
        expect(field.firstSupportedVersion).toBeDefined();
        expect(field.configurable).toBe(true);
      }
    });
  });

  describe('the non-advanced surface', () => {
    it('matches a fresh recursive walk of policyFactory() exactly, with no drift', () => {
      const expected = new Set(
        [...factoryLeafPaths()].filter((path) => !/^(windows|mac|linux)\.advanced\./.test(path))
      );

      const actual = new Set(
        registry.fields
          .filter(
            ({ defaultSource, keyPath }) =>
              defaultSource === 'policy_factory' && !keyPath.startsWith('advanced.')
          )
          .map(({ keyPath, os }) => (os.length === 0 ? keyPath : `${os[0]}.${keyPath}`))
      );

      expected.delete('mac.ransomware.mode');

      expect([...actual].sort()).toEqual([...expected].sort());
    });

    it('accounts for every factory leaf, whether via the factory or the advanced schema', () => {
      const registryPaths = new Set(
        registry.fields.map(({ keyPath, os }) =>
          os.length === 0 ? keyPath : `${os[0]}.${keyPath}`
        )
      );

      for (const path of factoryLeafPaths()) {
        expect(registryPaths).toContain(path);
      }
    });

    it('scopes root globals with an empty os and a root keyPath', () => {
      const globals = registry.fields.filter(({ category }) => category === 'global');

      expect(globals.map(({ keyPath }) => keyPath).sort()).toEqual([
        'global_manifest_version',
        'global_telemetry_enabled',
      ]);

      for (const field of globals) {
        expect(field.os).toEqual([]);
        expect(field.defaultSource).toBe('policy_factory');
        expect(field.configurable).toBe(true);
      }
    });

    it('assigns a category from the owning branch', () => {
      const categoryOf = (keyPath: string, os: PolicyOperatingSystem) =>
        registry.fields.find((field) => field.keyPath === keyPath && field.os[0] === os)?.category;

      expect(categoryOf('malware.mode', PolicyOperatingSystem.windows)).toBe('protection');
      expect(categoryOf('ransomware.supported', PolicyOperatingSystem.windows)).toBe('protection');
      expect(categoryOf('memory_protection.mode', PolicyOperatingSystem.mac)).toBe('protection');
      expect(categoryOf('behavior_protection.mode', PolicyOperatingSystem.linux)).toBe(
        'protection'
      );
      expect(categoryOf('popup.malware.message', PolicyOperatingSystem.windows)).toBe('popup');
      expect(categoryOf('events.dns', PolicyOperatingSystem.linux)).toBe('events');
      expect(categoryOf('device_control.enabled', PolicyOperatingSystem.windows)).toBe(
        'device_control'
      );
      expect(categoryOf('antivirus_registration.mode', PolicyOperatingSystem.windows)).toBe(
        'antivirus_registration'
      );
      expect(
        categoryOf(
          'attack_surface_reduction.credential_hardening.enabled',
          PolicyOperatingSystem.windows
        )
      ).toBe('attack_surface_reduction');
      expect(categoryOf('logging.file', PolicyOperatingSystem.mac)).toBe('logging');
    });

    it('types the protection mode leaves as enums with their real allowed values', () => {
      const malwareMode = registry.fields.find(
        (field) => field.keyPath === 'malware.mode' && field.os[0] === PolicyOperatingSystem.windows
      );

      expect(malwareMode).toMatchObject({ type: 'enum', default: 'prevent' });
      expect(malwareMode?.enumValues).toEqual(['detect', 'prevent', 'off']);
    });

    it('types the device control access level as an enum', () => {
      const usbStorage = registry.fields.find(
        (field) =>
          field.keyPath === 'device_control.usb_storage' &&
          field.os[0] === PolicyOperatingSystem.windows
      );

      expect(usbStorage).toMatchObject({ type: 'enum', default: 'deny_all' });
      expect(usbStorage?.enumValues).toEqual(['audit', 'read_only', 'no_execute', 'deny_all']);
    });

    it('infers boolean and string types from the factory values', () => {
      const eventsDns = registry.fields.find(
        (field) => field.keyPath === 'events.dns' && field.os[0] === PolicyOperatingSystem.windows
      );
      const popupMessage = registry.fields.find(
        (field) =>
          field.keyPath === 'popup.malware.message' && field.os[0] === PolicyOperatingSystem.windows
      );

      expect(eventsDns).toMatchObject({ type: 'boolean', default: true });
      expect(popupMessage).toMatchObject({ type: 'string', default: '' });
    });
  });

  describe('meta fields', () => {
    const metaFields = registry.fields.filter(({ category }) => category === 'meta');

    it('emits the platform-stamped meta leaves', () => {
      expect(metaFields.length).toBeGreaterThan(0);
      expect(metaFields.map(({ keyPath }) => keyPath).sort()).toEqual(
        [
          'meta.billable',
          'meta.cloud',
          'meta.cluster_name',
          'meta.cluster_uuid',
          'meta.license',
          'meta.license_uuid',
          'meta.serverless',
        ].sort()
      );
    });

    it('marks every meta field non-configurable and root-scoped', () => {
      for (const field of metaFields) {
        expect(field.configurable).toBe(false);
        expect(field.os).toEqual([]);
        expect(field.keyPath.startsWith('meta.')).toBe(true);
      }
    });

    it('separates meta from the configurable surface: nothing else is non-configurable', () => {
      const nonConfigurable = registry.fields.filter(({ configurable }) => !configurable);

      expect(nonConfigurable).toEqual(metaFields);
    });

    it('includes `billable`, which is assigned after the factory object literal', () => {
      const billable = metaFields.find(({ keyPath }) => keyPath === 'meta.billable');

      expect(billable).toMatchObject({
        type: 'boolean',
        defaultSource: 'policy_factory',
        configurable: false,
      });
    });
  });

  describe('source precedence on collisions', () => {
    it('lets the advanced schema win capture_env_vars, keeping its version metadata', () => {
      const linuxCaptureEnvVars = registry.fields.filter(
        (field) =>
          field.keyPath === 'advanced.capture_env_vars' &&
          field.os[0] === PolicyOperatingSystem.linux
      );

      expect(linuxCaptureEnvVars).toHaveLength(1);
      expect(linuxCaptureEnvVars[0].firstSupportedVersion).toBeDefined();
      expect(linuxCaptureEnvVars[0].documentation).toBeDefined();
      expect(linuxCaptureEnvVars[0]).toMatchObject({
        defaultSource: 'policy_factory',
        default: osLeaves.get(PolicyOperatingSystem.linux)?.get('advanced.capture_env_vars'),
      });
    });

    it('resolves mac.ransomware.mode to the schema record that carries its license', () => {
      const macRansomwareMode = registry.fields.filter(
        (field) => field.keyPath === 'ransomware.mode' && field.os[0] === PolicyOperatingSystem.mac
      );

      expect(macRansomwareMode).toHaveLength(1);
      expect(macRansomwareMode[0]).toMatchObject({
        category: 'protection',
        license: 'platinum',
        firstSupportedVersion: '9.4',
        default: 'off',
        defaultSource: 'advanced_schema_documentation',
      });
    });
  });
});
