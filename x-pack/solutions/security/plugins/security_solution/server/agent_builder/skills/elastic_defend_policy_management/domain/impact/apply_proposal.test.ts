/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cloneDeep } from 'lodash';

import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import type { PolicyChangeOperation, PolicyChangeProposal } from './types';
import { applyChangeProposal, MAX_CHANGE_OPERATIONS } from './apply_proposal';
import { buildImpactFieldLookup } from './field_lookup';
import { buildTestRegistry, buildTestSnapshot, TEST_PACKAGE_VERSION } from './test_fixtures';

const buildProposal = (
  operations: readonly PolicyChangeOperation[],
  overrides: Partial<PolicyChangeProposal> = {}
): PolicyChangeProposal => {
  const snapshot = buildTestSnapshot();

  return {
    policyId: snapshot.identity.id,
    identity: { revision: snapshot.identity.revision, version: snapshot.identity.version },
    operations,
    ...overrides,
  };
};

describe('applyChangeProposal', () => {
  const registry = buildTestRegistry();
  const lookup = buildImpactFieldLookup(registry);

  it('applies an OS-scoped change to a clone and leaves the source config untouched', () => {
    const snapshot = buildTestSnapshot();
    const sourceBefore = cloneDeep(snapshot.config);

    const result = applyChangeProposal({
      proposal: buildProposal([
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.detect,
        },
      ]),
      snapshot,
      lookup,
    });

    if ('rejection' in result) {
      throw new Error(`expected acceptance, got rejection: ${result.rejection.message}`);
    }

    expect(result.config.windows.malware.mode).toBe(ProtectionModes.detect);
    expect(result.config.mac.malware.mode).toBe(snapshot.config.mac.malware.mode);
    expect(snapshot.config).toEqual(sourceBefore);
    expect(result.config).not.toBe(snapshot.config);
  });

  it('does not mutate a deep-frozen source config', () => {
    const snapshot = buildTestSnapshot();

    const deepFreeze = (value: unknown): void => {
      if (typeof value !== 'object' || value === null) {
        return;
      }

      Object.freeze(value);

      for (const nested of Object.values(value)) {
        deepFreeze(nested);
      }
    };

    deepFreeze(snapshot.config);

    const result = applyChangeProposal({
      proposal: buildProposal([
        { keyPath: 'events.file', os: PolicyOperatingSystem.linux, proposedValue: false },
      ]),
      snapshot,
      lookup,
    });

    if ('rejection' in result) {
      throw new Error(`expected acceptance, got rejection: ${result.rejection.message}`);
    }

    expect(result.config.linux.events.file).toBe(false);
    expect(snapshot.config.linux.events.file).toBe(true);
  });

  it('applies a policy-root change when no os is supplied', () => {
    const snapshot = buildTestSnapshot();

    const result = applyChangeProposal({
      proposal: buildProposal([
        { keyPath: 'global_manifest_version', proposedValue: '2026-01-02' },
      ]),
      snapshot,
      lookup,
    });

    if ('rejection' in result) {
      throw new Error(`expected acceptance, got rejection: ${result.rejection.message}`);
    }

    expect(result.config.global_manifest_version).toBe('2026-01-02');
    expect(snapshot.config.global_manifest_version).toBe('latest');
  });

  describe('rejections', () => {
    it('distinguishes an unknown key path from a field that does not apply to the OS', () => {
      const snapshot = buildTestSnapshot();

      const unknown = applyChangeProposal({
        proposal: buildProposal([
          {
            keyPath: 'malware.definitely_not_a_field',
            os: PolicyOperatingSystem.windows,
            proposedValue: true,
          },
        ]),
        snapshot,
        lookup,
      });

      const inapplicable = applyChangeProposal({
        proposal: buildProposal([
          {
            keyPath: 'antivirus_registration.enabled',
            os: PolicyOperatingSystem.linux,
            proposedValue: true,
          },
        ]),
        snapshot,
        lookup,
      });

      expect(unknown).toEqual({
        rejection: {
          reason: 'unknown_key_path',
          message:
            'No configurable Elastic Defend policy field matches [malware.definitely_not_a_field].',
          keyPath: 'malware.definitely_not_a_field',
          os: PolicyOperatingSystem.windows,
        },
      });

      expect(inapplicable).toEqual({
        rejection: {
          reason: 'not_applicable_for_os',
          message:
            '[antivirus_registration.enabled] exists but does not apply to [linux]. It applies to: windows.',
          keyPath: 'antivirus_registration.enabled',
          os: PolicyOperatingSystem.linux,
        },
      });

      expect('rejection' in unknown && unknown.rejection.reason).not.toEqual(
        'rejection' in inapplicable && inapplicable.rejection.reason
      );
    });

    it('rejects a platform-stamped field as an unknown key path rather than applying it', () => {
      const snapshot = buildTestSnapshot();

      const result = applyChangeProposal({
        proposal: buildProposal([{ keyPath: 'meta.license', proposedValue: 'trial' }]),
        snapshot,
        lookup,
      });

      expect(result).toEqual({
        rejection: {
          reason: 'unknown_key_path',
          message: 'No configurable Elastic Defend policy field matches [meta.license].',
          keyPath: 'meta.license',
          os: undefined,
        },
      });
    });

    it('rejects a key path retired before the policy package version', () => {
      const snapshot = buildTestSnapshot();

      const result = applyChangeProposal({
        proposal: buildProposal([
          {
            keyPath: 'advanced.retired_setting',
            os: PolicyOperatingSystem.windows,
            proposedValue: 'anything',
          },
        ]),
        snapshot,
        lookup,
      });

      expect(result).toEqual({
        rejection: {
          reason: 'outside_version_window',
          message: `[advanced.retired_setting] is not supported by Elastic Defend package version ${TEST_PACKAGE_VERSION}; it was supported through 8.10.`,
          keyPath: 'advanced.retired_setting',
          os: PolicyOperatingSystem.windows,
        },
      });
    });

    it('rejects a key path introduced after the policy package version', () => {
      const snapshot = buildTestSnapshot();

      const result = applyChangeProposal({
        proposal: buildProposal([
          {
            keyPath: 'advanced.future_setting',
            os: PolicyOperatingSystem.windows,
            proposedValue: 'on',
          },
        ]),
        snapshot,
        lookup,
      });

      expect(result).toEqual({
        rejection: {
          reason: 'outside_version_window',
          message: `[advanced.future_setting] is not available in Elastic Defend package version ${TEST_PACKAGE_VERSION}; it was introduced in 9.4.`,
          keyPath: 'advanced.future_setting',
          os: PolicyOperatingSystem.windows,
        },
      });
    });

    it('rejects a proposal naming a different policy than the snapshot, even when revision and version match', () => {
      const snapshot = buildTestSnapshot({ revision: 4, version: 'WzEsMV0=' });
      const sourceBefore = cloneDeep(snapshot.config);

      const result = applyChangeProposal({
        proposal: buildProposal(
          [
            {
              keyPath: 'malware.mode',
              os: PolicyOperatingSystem.windows,
              proposedValue: ProtectionModes.off,
            },
          ],
          {
            policyId: 'a-different-policy',
            identity: { revision: 4, version: 'WzEsMV0=' },
          }
        ),
        snapshot,
        lookup,
      });

      if (!('rejection' in result)) {
        throw new Error('expected an identity_mismatch rejection');
      }

      expect(result.rejection.reason).toBe('identity_mismatch');
      expect(result.rejection.currentIdentity).toEqual(snapshot.identity);
      expect(result.rejection.message).toContain('a-different-policy');
      expect(result.rejection.message).toContain(snapshot.identity.id);
      expect(result.rejection.message).toContain('Nothing was assessed');
      expect(snapshot.config).toEqual(sourceBefore);
    });

    it('rejects a stale revision, reports the current identity, and assesses nothing', () => {
      const snapshot = buildTestSnapshot({ revision: 9 });
      const sourceBefore = cloneDeep(snapshot.config);

      const result = applyChangeProposal({
        proposal: buildProposal(
          [
            {
              keyPath: 'malware.mode',
              os: PolicyOperatingSystem.windows,
              proposedValue: ProtectionModes.off,
            },
          ],
          { identity: { revision: 4, version: snapshot.identity.version } }
        ),
        snapshot,
        lookup,
      });

      if (!('rejection' in result)) {
        throw new Error('expected a stale_snapshot rejection');
      }

      expect(result.rejection.reason).toBe('stale_snapshot');
      expect(result.rejection.currentIdentity).toEqual(snapshot.identity);
      expect(result.rejection.message).toContain('revision 9');
      expect(result.rejection.message).toContain('Nothing was assessed');
      expect(snapshot.config).toEqual(sourceBefore);
    });

    it('rejects a stale saved-object version even when the revision matches', () => {
      const snapshot = buildTestSnapshot({ revision: 4, version: 'Wzk5OSw1XQ==' });

      const result = applyChangeProposal({
        proposal: buildProposal(
          [{ keyPath: 'events.file', os: PolicyOperatingSystem.mac, proposedValue: false }],
          { identity: { revision: 4, version: 'WzEsMV0=' } }
        ),
        snapshot,
        lookup,
      });

      if (!('rejection' in result)) {
        throw new Error('expected a stale_snapshot rejection');
      }

      expect(result.rejection.reason).toBe('stale_snapshot');
      expect(result.rejection.currentIdentity).toEqual(snapshot.identity);
    });

    it('rejects an omitted saved-object version when the snapshot has one', () => {
      const snapshot = buildTestSnapshot({ revision: 4, version: 'Wzk5OSw1XQ==' });

      const result = applyChangeProposal({
        proposal: buildProposal(
          [{ keyPath: 'events.file', os: PolicyOperatingSystem.mac, proposedValue: false }],
          { identity: { revision: 4 } }
        ),
        snapshot,
        lookup,
      });

      if (!('rejection' in result)) {
        throw new Error('expected a stale_snapshot rejection');
      }

      expect(result.rejection.reason).toBe('stale_snapshot');
      expect(result.rejection.currentIdentity).toEqual(snapshot.identity);
      expect(result.rejection.message).toContain('does not identify that saved-object version');
      expect(result.rejection.message).toContain('Nothing was assessed');
    });

    it('rejects an expectedCurrentValue mismatch', () => {
      const snapshot = buildTestSnapshot();

      const result = applyChangeProposal({
        proposal: buildProposal([
          {
            keyPath: 'malware.mode',
            os: PolicyOperatingSystem.windows,
            expectedCurrentValue: ProtectionModes.off,
            proposedValue: ProtectionModes.detect,
          },
        ]),
        snapshot,
        lookup,
      });

      if (!('rejection' in result)) {
        throw new Error('expected a current_value_mismatch rejection');
      }

      expect(result.rejection.reason).toBe('current_value_mismatch');
      expect(result.rejection.keyPath).toBe('malware.mode');
      expect(result.rejection.os).toBe(PolicyOperatingSystem.windows);
      expect(result.rejection.message).toContain('"prevent"');
      expect(result.rejection.message).toContain('"off"');
    });

    it('accepts a matching expectedCurrentValue', () => {
      const snapshot = buildTestSnapshot();

      const result = applyChangeProposal({
        proposal: buildProposal([
          {
            keyPath: 'malware.mode',
            os: PolicyOperatingSystem.windows,
            expectedCurrentValue: ProtectionModes.prevent,
            proposedValue: ProtectionModes.detect,
          },
        ]),
        snapshot,
        lookup,
      });

      expect('config' in result).toBe(true);
    });

    it(`rejects more than ${MAX_CHANGE_OPERATIONS} operations`, () => {
      const snapshot = buildTestSnapshot();
      const operations: PolicyChangeOperation[] = Array.from(
        { length: MAX_CHANGE_OPERATIONS + 1 },
        () => ({
          keyPath: 'malware.blocklist',
          os: PolicyOperatingSystem.windows,
          proposedValue: false,
        })
      );

      const result = applyChangeProposal({
        proposal: buildProposal(operations),
        snapshot,
        lookup,
      });

      if (!('rejection' in result)) {
        throw new Error('expected a too_many_operations rejection');
      }

      expect(result.rejection.reason).toBe('too_many_operations');
      expect(result.rejection.message).toContain(`at most ${MAX_CHANGE_OPERATIONS}`);
      expect(result.rejection.message).toContain(`${MAX_CHANGE_OPERATIONS + 1}`);
    });

    it(`accepts exactly ${MAX_CHANGE_OPERATIONS} operations`, () => {
      const snapshot = buildTestSnapshot();
      const operations: PolicyChangeOperation[] = Array.from(
        { length: MAX_CHANGE_OPERATIONS },
        () => ({
          keyPath: 'malware.blocklist',
          os: PolicyOperatingSystem.windows,
          proposedValue: false,
        })
      );

      const result = applyChangeProposal({
        proposal: buildProposal(operations),
        snapshot,
        lookup,
      });

      expect('config' in result).toBe(true);
    });

    it('rejects an OS-scoped field proposed at the policy root', () => {
      const snapshot = buildTestSnapshot();

      const result = applyChangeProposal({
        proposal: buildProposal([{ keyPath: 'malware.mode', proposedValue: ProtectionModes.off }]),
        snapshot,
        lookup,
      });

      if (!('rejection' in result)) {
        throw new Error('expected a not_applicable_for_os rejection');
      }

      expect(result.rejection.reason).toBe('not_applicable_for_os');
      expect(result.rejection.message).toContain('windows, mac, linux');
    });

    it('rejects a policy-root field proposed for one OS', () => {
      const snapshot = buildTestSnapshot();

      const result = applyChangeProposal({
        proposal: buildProposal([
          {
            keyPath: 'global_manifest_version',
            os: PolicyOperatingSystem.windows,
            proposedValue: '2026-01-02',
          },
        ]),
        snapshot,
        lookup,
      });

      if (!('rejection' in result)) {
        throw new Error('expected a not_applicable_for_os rejection');
      }

      expect(result.rejection.reason).toBe('not_applicable_for_os');
      expect(result.rejection.message).toContain('policy-root field');
    });

    it('refuses the whole proposal when any one operation is invalid', () => {
      const snapshot = buildTestSnapshot();

      const result = applyChangeProposal({
        proposal: buildProposal([
          {
            keyPath: 'malware.mode',
            os: PolicyOperatingSystem.windows,
            proposedValue: ProtectionModes.off,
          },
          { keyPath: 'nope.not.here', os: PolicyOperatingSystem.windows, proposedValue: true },
        ]),
        snapshot,
        lookup,
      });

      expect('rejection' in result).toBe(true);
      expect(snapshot.config.windows.malware.mode).toBe(ProtectionModes.prevent);
    });
  });
});
