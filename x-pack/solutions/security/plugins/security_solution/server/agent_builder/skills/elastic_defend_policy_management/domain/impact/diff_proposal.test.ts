/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import type { PolicyChangeOperation, PolicyChangeProposal } from './types';
import { applyChangeProposal } from './apply_proposal';
import { diffProposal, unionPersistPreviewDiffs } from './diff_proposal';
import { buildImpactFieldLookup } from './field_lookup';
import { buildTestRegistry, buildTestSnapshot, TEST_PACKAGE_VERSION } from './test_fixtures';

const registry = buildTestRegistry();
const lookup = buildImpactFieldLookup(registry);

const diffFor = (operations: readonly PolicyChangeOperation[]) => {
  const snapshot = buildTestSnapshot();
  const proposal: PolicyChangeProposal = {
    policyId: snapshot.identity.id,
    identity: { revision: snapshot.identity.revision, version: snapshot.identity.version },
    operations,
  };

  const applied = applyChangeProposal({ proposal, snapshot, lookup });

  if ('rejection' in applied) {
    throw new Error(`fixture proposal was rejected: ${applied.rejection.message}`);
  }

  return diffProposal({
    before: snapshot.config,
    after: applied.config,
    proposal,
    lookup,
    packageVersion: TEST_PACKAGE_VERSION,
  });
};

describe('diffProposal', () => {
  it('reports before, after, and the registry default for a changed leaf', () => {
    expect(
      diffFor([
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.detect,
        },
      ])
    ).toEqual([
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        before: ProtectionModes.prevent,
        after: ProtectionModes.detect,
        defaultValue: ProtectionModes.prevent,
        type: 'enum',
        enumValues: [ProtectionModes.detect, ProtectionModes.prevent, ProtectionModes.off],
      },
    ]);
  });

  it('shows when a change returns a field to its default', () => {
    const snapshot = buildTestSnapshot();
    snapshot.config.linux.events.file = false;

    const proposal: PolicyChangeProposal = {
      policyId: snapshot.identity.id,
      identity: { revision: snapshot.identity.revision, version: snapshot.identity.version },
      operations: [
        { keyPath: 'events.file', os: PolicyOperatingSystem.linux, proposedValue: true },
      ],
    };

    const applied = applyChangeProposal({ proposal, snapshot, lookup });

    if ('rejection' in applied) {
      throw new Error(`fixture proposal was rejected: ${applied.rejection.message}`);
    }

    const [diff] = diffProposal({
      before: snapshot.config,
      after: applied.config,
      proposal,
      lookup,
      packageVersion: TEST_PACKAGE_VERSION,
    });

    expect(diff).toEqual({
      keyPath: 'events.file',
      os: PolicyOperatingSystem.linux,
      before: false,
      after: true,
      defaultValue: true,
      type: 'boolean',
    });
    expect(diff.after).toBe(diff.defaultValue);
  });

  it('emits nothing for an operation that proposes the value already stored', () => {
    expect(
      diffFor([
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.prevent,
        },
      ])
    ).toEqual([]);
  });

  it('reports one diff per leaf even when the same leaf is named twice', () => {
    const diffs = diffFor([
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        proposedValue: ProtectionModes.detect,
      },
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        proposedValue: ProtectionModes.off,
      },
    ]);

    expect(diffs).toEqual([
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        before: ProtectionModes.prevent,
        after: ProtectionModes.off,
        defaultValue: ProtectionModes.prevent,
        type: 'enum',
        enumValues: [ProtectionModes.detect, ProtectionModes.prevent, ProtectionModes.off],
      },
    ]);
  });

  it('keeps per-OS changes to the same key path separate', () => {
    const diffs = diffFor([
      { keyPath: 'events.file', os: PolicyOperatingSystem.windows, proposedValue: false },
      { keyPath: 'events.file', os: PolicyOperatingSystem.mac, proposedValue: false },
    ]);

    expect(diffs.map(({ os }) => os)).toEqual([
      PolicyOperatingSystem.windows,
      PolicyOperatingSystem.mac,
    ]);
  });

  it('reports a policy-root change with no os', () => {
    expect(diffFor([{ keyPath: 'global_manifest_version', proposedValue: '2026-01-02' }])).toEqual([
      {
        keyPath: 'global_manifest_version',
        os: undefined,
        before: 'latest',
        after: '2026-01-02',
        defaultValue: 'latest',
        type: 'string',
      },
    ]);
  });

  it('omits defaultValue when the registry has no recoverable default', () => {
    const snapshot = buildTestSnapshot();
    const registryWithoutDefault = {
      packageVersion: TEST_PACKAGE_VERSION,
      fields: [
        {
          keyPath: 'malware.mode',
          os: [PolicyOperatingSystem.windows],
          category: 'protection' as const,
          type: 'enum' as const,
          defaultSource: 'unknown' as const,
          firstSupportedVersion: '7.9',
          configurable: true,
        },
      ],
    };
    const lookupWithoutDefault = buildImpactFieldLookup(registryWithoutDefault);

    const proposal: PolicyChangeProposal = {
      policyId: snapshot.identity.id,
      identity: { revision: snapshot.identity.revision, version: snapshot.identity.version },
      operations: [
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.off,
        },
      ],
    };

    const applied = applyChangeProposal({ proposal, snapshot, lookup: lookupWithoutDefault });

    if ('rejection' in applied) {
      throw new Error(`fixture proposal was rejected: ${applied.rejection.message}`);
    }

    const [diff] = diffProposal({
      before: snapshot.config,
      after: applied.config,
      proposal,
      lookup: lookupWithoutDefault,
      packageVersion: TEST_PACKAGE_VERSION,
    });

    expect(diff).toEqual({
      keyPath: 'malware.mode',
      os: PolicyOperatingSystem.windows,
      before: ProtectionModes.prevent,
      after: ProtectionModes.off,
      type: 'enum',
    });
    expect('defaultValue' in diff).toBe(false);
  });

  it('includes documentation only when the registry provides it', () => {
    const snapshot = buildTestSnapshot();
    const documentedRegistry = {
      packageVersion: TEST_PACKAGE_VERSION,
      fields: registry.fields.map((field) =>
        field.keyPath === 'malware.mode'
          ? { ...field, documentation: 'Controls malware protection behavior.' }
          : field
      ),
    };
    const documentedLookup = buildImpactFieldLookup(documentedRegistry);
    const proposal: PolicyChangeProposal = {
      policyId: snapshot.identity.id,
      identity: { revision: snapshot.identity.revision, version: snapshot.identity.version },
      operations: [
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.detect,
        },
      ],
    };
    const applied = applyChangeProposal({ proposal, snapshot, lookup: documentedLookup });

    if ('rejection' in applied) {
      throw new Error(`fixture proposal was rejected: ${applied.rejection.message}`);
    }

    expect(
      diffProposal({
        before: snapshot.config,
        after: applied.config,
        proposal,
        lookup: documentedLookup,
        packageVersion: TEST_PACKAGE_VERSION,
      })[0]
    ).toMatchObject({
      type: 'enum',
      enumValues: [ProtectionModes.detect, ProtectionModes.prevent, ProtectionModes.off],
      documentation: 'Controls malware protection behavior.',
    });
  });

  it('preserves an unknown changed leaf without inventing registry metadata', () => {
    const snapshot = buildTestSnapshot();
    const proposal: PolicyChangeProposal = {
      policyId: snapshot.identity.id,
      identity: { revision: snapshot.identity.revision, version: snapshot.identity.version },
      operations: [
        {
          keyPath: 'advanced.new_package_setting',
          os: PolicyOperatingSystem.windows,
          proposedValue: 'after',
        },
      ],
    };
    const before = {
      ...snapshot.config,
      windows: {
        ...snapshot.config.windows,
        advanced: { ...snapshot.config.windows.advanced, new_package_setting: 'before' },
      },
    };
    const after = {
      ...before,
      windows: {
        ...before.windows,
        advanced: { ...before.windows.advanced, new_package_setting: 'after' },
      },
    };

    expect(
      diffProposal({ before, after, proposal, lookup, packageVersion: TEST_PACKAGE_VERSION })
    ).toEqual([
      {
        keyPath: 'advanced.new_package_setting',
        os: PolicyOperatingSystem.windows,
        before: 'before',
        after: 'after',
      },
    ]);
  });
});

describe('unionPersistPreviewDiffs', () => {
  it('uses persisted after values on operation paths and unions silent proposed-to-persisted leaves', () => {
    const snapshot = buildTestSnapshot();
    const proposal: PolicyChangeProposal = {
      policyId: snapshot.identity.id,
      identity: { revision: snapshot.identity.revision, version: snapshot.identity.version },
      operations: [
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.detect,
        },
      ],
    };
    const proposed = {
      ...snapshot.config,
      windows: {
        ...snapshot.config.windows,
        malware: { ...snapshot.config.windows.malware, mode: ProtectionModes.detect },
      },
    };
    const persisted = {
      ...proposed,
      windows: {
        ...proposed.windows,
        malware: { ...proposed.windows.malware, mode: ProtectionModes.off },
        antivirus_registration: {
          ...proposed.windows.antivirus_registration,
          enabled: false,
        },
      },
    };

    expect(
      unionPersistPreviewDiffs({
        before: snapshot.config,
        proposed,
        persisted,
        proposal,
        lookup,
        packageVersion: TEST_PACKAGE_VERSION,
      })
    ).toEqual([
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        before: ProtectionModes.prevent,
        after: ProtectionModes.off,
        defaultValue: ProtectionModes.prevent,
        type: 'enum',
        enumValues: [ProtectionModes.detect, ProtectionModes.prevent, ProtectionModes.off],
      },
      {
        keyPath: 'antivirus_registration.enabled',
        os: PolicyOperatingSystem.windows,
        before: true,
        after: false,
        defaultValue: false,
        type: 'boolean',
      },
    ]);
  });

  it('omits meta leaves from silent persist deltas', () => {
    const snapshot = buildTestSnapshot();
    const proposal: PolicyChangeProposal = {
      policyId: snapshot.identity.id,
      identity: { revision: snapshot.identity.revision, version: snapshot.identity.version },
      operations: [
        {
          keyPath: 'malware.blocklist',
          os: PolicyOperatingSystem.windows,
          proposedValue: false,
        },
      ],
    };
    const proposed = {
      ...snapshot.config,
      windows: {
        ...snapshot.config.windows,
        malware: { ...snapshot.config.windows.malware, blocklist: false },
      },
    };
    const persisted = {
      ...proposed,
      meta: { ...proposed.meta, license: 'platinum', billable: true },
    };

    expect(
      unionPersistPreviewDiffs({
        before: snapshot.config,
        proposed,
        persisted,
        proposal,
        lookup,
        packageVersion: TEST_PACKAGE_VERSION,
      })
    ).toEqual([
      {
        keyPath: 'malware.blocklist',
        os: PolicyOperatingSystem.windows,
        before: true,
        after: false,
        defaultValue: true,
        type: 'boolean',
      },
    ]);
  });
});
