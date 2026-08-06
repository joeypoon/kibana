/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { set } from '@kbn/safer-lodash-set';

import {
  DefaultPolicyNotificationMessage,
  policyFactory,
} from '../../../../../../common/endpoint/models/policy_config';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { ProtectionModes } from '../../../../../../common/endpoint/types';
import { buildPolicyFieldRegistry } from '../field_registry/generate_field_registry';
import type { PolicyFieldRegistry } from '../field_registry/types';
import { normalizePolicyConfig } from '../normalize/normalize_policy_config';
import type { DuplicateCandidate } from './group_duplicates';
import { groupDuplicatePolicies } from './group_duplicates';

const PACKAGE_VERSION = '9.4.0';
const registry = buildPolicyFieldRegistry({ packageVersion: PACKAGE_VERSION });

interface CandidateOverrides {
  readonly name?: string;
  readonly revision?: number;
  readonly packageVersion?: string;
  readonly policyIds?: readonly string[];
  readonly normalizeAgainst?: PolicyFieldRegistry;
}

const candidate = (
  id: string,
  config: PolicyConfig,
  {
    name,
    revision = 3,
    packageVersion = PACKAGE_VERSION,
    policyIds = [],
    normalizeAgainst = registry,
  }: CandidateOverrides = {}
): DuplicateCandidate => ({
  id,
  name: name ?? `policy-${id}`,
  revision,
  packageVersion,
  policyIds,
  configNormalized: normalizePolicyConfig(config, normalizeAgainst),
});

const group = (policies: readonly DuplicateCandidate[]) => groupDuplicatePolicies({ policies });

describe('groupDuplicatePolicies', () => {
  describe('exact grouping', () => {
    it('groups identical policies as exact', () => {
      const { groups } = group([candidate('a', policyFactory()), candidate('b', policyFactory())]);

      expect(groups).toHaveLength(1);
      expect(groups[0].members.map(({ id }) => id)).toEqual(['a', 'b']);
      expect(groups[0].configHash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('does not emit a group for a policy with no duplicate', () => {
      const lonely = policyFactory();
      set(lonely, 'windows.malware.mode', ProtectionModes.off);
      set(lonely, 'windows.events.dns', false);
      set(lonely, 'windows.events.registry', false);
      set(lonely, 'mac.malware.mode', ProtectionModes.off);
      set(lonely, 'linux.malware.mode', ProtectionModes.off);
      set(lonely, 'linux.events.file', false);

      const { groups } = group([candidate('a', policyFactory()), candidate('b', lonely)]);

      expect(groups).toEqual([]);
    });

    it('emits no group for policies that merely differ in one leaf', () => {
      const tuned = policyFactory();
      set(tuned, 'windows.malware.mode', ProtectionModes.detect);

      const { groups, accounting } = group([
        candidate('a', policyFactory()),
        candidate('b', tuned),
      ]);

      expect(groups).toEqual([]);
      expect(accounting).toMatchObject({
        policiesConsidered: 2,
        duplicateGroupCount: 0,
        policiesInDuplicateGroups: 0,
      });
    });

    it('groups policies that are default-equal but written differently', () => {
      const explicitlyWritten = policyFactory();
      const { mode, blocklist, on_write_scan: onWriteScan } = explicitlyWritten.windows.malware;
      explicitlyWritten.windows.malware = { on_write_scan: onWriteScan, blocklist, mode };
      set(explicitlyWritten, 'windows.popup.malware.message', DefaultPolicyNotificationMessage);
      set(explicitlyWritten, 'mac.popup.malware.message', DefaultPolicyNotificationMessage);
      set(explicitlyWritten, 'linux.malware.mode', ProtectionModes.prevent);

      const { groups } = group([
        candidate('written-plainly', policyFactory()),
        candidate('written-verbosely', explicitlyWritten),
      ]);

      expect(groups).toHaveLength(1);
      expect(groups[0].members.map(({ id }) => id)).toEqual([
        'written-plainly',
        'written-verbosely',
      ]);
    });

    it('groups despite differing meta and logging, which are not configuration', () => {
      const other = policyFactory({ license: 'platinum', clusterName: 'prod', serverless: true });
      set(other, 'linux.logging.file', 'debug');

      const { groups } = group([candidate('a', policyFactory()), candidate('b', other)]);

      expect(groups).toHaveLength(1);
    });

    it('emits separate groups for separate configurations', () => {
      const tunedA = policyFactory();
      set(tunedA, 'windows.malware.mode', ProtectionModes.detect);

      const tunedB = policyFactory();
      set(tunedB, 'windows.events.dns', false);

      const { groups, accounting } = group([
        candidate('a1', policyFactory()),
        candidate('a2', policyFactory()),
        candidate('a3', policyFactory()),
        candidate('b1', tunedA),
        candidate('b2', tunedA),
        candidate('lonely', tunedB),
      ]);

      expect(groups).toHaveLength(2);
      expect(groups.map(({ members }) => members.map(({ id }) => id))).toEqual([
        ['a1', 'a2', 'a3'],
        ['b1', 'b2'],
      ]);
      expect(accounting).toEqual({
        policiesConsidered: 6,
        duplicateGroupCount: 2,
        policiesInDuplicateGroups: 5,
      });
    });
  });

  describe('policy_ids is assignment context, never a grouping key', () => {
    it('groups configuration-identical policies with different assignments as exact', () => {
      const { groups } = group([
        candidate('a', policyFactory(), { policyIds: ['agent-policy-1'] }),
        candidate('b', policyFactory(), { policyIds: ['agent-policy-2', 'agent-policy-3'] }),
      ]);

      expect(groups).toHaveLength(1);
      expect(groups[0].members.map(({ id }) => id)).toEqual(['a', 'b']);
    });

    it('groups an unassigned policy with an assigned one', () => {
      const { groups } = group([
        candidate('unassigned', policyFactory(), { policyIds: [] }),
        candidate('assigned', policyFactory(), { policyIds: ['agent-policy-1'] }),
      ]);

      expect(groups).toHaveLength(1);
    });

    it('attaches policyIds to each member, sorted, after classification', () => {
      const { groups } = group([
        candidate('a', policyFactory(), { policyIds: ['zeta', 'alpha', 'mu'] }),
        candidate('b', policyFactory(), { policyIds: ['beta'] }),
      ]);

      expect(groups[0].members.map(({ policyIds }) => policyIds)).toEqual([
        ['alpha', 'mu', 'zeta'],
        ['beta'],
      ]);
    });

    it('does not mutate the caller policyIds array while sorting', () => {
      const policyIds = ['zeta', 'alpha'];

      group([candidate('a', policyFactory(), { policyIds }), candidate('b', policyFactory())]);

      expect(policyIds).toEqual(['zeta', 'alpha']);
    });
  });

  describe('the protection-updates pin', () => {
    it('groups pin-only differences as exact and flags the pin', () => {
      const pinned = policyFactory();
      pinned.global_manifest_version = '2024-06-01';

      const { groups } = group([candidate('a', policyFactory()), candidate('b', pinned)]);

      expect(groups).toHaveLength(1);
      expect(groups[0].differsOnlyByProtectionUpdatesPin).toBe(true);
    });

    it('does not flag the pin when every member shares it', () => {
      const { groups } = group([candidate('a', policyFactory()), candidate('b', policyFactory())]);

      expect(groups[0].differsOnlyByProtectionUpdatesPin).toBe(false);
    });

    it('flags the pin across package versions without splitting the group', () => {
      const pinned = policyFactory();
      pinned.global_manifest_version = '2024-06-01';

      const { groups } = group([
        candidate('old', policyFactory(), { packageVersion: '9.3.0' }),
        candidate('new', pinned, { packageVersion: '9.4.0' }),
      ]);

      expect(groups).toHaveLength(1);
      expect(groups[0].differsOnlyByProtectionUpdatesPin).toBe(true);
    });
  });

  describe('provenance', () => {
    it('carries revision and packageVersion on every member of every group', () => {
      const tuned = policyFactory();
      set(tuned, 'windows.malware.mode', ProtectionModes.detect);

      const { groups } = group([
        candidate('a', policyFactory(), { revision: 7, name: 'Prod Windows' }),
        candidate('b', policyFactory(), { revision: 2, name: 'Prod Windows Copy' }),
        candidate('c', tuned, { revision: 11, name: 'Prod Windows Tuned' }),
      ]);

      expect(groups).toHaveLength(1);

      for (const member of groups[0].members) {
        expect(member.packageVersion).toBe(PACKAGE_VERSION);
        expect(typeof member.revision).toBe('number');
        expect(member.name).toBeTruthy();
        expect(member.id).toBeTruthy();
      }

      const revisions = groups[0].members.map(({ revision }) => revision).sort();

      expect(revisions).toEqual([2, 7]);
    });
  });

  describe('exact grouping spans package versions', () => {
    it('groups configuration-identical policies on different package versions as exact', () => {
      const { groups } = group([
        candidate('old', policyFactory(), { packageVersion: '9.3.0' }),
        candidate('new', policyFactory(), { packageVersion: '9.4.0' }),
      ]);

      expect(groups).toHaveLength(1);
      expect(groups[0].members.map(({ id }) => id)).toEqual(['old', 'new']);
    });

    it('carries each member package version so the group is readable as cross-version', () => {
      const { groups } = group([
        candidate('old', policyFactory(), { packageVersion: '9.3.0' }),
        candidate('new', policyFactory(), { packageVersion: '9.4.0' }),
      ]);

      expect(groups[0].members.map(({ packageVersion }) => packageVersion)).toEqual([
        '9.3.0',
        '9.4.0',
      ]);
    });

    it('groups mixed versions normalized against their own version registries', () => {
      const registry93 = buildPolicyFieldRegistry({ packageVersion: '9.3.0' });
      const registry94 = buildPolicyFieldRegistry({ packageVersion: '9.4.0' });

      const { groups } = group([
        candidate('old', policyFactory(), {
          packageVersion: '9.3.0',
          normalizeAgainst: registry93,
        }),
        candidate('new', policyFactory(), {
          packageVersion: '9.4.0',
          normalizeAgainst: registry94,
        }),
      ]);

      expect(groups).toHaveLength(1);
      expect(groups[0].members.map(({ id, packageVersion }) => ({ id, packageVersion }))).toEqual([
        { id: 'old', packageVersion: '9.3.0' },
        { id: 'new', packageVersion: '9.4.0' },
      ]);
    });
  });

  describe('unrecognized stored leaves stay part of the exact key', () => {
    it('does not group policies differing only in a registry-unknown leaf', () => {
      const aggressive = policyFactory();
      set(aggressive, 'windows.advanced.some_new_9_7_key', 'aggressive');

      const off = policyFactory();
      set(off, 'windows.advanced.some_new_9_7_key', 'off');

      const { groups } = group([candidate('a', aggressive), candidate('b', off)]);

      expect(groups).toEqual([]);
    });

    it('groups policies sharing the same unrecognized leaf value', () => {
      const left = policyFactory();
      set(left, 'windows.advanced.some_new_9_7_key', 'aggressive');

      const right = policyFactory();
      set(right, 'windows.advanced.some_new_9_7_key', 'aggressive');

      const { groups } = group([candidate('a', left), candidate('b', right)]);

      expect(groups).toHaveLength(1);
    });
  });

  describe('degenerate inputs', () => {
    it('returns no groups and a zeroed accounting record for an empty estate', () => {
      const { groups, accounting } = group([]);

      expect(groups).toEqual([]);
      expect(accounting).toEqual({
        policiesConsidered: 0,
        duplicateGroupCount: 0,
        policiesInDuplicateGroups: 0,
      });
    });

    it('returns no groups for a single policy', () => {
      const { groups, accounting } = group([candidate('a', policyFactory())]);

      expect(groups).toEqual([]);
      expect(accounting).toEqual({
        policiesConsidered: 1,
        duplicateGroupCount: 0,
        policiesInDuplicateGroups: 0,
      });
    });
  });
});
