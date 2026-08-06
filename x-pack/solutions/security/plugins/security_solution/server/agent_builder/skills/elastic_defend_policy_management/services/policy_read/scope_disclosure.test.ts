/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyReadPrivilegeBasis } from '../../domain/read/types';
import type { DescribeScopeOptions } from './scope_disclosure';
import { readDefendPolicyInventory } from './inventory_traversal';
import {
  buildScopeDisclosure,
  createFleetAgentsPrivilegeDisclosure,
  createRegistryCoverageDisclosure,
  createResultLimitDisclosure,
  createUpstreamFailureDisclosure,
  describeScope,
} from './scope_disclosure';
import type { PolicyReadMocks } from './mocks';
import {
  createDefendPolicyMock,
  createPolicyReadMocks,
  grantedPrivilegeBasis,
  mockFetchAllItems,
} from './mocks';

const privilegeBasis: PolicyReadPrivilegeBasis = {
  securityPolicyManagementRead: true,
  fleetIntegrationPoliciesRead: false,
  fleetAgentsRead: false,
};

const FORBIDDEN_PHRASES: readonly string[] = [
  'space awareness',
  'space-awareness',
  'spaceAwareness',
  'all policies',
  'all Elastic Defend policies',
  'every policy',
  'complete list',
  'entire estate',
  'not enabled',
  'disabled',
];

describe('scope disclosure', () => {
  describe('spaceId', () => {
    it('is populated when space is an enforced result dimension', () => {
      const scope = buildScopeDisclosure({
        privilegeBasis,
        returned: 2,
        total: 2,
        enforcedSpaceId: 'finance',
      });

      expect(scope.spaceId).toBe('finance');
    });

    it('is absent when space is not an enforced result dimension', () => {
      const scope = buildScopeDisclosure({ privilegeBasis, returned: 2, total: 2 });

      expect(scope).not.toHaveProperty('spaceId');
    });
  });

  describe('counts', () => {
    it('reports exact returned and total counts', () => {
      const scope = buildScopeDisclosure({ privilegeBasis, returned: 3, total: 11 });

      expect(scope.returned).toBe(3);
      expect(scope.total).toBe(11);
      expect(describeScope(scope)).toBe('Showing 3 of 11 Elastic Defend policies you can access.');
    });
  });

  describe('neutral wording', () => {
    it.each<[string, ReturnType<typeof buildScopeDisclosure>, DescribeScopeOptions | undefined]>([
      [
        'complete result',
        buildScopeDisclosure({ privilegeBasis, returned: 4, total: 4 }),
        undefined,
      ],
      [
        'space-scoped result',
        buildScopeDisclosure({
          privilegeBasis,
          returned: 4,
          total: 4,
          enforcedSpaceId: 'finance',
        }),
        undefined,
      ],
      [
        'result-limited result',
        buildScopeDisclosure({
          privilegeBasis,
          returned: 2,
          total: 9,
          partial: createResultLimitDisclosure({ returned: 2, total: 9 }),
        }),
        undefined,
      ],
      [
        'privilege-limited result',
        buildScopeDisclosure({
          privilegeBasis,
          returned: 4,
          total: 4,
          partial: createFleetAgentsPrivilegeDisclosure(),
        }),
        undefined,
      ],
      [
        'upstream-failure result',
        buildScopeDisclosure({
          privilegeBasis,
          returned: 4,
          total: 9,
          partial: createUpstreamFailureDisclosure('estate traversal', 4),
        }),
        undefined,
      ],
      [
        'filtered result',
        buildScopeDisclosure({ privilegeBasis, returned: 4, total: 4 }),
        { searchActive: true },
      ],
      [
        'filtered result-limited result',
        buildScopeDisclosure({
          privilegeBasis,
          returned: 2,
          total: 9,
          partial: createResultLimitDisclosure({ returned: 2, total: 9 }),
        }),
        { searchActive: true },
      ],
    ])('never claims exhaustiveness or platform state (%s)', (_label, scope, options) => {
      const sentence = describeScope(scope, options);

      expect(sentence).toContain('you can access');

      for (const phrase of FORBIDDEN_PHRASES) {
        expect(sentence.toLowerCase()).not.toContain(phrase.toLowerCase());
      }
    });

    it('scopes the sentence to the name filter when a search was active', () => {
      const sentence = describeScope(
        buildScopeDisclosure({ privilegeBasis, returned: 3, total: 3 }),
        { searchActive: true }
      );

      expect(sentence).toContain(
        'Showing 3 of 3 Elastic Defend policies you can access that match the name filter.'
      );
      expect(sentence).toContain('Omit `search`');
      expect(sentence).not.toContain('Showing 3 of 3 Elastic Defend policies you can access.');
    });

    it('keeps the unfiltered sentence unchanged', () => {
      expect(describeScope(buildScopeDisclosure({ privilegeBasis, returned: 3, total: 3 }))).toBe(
        'Showing 3 of 3 Elastic Defend policies you can access.'
      );
    });

    it('never claims a space scope in the sentence, even when a space is enforced', () => {
      const sentence = describeScope(
        buildScopeDisclosure({
          privilegeBasis,
          returned: 4,
          total: 4,
          enforcedSpaceId: 'finance',
        })
      );

      expect(sentence).not.toContain('finance');
      expect(sentence).not.toContain('space');
    });
  });

  describe('partial disclosures', () => {
    it('are omitted entirely when the result is complete', () => {
      expect(buildScopeDisclosure({ privilegeBasis, returned: 4, total: 4 })).not.toHaveProperty(
        'partial'
      );
    });
    it.each([
      ['missing_privilege', createFleetAgentsPrivilegeDisclosure()],
      ['result_limit_reached', createResultLimitDisclosure({ returned: 2, total: 9 })],
      ['upstream_failure', createUpstreamFailureDisclosure('estate traversal', 4)],
      ['upstream_failure', createRegistryCoverageDisclosure(['8.4.0'], 1)],
    ])('carry an actionable continuation (%s)', (reason, partial) => {
      expect(partial.reason).toBe(reason);
      expect(partial.detail.length).toBeGreaterThan(0);
      expect(partial.continuation.length).toBeGreaterThan(0);
    });

    it('names every unsupported package version in a coverage disclosure', () => {
      const partial = createRegistryCoverageDisclosure(['8.4.0', '8.6.1'], 3);

      expect(partial.detail).toContain('8.4.0');
      expect(partial.detail).toContain('8.6.1');
      expect(partial.detail).toContain('3 Elastic Defend policies were left out');
      expect(partial.detail).toContain('versions');
    });

    it('uses singular wording for a single omitted policy on a single version', () => {
      const partial = createRegistryCoverageDisclosure(['8.4.0'], 1);

      expect(partial.detail).toContain('1 Elastic Defend policy was left out');
      expect(partial.detail).toContain('version 8.4.0');
    });

    it('name the failed operation but never a policy, in an upstream failure', () => {
      const partial = createUpstreamFailureDisclosure('estate traversal', 4);

      expect(partial.detail).toContain('estate traversal');
      expect(partial.detail).toContain('4 policies');
    });
  });

  describe('as produced by the inventory read', () => {
    let mocks: PolicyReadMocks;

    const readInventory = (maxPoliciesTraversed?: number) =>
      readDefendPolicyInventory({
        packagePolicyService: mocks.packagePolicyService,
        privilegeBasis: grantedPrivilegeBasis(),
        getSoClient: mocks.getSoClient,
        spaceId: mocks.spaceId,
        resolveRegistry: mocks.resolveRegistry,
        logger: mocks.logger,
        ...(maxPoliciesTraversed === undefined ? {} : { maxPoliciesTraversed }),
      });

    beforeEach(() => {
      mocks = createPolicyReadMocks({ spaceId: 'finance' });
      mockFetchAllItems(mocks.packagePolicyService, [[createDefendPolicyMock()]]);
    });

    it('discloses a work bound that was hit, with an executable narrowing continuation', async () => {
      mockFetchAllItems(mocks.packagePolicyService, [
        [createDefendPolicyMock({ id: 'p0' }), createDefendPolicyMock({ id: 'p1' })],
      ]);

      const result = await readInventory(1);
      const scope = result.ok === true ? result.value.scope : undefined;

      expect(scope?.partial?.reason).toBe('result_limit_reached');
      expect(scope?.partial?.continuation).toContain('search');
      expect(scope?.partial?.continuation).not.toMatch(/next page/i);
      expect(scope?.partial?.detail).not.toMatch(/\bpage\b/i);
      expect(scope?.partial?.detail).toContain('work limit');
      expect(scope?.partial?.detail).not.toContain('policies matching your request');
      expect(scope?.returned).toBe(1);
      expect(result.ok === true && result.value.accounting.complete).toBe(false);
    });
  });
});
