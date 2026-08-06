/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SavedObjectsErrorHelpers } from '@kbn/core/server';
import { SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';
import { PackagePolicyNotFoundError } from '@kbn/fleet-plugin/server/errors';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { readDefendPolicy } from './read_defend_policy_management';
import type { ReadDefendPolicyOptions } from './read_defend_policy_management';
import { PolicyRegistryVersionUnknownError } from './to_policy_snapshot';
import type { PolicyReadMocks } from './mocks';
import {
  createDefendPolicyMock,
  createDerivationsMock,
  createPolicyReadMocks,
  grantedPrivilegeBasis,
} from './mocks';

describe('readDefendPolicy', () => {
  let mocks: PolicyReadMocks;

  const read = (overrides: Partial<ReadDefendPolicyOptions> = {}) =>
    readDefendPolicy({
      packagePolicyService: mocks.packagePolicyService,
      privilegeBasis: grantedPrivilegeBasis(),
      derivations: mocks.derivations,
      spaceId: mocks.spaceId,
      getSoClient: mocks.getSoClient,
      policyId: 'defend-1',
      ...overrides,
    });

  beforeEach(() => {
    mocks = createPolicyReadMocks({ spaceId: 'finance' });
    mocks.packagePolicyService.get.mockResolvedValue(createDefendPolicyMock());
  });

  describe('authorization is assumed already granted', () => {
    it('reads through a client with the security extension excluded', async () => {
      await read();

      expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
        excludedExtensions: [SECURITY_EXTENSION_ID],
      });
    });
  });

  describe('the read itself', () => {
    it('reads the policy as the requesting user in the active space', async () => {
      await read({ policyId: 'defend-9' });

      expect(mocks.packagePolicyService.get).toHaveBeenCalledWith(mocks.soClient, 'defend-9', {
        spaceId: 'finance',
      });
    });

    it('returns the snapshot, the raw Fleet inputs, and the privilege basis from ONE read', async () => {
      const privilegeBasis = grantedPrivilegeBasis({
        fleetIntegrationPoliciesRead: false,
        fleetAgentsRead: false,
      });
      const policy = createDefendPolicyMock();
      mocks.packagePolicyService.get.mockResolvedValue(policy);

      const result = await read({ privilegeBasis });

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.value.snapshot.identity.id).toBe('defend-1');
        expect(result.value.inputs).toBe(policy.inputs);
        expect(result.value.inputs.length).toBeGreaterThan(0);
        expect(result.value.privilegeBasis).toEqual(privilegeBasis);
      }
    });
  });

  describe('not found', () => {
    it('maps a Fleet 404 throw to a `not_found` denial', async () => {
      mocks.packagePolicyService.get.mockRejectedValue(
        new PackagePolicyNotFoundError('defend-1 not found')
      );

      const result = await read();

      expect(result.ok === false && result.denial.reason).toBe('not_found');
    });

    it('maps a saved-objects 404 to the same `not_found` denial', async () => {
      mocks.packagePolicyService.get.mockRejectedValue(
        SavedObjectsErrorHelpers.createGenericNotFoundError('ingest-package-policies', 'defend-1')
      );

      const result = await read();

      expect(result.ok === false && result.denial.reason).toBe('not_found');
    });

    it('maps a `null` from Fleet to the same `not_found` denial', async () => {
      mocks.packagePolicyService.get.mockResolvedValue(null);

      const result = await read();

      expect(result.ok === false && result.denial.reason).toBe('not_found');
    });

    it('reports a non-Defend policy at that id as not_found, not as a type mismatch', async () => {
      const nginxPolicy: PackagePolicy = {
        ...createDefendPolicyMock(),
        package: { name: 'nginx', title: 'Nginx', version: '2.1.0' },
      };
      mocks.packagePolicyService.get.mockResolvedValue(nginxPolicy);

      const result = await read();

      expect(result.ok).toBe(false);
      expect(result.ok === false && result.denial.reason).toBe('not_found');
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain('nginx');
      expect(serialized).not.toContain(nginxPolicy.name);
    });

    it('maps a Defend policy with no endpoint input configuration to the same `not_found` denial', async () => {
      const policy = createDefendPolicyMock();
      mocks.packagePolicyService.get.mockResolvedValue({ ...policy, inputs: [] });

      const result = await read();

      expect(result.ok === false && result.denial.reason).toBe('not_found');
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain('inputs');
      expect(serialized).not.toContain(policy.name);
    });

    it('rethrows errors that are not a not-found', async () => {
      mocks.packagePolicyService.get.mockRejectedValue(new Error('fleet exploded'));

      await expect(read()).rejects.toThrow('fleet exploded');
    });
  });

  describe('snapshot failures propagate rather than masquerading as denials', () => {
    it('throws the registry-coverage error for a package version with no field registry', async () => {
      mocks.packagePolicyService.get.mockResolvedValue(
        createDefendPolicyMock({
          package: { name: 'endpoint', title: 'Elastic Defend', version: '8.4.0' },
        })
      );

      await expect(
        read({ derivations: createDerivationsMock({ knownVersions: ['9.2.0'] }) })
      ).rejects.toThrow(PolicyRegistryVersionUnknownError);
    });
  });

  describe('prohibited Fleet methods', () => {
    it('reaches only `get` on the package-policy service', async () => {
      await read();

      const calledMethods = Object.entries(mocks.packagePolicyService)
        .filter(([, value]) => jest.isMockFunction(value) && value.mock.calls.length > 0)
        .map(([name]) => name)
        .sort();

      expect(calledMethods).toEqual(['get']);
    });
  });
});
