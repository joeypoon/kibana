/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { getPolicyDataForUpdate } from '../../../../../../common/endpoint/service/policy/get_policy_data_for_update';
import type { PolicyData } from '../../../../../../common/endpoint/types';
import {
  DefendPolicyInputNotFoundError,
  isDefendPackagePolicy,
  PolicyRegistryVersionUnknownError,
  toPolicyInventoryIdentity,
  toPolicySnapshot,
} from './to_policy_snapshot';
import type { PolicyConfigDerivations } from './to_policy_snapshot';
import { createDefendPolicyMock, createDerivationsMock, createRegistryResolveMock } from './mocks';

describe('toPolicySnapshot', () => {
  let derivations: jest.Mocked<PolicyConfigDerivations>;

  beforeEach(() => {
    derivations = createDerivationsMock();
  });

  describe('identity', () => {
    it('captures `id`, `revision`, `version`, and `updatedAt`', () => {
      const snapshot = toPolicySnapshot(createDefendPolicyMock(), derivations);

      expect(snapshot.identity).toEqual({
        id: 'defend-1',
        revision: 3,
        version: 'WzEyMyw0XQ==',
        updatedAt: '2026-02-02T00:00:00.000Z',
      });
    });

    it('leaves `version` undefined when Fleet did not supply one', () => {
      const policy = createDefendPolicyMock();
      delete policy.version;

      expect(toPolicySnapshot(policy, derivations).identity.version).toBeUndefined();
    });
  });

  describe('provenance', () => {
    it('captures the four fields normalization strips', () => {
      const snapshot = toPolicySnapshot(createDefendPolicyMock(), derivations);

      expect(snapshot.provenance).toEqual({
        createdAt: '2026-01-01T00:00:00.000Z',
        createdBy: 'creator',
        updatedAt: '2026-02-02T00:00:00.000Z',
        updatedBy: 'updater',
      });
    });

    it('captures fields that `getPolicyDataForUpdate` genuinely removes', () => {
      const policy = createDefendPolicyMock() as PolicyData;
      const stripped = getPolicyDataForUpdate(policy);

      expect(stripped).not.toHaveProperty('created_at');
      expect(stripped).not.toHaveProperty('created_by');
      expect(stripped).not.toHaveProperty('updated_at');
      expect(stripped).not.toHaveProperty('updated_by');
      expect(stripped).not.toHaveProperty('revision');
      expect(stripped).not.toHaveProperty('id');

      expect(toPolicySnapshot(policy, derivations).provenance.createdBy).toBe('creator');
    });
  });

  describe('Defend input selection', () => {
    it('selects the input by `type === "endpoint"`, not by position', () => {
      const defendPolicy = createDefendPolicyMock();
      const [endpointInput] = defendPolicy.inputs;
      const policy: PackagePolicy = {
        ...defendPolicy,
        inputs: [
          { id: 'other', type: 'system/metrics', enabled: true, streams: [], config: {} },
          endpointInput,
        ],
      };

      const snapshot = toPolicySnapshot(policy, derivations);

      expect(snapshot.config.global_manifest_version).toBe(
        endpointInput.config?.policy?.value.global_manifest_version
      );
    });

    it('rejects a policy whose only input is not the Defend input', () => {
      const policy: PackagePolicy = {
        ...createDefendPolicyMock(),
        inputs: [{ id: 'other', type: 'system/metrics', enabled: true, streams: [], config: {} }],
      };

      expect(() => toPolicySnapshot(policy, derivations)).toThrow(DefendPolicyInputNotFoundError);
    });

    it('rejects a Defend input with no policy configuration', () => {
      const defendPolicy = createDefendPolicyMock();
      const policy: PackagePolicy = {
        ...defendPolicy,
        inputs: [{ ...defendPolicy.inputs[0], config: {} }],
      };

      expect(() => toPolicySnapshot(policy, derivations)).toThrow(DefendPolicyInputNotFoundError);
    });

    it('rejects a non-Defend package policy', () => {
      const policy: PackagePolicy = {
        ...createDefendPolicyMock(),
        package: { name: 'nginx', title: 'Nginx', version: '2.1.0' },
      };

      expect(() => toPolicySnapshot(policy, derivations)).toThrow(DefendPolicyInputNotFoundError);
      expect(isDefendPackagePolicy(policy)).toBe(false);
    });
  });

  describe('config cloning', () => {
    it('preserves every stored key verbatim, including `secret_references`-shaped keys', () => {
      const defendPolicy = createDefendPolicyMock();
      const configValue = defendPolicy.inputs[0].config?.policy?.value;
      const policy: PackagePolicy = {
        ...defendPolicy,
        inputs: [
          {
            ...defendPolicy.inputs[0],
            config: {
              ...defendPolicy.inputs[0].config,
              policy: {
                value: {
                  ...configValue,
                  windows: {
                    ...configValue.windows,
                    advanced: {
                      capture_env_vars: 'PATH',
                      token_secret_ref: { isSecretRef: true, id: 'secret-1' },
                    },
                  },
                  secret_references: [{ id: 'secret-2' }],
                },
              },
            },
          },
        ],
      };

      const { config } = toPolicySnapshot(policy, derivations);

      expect(config).toHaveProperty('secret_references', [{ id: 'secret-2' }]);
      expect(config.windows.advanced).toHaveProperty('token_secret_ref', {
        isSecretRef: true,
        id: 'secret-1',
      });
      expect(config.windows.advanced?.capture_env_vars).toBe('PATH');
    });

    it('does not mutate the Fleet document it was given', () => {
      const defendPolicy = createDefendPolicyMock();
      const configValue = defendPolicy.inputs[0].config?.policy?.value;
      configValue.secret_references = [{ id: 'secret-3' }];

      const { config } = toPolicySnapshot(defendPolicy, derivations);

      Object.assign(config, { injected: true });

      expect(defendPolicy.inputs[0].config?.policy?.value).toHaveProperty('secret_references');
      expect(defendPolicy.inputs[0].config?.policy?.value).not.toHaveProperty('injected');
    });

    it('preserves ordinary policy structure, including nested arrays', () => {
      const snapshot = toPolicySnapshot(createDefendPolicyMock(), derivations);

      expect(snapshot.config.windows.events.dns).toBe(true);
      expect(snapshot.config.linux.malware.mode).toBeDefined();
      expect(snapshot.config.windows.popup.malware.enabled).toBe(true);
    });
  });

  describe('injected derivations', () => {
    it('normalizes the cloned config against the policy OWN package version, then hashes it', () => {
      const snapshot = toPolicySnapshot(
        createDefendPolicyMock({
          package: { name: 'endpoint', title: 'Elastic Defend', version: '9.2.0' },
        }),
        derivations
      );

      expect(derivations.normalize).toHaveBeenCalledWith(snapshot.config, '9.2.0');
      expect(derivations.hash).toHaveBeenCalledWith(snapshot.configNormalized);
      expect(snapshot.configHash).toBe('hash:latest:true');
    });

    it('normalizes each policy of a mixed-version estate against its own version', () => {
      const versionedDerivations = createDerivationsMock({ knownVersions: ['9.1.0', '9.2.0'] });

      toPolicySnapshot(
        createDefendPolicyMock({
          id: 'old',
          package: { name: 'endpoint', title: 'Elastic Defend', version: '9.1.0' },
        }),
        versionedDerivations
      );
      toPolicySnapshot(
        createDefendPolicyMock({
          id: 'new',
          package: { name: 'endpoint', title: 'Elastic Defend', version: '9.2.0' },
        }),
        versionedDerivations
      );

      expect(versionedDerivations.normalize.mock.calls.map(([, version]) => version)).toEqual([
        '9.1.0',
        '9.2.0',
      ]);
    });

    it('refuses to answer when no registry exists for the policy version, rather than using a neighbour', () => {
      const versionedDerivations = createDerivationsMock({ knownVersions: ['9.2.0'] });
      const policy = createDefendPolicyMock({
        package: { name: 'endpoint', title: 'Elastic Defend', version: '8.4.0' },
      });

      expect(() => toPolicySnapshot(policy, versionedDerivations)).toThrow(
        PolicyRegistryVersionUnknownError
      );
      expect(versionedDerivations.hash).not.toHaveBeenCalled();
    });

    it('reports the unresolvable version on the refusal, so it can be disclosed', () => {
      const versionedDerivations = createDerivationsMock({ knownVersions: ['9.2.0'] });
      const policy = createDefendPolicyMock({
        package: { name: 'endpoint', title: 'Elastic Defend', version: '8.4.0' },
      });

      try {
        toPolicySnapshot(policy, versionedDerivations);
        throw new Error('expected a registry refusal');
      } catch (error) {
        expect(error).toBeInstanceOf(PolicyRegistryVersionUnknownError);
        expect((error as PolicyRegistryVersionUnknownError).detail).toEqual({
          status: 'registry_version_unknown',
          requestedVersion: '8.4.0',
        });
      }
    });

    it('distinguishes a coverage gap from a malformed policy', () => {
      expect(PolicyRegistryVersionUnknownError.prototype).not.toBeInstanceOf(
        DefendPolicyInputNotFoundError
      );
    });
  });

  describe('descriptive fields', () => {
    it('carries name, description, package version, spaces, and agent-policy assignments', () => {
      const snapshot = toPolicySnapshot(
        createDefendPolicyMock({
          spaceIds: ['finance'],
          policy_ids: ['agent-policy-1', 'agent-policy-2'],
          package: { name: 'endpoint', title: 'Elastic Defend', version: '9.2.0' },
        }),
        derivations
      );

      expect(snapshot.name).toBe('Defend policy 1');
      expect(snapshot.description).toBe('Policy to protect the worlds data');
      expect(snapshot.packageName).toBe('endpoint');
      expect(snapshot.packageVersion).toBe('9.2.0');
      expect(snapshot.spaceIds).toEqual(['finance']);
      expect(snapshot.policyIds).toEqual(['agent-policy-1', 'agent-policy-2']);
    });

    it('leaves `spaceIds` undefined when Fleet reported no space dimension', () => {
      const policy = createDefendPolicyMock();
      delete policy.spaceIds;

      expect(toPolicySnapshot(policy, derivations).spaceIds).toBeUndefined();
    });
  });
});

describe('toPolicyInventoryIdentity', () => {
  it('captures identity, provenance, and assignment fields without config or hash', () => {
    const policy = createDefendPolicyMock({
      spaceIds: ['finance'],
      policy_ids: ['agent-policy-1', 'agent-policy-2'],
      package: { name: 'endpoint', title: 'Elastic Defend', version: '9.2.0' },
    });
    const resolve = createRegistryResolveMock();
    const identity = toPolicyInventoryIdentity(policy, resolve);
    const snapshot = toPolicySnapshot(policy, createDerivationsMock());

    expect(identity).toEqual({
      identity: snapshot.identity,
      name: snapshot.name,
      description: snapshot.description,
      packageName: snapshot.packageName,
      packageVersion: snapshot.packageVersion,
      spaceIds: snapshot.spaceIds,
      policyIds: snapshot.policyIds,
      provenance: snapshot.provenance,
    });
    expect(identity).not.toHaveProperty('config');
    expect(identity).not.toHaveProperty('configNormalized');
    expect(identity).not.toHaveProperty('configHash');
    expect(resolve).toHaveBeenCalledWith('9.2.0');
  });

  it('rejects a Defend input with no policy configuration', () => {
    const defendPolicy = createDefendPolicyMock();
    const policy: PackagePolicy = {
      ...defendPolicy,
      inputs: [{ ...defendPolicy.inputs[0], config: {} }],
    };

    expect(() => toPolicyInventoryIdentity(policy, createRegistryResolveMock())).toThrow(
      DefendPolicyInputNotFoundError
    );
  });

  it('rejects a non-Defend package policy', () => {
    const policy: PackagePolicy = {
      ...createDefendPolicyMock(),
      package: { name: 'nginx', title: 'Nginx', version: '2.1.0' },
    };

    expect(() => toPolicyInventoryIdentity(policy, createRegistryResolveMock())).toThrow(
      DefendPolicyInputNotFoundError
    );
    expect(isDefendPackagePolicy(policy)).toBe(false);
  });

  it('throws the full registry-unknown status object and does not hash', () => {
    const hash = jest.fn();
    const resolve = createRegistryResolveMock({
      knownVersions: ['9.2.0'],
      nearestKnownVersion: '9.4.0',
    });
    const policy = createDefendPolicyMock({
      package: { name: 'endpoint', title: 'Elastic Defend', version: '8.4.0' },
    });

    expect(() => toPolicyInventoryIdentity(policy, resolve)).toThrow(
      PolicyRegistryVersionUnknownError
    );
    expect(hash).not.toHaveBeenCalled();
    expect(resolve).toHaveBeenCalledWith('8.4.0');

    try {
      toPolicyInventoryIdentity(policy, resolve);
      throw new Error('expected a registry refusal');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyRegistryVersionUnknownError);
      expect((error as PolicyRegistryVersionUnknownError).detail).toEqual({
        status: 'registry_version_unknown',
        requestedVersion: '8.4.0',
        nearestKnownVersion: '9.4.0',
      });
    }
  });
});
