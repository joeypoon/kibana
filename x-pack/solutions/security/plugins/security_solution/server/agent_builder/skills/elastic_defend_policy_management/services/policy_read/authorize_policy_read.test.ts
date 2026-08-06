/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { httpServerMock } from '@kbn/core/server/mocks';
import { SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';
import type { KibanaRequest } from '@kbn/core-http-server';
import { authorizePolicyRead } from './authorize_policy_read';
import {
  createMissingPrivilegeDenial,
  createNotFoundDenial,
  FLEET_AGENT_POLICIES_READ_PRIVILEGE,
  FLEET_INTEGRATIONS_READ_PRIVILEGE,
  FLEET_POLICY_READ_PRIVILEGE,
  POLICY_READ_PRIVILEGE_NAMES,
  SECURITY_POLICY_MANAGEMENT_READ_PRIVILEGE,
} from './policy_read_denial';
import { readDefendPolicyInventory } from './inventory_traversal';
import type { AuthorizationMocks, PolicyReadMocks } from './mocks';
import {
  createAuthorizationMocks,
  createDefendPolicyMock,
  createPolicyReadMocks,
  grantedPrivilegeBasis,
  mockFetchAllItems,
} from './mocks';

describe('Elastic Defend policy read authorization', () => {
  let authorization: AuthorizationMocks;
  let request: KibanaRequest;

  beforeEach(() => {
    authorization = createAuthorizationMocks();
    request = httpServerMock.createKibanaRequest();
  });

  describe('privilege matrix', () => {
    it('grants a Security-only user (policy management read, no Fleet integration policy read)', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: true,
        fleetIntegrationPoliciesRead: false,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(true);
      expect(result.basis).toEqual({
        securityPolicyManagementRead: true,
        fleetIntegrationPoliciesRead: false,
        fleetAgentsRead: true,
      });
    });

    it('grants a Fleet-only user (integration policy read, no Security policy management read)', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: true,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(true);
      expect(result.basis.securityPolicyManagementRead).toBe(false);
      expect(result.basis.fleetIntegrationPoliciesRead).toBe(true);
    });

    it('grants a user holding both privileges and records both in the basis', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: true,
        fleetIntegrationPoliciesRead: true,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(true);
      expect(result.basis.securityPolicyManagementRead).toBe(true);
      expect(result.basis.fleetIntegrationPoliciesRead).toBe(true);
    });

    it('denies a user holding neither policy-read privilege', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(false);
      expect(result.granted === false && result.denial.reason).toBe('missing_privilege');
      expect(result.granted === false && result.denial.needAny).toEqual(
        POLICY_READ_PRIVILEGE_NAMES
      );
    });

    it('denies a caller with integrations read but no agent-policies read, naming only what they lack', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
        fleetAgentPoliciesRead: false,
        fleetIntegrationsRead: true,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(false);
      expect(result.granted === false && result.denial.needAny).toEqual([
        SECURITY_POLICY_MANAGEMENT_READ_PRIVILEGE,
        FLEET_AGENT_POLICIES_READ_PRIVILEGE,
      ]);
      expect(result.granted === false && result.denial.needAny).not.toContain(
        FLEET_INTEGRATIONS_READ_PRIVILEGE
      );
    });

    it('treats integrations write as still holding integrations read, naming only the remaining Fleet privilege', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
        fleetAgentPoliciesRead: false,
        fleetIntegrationsRead: true,
        fleetIntegrationsWrite: true,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(false);
      expect(result.granted === false && result.denial.needAny).toEqual([
        SECURITY_POLICY_MANAGEMENT_READ_PRIVILEGE,
        FLEET_AGENT_POLICIES_READ_PRIVILEGE,
      ]);
      expect(result.granted === false && result.denial.needAny).not.toContain(
        FLEET_INTEGRATIONS_READ_PRIVILEGE
      );
    });

    const grantNamedFleetAlternative = async ({
      heldAgentPoliciesRead,
      heldIntegrationsRead,
      fleetSetup,
      needAny,
    }: {
      heldAgentPoliciesRead: boolean;
      heldIntegrationsRead: boolean;
      fleetSetup: boolean;
      needAny: readonly string[];
    }) => {
      const fleetAgentPoliciesRead =
        heldAgentPoliciesRead ||
        needAny.includes(FLEET_AGENT_POLICIES_READ_PRIVILEGE) ||
        needAny.includes(FLEET_POLICY_READ_PRIVILEGE);
      const fleetIntegrationsRead =
        heldIntegrationsRead ||
        needAny.includes(FLEET_INTEGRATIONS_READ_PRIVILEGE) ||
        needAny.includes(FLEET_POLICY_READ_PRIVILEGE);

      authorization.setPrivileges({
        securityPolicyManagementRead: false,
        fleetSetup,
        fleetAgentPoliciesRead,
        fleetIntegrationsRead,
        fleetIntegrationPoliciesRead: fleetAgentPoliciesRead && fleetIntegrationsRead,
      });

      return authorizePolicyRead(authorization, request);
    };

    it('denies Fleet setup without agent-policies read and names an alternative that would restore access', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
        fleetSetup: true,
        fleetAgentPoliciesRead: false,
        fleetIntegrationsRead: false,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(false);
      expect(result.granted === false && result.denial.needAny).toEqual(
        POLICY_READ_PRIVILEGE_NAMES
      );
      expect(result.granted === false && result.denial.needAny).not.toContain(
        FLEET_INTEGRATIONS_READ_PRIVILEGE
      );
      expect(result.granted === false && result.denial.needAny).toContain(
        FLEET_POLICY_READ_PRIVILEGE
      );

      const restored = await grantNamedFleetAlternative({
        heldAgentPoliciesRead: false,
        heldIntegrationsRead: false,
        fleetSetup: true,
        needAny: result.granted === false ? result.denial.needAny ?? [] : [],
      });

      expect(restored.granted).toBe(true);
    });

    it('denies Fleet setup plus integrations read and names only the Fleet privilege that would restore access', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
        fleetSetup: true,
        fleetAgentPoliciesRead: false,
        fleetIntegrationsRead: true,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(false);
      expect(result.granted === false && result.denial.needAny).toEqual([
        SECURITY_POLICY_MANAGEMENT_READ_PRIVILEGE,
        FLEET_AGENT_POLICIES_READ_PRIVILEGE,
      ]);
      expect(result.granted === false && result.denial.needAny).not.toContain(
        FLEET_INTEGRATIONS_READ_PRIVILEGE
      );
      expect(result.granted === false && result.denial.needAny).not.toContain(
        FLEET_POLICY_READ_PRIVILEGE
      );

      const restored = await grantNamedFleetAlternative({
        heldAgentPoliciesRead: false,
        heldIntegrationsRead: true,
        fleetSetup: true,
        needAny: result.granted === false ? result.denial.needAny ?? [] : [],
      });

      expect(restored.granted).toBe(true);
    });
  });

  it('evaluates authorization for the request it was given', async () => {
    await authorizePolicyRead(authorization, request);

    expect(authorization.getEndpointAuthz).toHaveBeenCalledWith(request);
    expect(authorization.getFleetAuthz).toHaveBeenCalledWith(request);
  });

  describe('fleetAgentsRead propagation', () => {
    it('records `fleetAgentsRead: false` without affecting the grant, so downstream findings can degrade', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: true,
        fleetIntegrationPoliciesRead: false,
        fleetAgentsRead: false,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.granted).toBe(true);
      expect(result.basis.fleetAgentsRead).toBe(false);
    });

    it('records `fleetAgentsRead: true` when the privilege is held', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: true,
        fleetIntegrationPoliciesRead: true,
        fleetAgentsRead: true,
      });

      const result = await authorizePolicyRead(authorization, request);

      expect(result.basis.fleetAgentsRead).toBe(true);
    });
  });

  describe('deliberate narrowing away from Fleet endpoint-action alternatives', () => {
    it('does not grant on endpoint response-action privileges alone', async () => {
      authorization.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });

      const result = await authorizePolicyRead(authorization, request);
      const endpointAuthz = await authorization.getEndpointAuthz(request);

      expect(endpointAuthz.canIsolateHost).toBe(true);
      expect(endpointAuthz.canWriteFileOperations).toBe(true);
      expect(result.granted).toBe(false);
    });
  });

  describe('as enforced on the read path', () => {
    let mocks: PolicyReadMocks;

    const readInventory = () =>
      readDefendPolicyInventory({
        packagePolicyService: mocks.packagePolicyService,
        privilegeBasis: grantedPrivilegeBasis({
          securityPolicyManagementRead: true,
          fleetIntegrationPoliciesRead: false,
        }),
        getSoClient: mocks.getSoClient,
        spaceId: mocks.spaceId,
        resolveRegistry: mocks.resolveRegistry,
        logger: mocks.logger,
      });

    beforeEach(() => {
      mocks = createPolicyReadMocks();
      mockFetchAllItems(mocks.packagePolicyService, [[createDefendPolicyMock({ id: 'defend-a' })]]);
    });

    describe('a Security-only user never receives a false empty estate', () => {
      it('returns the policies Fleet holds rather than an empty list', async () => {
        const result = await readInventory();

        expect(result.ok).toBe(true);
        expect(result.ok === true && result.value.items).toHaveLength(1);
        expect(result.ok === true && result.value.scope.total).toBe(1);
      });

      it('reads through a client with the security extension excluded, which is what makes that answer possible', async () => {
        await readInventory();

        expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
          excludedExtensions: [SECURITY_EXTENSION_ID],
        });
      });
    });
  });

  describe('denial reasons stay separate', () => {
    it('distinguishes `missing_privilege` from `not_found`', () => {
      expect(createMissingPrivilegeDenial().reason).toBe('missing_privilege');
      expect(createNotFoundDenial('defend-1').reason).toBe('not_found');
    });

    it('a `not_found` denial carries no policy metadata beyond the id the caller supplied', () => {
      const denial = createNotFoundDenial('other-1');

      expect(JSON.stringify(denial)).toContain('other-1');
      expect(Object.keys(denial).sort()).toEqual(['message', 'reason']);
      expect(denial.needAny).toBeUndefined();
    });
  });
});
