/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest } from '@kbn/core-http-server';
import {
  httpServerMock,
  savedObjectsClientMock,
  savedObjectsServiceMock,
} from '@kbn/core/server/mocks';
import type { SavedObjectsClientContract } from '@kbn/core-saved-objects-api-server';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import type { MockedLogger } from '@kbn/logging-mocks';
import type { SavedObjectsServiceStart } from '@kbn/core-saved-objects-server';
import type { FleetAuthz, PackagePolicy } from '@kbn/fleet-plugin/common';
import { createFleetAuthzMock } from '@kbn/fleet-plugin/common/mocks';
import type { PackagePolicyClient } from '@kbn/fleet-plugin/server';
import { createPackagePolicyServiceMock } from '@kbn/fleet-plugin/server/mocks';
import type { PartialEndpointPolicyData } from '../../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import { FleetPackagePolicyGenerator } from '../../../../../../common/endpoint/data_generators/fleet_package_policy_generator';
import { getEndpointAuthzInitialStateMock } from '../../../../../../common/endpoint/service/authz/mocks';
import type { EndpointAuthz } from '../../../../../../common/endpoint/types/authz';
import type { NormalizedPolicyConfig } from '../../domain/normalize/types';
import type { PolicyReadPrivilegeBasis } from '../../domain/read/types';
import type { PolicyReadAuthorizationDependencies } from './authorize_policy_read';
import { createPolicyReadSavedObjectsClient } from './policy_read_client';
import type { PolicyConfigDerivations, PolicyRegistryResolve } from './to_policy_snapshot';

export const PROHIBITED_PACKAGE_POLICY_METHODS = [
  'create',
  'bulkCreate',
  'update',
  'bulkUpdate',
  'delete',
  'upgrade',
  'bulkUpgrade',
  'rollback',
  'restoreRollback',
  'cleanupRollbackSavedObjects',
  'removeOutputFromAll',
  'runExternalCallbacks',
  'inspect',
] as const satisfies ReadonlyArray<keyof PackagePolicyClient>;

export const policyGenerator = new FleetPackagePolicyGenerator('policy-read-seed');

export const createNormalizedConfigMock = (marker: string): NormalizedPolicyConfig => ({
  globalManifestVersion: 'latest',
  globalTelemetryEnabled: true,
  perOs: {
    windows: { 'malware.mode': marker },
    mac: { 'malware.mode': marker },
    linux: { 'malware.mode': marker },
  },
  unrecognizedPerOs: { windows: {}, mac: {}, linux: {} },
});

export const createDerivationsMock = ({
  knownVersions,
}: { knownVersions?: readonly string[] } = {}): jest.Mocked<PolicyConfigDerivations> => ({
  normalize: jest.fn((config, packageVersion) => {
    if (knownVersions && !knownVersions.includes(packageVersion)) {
      return { status: 'registry_version_unknown', requestedVersion: packageVersion };
    }

    return createNormalizedConfigMock(config.global_manifest_version);
  }),
  hash: jest.fn(
    (normalized) => `hash:${normalized.globalManifestVersion}:${normalized.globalTelemetryEnabled}`
  ),
});

export const createRegistryResolveMock = ({
  knownVersions,
  nearestKnownVersion,
}: {
  knownVersions?: readonly string[];
  nearestKnownVersion?: string;
} = {}): jest.MockedFunction<PolicyRegistryResolve> =>
  jest.fn((packageVersion) => {
    if (knownVersions && !knownVersions.includes(packageVersion)) {
      return {
        status: 'registry_version_unknown',
        requestedVersion: packageVersion,
        ...(nearestKnownVersion === undefined ? {} : { nearestKnownVersion }),
      };
    }

    return { packageVersion, fields: [] };
  });

export const grantedPrivilegeBasis = (
  overrides: Partial<PolicyReadPrivilegeBasis> = {}
): PolicyReadPrivilegeBasis => ({
  securityPolicyManagementRead: true,
  fleetIntegrationPoliciesRead: true,
  fleetAgentsRead: true,
  ...overrides,
});

export interface AuthorizationMocks extends PolicyReadAuthorizationDependencies {
  readonly getEndpointAuthz: jest.Mock<Promise<EndpointAuthz>, [KibanaRequest]>;
  readonly getFleetAuthz: jest.Mock<Promise<FleetAuthz>, [KibanaRequest]>;
  readonly setPrivileges: (privileges: {
    securityPolicyManagementRead: boolean;
    fleetIntegrationPoliciesRead: boolean;
    fleetAgentsRead?: boolean;
    fleetSetup?: boolean;
    fleetAgentPoliciesRead?: boolean;
    fleetIntegrationsRead?: boolean;
    fleetIntegrationsWrite?: boolean;
  }) => void;
}

export const createAuthorizationMocks = (): AuthorizationMocks => {
  const getEndpointAuthz = jest.fn<Promise<EndpointAuthz>, [KibanaRequest]>(async () =>
    getEndpointAuthzInitialStateMock()
  );
  const getFleetAuthz = jest.fn<Promise<FleetAuthz>, [KibanaRequest]>(async () =>
    createFleetAuthzMock()
  );

  return {
    getEndpointAuthz,
    getFleetAuthz,
    setPrivileges: ({
      securityPolicyManagementRead,
      fleetIntegrationPoliciesRead,
      fleetAgentsRead = true,
      fleetSetup = false,
      fleetAgentPoliciesRead = fleetIntegrationPoliciesRead,
      fleetIntegrationsRead = fleetIntegrationPoliciesRead,
      fleetIntegrationsWrite = false,
    }) => {
      getEndpointAuthz.mockImplementation(async () =>
        getEndpointAuthzInitialStateMock({ canReadPolicyManagement: securityPolicyManagementRead })
      );
      getFleetAuthz.mockImplementation(async () => {
        const fleetAuthz = createFleetAuthzMock();
        const hasAgentPoliciesRead = fleetAgentPoliciesRead;
        const hasIntegrationsRead = fleetIntegrationsRead;

        return {
          ...fleetAuthz,
          fleet: {
            ...fleetAuthz.fleet,
            all: false,
            setup: fleetSetup || hasAgentPoliciesRead,
            readAgents: fleetAgentsRead,
            readEnrollmentTokens: false,
            readAgentPolicies: fleetSetup || hasAgentPoliciesRead,
            allAgentPolicies: false,
            allAgents: false,
            allSettings: false,
            readSettings: false,
            addAgents: false,
            addFleetServers: false,
            generateAgentReports: false,
          },
          integrations: {
            ...fleetAuthz.integrations,
            all: false,
            readPackageInfo: false,
            readInstalledPackages: hasIntegrationsRead,
            installPackages: false,
            upgradePackages: false,
            uploadPackages: false,
            removePackages: false,
            readPackageSettings: hasIntegrationsRead,
            writePackageSettings: false,
            readIntegrationPolicies: hasAgentPoliciesRead && hasIntegrationsRead,
            writeIntegrationPolicies: fleetIntegrationsWrite,
          },
        };
      });
    },
  };
};

export interface PolicyReadMocks {
  readonly savedObjects: jest.Mocked<SavedObjectsServiceStart>;
  readonly soClient: jest.Mocked<SavedObjectsClientContract>;
  readonly packagePolicyService: jest.Mocked<PackagePolicyClient>;
  readonly authorization: AuthorizationMocks;
  readonly derivations: jest.Mocked<PolicyConfigDerivations>;
  readonly resolveRegistry: jest.MockedFunction<PolicyRegistryResolve>;
  readonly logger: MockedLogger;
  readonly spaceId: string;
  readonly request: KibanaRequest;
  readonly getSoClient: jest.Mock<SavedObjectsClientContract, []>;
}

export const createPolicyReadMocks = ({
  spaceId = 'default',
}: { spaceId?: string } = {}): PolicyReadMocks => {
  const savedObjects = savedObjectsServiceMock.createStartContract();
  const soClient = savedObjectsClientMock.create();
  const packagePolicyService = createPackagePolicyServiceMock();
  const request = httpServerMock.createKibanaRequest();

  savedObjects.getScopedClient.mockReturnValue(soClient);

  return {
    savedObjects,
    soClient,
    packagePolicyService,
    authorization: createAuthorizationMocks(),
    derivations: createDerivationsMock(),
    resolveRegistry: createRegistryResolveMock(),
    logger: loggingSystemMock.createLogger(),
    spaceId,
    request,
    getSoClient: jest.fn(() => createPolicyReadSavedObjectsClient({ savedObjects, request })),
  };
};

export const mockFetchAllItems = (
  packagePolicyService: jest.Mocked<PackagePolicyClient>,
  pages: ReadonlyArray<readonly PackagePolicy[]>
): void => {
  packagePolicyService.fetchAllItems.mockResolvedValue({
    async *[Symbol.asyncIterator]() {
      for (const page of pages) {
        yield [...page];
      }
      yield [];
    },
  });
};

export const createDefendPolicyMock = (overrides: PartialEndpointPolicyData = {}): PackagePolicy =>
  policyGenerator.generateEndpointPackagePolicy({
    id: 'defend-1',
    name: 'Defend policy 1',
    revision: 3,
    version: 'WzEyMyw0XQ==',
    created_at: '2026-01-01T00:00:00.000Z',
    created_by: 'creator',
    updated_at: '2026-02-02T00:00:00.000Z',
    updated_by: 'updater',
    policy_ids: ['agent-policy-1'],
    ...overrides,
  }) as PackagePolicy;
