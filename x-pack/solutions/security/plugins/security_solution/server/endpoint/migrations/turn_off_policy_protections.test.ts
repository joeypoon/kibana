/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createMockEndpointAppContextServiceStartContract } from '../mocks';
import type { Logger } from '@kbn/logging';
import type { ElasticsearchClient } from '@kbn/core-elasticsearch-server';
import type { EndpointInternalFleetServicesInterface } from '../services/fleet';

import { ALL_PRODUCT_FEATURE_KEYS } from '@kbn/security-solution-features/keys';
import { turnOffPolicyProtectionsIfNotSupported } from './turn_off_policy_protections';
import { FleetPackagePolicyGenerator } from '../../../common/endpoint/data_generators/fleet_package_policy_generator';
import type { PolicyData } from '../../../common/endpoint/types';
import {
  ensureOnlyEventCollectionIsAllowed,
  removeDeviceControl,
  resetCustomNotifications,
} from '../../../common/endpoint/models/policy_config_helpers';
import type { ProductFeaturesService } from '../../lib/product_features_service/product_features_service';
import { createProductFeaturesServiceMock } from '../../lib/product_features_service/mocks';
import { merge } from 'lodash';
import {
  DefaultPolicyDeviceNotificationMessage,
  DefaultPolicyNotificationMessage,
  DefaultPolicyRuleNotificationMessage,
} from '../../../common/endpoint/models/policy_config';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import { createEndpointFleetServicesFactoryMock } from '../services/fleet/endpoint_fleet_services_factory.mocks';

describe('Turn Off Policy Protections Migration', () => {
  let esClient: ElasticsearchClient;
  let fleetServices: EndpointInternalFleetServicesInterface;
  let productFeatureService: ProductFeaturesService;
  let logger: Logger;

  const callTurnOffPolicyProtections = () =>
    turnOffPolicyProtectionsIfNotSupported(esClient, fleetServices, productFeatureService, logger);

  const mockPolicyListResponse = (
    { total, items, page }: { total?: number; items?: PolicyData[]; page?: number } = {
      total: 1,
      page: 2,
      items: [],
    }
  ) => {
    const packagePolicyListSrv = fleetServices.packagePolicy.list as jest.Mock;
    return packagePolicyListSrv.mockResolvedValueOnce({
      total,
      page,
      perPage: 1500,
      items,
    });
  };

  const generatePolicyMock = (
    withDisabledProtections = false,
    withCustomProtectionUpdates = true,
    withCustomNotifications = true
  ): PolicyData => {
    const policy = new FleetPackagePolicyGenerator('seed').generateEndpointPackagePolicy();
    if (withDisabledProtections) {
      policy.inputs[0].config.policy.value = ensureOnlyEventCollectionIsAllowed(
        policy.inputs[0].config.policy.value
      );
    }
    if (withCustomProtectionUpdates) {
      policy.inputs[0].config.policy.value.global_manifest_version = '2023-01-01';
    }
    if (!withCustomNotifications) {
      policy.inputs[0].config.policy.value = merge(
        {},
        policy.inputs[0].config.policy.value,
        resetCustomNotifications()
      );
    } else if (withCustomNotifications) {
      policy.inputs[0].config.policy.value = merge(
        {},
        policy.inputs[0].config.policy.value,
        resetCustomNotifications('custom test')
      );
    }
    return policy;
  };

  // I’ve decided to keep the content hardcoded for better readability instead of generating it dynamically.
  const generateExpectedPolicyMock = ({
    defaultProtections,
    defaultNotes,
    defaultUpdates,
    id,
  }: {
    id: string;
    defaultProtections: boolean;
    defaultNotes: boolean;
    defaultUpdates: boolean;
  }) => {
    const globalManifestVersion = defaultUpdates ? 'latest' : '2023-01-01';
    const protectionMode = defaultProtections ? 'off' : 'prevent';
    const ruleNotificationMessage = defaultNotes
      ? DefaultPolicyRuleNotificationMessage
      : 'custom test';
    const notificationMessage = defaultNotes ? DefaultPolicyNotificationMessage : 'custom test';
    const deviceNotificationMessage = defaultNotes
      ? DefaultPolicyDeviceNotificationMessage
      : 'custom test';

    return expect.arrayContaining([
      expect.objectContaining({
        id,
        inputs: [
          expect.objectContaining({
            config: expect.objectContaining({
              policy: expect.objectContaining({
                value: expect.objectContaining({
                  global_manifest_version: globalManifestVersion,
                  linux: expect.objectContaining({
                    behavior_protection: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    memory_protection: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    malware: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    popup: expect.objectContaining({
                      behavior_protection: expect.objectContaining({
                        message: ruleNotificationMessage,
                      }),
                      memory_protection: expect.objectContaining({
                        message: ruleNotificationMessage,
                      }),
                      malware: expect.objectContaining({
                        message: notificationMessage,
                      }),
                    }),
                  }),
                  mac: expect.objectContaining({
                    behavior_protection: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    memory_protection: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    malware: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    popup: expect.objectContaining({
                      behavior_protection: expect.objectContaining({
                        message: ruleNotificationMessage,
                      }),
                      memory_protection: expect.objectContaining({
                        message: ruleNotificationMessage,
                      }),
                      malware: expect.objectContaining({
                        message: notificationMessage,
                      }),
                      ransomware: expect.objectContaining({
                        message: notificationMessage,
                      }),
                      device_control: expect.objectContaining({
                        message: deviceNotificationMessage,
                      }),
                    }),
                  }),
                  windows: expect.objectContaining({
                    behavior_protection: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    memory_protection: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    malware: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    ransomware: expect.objectContaining({
                      mode: protectionMode,
                    }),
                    popup: expect.objectContaining({
                      behavior_protection: expect.objectContaining({
                        message: ruleNotificationMessage,
                      }),
                      memory_protection: expect.objectContaining({
                        message: ruleNotificationMessage,
                      }),
                      malware: expect.objectContaining({
                        message: notificationMessage,
                      }),
                      ransomware: expect.objectContaining({
                        message: notificationMessage,
                      }),
                      device_control: expect.objectContaining({
                        message: deviceNotificationMessage,
                      }),
                    }),
                  }),
                }),
              }),
            }),
          }),
        ],
      }),
    ]);
  };

  const createFilteredProductFeaturesServiceMock = (
    keysToExclude: string[] = [
      'endpoint_policy_protections',
      'endpoint_custom_notification',
      'endpoint_protection_updates',
    ]
  ) =>
    createProductFeaturesServiceMock(
      ALL_PRODUCT_FEATURE_KEYS.filter((key) => !keysToExclude.includes(key))
    );

  beforeEach(() => {
    const endpointContextStartContract = createMockEndpointAppContextServiceStartContract();

    logger = loggingSystemMock.createLogger();
    ({ esClient } = endpointContextStartContract);
    productFeatureService = createFilteredProductFeaturesServiceMock();

    // productFeatureService = endpointContextStartContract.productFeaturesService;

    fleetServices = createEndpointFleetServicesFactoryMock().service.asInternalUser();
  });

  describe('when merging policy updates for different product features', () => {
    beforeEach(() => {
      // We only check for the `bulkUpdate` call, so we mock it to avoid side effects
      fleetServices.packagePolicy.bulkUpdate = jest.fn().mockResolvedValue({
        updatedPolicies: [],
        failedPolicies: [],
      });
    });
    describe('All policies compliant', () => {
      it('should not update if all all features are enabled', async () => {
        productFeatureService = createProductFeaturesServiceMock();

        const items = [generatePolicyMock(false, true, true)]; // Custom protections, custom manifest, custom notifications set

        mockPolicyListResponse({ items });

        await callTurnOffPolicyProtections();

        expect(fleetServices.packagePolicy.bulkUpdate).not.toHaveBeenCalled();
      });

      it('should not update if all policies are compliant', async () => {
        const items = [generatePolicyMock(true, false, false)]; // Custom protections, default manifest, default notifications set

        mockPolicyListResponse({ items });

        await callTurnOffPolicyProtections();

        expect(fleetServices.packagePolicy.bulkUpdate).not.toHaveBeenCalled();
      });

      it('should not update a stripped policy solely for absent device-control popup messages', async () => {
        productFeatureService = createFilteredProductFeaturesServiceMock([
          'endpoint_custom_notification',
        ]);

        const policy = new FleetPackagePolicyGenerator('seed').generateEndpointPackagePolicy();
        policy.inputs[0].config.policy.value = removeDeviceControl(
          policy.inputs[0].config.policy.value
        );

        mockPolicyListResponse({ items: [policy] });

        await callTurnOffPolicyProtections();

        expect(fleetServices.packagePolicy.bulkUpdate).not.toHaveBeenCalled();
        expect(policy.inputs[0].config.policy.value.windows.popup).not.toHaveProperty(
          'device_control'
        );
        expect(policy.inputs[0].config.policy.value.mac.popup).not.toHaveProperty('device_control');
      });
    });

    describe('Single feature not compliant with product features', () => {
      it('should update properly if only `endpointPolicyProtections` changed', async () => {
        const items = [
          generatePolicyMock(false, false, false), // Custom protections, default manifest, default notifications set
          generatePolicyMock(true, false, false), // Compliant policy
        ];

        mockPolicyListResponse({ items });

        await callTurnOffPolicyProtections();

        const mockCalls = (fleetServices.packagePolicy.bulkUpdate as jest.Mock).mock.calls;
        expect(mockCalls.length).toBeGreaterThan(0);
        const mockArguments = mockCalls[0][2];
        expect(mockArguments.length).toBe(1); // Only one policy should be updated
        expect(mockArguments).toEqual(
          generateExpectedPolicyMock({
            id: items[0].id, // Only the first policy should be updated
            defaultProtections: true,
            defaultNotes: true,
            defaultUpdates: true,
          })
        );
      });

      it('should update properly if only `endpointPolicyProtections` changed across 2 result pages', async () => {
        const packagePolicyListSrv = fleetServices.packagePolicy.list as jest.Mock;

        const allPolicies = [
          generatePolicyMock(false, false, false), // Custom protections, default manifest, default notifications set
          generatePolicyMock(false, false, false), // Custom protections, default manifest, default notifications set
        ];

        mockPolicyListResponse({ total: 1500, items: [allPolicies[0]] });
        mockPolicyListResponse({ total: 1500, items: [allPolicies[1]] });

        await callTurnOffPolicyProtections();
        expect(packagePolicyListSrv).toHaveBeenCalledTimes(2);
        expect(fleetServices.packagePolicy.bulkUpdate).toHaveBeenCalledTimes(1);

        const mockCalls = (fleetServices.packagePolicy.bulkUpdate as jest.Mock).mock.calls;
        const mockArguments = mockCalls[0][2];
        expect(mockArguments.length).toBe(2);
        expect(mockArguments[0].inputs[0].config.policy.value.global_manifest_version).toBe(
          'latest'
        );
        expect(mockArguments[1].inputs[0].config.policy.value.windows.ransomware.mode).toBe('off');
        expect(mockArguments[0].inputs[0].config.policy.value.windows.ransomware.mode).toBe('off');
      });

      it('should update properly if only `endpointProtectionUpdates` not compliant', async () => {
        const allPolicies = [
          generatePolicyMock(true, false, false), // Compliant policy
          generatePolicyMock(true, true, false), // Default protections, custom manifest, default notifications set
        ];

        mockPolicyListResponse({ total: 2, items: allPolicies });

        await callTurnOffPolicyProtections();

        const mockCalls = (fleetServices.packagePolicy.bulkUpdate as jest.Mock).mock.calls;
        expect(mockCalls.length).toBeGreaterThan(0);
        const mockArguments = mockCalls[0][2];
        expect(mockArguments.length).toBe(1); // Only one policy should be updated
        expect(mockArguments).toEqual(
          generateExpectedPolicyMock({
            id: allPolicies[1].id, // Only the second policy should be updated
            defaultProtections: true,
            defaultNotes: true,
            defaultUpdates: true,
          })
        );
      });

      it('should reset notifications when a stripped policy has one explicit custom message', async () => {
        productFeatureService = createFilteredProductFeaturesServiceMock([
          'endpoint_custom_notification',
        ]);

        const policy = new FleetPackagePolicyGenerator('seed').generateEndpointPackagePolicy();
        policy.inputs[0].config.policy.value = removeDeviceControl(
          policy.inputs[0].config.policy.value
        );
        policy.inputs[0].config.policy.value.windows.popup.malware.message = 'custom test';

        mockPolicyListResponse({ items: [policy] });

        await callTurnOffPolicyProtections();

        expect(fleetServices.packagePolicy.bulkUpdate).toHaveBeenCalledTimes(1);
        const mockArguments = (fleetServices.packagePolicy.bulkUpdate as jest.Mock).mock
          .calls[0][2];
        expect(mockArguments.length).toBe(1);
        expect(mockArguments[0].inputs[0].config.policy.value.windows.popup.malware.message).toBe(
          DefaultPolicyNotificationMessage
        );
      });

      it('should update properly if only `endpointCustomNote` not compliant', async () => {
        const allPolicies = [
          generatePolicyMock(true, false, true), // Default protections, default manifest, custom notifications set
          generatePolicyMock(true, false, false), // Compliant policy
        ];

        mockPolicyListResponse({ total: 2, items: allPolicies });

        await callTurnOffPolicyProtections();

        const mockCalls = (fleetServices.packagePolicy.bulkUpdate as jest.Mock).mock.calls;
        expect(mockCalls.length).toBeGreaterThan(0);
        const mockArguments = mockCalls[0][2];
        expect(mockArguments.length).toBe(1); // Only one policy should be updated
        expect(mockArguments).toEqual(
          generateExpectedPolicyMock({
            id: allPolicies[0].id, // Only the first policy should be updated
            defaultProtections: true,
            defaultNotes: true,
            defaultUpdates: true,
          })
        );
      });

      it('should update properly if only `endpointCustomNote` and `endpointProtectionUpdates` not compliant across 2 policies', async () => {
        const allPolicies = [
          generatePolicyMock(true, false, true), // Default protections, default manifest, custom notifications set
          generatePolicyMock(true, true, false), // Default protections, custom manifest, default notifications set
          generatePolicyMock(true, false, false), // Default protections, default manifest, default notifications set
        ];

        mockPolicyListResponse({ total: 3, items: allPolicies });

        await callTurnOffPolicyProtections();

        const mockCalls = (fleetServices.packagePolicy.bulkUpdate as jest.Mock).mock.calls;
        expect(mockCalls.length).toBeGreaterThan(0);
        const mockArguments = mockCalls[0][2];
        expect(mockArguments.length).toBe(2); // Two policies should be updated
        expect(mockArguments[0].inputs[0].config.policy.value.global_manifest_version).toBe(
          'latest'
        );
        expect(mockArguments[1].inputs[0].config.policy.value.global_manifest_version).toBe(
          'latest'
        );
        expect(
          mockArguments[0].inputs[0].config.policy.value.windows.popup.memory_protection.message
        ).toBe(DefaultPolicyRuleNotificationMessage);
        expect(
          mockArguments[1].inputs[0].config.policy.value.windows.popup.memory_protection.message
        ).toBe(DefaultPolicyRuleNotificationMessage);
      });
    });

    describe('Multiple features not compliant with product features', () => {
      const verifyGeneratedPolicies = (policies: PolicyData[]) => {
        expect(policies[0].inputs[0].config.policy.value.global_manifest_version).toBe(
          '2023-01-01'
        );
        expect(policies[0].inputs[0].config.policy.value.windows.memory_protection.mode).toBe(
          'prevent'
        );
        expect(
          policies[0].inputs[0].config.policy.value.windows.popup.memory_protection.message
        ).toBe('custom test');
      };

      it('should merge updates for `endpointPolicyProtections` and `endpointCustomNotification`', async () => {
        productFeatureService = createFilteredProductFeaturesServiceMock([
          'endpoint_custom_notification',
          'endpoint_policy_protections',
        ]);

        const policiesNeedingUpdate = [
          generatePolicyMock(false, true, true), // Custom protections, custom manifest, custom notifications set
        ];

        // Sanity check to ensure the policies are generated correctly
        verifyGeneratedPolicies(policiesNeedingUpdate);

        mockPolicyListResponse({ total: 1, items: policiesNeedingUpdate });

        await callTurnOffPolicyProtections();

        expect(fleetServices.packagePolicy.bulkUpdate).toHaveBeenCalledWith(
          fleetServices.savedObjects.createInternalScopedSoClient({ readonly: false }),
          esClient,
          generateExpectedPolicyMock({
            id: policiesNeedingUpdate[0].id,
            defaultProtections: true,
            defaultNotes: true,
            defaultUpdates: false,
          }),
          { user: { username: 'elastic' } }
        );
      });

      it('should merge updates for `endpointProtectionUpdates` and `endpointCustomNotification`', async () => {
        productFeatureService = createFilteredProductFeaturesServiceMock([
          'endpoint_custom_notification',
          'endpoint_protection_updates',
        ]);

        const policiesNeedingUpdate = [
          generatePolicyMock(false, true, true), // Custom protections, custom manifest, custom notifications set
        ];

        // Sanity check to ensure the policies are generated correctly
        verifyGeneratedPolicies(policiesNeedingUpdate);

        mockPolicyListResponse({ total: 1, items: policiesNeedingUpdate });

        await callTurnOffPolicyProtections();

        expect(fleetServices.packagePolicy.bulkUpdate).toHaveBeenCalledWith(
          fleetServices.savedObjects.createInternalScopedSoClient({ readonly: false }),
          esClient,
          generateExpectedPolicyMock({
            id: policiesNeedingUpdate[0].id,
            defaultProtections: false,
            defaultNotes: true,
            defaultUpdates: true,
          }),
          { user: { username: 'elastic' } }
        );
      });

      it('should merge updates for `endpointPolicyProtections`, `endpointProtectionUpdates`, and `endpointCustomNotification`', async () => {
        const policiesNeedingUpdate = [
          generatePolicyMock(false, true, true), // Custom protections, custom manifest, custom notifications set
        ];

        // Sanity check to ensure the policies are generated correctly
        verifyGeneratedPolicies(policiesNeedingUpdate);

        mockPolicyListResponse({ total: 1, items: policiesNeedingUpdate });

        await callTurnOffPolicyProtections();

        expect(fleetServices.packagePolicy.bulkUpdate).toHaveBeenCalledWith(
          fleetServices.savedObjects.createInternalUnscopedSoClient(),
          esClient,
          generateExpectedPolicyMock({
            id: policiesNeedingUpdate[0].id,
            defaultProtections: true,
            defaultNotes: true,
            defaultUpdates: true,
          }),
          { user: { username: 'elastic' } }
        );
      });
    });
  });
});
