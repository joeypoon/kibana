/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyConfig } from '../types';
import {
  PolicyOperatingSystem,
  ProtectionModes,
  AntivirusRegistrationModes,
  DeviceControlAccessLevel,
} from '../types';
import {
  DefaultPolicyDeviceNotificationMessage,
  DefaultPolicyNotificationMessage,
  DefaultPolicyRuleNotificationMessage,
  policyFactory,
} from './policy_config';
import {
  disableProtections,
  isPolicySetToEventCollectionOnly,
  ensureOnlyEventCollectionIsAllowed,
  isBillablePolicy,
  getPolicyProtectionsReference,
  checkIfPopupMessagesContainCustomNotifications,
  resetCustomNotifications,
  removeDeviceControl,
  removeLinuxDnsEvents,
  setProtectionModeAndPopup,
  setBehaviorReputationService,
  setMalwareBoolean,
  setDeviceControlSwitch,
  setDeviceControlUsbStorage,
  constrainLinuxTtyIo,
  setPopupEnabled,
} from './policy_config_helpers';
import { cloneDeep, get, merge } from 'lodash';
import { set } from '@kbn/safer-lodash-set';

describe('Policy Config helpers', () => {
  describe('disableProtections', () => {
    it('disables all the protections in the default policy', () => {
      expect(disableProtections(policyFactory())).toEqual<PolicyConfig>(eventsOnlyPolicy());
    });

    it('does not enable supported fields', () => {
      const defaultPolicy: PolicyConfig = policyFactory();

      const notSupported: PolicyConfig['windows']['memory_protection'] = {
        mode: ProtectionModes.off,
        supported: false,
      };

      const notSupportedBehaviorProtection: PolicyConfig['windows']['behavior_protection'] = {
        mode: ProtectionModes.off,
        supported: false,
        reputation_service: false,
      };

      const inputPolicyWithoutSupportedProtections: PolicyConfig = {
        ...defaultPolicy,
        windows: {
          ...defaultPolicy.windows,
          memory_protection: notSupported,
          behavior_protection: notSupportedBehaviorProtection,
          ransomware: notSupported,
        },
        mac: {
          ...defaultPolicy.mac,
          memory_protection: notSupported,
          behavior_protection: notSupportedBehaviorProtection,
        },
        linux: {
          ...defaultPolicy.linux,
          memory_protection: notSupported,
          behavior_protection: notSupportedBehaviorProtection,
        },
      };

      const expectedPolicyWithoutSupportedProtections: PolicyConfig = {
        ...eventsOnlyPolicy(),
        windows: {
          ...eventsOnlyPolicy().windows,
          memory_protection: notSupported,
          behavior_protection: notSupportedBehaviorProtection,
          ransomware: notSupported,
        },
        mac: {
          ...eventsOnlyPolicy().mac,
          memory_protection: notSupported,
          behavior_protection: notSupportedBehaviorProtection,
        },
        linux: {
          ...eventsOnlyPolicy().linux,
          memory_protection: notSupported,
          behavior_protection: notSupportedBehaviorProtection,
        },
      };

      const policy = disableProtections(inputPolicyWithoutSupportedProtections);

      expect(policy).toEqual<PolicyConfig>(expectedPolicyWithoutSupportedProtections);
    });

    it('does not enable events', () => {
      const defaultPolicy: PolicyConfig = policyFactory();

      const windowsEvents: typeof defaultPolicy.windows.events = {
        credential_access: false,
        dll_and_driver_load: false,
        dns: false,
        file: false,
        network: false,
        process: false,
        registry: false,
        security: false,
      };

      const macEvents: typeof defaultPolicy.mac.events = {
        dns: false,
        file: false,
        process: false,
        network: false,
        security: false,
      };

      const linuxEvents: typeof defaultPolicy.linux.events = {
        dns: false,
        file: false,
        process: false,
        network: false,
        session_data: false,
        tty_io: false,
      };

      const expectedPolicy: PolicyConfig = {
        ...eventsOnlyPolicy(),
        windows: { ...eventsOnlyPolicy().windows, events: { ...windowsEvents } },
        mac: { ...eventsOnlyPolicy().mac, events: { ...macEvents } },
        linux: { ...eventsOnlyPolicy().linux, events: { ...linuxEvents } },
      };

      const inputPolicy = {
        ...defaultPolicy,
        windows: { ...defaultPolicy.windows, events: { ...windowsEvents } },
        mac: { ...defaultPolicy.mac, events: { ...macEvents } },
        linux: { ...defaultPolicy.linux, events: { ...linuxEvents } },
      };

      expect(disableProtections(inputPolicy)).toEqual<PolicyConfig>(expectedPolicy);
    });
  });

  describe('setPolicyToEventCollectionOnly()', () => {
    it('should set the policy to event collection only', () => {
      const policyConfig = policyFactory();
      policyConfig.windows.antivirus_registration = {
        enabled: true,
        mode: AntivirusRegistrationModes.enabled,
      };
      expect(ensureOnlyEventCollectionIsAllowed(policyConfig)).toEqual(eventsOnlyPolicy());
    });
  });

  describe('isPolicySetToEventCollectionOnly', () => {
    let policy: PolicyConfig;

    beforeEach(() => {
      policy = ensureOnlyEventCollectionIsAllowed(policyFactory());
    });

    it.each([
      {
        keyPath: `${PolicyOperatingSystem.windows}.malware.mode`,
        keyValue: ProtectionModes.prevent,
        expectedResult: false,
      },
      {
        keyPath: `${PolicyOperatingSystem.mac}.malware.mode`,
        keyValue: ProtectionModes.off,
        expectedResult: true,
      },
      {
        keyPath: `${PolicyOperatingSystem.windows}.ransomware.mode`,
        keyValue: ProtectionModes.prevent,
        expectedResult: false,
      },
      {
        keyPath: `${PolicyOperatingSystem.linux}.memory_protection.mode`,
        keyValue: ProtectionModes.off,
        expectedResult: true,
      },
      {
        keyPath: `${PolicyOperatingSystem.mac}.behavior_protection.mode`,
        keyValue: ProtectionModes.detect,
        expectedResult: false,
      },
      {
        keyPath: `${PolicyOperatingSystem.windows}.attack_surface_reduction.credential_hardening.enabled`,
        keyValue: true,
        expectedResult: false,
      },
      {
        keyPath: `${PolicyOperatingSystem.windows}.antivirus_registration.enabled`,
        keyValue: true,
        expectedResult: false,
      },
    ])(
      'should return `$expectedResult` if `$keyPath` is set to `$keyValue`',
      ({ keyPath, keyValue, expectedResult }) => {
        set(policy, keyPath, keyValue);

        expect(isPolicySetToEventCollectionOnly(policy)).toEqual({
          isOnlyCollectingEvents: expectedResult,
          message: expectedResult ? undefined : `property [${keyPath}] is set to [${keyValue}]`,
        });
      }
    );
  });

  describe('isBillablePolicy', () => {
    it('doesnt bill if serverless false', () => {
      const policy = policyFactory();
      const isBillable = isBillablePolicy(policy);
      expect(policy.meta.serverless).toBe(false);
      expect(isBillable).toBe(false);
    });

    it('doesnt bill if event collection only', () => {
      const policy = ensureOnlyEventCollectionIsAllowed(policyFactory());
      policy.meta.serverless = true;
      const isBillable = isBillablePolicy(policy);
      expect(isBillable).toBe(false);
    });

    it.each(getPolicyProtectionsReference())(
      'correctly bills if $keyPath is enabled',
      (feature) => {
        for (const os of feature.osList) {
          const policy = ensureOnlyEventCollectionIsAllowed(policyFactory());
          policy.meta.serverless = true;
          set(policy, `${os}.${feature.keyPath}`, feature.enableValue);
          const isBillable = isBillablePolicy(policy);
          expect(isBillable).toBe(true);
        }
      }
    );
  });

  describe('checkIfPopupMessagesContainCustomNotifications', () => {
    let policy: PolicyConfig;

    beforeEach(() => {
      policy = policyFactory();
    });

    it('returns false when all popup messages are default', () => {
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(false);
    });

    it('returns true when any popup message is custom', () => {
      set(policy, 'windows.popup.malware.message', 'Custom message');
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(true);
    });

    it('returns false when all popup messages are empty', () => {
      set(policy, 'windows.popup.malware.message', '');
      set(policy, 'mac.popup.memory_protection.message', '');
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(false);
    });

    it('returns true when any popup message is not empty or default', () => {
      set(policy, 'linux.popup.behavior_protection.message', 'Another custom message');
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(true);
    });

    it('returns false when hydrated filename, rule, and device defaults are set', () => {
      set(policy, 'windows.popup.malware.message', DefaultPolicyNotificationMessage);
      set(policy, 'windows.popup.ransomware.message', DefaultPolicyNotificationMessage);
      set(policy, 'mac.popup.ransomware.message', DefaultPolicyNotificationMessage);
      set(policy, 'mac.popup.memory_protection.message', DefaultPolicyRuleNotificationMessage);
      set(policy, 'linux.popup.behavior_protection.message', DefaultPolicyRuleNotificationMessage);
      set(policy, 'windows.popup.device_control.message', DefaultPolicyDeviceNotificationMessage);
      set(policy, 'mac.popup.device_control.message', DefaultPolicyDeviceNotificationMessage);
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(false);
    });

    it('returns true when a rule-family path uses the filename default', () => {
      set(policy, 'linux.popup.behavior_protection.message', DefaultPolicyNotificationMessage);
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(true);
    });

    it('returns true when a device-family path uses the filename default', () => {
      set(policy, 'windows.popup.device_control.message', DefaultPolicyNotificationMessage);
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(true);
    });

    it('returns false when device-control popup paths are missing after removeDeviceControl', () => {
      expect(checkIfPopupMessagesContainCustomNotifications(removeDeviceControl(policy))).toBe(
        false
      );
    });

    it('returns false when device-control popup objects were never set', () => {
      delete policy.windows.popup.device_control;
      delete policy.mac.popup.device_control;
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(false);
    });

    it('returns false when a popup message is null', () => {
      set(policy, 'windows.popup.malware.message', null);
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(false);
    });

    it('returns true when a stripped policy still has one explicit custom message', () => {
      const stripped = removeDeviceControl(policy);
      set(stripped, 'windows.popup.malware.message', 'Custom message');
      expect(checkIfPopupMessagesContainCustomNotifications(stripped)).toBe(true);
    });

    it('does not read or change popup enabled values', () => {
      const enabledBefore = {
        windowsMalware: policy.windows.popup.malware.enabled,
        macRansomware: policy.mac.popup.ransomware.enabled,
        windowsDevice: get(policy, 'windows.popup.device_control.enabled'),
      };

      set(policy, 'windows.popup.malware.enabled', !enabledBefore.windowsMalware);
      expect(checkIfPopupMessagesContainCustomNotifications(policy)).toBe(false);
      expect(policy.windows.popup.malware.enabled).toBe(!enabledBefore.windowsMalware);
      expect(policy.mac.popup.ransomware.enabled).toBe(enabledBefore.macRansomware);
      expect(get(policy, 'windows.popup.device_control.enabled')).toBe(enabledBefore.windowsDevice);

      const stripped = removeDeviceControl(policy);
      expect(checkIfPopupMessagesContainCustomNotifications(stripped)).toBe(false);
      expect(stripped.windows.popup.malware.enabled).toBe(!enabledBefore.windowsMalware);
      expect(stripped.mac.popup.ransomware.enabled).toBe(enabledBefore.macRansomware);
      expect(get(stripped, 'windows.popup.device_control.enabled')).toBeUndefined();
    });
  });

  describe('resetCustomNotifications', () => {
    let policy: PolicyConfig;

    beforeEach(() => {
      policy = policyFactory();
    });

    it.each([
      ['windows.popup.malware.message', DefaultPolicyNotificationMessage],
      ['windows.popup.behavior_protection.message', DefaultPolicyRuleNotificationMessage],
      ['windows.popup.memory_protection.message', DefaultPolicyRuleNotificationMessage],
      ['windows.popup.ransomware.message', DefaultPolicyNotificationMessage],
      ['windows.popup.device_control.message', DefaultPolicyDeviceNotificationMessage],
      ['linux.popup.malware.message', DefaultPolicyNotificationMessage],
      ['linux.popup.behavior_protection.message', DefaultPolicyRuleNotificationMessage],
      ['linux.popup.memory_protection.message', DefaultPolicyRuleNotificationMessage],
      ['mac.popup.malware.message', DefaultPolicyNotificationMessage],
      ['mac.popup.behavior_protection.message', DefaultPolicyRuleNotificationMessage],
      ['mac.popup.memory_protection.message', DefaultPolicyRuleNotificationMessage],
      ['mac.popup.ransomware.message', DefaultPolicyNotificationMessage],
      ['mac.popup.device_control.message', DefaultPolicyDeviceNotificationMessage],
    ])('resets %s to the family default', (keyPath, expectedMessage) => {
      set(policy, keyPath, `Custom message`);
      const defaultNotifications = resetCustomNotifications();

      const updatedPolicy = merge({}, policy, defaultNotifications);
      expect(get(updatedPolicy, keyPath)).toBe(expectedMessage);
    });

    it('does not change default messages', () => {
      set(policy, 'windows.popup.malware.message', DefaultPolicyNotificationMessage);
      const defaultNotifications = resetCustomNotifications();

      const updatedPolicy = merge({}, policy, defaultNotifications);
      expect(get(updatedPolicy, 'windows.popup.malware.message')).toBe(
        DefaultPolicyNotificationMessage
      );
    });

    it('resets empty messages to default messages', () => {
      set(policy, 'windows.popup.malware.message', '');
      const defaultNotifications = resetCustomNotifications();

      const updatedPolicy = merge({}, policy, defaultNotifications);
      expect(get(updatedPolicy, 'windows.popup.malware.message')).toBe(
        DefaultPolicyNotificationMessage
      );
    });

    it('resets messages for all operating systems to family defaults', () => {
      set(policy, 'windows.popup.malware.message', 'Custom message');
      set(policy, 'mac.popup.memory_protection.message', 'Another custom message');
      set(policy, 'linux.popup.behavior_protection.message', 'Yet another custom message');
      set(policy, 'mac.popup.ransomware.message', 'Mac ransomware custom');
      set(policy, 'windows.popup.device_control.message', 'Device custom');
      const defaultNotifications = resetCustomNotifications();

      const updatedPolicy = merge({}, policy, defaultNotifications);
      expect(get(updatedPolicy, 'windows.popup.malware.message')).toBe(
        DefaultPolicyNotificationMessage
      );
      expect(get(updatedPolicy, 'mac.popup.memory_protection.message')).toBe(
        DefaultPolicyRuleNotificationMessage
      );
      expect(get(updatedPolicy, 'linux.popup.behavior_protection.message')).toBe(
        DefaultPolicyRuleNotificationMessage
      );
      expect(get(updatedPolicy, 'mac.popup.ransomware.message')).toBe(
        DefaultPolicyNotificationMessage
      );
      expect(get(updatedPolicy, 'windows.popup.device_control.message')).toBe(
        DefaultPolicyDeviceNotificationMessage
      );
    });

    it('writes a supplied override to every popup message path', () => {
      const override = 'custom test';
      const defaultNotifications = resetCustomNotifications(override);

      expect(get(defaultNotifications, 'windows.popup.malware.message')).toBe(override);
      expect(get(defaultNotifications, 'mac.popup.memory_protection.message')).toBe(override);
      expect(get(defaultNotifications, 'linux.popup.behavior_protection.message')).toBe(override);
      expect(get(defaultNotifications, 'mac.popup.ransomware.message')).toBe(override);
      expect(get(defaultNotifications, 'windows.popup.device_control.message')).toBe(override);
      expect(get(defaultNotifications, 'mac.popup.device_control.message')).toBe(override);
    });

    it('does not write popup enabled values', () => {
      const enabledBefore = {
        windowsMalware: policy.windows.popup.malware.enabled,
        macRansomware: policy.mac.popup.ransomware.enabled,
        windowsDevice: get(policy, 'windows.popup.device_control.enabled'),
      };

      const defaultNotifications = resetCustomNotifications();
      const updatedPolicy = merge({}, policy, defaultNotifications);

      expect(get(defaultNotifications, 'windows.popup.malware.enabled')).toBeUndefined();
      expect(updatedPolicy.windows.popup.malware.enabled).toBe(enabledBefore.windowsMalware);
      expect(updatedPolicy.mac.popup.ransomware.enabled).toBe(enabledBefore.macRansomware);
      expect(get(updatedPolicy, 'windows.popup.device_control.enabled')).toBe(
        enabledBefore.windowsDevice
      );
    });
  });

  describe('removeDeviceControl', () => {
    let policy: PolicyConfig;

    beforeEach(() => {
      policy = policyFactory();
    });

    it('removes device_control fields from Windows OS configuration', () => {
      const result = removeDeviceControl(policy);

      expect(result.windows).not.toHaveProperty('device_control');
      expect(result.windows.popup).not.toHaveProperty('device_control');
    });

    it('removes device_control fields from Mac OS configuration', () => {
      const result = removeDeviceControl(policy);

      expect(result.mac).not.toHaveProperty('device_control');
      expect(result.mac.popup).not.toHaveProperty('device_control');
    });

    it('preserves all other Windows fields when removing device_control', () => {
      const result = removeDeviceControl(policy);

      // Check that all other Windows fields are preserved
      expect(result.windows.malware).toEqual(policy.windows.malware);
      expect(result.windows.ransomware).toEqual(policy.windows.ransomware);
      expect(result.windows.memory_protection).toEqual(policy.windows.memory_protection);
      expect(result.windows.behavior_protection).toEqual(policy.windows.behavior_protection);
      expect(result.windows.events).toEqual(policy.windows.events);
      expect(result.windows.logging).toEqual(policy.windows.logging);
      expect(result.windows.antivirus_registration).toEqual(policy.windows.antivirus_registration);
      expect(result.windows.attack_surface_reduction).toEqual(
        policy.windows.attack_surface_reduction
      );

      // Check that all other Windows popup fields are preserved
      expect(result.windows.popup.malware).toEqual(policy.windows.popup.malware);
      expect(result.windows.popup.ransomware).toEqual(policy.windows.popup.ransomware);
      expect(result.windows.popup.memory_protection).toEqual(
        policy.windows.popup.memory_protection
      );
      expect(result.windows.popup.behavior_protection).toEqual(
        policy.windows.popup.behavior_protection
      );
    });

    it('preserves all other Mac fields when removing device_control', () => {
      const result = removeDeviceControl(policy);

      // Check that all other Mac fields are preserved
      expect(result.mac.malware).toEqual(policy.mac.malware);
      expect(result.mac.memory_protection).toEqual(policy.mac.memory_protection);
      expect(result.mac.behavior_protection).toEqual(policy.mac.behavior_protection);
      expect(result.mac.events).toEqual(policy.mac.events);
      expect(result.mac.logging).toEqual(policy.mac.logging);
      expect(result.mac.advanced).toEqual(policy.mac.advanced);

      // Check that all other Mac popup fields are preserved
      expect(result.mac.popup.malware).toEqual(policy.mac.popup.malware);
      expect(result.mac.popup.memory_protection).toEqual(policy.mac.popup.memory_protection);
      expect(result.mac.popup.behavior_protection).toEqual(policy.mac.popup.behavior_protection);
    });

    it('preserves global and Linux configurations unchanged', () => {
      const result = removeDeviceControl(policy);

      // Check that global fields are preserved
      expect(result.global_manifest_version).toEqual(policy.global_manifest_version);
      expect(result.global_telemetry_enabled).toEqual(policy.global_telemetry_enabled);
      expect(result.meta).toEqual(policy.meta);

      // Check that Linux configuration is completely preserved (no device_control in Linux)
      expect(result.linux).toEqual(policy.linux);
    });

    it('works correctly with custom device_control values', () => {
      // Set custom device_control values
      policy.windows.device_control = { enabled: true, usb_storage: 'deny_all' };
      policy.mac.device_control = { enabled: true, usb_storage: 'audit' };
      policy.windows.popup.device_control = { enabled: true, message: 'Windows custom message' };
      policy.mac.popup.device_control = { enabled: false, message: 'Mac custom message' };

      const result = removeDeviceControl(policy);

      // Verify device_control fields are completely removed
      expect(result.windows).not.toHaveProperty('device_control');
      expect(result.mac).not.toHaveProperty('device_control');
      expect(result.windows.popup).not.toHaveProperty('device_control');
      expect(result.mac.popup).not.toHaveProperty('device_control');

      // Verify other fields are still preserved
      expect(result.windows.malware).toEqual(policy.windows.malware);
      expect(result.mac.malware).toEqual(policy.mac.malware);
    });

    it('returns a new policy object without mutating the original', () => {
      const originalPolicy = JSON.parse(JSON.stringify(policy)); // Deep clone for comparison
      const result = removeDeviceControl(policy);

      // Verify original policy is unchanged
      expect(policy).toEqual(originalPolicy);
      expect(policy.windows.device_control).toBeDefined();
      expect(policy.mac.device_control).toBeDefined();
      expect(policy.windows.popup.device_control).toBeDefined();
      expect(policy.mac.popup.device_control).toBeDefined();

      // Verify result is a different object
      expect(result).not.toBe(policy);
      expect(result.windows).not.toBe(policy.windows);
      expect(result.mac).not.toBe(policy.mac);
    });
  });

  describe('removeLinuxDnsEvents', () => {
    let policy: PolicyConfig;

    beforeEach(() => {
      policy = policyFactory();
    });

    it('removes dns field from Linux events', () => {
      const result = removeLinuxDnsEvents(policy);

      expect(result.linux.events).not.toHaveProperty('dns');
    });

    it('preserves all other Linux event fields', () => {
      const result = removeLinuxDnsEvents(policy);

      expect(result.linux.events.file).toEqual(policy.linux.events.file);
      expect(result.linux.events.process).toEqual(policy.linux.events.process);
      expect(result.linux.events.network).toEqual(policy.linux.events.network);
      expect(result.linux.events.session_data).toEqual(policy.linux.events.session_data);
      expect(result.linux.events.tty_io).toEqual(policy.linux.events.tty_io);
    });

    it('preserves all other Linux fields', () => {
      const result = removeLinuxDnsEvents(policy);

      expect(result.linux.malware).toEqual(policy.linux.malware);
      expect(result.linux.memory_protection).toEqual(policy.linux.memory_protection);
      expect(result.linux.behavior_protection).toEqual(policy.linux.behavior_protection);
      expect(result.linux.popup).toEqual(policy.linux.popup);
      expect(result.linux.logging).toEqual(policy.linux.logging);
      expect(result.linux.advanced).toEqual(policy.linux.advanced);
    });

    it('preserves Windows and Mac configurations unchanged', () => {
      const result = removeLinuxDnsEvents(policy);

      expect(result.windows).toEqual(policy.windows);
      expect(result.mac).toEqual(policy.mac);
    });

    it('preserves global fields unchanged', () => {
      const result = removeLinuxDnsEvents(policy);

      expect(result.global_manifest_version).toEqual(policy.global_manifest_version);
      expect(result.global_telemetry_enabled).toEqual(policy.global_telemetry_enabled);
      expect(result.meta).toEqual(policy.meta);
    });

    it('returns a new policy object without mutating the original', () => {
      const originalPolicy = JSON.parse(JSON.stringify(policy));
      const result = removeLinuxDnsEvents(policy);

      // Verify original policy is unchanged
      expect(policy).toEqual(originalPolicy);
      expect(policy.linux.events.dns).toBeDefined();

      // Verify result is a different object
      expect(result).not.toBe(policy);
      expect(result.linux).not.toBe(policy.linux);
      expect(result.linux.events).not.toBe(policy.linux.events);
    });
  });

  describe('coupling helpers', () => {
    const allOsList = [
      PolicyOperatingSystem.windows,
      PolicyOperatingSystem.mac,
      PolicyOperatingSystem.linux,
    ];
    const ransomwareOsList = [PolicyOperatingSystem.windows];
    const deviceSwitchOnValues: unknown[] = [
      true,
      'false',
      'true',
      0,
      1,
      '',
      null,
      [],
      {},
      { enabled: false },
    ];
    const usbElseValues: unknown[] = ['audit', 'DENY_ALL', 'block', true, false, null, {}];

    const unchangedLeaves = (policy: PolicyConfig) => ({
      antivirus: cloneDeep(policy.windows.antivirus_registration),
      ransomwareMac: cloneDeep(policy.mac.ransomware),
      ransomwareMacPopup: cloneDeep(policy.mac.popup.ransomware),
      malwareMessages: {
        windows: policy.windows.popup.malware.message,
        mac: policy.mac.popup.malware.message,
        linux: policy.linux.popup.malware.message,
      },
      reputation: {
        windows: policy.windows.behavior_protection.reputation_service,
        mac: policy.mac.behavior_protection.reputation_service,
        linux: policy.linux.behavior_protection.reputation_service,
      },
      malwareSubfeatures: {
        windowsBlocklist: policy.windows.malware.blocklist,
        macBlocklist: policy.mac.malware.blocklist,
        linuxBlocklist: policy.linux.malware.blocklist,
        windowsOnWrite: policy.windows.malware.on_write_scan,
        macOnWrite: policy.mac.malware.on_write_scan,
        linuxOnWrite: policy.linux.malware.on_write_scan,
      },
    });

    describe('setProtectionModeAndPopup', () => {
      it.each([
        ['malware', allOsList],
        ['memory_protection', allOsList],
        ['behavior_protection', allOsList],
      ] as const)('writes %s mode and popup across the card OS list', (protection, osList) => {
        const policy = policyFactory();
        const before = unchangedLeaves(policy);

        setProtectionModeAndPopup({
          policy,
          protection,
          osList,
          mode: ProtectionModes.detect,
          syncPopupEnabled: true,
          popupEnabled: false,
        });

        for (const os of osList) {
          expect(get(policy, `${os}.${protection}.mode`)).toBe(ProtectionModes.detect);
          expect(get(policy, `${os}.popup.${protection}.enabled`)).toBe(false);
        }

        expect(policy.windows.antivirus_registration).toEqual(before.antivirus);
        expect(policy.mac.ransomware).toEqual(before.ransomwareMac);
        expect(unchangedLeaves(policy).reputation).toEqual(before.reputation);
        expect(unchangedLeaves(policy).malwareSubfeatures).toEqual(before.malwareSubfeatures);
        expect(unchangedLeaves(policy).malwareMessages).toEqual(before.malwareMessages);
      });

      it('writes ransomware only on the Windows card OS list', () => {
        const policy = policyFactory();
        const macRansomware = cloneDeep(policy.mac.ransomware);
        const macPopup = cloneDeep(policy.mac.popup.ransomware);

        setProtectionModeAndPopup({
          policy,
          protection: 'ransomware',
          osList: ransomwareOsList,
          mode: ProtectionModes.off,
          syncPopupEnabled: true,
          popupEnabled: false,
        });

        expect(policy.windows.ransomware.mode).toBe(ProtectionModes.off);
        expect(policy.windows.popup.ransomware.enabled).toBe(false);
        expect(policy.mac.ransomware).toEqual(macRansomware);
        expect(policy.mac.popup.ransomware).toEqual(macPopup);
        expect(policy.linux).not.toHaveProperty('ransomware');
      });

      it('does not write popup.enabled when syncPopupEnabled is false', () => {
        const policy = policyFactory();
        const popupBefore = {
          windows: policy.windows.popup.malware.enabled,
          mac: policy.mac.popup.malware.enabled,
          linux: policy.linux.popup.malware.enabled,
        };

        setProtectionModeAndPopup({
          policy,
          protection: 'malware',
          osList: allOsList,
          mode: ProtectionModes.off,
          syncPopupEnabled: false,
          popupEnabled: false,
        });

        expect(policy.windows.malware.mode).toBe(ProtectionModes.off);
        expect(policy.mac.malware.mode).toBe(ProtectionModes.off);
        expect(policy.linux.malware.mode).toBe(ProtectionModes.off);
        expect(policy.windows.popup.malware.enabled).toBe(popupBefore.windows);
        expect(policy.mac.popup.malware.enabled).toBe(popupBefore.mac);
        expect(policy.linux.popup.malware.enabled).toBe(popupBefore.linux);
      });

      it('writes prevent with popup true when syncPopupEnabled is true', () => {
        const policy = policyFactory();
        policy.windows.malware.mode = ProtectionModes.detect;
        policy.windows.popup.malware.enabled = false;

        setProtectionModeAndPopup({
          policy,
          protection: 'malware',
          osList: ['windows'],
          mode: ProtectionModes.prevent,
          syncPopupEnabled: true,
          popupEnabled: true,
        });

        expect(policy.windows.malware.mode).toBe(ProtectionModes.prevent);
        expect(policy.windows.popup.malware.enabled).toBe(true);
      });
    });

    describe('setBehaviorReputationService', () => {
      it('assigns the raw value on all three operating systems', () => {
        const policy = policyFactory();
        policy.windows.behavior_protection.reputation_service = false;
        policy.mac.behavior_protection.reputation_service = false;
        policy.linux.behavior_protection.reputation_service = false;
        const modes = {
          windows: policy.windows.behavior_protection.mode,
          mac: policy.mac.behavior_protection.mode,
          linux: policy.linux.behavior_protection.mode,
        };

        setBehaviorReputationService(policy, true);

        expect(policy.windows.behavior_protection.reputation_service).toBe(true);
        expect(policy.mac.behavior_protection.reputation_service).toBe(true);
        expect(policy.linux.behavior_protection.reputation_service).toBe(true);
        expect(policy.windows.behavior_protection.mode).toBe(modes.windows);
        expect(policy.mac.behavior_protection.mode).toBe(modes.mac);
        expect(policy.linux.behavior_protection.mode).toBe(modes.linux);
      });

      it('does not inspect cloud state when assigning reputation', () => {
        const policy = policyFactory();
        policy.meta.cloud = false;
        const expected = cloneDeep(policy);

        setBehaviorReputationService(policy, policy.windows.behavior_protection.reputation_service);

        expect(policy).toEqual(expected);
      });
    });

    describe('setMalwareBoolean', () => {
      it('writes blocklist then on_write_scan across Windows, macOS, and Linux', () => {
        const policy = policyFactory();
        const modes = {
          windows: policy.windows.malware.mode,
          mac: policy.mac.malware.mode,
          linux: policy.linux.malware.mode,
        };

        setMalwareBoolean(policy, 'blocklist', false, allOsList);
        expect(policy.windows.malware.blocklist).toBe(false);
        expect(policy.mac.malware.blocklist).toBe(false);
        expect(policy.linux.malware.blocklist).toBe(false);
        expect(policy.windows.malware.on_write_scan).toBe(true);

        setMalwareBoolean(policy, 'on_write_scan', false, allOsList);
        expect(policy.windows.malware.on_write_scan).toBe(false);
        expect(policy.mac.malware.on_write_scan).toBe(false);
        expect(policy.linux.malware.on_write_scan).toBe(false);
        expect(policy.windows.malware.mode).toBe(modes.windows);
        expect(policy.mac.malware.mode).toBe(modes.mac);
        expect(policy.linux.malware.mode).toBe(modes.linux);
      });
    });

    describe('setDeviceControlSwitch', () => {
      it('uses the off branch only for exact false', () => {
        const policy = policyFactory();
        policy.windows.popup.device_control = { enabled: true, message: 'keep' };
        policy.mac.popup.device_control = { enabled: true, message: 'keep-mac' };

        setDeviceControlSwitch(policy, false);

        expect(policy.windows.device_control).toEqual({
          enabled: false,
          usb_storage: DeviceControlAccessLevel.audit,
        });
        expect(policy.mac.device_control).toEqual({
          enabled: false,
          usb_storage: DeviceControlAccessLevel.audit,
        });
        expect(policy.windows.popup.device_control).toEqual({ enabled: false, message: 'keep' });
        expect(policy.mac.popup.device_control).toEqual({ enabled: false, message: 'keep-mac' });
      });

      it.each(deviceSwitchOnValues)(
        'uses the on branch for %j and does not store the raw value',
        (value) => {
          const policy = policyFactory();
          policy.windows.device_control = {
            enabled: false,
            usb_storage: DeviceControlAccessLevel.audit,
          };
          policy.mac.device_control = {
            enabled: false,
            usb_storage: DeviceControlAccessLevel.audit,
          };
          policy.windows.popup.device_control = { enabled: false, message: 'existing' };
          policy.mac.popup.device_control = { enabled: false, message: 'existing-mac' };

          setDeviceControlSwitch(policy, value);

          expect(policy.windows.device_control).toEqual({
            enabled: true,
            usb_storage: DeviceControlAccessLevel.deny_all,
          });
          expect(policy.mac.device_control).toEqual({
            enabled: true,
            usb_storage: DeviceControlAccessLevel.deny_all,
          });
          expect(policy.windows.popup.device_control).toEqual({
            enabled: true,
            message: 'existing',
          });
          expect(policy.mac.popup.device_control).toEqual({
            enabled: true,
            message: 'existing-mac',
          });
          expect(policy.windows.device_control?.usb_storage).not.toBe(value);
          expect(policy.mac.device_control?.usb_storage).not.toBe(value);
        }
      );

      it('materializes a missing popup object with an empty message', () => {
        const policy = policyFactory();
        delete policy.windows.popup.device_control;
        delete policy.mac.popup.device_control;

        setDeviceControlSwitch(policy, false);

        expect(policy.windows.popup.device_control).toEqual({ enabled: false, message: '' });
        expect(policy.mac.popup.device_control).toEqual({ enabled: false, message: '' });
      });
    });

    describe('setDeviceControlUsbStorage', () => {
      it('sets both popup.enabled true for deny_all when popup objects exist', () => {
        const policy = policyFactory();
        policy.windows.popup.device_control = { enabled: false, message: 'usb' };
        policy.mac.popup.device_control = { enabled: false, message: 'usb-mac' };

        setDeviceControlUsbStorage(policy, DeviceControlAccessLevel.deny_all);

        expect(policy.windows.device_control?.usb_storage).toBe(DeviceControlAccessLevel.deny_all);
        expect(policy.mac.device_control?.usb_storage).toBe(DeviceControlAccessLevel.deny_all);
        expect(policy.windows.popup.device_control?.enabled).toBe(true);
        expect(policy.mac.popup.device_control?.enabled).toBe(true);
        expect(policy.windows.popup.device_control?.message).toBe('usb');
        expect(policy.mac.popup.device_control?.message).toBe('usb-mac');
      });

      it.each(usbElseValues)('assigns raw %j and sets existing popup.enabled false', (value) => {
        const policy = policyFactory();
        policy.windows.popup.device_control = { enabled: true, message: 'usb' };
        policy.mac.popup.device_control = { enabled: true, message: 'usb-mac' };

        setDeviceControlUsbStorage(policy, value);

        expect(policy.windows.device_control?.usb_storage).toBe(value);
        expect(policy.mac.device_control?.usb_storage).toBe(value);
        expect(policy.windows.popup.device_control?.enabled).toBe(false);
        expect(policy.mac.popup.device_control?.enabled).toBe(false);
        expect(policy.windows.popup.device_control?.message).toBe('usb');
      });

      it('skips a missing popup object and never materializes it', () => {
        const policy = policyFactory();
        delete policy.mac.popup.device_control;
        policy.windows.popup.device_control = { enabled: false, message: 'keep' };

        setDeviceControlUsbStorage(policy, DeviceControlAccessLevel.deny_all);

        expect(policy.mac.popup.device_control).toBeUndefined();
        expect(policy.windows.popup.device_control).toEqual({ enabled: true, message: 'keep' });
      });

      it('creates a missing device-control object with enabled true', () => {
        const policy = policyFactory();
        delete policy.windows.device_control;
        delete policy.mac.device_control;

        setDeviceControlUsbStorage(policy, DeviceControlAccessLevel.audit);

        expect(policy.windows.device_control).toEqual({
          enabled: true,
          usb_storage: DeviceControlAccessLevel.audit,
        });
        expect(policy.mac.device_control).toEqual({
          enabled: true,
          usb_storage: DeviceControlAccessLevel.audit,
        });
      });
    });

    describe('constrainLinuxTtyIo', () => {
      it('forces tty_io false only when session_data is exact false', () => {
        const policy = policyFactory();
        policy.linux.events.session_data = false;
        policy.linux.events.tty_io = true;

        constrainLinuxTtyIo(policy);

        expect(policy.linux.events.tty_io).toBe(false);
      });

      it('never forces tty_io true when session_data is enabled', () => {
        const policy = policyFactory();
        policy.linux.events.session_data = true;
        policy.linux.events.tty_io = false;

        constrainLinuxTtyIo(policy);

        expect(policy.linux.events.session_data).toBe(true);
        expect(policy.linux.events.tty_io).toBe(false);
      });

      it('does not coerce a non-false session_data value', () => {
        const policy = policyFactory();
        set(policy, 'linux.events.session_data', 'false');
        policy.linux.events.tty_io = true;

        constrainLinuxTtyIo(policy);

        expect(policy.linux.events.tty_io).toBe(true);
      });
    });

    describe('setPopupEnabled', () => {
      it('assigns enabled only and leaves messages unchanged', () => {
        const policy = policyFactory();
        policy.windows.popup.malware.message = 'custom';
        policy.mac.popup.malware.message = 'custom-mac';
        policy.linux.popup.malware.message = 'custom-linux';

        setPopupEnabled(policy, 'malware', allOsList, false);

        expect(policy.windows.popup.malware.enabled).toBe(false);
        expect(policy.mac.popup.malware.enabled).toBe(false);
        expect(policy.linux.popup.malware.enabled).toBe(false);
        expect(policy.windows.popup.malware.message).toBe('custom');
        expect(policy.mac.popup.malware.message).toBe('custom-mac');
        expect(policy.linux.popup.malware.message).toBe('custom-linux');
      });

      it('uses the ransomware card OS list and does not write mac', () => {
        const policy = policyFactory();
        const macPopup = cloneDeep(policy.mac.popup.ransomware);

        setPopupEnabled(policy, 'ransomware', ransomwareOsList, false);

        expect(policy.windows.popup.ransomware.enabled).toBe(false);
        expect(policy.mac.popup.ransomware).toEqual(macPopup);
      });
    });

    describe('helper contract', () => {
      it('does not derive antivirus registration when malware mode changes', () => {
        const policy = policyFactory();
        policy.windows.antivirus_registration = {
          mode: AntivirusRegistrationModes.sync,
          enabled: true,
        };

        setProtectionModeAndPopup({
          policy,
          protection: 'malware',
          osList: allOsList,
          mode: ProtectionModes.off,
          syncPopupEnabled: true,
          popupEnabled: false,
        });

        expect(policy.windows.antivirus_registration).toEqual({
          mode: AntivirusRegistrationModes.sync,
          enabled: true,
        });
      });

      it('keeps a below-license malware off payload byte-equal to the React fixture', () => {
        const policy = policyFactory();
        const expected = cloneDeep(policy);
        expected.windows.malware.mode = ProtectionModes.off;
        expected.mac.malware.mode = ProtectionModes.off;
        expected.linux.malware.mode = ProtectionModes.off;

        setProtectionModeAndPopup({
          policy,
          protection: 'malware',
          osList: allOsList,
          mode: ProtectionModes.off,
          syncPopupEnabled: false,
          popupEnabled: false,
        });

        expect(policy).toEqual(expected);
      });
    });
  });
});

// This constant makes sure that if the type `PolicyConfig` is ever modified,
// the logic for disabling protections is also modified due to type check.
const eventsOnlyPolicy = (): PolicyConfig => ({
  global_manifest_version: 'latest',
  global_telemetry_enabled: false,
  meta: {
    license: '',
    cloud: false,
    license_uuid: '',
    cluster_name: '',
    cluster_uuid: '',
    serverless: false,
    billable: false,
  },
  windows: {
    events: {
      credential_access: true,
      dll_and_driver_load: true,
      dns: true,
      file: true,
      network: true,
      process: true,
      registry: true,
      security: true,
    },
    malware: { mode: ProtectionModes.off, blocklist: false, on_write_scan: false },
    ransomware: { mode: ProtectionModes.off, supported: true },
    memory_protection: { mode: ProtectionModes.off, supported: true },
    behavior_protection: { mode: ProtectionModes.off, supported: true, reputation_service: false },
    device_control: { enabled: false, usb_storage: 'audit' },
    popup: {
      malware: { message: '', enabled: false },
      ransomware: { message: '', enabled: false },
      memory_protection: { message: '', enabled: false },
      behavior_protection: { message: '', enabled: false },
      device_control: { message: '', enabled: false },
    },
    logging: { file: 'info' },
    antivirus_registration: { enabled: false, mode: AntivirusRegistrationModes.disabled },
    attack_surface_reduction: { credential_hardening: { enabled: false } },
  },
  mac: {
    events: { dns: true, process: true, file: true, network: true, security: true },
    malware: { mode: ProtectionModes.off, blocklist: false, on_write_scan: false },
    behavior_protection: { mode: ProtectionModes.off, supported: true, reputation_service: false },
    memory_protection: { mode: ProtectionModes.off, supported: true },
    ransomware: { mode: ProtectionModes.off, supported: true },
    device_control: { enabled: false, usb_storage: 'audit' },
    popup: {
      malware: { message: '', enabled: false },
      ransomware: { message: '', enabled: false },
      behavior_protection: { message: '', enabled: false },
      memory_protection: { message: '', enabled: false },
      device_control: { message: '', enabled: false },
    },
    logging: { file: 'info' },
    advanced: {
      capture_env_vars: 'DYLD_INSERT_LIBRARIES,DYLD_FRAMEWORK_PATH,DYLD_LIBRARY_PATH,LD_PRELOAD',
    },
  },
  linux: {
    events: {
      dns: true,
      file: true,
      process: true,
      network: true,
      session_data: false,
      tty_io: false,
    },
    malware: { mode: ProtectionModes.off, blocklist: false, on_write_scan: false },
    behavior_protection: { mode: ProtectionModes.off, supported: true, reputation_service: false },
    memory_protection: { mode: ProtectionModes.off, supported: true },
    popup: {
      malware: { message: '', enabled: false },
      behavior_protection: { message: '', enabled: false },
      memory_protection: { message: '', enabled: false },
    },
    logging: { file: 'info' },
    advanced: {
      capture_env_vars: 'LD_PRELOAD,LD_LIBRARY_PATH',
    },
  },
});
