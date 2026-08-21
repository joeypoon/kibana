/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { set } from '@kbn/safer-lodash-set';
import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import * as policyConfigHelpers from '../../../../../../common/endpoint/models/policy_config_helpers';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { DeviceControlAccessLevel, ProtectionModes } from '../../../../../../common/endpoint/types';
import { expandChangeSet } from './expand_change_set';
import type { ExplicitPolicyChange } from './policy_change_operation';
import {
  DEVICE_CONTROL_MISSING_POPUP_MESSAGE,
  DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE,
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  PolicyChangePreparationError,
  nonWritablePathMessage,
  unknownCurrentValueMessage,
} from './policy_change_operation';

const pathsOf = (changes: readonly ExplicitPolicyChange[]): string[] =>
  changes.map((change) => change.path);

const changeAt = (
  changes: readonly ExplicitPolicyChange[],
  path: string
): ExplicitPolicyChange | undefined => changes.find((change) => change.path === path);

const requirePresent = <T>(value: T | undefined, label: string): T => {
  if (value === undefined) {
    throw new Error(`expected ${label}`);
  }
  return value;
};

const expectPreparationError = (
  run: () => unknown,
  code: (typeof POLICY_CHANGE_PREPARATION_ERROR_CODE)[keyof typeof POLICY_CHANGE_PREPARATION_ERROR_CODE],
  message: string
): PolicyChangePreparationError => {
  try {
    run();
    throw new Error('expected preparation to fail');
  } catch (error) {
    expect(error).toBeInstanceOf(PolicyChangePreparationError);
    const preparationError = error as PolicyChangePreparationError;
    expect(preparationError.code).toBe(code);
    expect(preparationError.message).toBe(message);
    return preparationError;
  }
};

const deviceOffPaths = [
  'windows.device_control.enabled',
  'windows.device_control.usb_storage',
  'windows.popup.device_control.enabled',
  'mac.device_control.enabled',
  'mac.device_control.usb_storage',
  'mac.popup.device_control.enabled',
] as const;

describe('expandChangeSet', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('dispatches protection enabled across the card OS lists', () => {
    const ransomware = expandChangeSet(
      [{ op: 'set_protection_enabled', protection: 'ransomware', enabled: false }],
      policyFactory()
    );
    expect(pathsOf(ransomware.explicitChanges)).toEqual(
      expect.arrayContaining(['windows.ransomware.mode', 'windows.popup.ransomware.enabled'])
    );
    expect(pathsOf(ransomware.explicitChanges)).not.toEqual(
      expect.arrayContaining(['mac.ransomware.mode', 'linux.ransomware.mode'])
    );

    const malware = expandChangeSet(
      [{ op: 'set_protection_enabled', protection: 'malware', enabled: false }],
      policyFactory()
    );
    expect(changeAt(malware.explicitChanges, 'linux.malware.mode')?.to).toBe(ProtectionModes.off);
    expect(changeAt(malware.explicitChanges, 'linux.malware.blocklist')?.to).toBe(false);
    expect(changeAt(malware.explicitChanges, 'linux.malware.on_write_scan')?.to).toBe(false);
    expect(changeAt(malware.explicitChanges, 'windows.popup.malware.enabled')?.to).toBe(false);
    expect(pathsOf(malware.explicitChanges)).not.toContain(
      'windows.behavior_protection.reputation_service'
    );

    const behaviorPolicy = policyFactory();
    behaviorPolicy.windows.behavior_protection.reputation_service = true;
    behaviorPolicy.mac.behavior_protection.reputation_service = true;
    behaviorPolicy.linux.behavior_protection.reputation_service = true;
    const behavior = expandChangeSet(
      [{ op: 'set_protection_enabled', protection: 'behavior_protection', enabled: false }],
      behaviorPolicy
    );
    expect(
      changeAt(behavior.explicitChanges, 'linux.behavior_protection.reputation_service')?.to
    ).toBe(false);
  });

  it('dispatches protection level without malware or reputation siblings', () => {
    const prepared = expandChangeSet(
      [{ op: 'set_protection_level', protection: 'malware', mode: ProtectionModes.detect }],
      policyFactory()
    );

    expect(changeAt(prepared.explicitChanges, 'windows.malware.mode')?.to).toBe(
      ProtectionModes.detect
    );
    expect(changeAt(prepared.explicitChanges, 'windows.popup.malware.enabled')?.to).toBe(false);
    expect(pathsOf(prepared.explicitChanges)).not.toEqual(
      expect.arrayContaining([
        'windows.malware.blocklist',
        'windows.malware.on_write_scan',
        'windows.behavior_protection.reputation_service',
      ])
    );
  });

  it('dispatches ordinary writable leaves without card inference', () => {
    const prepared = expandChangeSet(
      [{ op: 'set_field', path: 'mac.ransomware.mode', value: ProtectionModes.prevent }],
      policyFactory()
    );

    expect(prepared.explicitChanges).toEqual([
      {
        path: 'mac.ransomware.mode',
        from: ProtectionModes.off,
        to: ProtectionModes.prevent,
        origin: { operationIndex: 0, op: 'set_field', kind: 'direct' },
      },
    ]);
    expect(prepared.proposedConfig.windows.ransomware.mode).toBe(ProtectionModes.prevent);
  });

  it('forwards raw device-switch values unchanged', () => {
    const switchSpy = jest.spyOn(policyConfigHelpers, 'setDeviceControlSwitch');
    const rawValues: unknown[] = [false, true, 'false', 'true', 0, 1, '', null, [], {}];

    for (const value of rawValues) {
      switchSpy.mockClear();
      const policy = policyFactory();
      if (value !== false) {
        policyConfigHelpers.setDeviceControlSwitch(policy, false);
        switchSpy.mockClear();
      }

      expandChangeSet([{ op: 'set_field', path: 'windows.device_control.enabled', value }], policy);

      expect(switchSpy).toHaveBeenCalledTimes(1);
      expect(switchSpy.mock.calls[0]?.[1]).toBe(value);
    }
  });

  it('expands off and on siblings once per Boolean branch', () => {
    const off = expandChangeSet(
      [{ op: 'set_field', path: 'windows.device_control.enabled', value: false }],
      policyFactory()
    );

    expect(changeAt(off.explicitChanges, 'windows.device_control.enabled')?.to).toBe(false);
    expect(changeAt(off.explicitChanges, 'windows.device_control.usb_storage')?.to).toBe(
      DeviceControlAccessLevel.audit
    );
    expect(changeAt(off.explicitChanges, 'mac.popup.device_control.enabled')?.to).toBe(false);
    expect(pathsOf(off.explicitChanges)).toEqual(expect.arrayContaining([...deviceOffPaths]));

    const onPolicy = policyFactory();
    policyConfigHelpers.setDeviceControlSwitch(onPolicy, false);
    const on = expandChangeSet(
      [{ op: 'set_field', path: 'windows.device_control.enabled', value: true }],
      onPolicy
    );

    expect(changeAt(on.explicitChanges, 'windows.device_control.enabled')?.to).toBe(true);
    expect(changeAt(on.explicitChanges, 'windows.device_control.usb_storage')?.to).toBe(
      DeviceControlAccessLevel.deny_all
    );
    expect(changeAt(on.explicitChanges, 'mac.popup.device_control.enabled')?.to).toBe(true);
  });

  it('forwards raw values for every coupled family and one ordinary leaf', () => {
    const usbSpy = jest.spyOn(policyConfigHelpers, 'setDeviceControlUsbStorage');
    const popupSpy = jest.spyOn(policyConfigHelpers, 'setPopupEnabled');
    const malwareSpy = jest.spyOn(policyConfigHelpers, 'setMalwareBoolean');
    const reputationSpy = jest.spyOn(policyConfigHelpers, 'setBehaviorReputationService');

    const usbValue = 0;
    expandChangeSet(
      [{ op: 'set_field', path: 'windows.device_control.usb_storage', value: usbValue }],
      policyFactory()
    );
    expect(usbSpy.mock.calls[0]?.[1]).toBe(usbValue);

    const sessionPolicy = policyFactory();
    sessionPolicy.linux.events.session_data = true;
    sessionPolicy.linux.events.tty_io = true;
    const session = expandChangeSet(
      [{ op: 'set_field', path: 'linux.events.session_data', value: 'false' }],
      sessionPolicy
    );
    expect(changeAt(session.explicitChanges, 'linux.events.session_data')?.to).toBe('false');
    expect(pathsOf(session.explicitChanges)).not.toContain('linux.events.tty_io');

    const forced = expandChangeSet(
      [{ op: 'set_field', path: 'linux.events.session_data', value: false }],
      sessionPolicy
    );
    expect(changeAt(forced.explicitChanges, 'linux.events.tty_io')?.to).toBe(false);

    expandChangeSet(
      [{ op: 'set_field', path: 'windows.popup.malware.enabled', value: 1 }],
      policyFactory()
    );
    expect(popupSpy.mock.calls[0]?.[3]).toBe(1);

    expandChangeSet(
      [{ op: 'set_field', path: 'mac.malware.blocklist', value: 'yes' }],
      policyFactory()
    );
    expect(malwareSpy.mock.calls[0]?.[2]).toBe('yes');

    expandChangeSet(
      [{ op: 'set_field', path: 'linux.behavior_protection.reputation_service', value: [] }],
      policyFactory()
    );
    expect(reputationSpy.mock.calls[0]?.[1]).toEqual([]);

    const leaf = expandChangeSet(
      [{ op: 'set_field', path: 'windows.malware.mode', value: 1 }],
      policyFactory()
    );
    expect(changeAt(leaf.explicitChanges, 'windows.malware.mode')?.to).toBe(1);
  });

  it('expands usb_storage deny_all/else popup siblings when popups exist', () => {
    const denyPolicy = policyFactory();
    requirePresent(denyPolicy.windows.popup.device_control, 'windows popup').enabled = false;
    requirePresent(denyPolicy.mac.popup.device_control, 'mac popup').enabled = false;
    requirePresent(denyPolicy.windows.device_control, 'windows device').usb_storage =
      DeviceControlAccessLevel.audit;
    requirePresent(denyPolicy.mac.device_control, 'mac device').usb_storage =
      DeviceControlAccessLevel.audit;

    const denyAll = expandChangeSet(
      [{ op: 'set_field', path: 'windows.device_control.usb_storage', value: 'deny_all' }],
      denyPolicy
    );
    expect(changeAt(denyAll.explicitChanges, 'windows.popup.device_control.enabled')?.to).toBe(
      true
    );
    expect(changeAt(denyAll.explicitChanges, 'mac.popup.device_control.enabled')?.to).toBe(true);

    const elseValues: unknown[] = ['audit', 'DENY_ALL', 'block', true, false, null, {}];
    for (const value of elseValues) {
      const prepared = expandChangeSet(
        [{ op: 'set_field', path: 'mac.device_control.usb_storage', value }],
        policyFactory()
      );
      expect(changeAt(prepared.explicitChanges, 'windows.device_control.usb_storage')?.to).toBe(
        value
      );
      expect(changeAt(prepared.explicitChanges, 'windows.popup.device_control.enabled')?.to).toBe(
        false
      );
      expect(changeAt(prepared.explicitChanges, 'mac.popup.device_control.enabled')?.to).toBe(
        false
      );
    }
  });

  it('refuses both device popup-enabled paths for any value', () => {
    const switchSpy = jest.spyOn(policyConfigHelpers, 'setDeviceControlSwitch');

    for (const path of [
      'windows.popup.device_control.enabled',
      'mac.popup.device_control.enabled',
    ]) {
      for (const value of [true, false, 'x']) {
        const policy = policyFactory();
        const before = structuredClone(policy);
        expectPreparationError(
          () => expandChangeSet([{ op: 'set_field', path, value }], policy),
          POLICY_CHANGE_PREPARATION_ERROR_CODE.unsupported_operation,
          DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE
        );
        expect(policy).toEqual(before);
        expect(switchSpy).not.toHaveBeenCalled();
      }
    }
  });

  it('refuses device-control switch when either OS popup object is missing', () => {
    const switchSpy = jest.spyOn(policyConfigHelpers, 'setDeviceControlSwitch');
    const fixtures: Array<() => PolicyConfig> = [
      () => {
        const policy = policyFactory();
        delete policy.windows.popup.device_control;
        return policy;
      },
      () => {
        const policy = policyFactory();
        delete policy.mac.popup.device_control;
        return policy;
      },
    ];

    for (const createPolicy of fixtures) {
      for (const path of ['windows.device_control.enabled', 'mac.device_control.enabled']) {
        for (const value of [false, true]) {
          const policy = createPolicy();
          const before = structuredClone(policy);
          expectPreparationError(
            () => expandChangeSet([{ op: 'set_field', path, value }], policy),
            POLICY_CHANGE_PREPARATION_ERROR_CODE.unsupported_operation,
            DEVICE_CONTROL_MISSING_POPUP_MESSAGE
          );
          expect(policy).toEqual(before);
          expect(switchSpy).not.toHaveBeenCalled();
        }
      }

      const missing = createPolicy();
      const usb = expandChangeSet(
        [{ op: 'set_field', path: 'windows.device_control.usb_storage', value: 'audit' }],
        missing
      );
      expect(changeAt(usb.explicitChanges, 'windows.device_control.usb_storage')?.to).toBe('audit');
      expect(pathsOf(usb.explicitChanges)).not.toContain('windows.popup.device_control.message');
    }
  });

  it('keeps an existing device popup message out of expanded changes', () => {
    const policy = policyFactory();
    requirePresent(policy.windows.popup.device_control, 'windows popup').message = 'keep-windows';
    requirePresent(policy.mac.popup.device_control, 'mac popup').message = 'keep-mac';

    const prepared = expandChangeSet(
      [{ op: 'set_field', path: 'windows.device_control.enabled', value: false }],
      policy
    );

    expect(pathsOf(prepared.explicitChanges)).not.toEqual(
      expect.arrayContaining([
        'windows.popup.device_control.message',
        'mac.popup.device_control.message',
      ])
    );
    expect(prepared.proposedConfig.windows.popup.device_control?.message).toBe('keep-windows');
    expect(prepared.proposedConfig.mac.popup.device_control?.message).toBe('keep-mac');
  });

  it('lets later operations own origin and omits no-ops', () => {
    const laterWins = expandChangeSet(
      [
        { op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.detect },
        { op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.off },
      ],
      policyFactory()
    );
    expect(laterWins.explicitChanges).toEqual([
      {
        path: 'windows.malware.mode',
        from: ProtectionModes.prevent,
        to: ProtectionModes.off,
        origin: { operationIndex: 1, op: 'set_field', kind: 'direct' },
      },
    ]);

    const reverted = expandChangeSet(
      [
        { op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.detect },
        { op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.prevent },
      ],
      policyFactory()
    );
    expect(reverted.explicitChanges).toEqual([]);

    const noOp = expandChangeSet(
      [{ op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.prevent }],
      policyFactory()
    );
    expect(noOp.explicitChanges).toEqual([]);
  });

  it('refuses unknown, excluded, derived, and other non-writable direct paths', () => {
    const unknownPolicy = policyFactory();
    const unknownBefore = structuredClone(unknownPolicy);
    expectPreparationError(
      () =>
        expandChangeSet([{ op: 'set_field', path: 'not.a.real.path', value: true }], unknownPolicy),
      POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
      nonWritablePathMessage('not.a.real.path')
    );
    expect(unknownPolicy).toEqual(unknownBefore);

    expectPreparationError(
      () =>
        expandChangeSet(
          [{ op: 'set_field', path: 'windows.popup.malware.message', value: 'hi' }],
          policyFactory()
        ),
      POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
      nonWritablePathMessage('windows.popup.malware.message')
    );
    expectPreparationError(
      () =>
        expandChangeSet(
          [{ op: 'set_field', path: 'windows.antivirus_registration.enabled', value: false }],
          policyFactory()
        ),
      POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
      nonWritablePathMessage('windows.antivirus_registration.enabled')
    );
    expectPreparationError(
      () =>
        expandChangeSet(
          [{ op: 'set_field', path: 'windows.logging.file', value: 'debug' }],
          policyFactory()
        ),
      POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
      nonWritablePathMessage('windows.logging.file')
    );
  });

  it('fails the request when expansion produces a non-writable path', () => {
    jest.spyOn(policyConfigHelpers, 'setPopupEnabled').mockImplementation((policy) => {
      set(policy, 'windows.popup.malware.message', 'injected');
      return policy;
    });

    expectPreparationError(
      () =>
        expandChangeSet(
          [{ op: 'set_field', path: 'windows.popup.malware.enabled', value: false }],
          policyFactory()
        ),
      POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
      nonWritablePathMessage('windows.popup.malware.message')
    );
  });

  it('refuses set_field when the live current value is unknown', () => {
    const policy = policyFactory();
    delete (policy as unknown as { global_manifest_version?: unknown }).global_manifest_version;
    const before = structuredClone(policy);

    expectPreparationError(
      () =>
        expandChangeSet(
          [{ op: 'set_field', path: 'global_manifest_version', value: '2024-01-01' }],
          policy
        ),
      POLICY_CHANGE_PREPARATION_ERROR_CODE.unknown_current_value,
      unknownCurrentValueMessage('global_manifest_version')
    );
    expect(policy).toEqual(before);
  });

  it('marks protection mode rows as direct and coupled siblings as coupled', () => {
    const prepared = expandChangeSet(
      [{ op: 'set_protection_enabled', protection: 'malware', enabled: false }],
      policyFactory()
    );

    expect(changeAt(prepared.explicitChanges, 'windows.malware.mode')?.origin).toEqual({
      operationIndex: 0,
      op: 'set_protection_enabled',
      kind: 'direct',
    });
    expect(changeAt(prepared.explicitChanges, 'windows.malware.blocklist')?.origin).toEqual({
      operationIndex: 0,
      op: 'set_protection_enabled',
      kind: 'coupled',
    });
    expect(changeAt(prepared.explicitChanges, 'windows.popup.malware.enabled')?.origin).toEqual({
      operationIndex: 0,
      op: 'set_protection_enabled',
      kind: 'coupled',
    });
  });

  it('marks protection level mode rows direct across the card OS list', () => {
    const prepared = expandChangeSet(
      [{ op: 'set_protection_level', protection: 'ransomware', mode: ProtectionModes.detect }],
      policyFactory()
    );

    expect(pathsOf(prepared.explicitChanges)).toContain('windows.ransomware.mode');
    expect(changeAt(prepared.explicitChanges, 'windows.ransomware.mode')?.origin).toEqual({
      operationIndex: 0,
      op: 'set_protection_level',
      kind: 'direct',
    });
    expect(changeAt(prepared.explicitChanges, 'windows.popup.ransomware.enabled')?.origin).toEqual({
      operationIndex: 0,
      op: 'set_protection_level',
      kind: 'coupled',
    });
  });

  it('marks a set_field requested path direct and its cross-OS siblings coupled', () => {
    const prepared = expandChangeSet(
      [{ op: 'set_field', path: 'windows.malware.blocklist', value: false }],
      policyFactory()
    );

    expect(changeAt(prepared.explicitChanges, 'windows.malware.blocklist')?.origin).toEqual({
      operationIndex: 0,
      op: 'set_field',
      kind: 'direct',
    });
    expect(changeAt(prepared.explicitChanges, 'mac.malware.blocklist')?.origin).toEqual({
      operationIndex: 0,
      op: 'set_field',
      kind: 'coupled',
    });
    expect(changeAt(prepared.explicitChanges, 'linux.malware.blocklist')?.origin).toEqual({
      operationIndex: 0,
      op: 'set_field',
      kind: 'coupled',
    });
  });
});
