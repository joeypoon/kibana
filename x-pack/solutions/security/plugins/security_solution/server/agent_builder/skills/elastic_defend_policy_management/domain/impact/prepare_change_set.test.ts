/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import * as policyConfigHelpers from '../../../../../../common/endpoint/models/policy_config_helpers';
import {
  AntivirusRegistrationModes,
  DeviceControlAccessLevel,
  ProtectionModes,
} from '../../../../../../common/endpoint/types';
import { MAX_NESTING_DEPTH, MAX_SERIALIZED_BYTES } from './parameter_bounds';
import { prepareChangeSet } from './prepare_change_set';
import {
  POLICY_CHANGE_BOUNDS_MESSAGE,
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  POLICY_CHANGE_SCHEMA_MESSAGE,
  PolicyChangePreparationError,
  invalidSetFieldValueMessage,
} from './policy_change_operation';

const rawRequest = (changes: unknown, idOrName = 'policy-1'): unknown => ({
  idOrName,
  changes,
});

const nestValue = (extraLevels: number): unknown => {
  let value: unknown = 'leaf';
  for (let index = 0; index < extraLevels; index++) {
    value = { n: value };
  }
  return rawRequest([{ op: 'set_field', path: 'windows.malware.mode', value }]);
};

describe('prepareChangeSet', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('rejects oversized and unparseable raw input before registry or helper work', () => {
    const helperSpy = jest.spyOn(policyConfigHelpers, 'setDeviceControlSwitch');
    const policy = policyFactory();
    const before = structuredClone(policy);

    const tooDeep = nestValue(MAX_NESTING_DEPTH);
    try {
      prepareChangeSet(tooDeep, policy);
      throw new Error('expected depth bounds to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyChangePreparationError);
      expect((error as PolicyChangePreparationError).code).toBe(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input
      );
      expect((error as PolicyChangePreparationError).message).toBe(POLICY_CHANGE_BOUNDS_MESSAGE);
    }

    try {
      prepareChangeSet({ idOrName: 'a'.repeat(MAX_SERIALIZED_BYTES), changes: [] }, policy);
      throw new Error('expected byte bounds to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyChangePreparationError);
      expect((error as PolicyChangePreparationError).code).toBe(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input
      );
    }

    try {
      prepareChangeSet({ idOrName: 'policy-1', changes: [{ op: 'set_field' }] }, policy);
      throw new Error('expected schema parse to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyChangePreparationError);
      expect((error as PolicyChangePreparationError).code).toBe(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input
      );
      expect((error as PolicyChangePreparationError).message).toBe(POLICY_CHANGE_SCHEMA_MESSAGE);
    }

    expect(helperSpy).not.toHaveBeenCalled();
    expect(policy).toEqual(before);
  });

  it('accepts a bounded raw request and does not mutate the current config', () => {
    const policy = policyFactory();
    const before = structuredClone(policy);

    const prepared = prepareChangeSet(
      rawRequest([{ op: 'set_protection_enabled', protection: 'malware', enabled: false }]),
      policy
    );

    expect(policy).toEqual(before);
    expect(prepared.operations).toEqual([
      { op: 'set_protection_enabled', protection: 'malware', enabled: false },
    ]);
    expect(prepared.proposedConfig.windows.malware.mode).toBe(ProtectionModes.off);
    expect(prepared.explicitChanges.length).toBeGreaterThan(0);
  });

  it('rejects invalid Boolean set_field values with invalid_input before dispatch', () => {
    const helperSpy = jest.spyOn(policyConfigHelpers, 'setDeviceControlSwitch');
    const policy = policyFactory();
    const before = structuredClone(policy);

    const invalidCases = [
      { path: 'linux.events.process', value: 'garbage' },
      { path: 'windows.device_control.enabled', value: 0 },
      { path: 'windows.device_control.enabled', value: 'false' },
    ] as const;

    for (const { path, value } of invalidCases) {
      try {
        prepareChangeSet(rawRequest([{ op: 'set_field', path, value }]), policy);
        throw new Error(`expected invalid set_field to fail for ${path}`);
      } catch (error) {
        expect(error).toBeInstanceOf(PolicyChangePreparationError);
        expect((error as PolicyChangePreparationError).code).toBe(
          POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input
        );
        expect((error as PolicyChangePreparationError).message).toBe(
          invalidSetFieldValueMessage(path)
        );
      }
    }

    expect(helperSpy).not.toHaveBeenCalled();
    expect(policy).toEqual(before);
  });

  it('rejects invalid device-control enum set_field values with invalid_input before dispatch', () => {
    const helperSpy = jest.spyOn(policyConfigHelpers, 'setDeviceControlUsbStorage');
    const policy = policyFactory();
    const before = structuredClone(policy);
    const path = 'windows.device_control.usb_storage';

    try {
      prepareChangeSet(rawRequest([{ op: 'set_field', path, value: 'garbage' }]), policy);
      throw new Error('expected invalid enum set_field to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyChangePreparationError);
      expect((error as PolicyChangePreparationError).code).toBe(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input
      );
      expect((error as PolicyChangePreparationError).message).toBe(
        invalidSetFieldValueMessage(path)
      );
    }

    expect(helperSpy).not.toHaveBeenCalled();
    expect(policy).toEqual(before);
  });

  it('accepts valid Tier 1 Boolean and enum set_field values', () => {
    const prepared = prepareChangeSet(
      rawRequest([
        { op: 'set_field', path: 'linux.events.process', value: false },
        {
          op: 'set_field',
          path: 'windows.device_control.usb_storage',
          value: DeviceControlAccessLevel.read_only,
        },
        { op: 'set_field', path: 'windows.malware.mode', value: ProtectionModes.prevent },
        {
          op: 'set_field',
          path: 'windows.antivirus_registration.mode',
          value: AntivirusRegistrationModes.disabled,
        },
      ]),
      policyFactory()
    );

    expect(prepared.explicitChanges.length).toBeGreaterThan(0);
  });

  it('classifies antivirus enabled only as a side effect after normalize', () => {
    const malwareOff = prepareChangeSet(
      rawRequest([{ op: 'set_protection_enabled', protection: 'malware', enabled: false }]),
      policyFactory()
    );

    expect(malwareOff.explicitChanges.map((change) => change.path)).not.toContain(
      'windows.antivirus_registration.enabled'
    );
    expect(malwareOff.sideEffects).toEqual([
      expect.objectContaining({
        path: 'windows.antivirus_registration.enabled',
        from: true,
        to: false,
        reason: 'derived_field_update',
      }),
    ]);
    expect(
      malwareOff.normalizedDiff.some(
        (entry) => entry.path === 'windows.antivirus_registration.enabled'
      )
    ).toBe(true);

    const ransomwareOff = prepareChangeSet(
      rawRequest([{ op: 'set_protection_enabled', protection: 'ransomware', enabled: false }]),
      policyFactory()
    );
    expect(ransomwareOff.sideEffects).toEqual([]);

    const avMode = prepareChangeSet(
      rawRequest([
        {
          op: 'set_field',
          path: 'windows.antivirus_registration.mode',
          value: AntivirusRegistrationModes.disabled,
        },
      ]),
      policyFactory()
    );
    expect(avMode.explicitChanges.map((change) => change.path)).toEqual([
      'windows.antivirus_registration.mode',
    ]);
    expect(avMode.sideEffects).toEqual([
      expect.objectContaining({
        path: 'windows.antivirus_registration.enabled',
        from: true,
        to: false,
        reason: 'derived_field_update',
      }),
    ]);
  });
});
