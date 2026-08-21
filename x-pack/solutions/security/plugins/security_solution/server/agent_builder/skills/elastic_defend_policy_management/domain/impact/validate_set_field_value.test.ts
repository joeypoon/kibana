/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  AntivirusRegistrationModes,
  DeviceControlAccessLevel,
  ProtectionModes,
} from '../../../../../../common/endpoint/types';
import {
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  PolicyChangePreparationError,
  invalidSetFieldValueMessage,
} from './policy_change_operation';
import { validateSetFieldValue } from './validate_set_field_value';

const expectInvalidInput = (path: string, value: unknown): void => {
  try {
    validateSetFieldValue(path, value);
    throw new Error(`expected set_field validation to fail for ${path}`);
  } catch (error) {
    expect(error).toBeInstanceOf(PolicyChangePreparationError);
    const preparationError = error as PolicyChangePreparationError;
    expect(preparationError.code).toBe(POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input);
    expect(preparationError.message).toBe(invalidSetFieldValueMessage(path));
  }
};

describe('validateSetFieldValue', () => {
  it('rejects invalid Boolean values for Boolean fields', () => {
    expectInvalidInput('linux.events.process', 'garbage');
    expectInvalidInput('windows.device_control.enabled', 0);
    expectInvalidInput('windows.device_control.enabled', 'false');
  });

  it('rejects invalid protection, antivirus-registration, and device-control enum values', () => {
    expectInvalidInput('windows.malware.mode', 'garbage');
    expectInvalidInput('windows.antivirus_registration.mode', 'garbage');
    expectInvalidInput('windows.device_control.usb_storage', 'garbage');
  });

  it('accepts valid runtime enum values', () => {
    validateSetFieldValue('windows.malware.mode', ProtectionModes.prevent);
    validateSetFieldValue(
      'windows.antivirus_registration.mode',
      AntivirusRegistrationModes.disabled
    );
    validateSetFieldValue('windows.device_control.usb_storage', DeviceControlAccessLevel.read_only);
  });

  it('accepts values matching the registered/default runtime shape', () => {
    validateSetFieldValue('linux.events.process', true);
    validateSetFieldValue('windows.device_control.enabled', false);
    validateSetFieldValue('global_manifest_version', '2024-01-01');
  });

  it('defers non-writable and unknown paths to path validation', () => {
    validateSetFieldValue('windows.logging.file', 'garbage');
    validateSetFieldValue('windows.antivirus_registration.enabled', false);
    validateSetFieldValue('not.a.real.path', 'garbage');
  });
});
