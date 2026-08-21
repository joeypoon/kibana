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
import { getFieldRegistryEntry, isWritablePath } from '../field_registry';
import {
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  PolicyChangePreparationError,
  invalidSetFieldValueMessage,
} from './policy_change_operation';

const PROTECTION_MODE_SECTIONS = new Set([
  'malware',
  'ransomware',
  'memory_protection',
  'behavior_protection',
]);

const PROTECTION_MODE_VALUES = new Set<string>(Object.values(ProtectionModes));
const ANTIVIRUS_REGISTRATION_MODE_VALUES = new Set<string>(
  Object.values(AntivirusRegistrationModes)
);
const DEVICE_CONTROL_ACCESS_LEVEL_VALUES = new Set<string>(Object.values(DeviceControlAccessLevel));

const isProtectionModePath = (path: string): boolean => {
  const segments = path.split('.');
  return (
    segments.length === 3 &&
    segments[2] === 'mode' &&
    PROTECTION_MODE_SECTIONS.has(segments[1] ?? '')
  );
};

const isDeviceControlUsbStoragePath = (path: string): boolean => {
  const segments = path.split('.');
  return segments.length === 3 && segments[1] === 'device_control' && segments[2] === 'usb_storage';
};

const assertEnumValue = (path: string, value: unknown, allowed: ReadonlySet<string>): void => {
  if (typeof value !== 'string' || !allowed.has(value)) {
    throw new PolicyChangePreparationError(
      POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input,
      invalidSetFieldValueMessage(path)
    );
  }
};

export const validateSetFieldValue = (path: string, value: unknown): void => {
  const entry = getFieldRegistryEntry(path);
  if (entry === undefined || !isWritablePath(entry)) {
    return;
  }

  if (isProtectionModePath(path)) {
    assertEnumValue(path, value, PROTECTION_MODE_VALUES);
    return;
  }

  if (path === 'windows.antivirus_registration.mode') {
    assertEnumValue(path, value, ANTIVIRUS_REGISTRATION_MODE_VALUES);
    return;
  }

  if (isDeviceControlUsbStoragePath(path)) {
    assertEnumValue(path, value, DEVICE_CONTROL_ACCESS_LEVEL_VALUES);
    return;
  }

  if (entry.defaultValue === undefined) {
    return;
  }

  if (typeof value !== typeof entry.defaultValue) {
    throw new PolicyChangePreparationError(
      POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input,
      invalidSetFieldValueMessage(path)
    );
  }
};
