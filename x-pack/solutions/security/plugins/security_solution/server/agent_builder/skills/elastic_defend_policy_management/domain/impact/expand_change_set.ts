/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { set } from '@kbn/safer-lodash-set';
import { get } from 'lodash';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../../common/endpoint/types';
import type { PolicyCouplingProtection } from '../../../../../../common/endpoint/models/policy_config_helpers';
import * as policyConfigHelpers from '../../../../../../common/endpoint/models/policy_config_helpers';
import * as fieldRegistry from '../field_registry';
import type {
  ExplicitPolicyChange,
  PolicyChangeOperation,
  PreparedPolicyChangeSet,
} from './policy_change_operation';
import {
  DEVICE_CONTROL_MISSING_POPUP_MESSAGE,
  DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE,
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  PolicyChangePreparationError,
  nonWritablePathMessage,
  unknownCurrentValueMessage,
} from './policy_change_operation';

const ALL_CARD_OS = [
  PolicyOperatingSystem.windows,
  PolicyOperatingSystem.mac,
  PolicyOperatingSystem.linux,
] as const;

const CARD_OS_LIST: Readonly<Record<PolicyCouplingProtection, readonly PolicyOperatingSystem[]>> = {
  malware: ALL_CARD_OS,
  ransomware: [PolicyOperatingSystem.windows],
  memory_protection: ALL_CARD_OS,
  behavior_protection: ALL_CARD_OS,
};

const DEVICE_CONTROL_ENABLED_PATHS = new Set([
  'windows.device_control.enabled',
  'mac.device_control.enabled',
]);

const DEVICE_CONTROL_USB_PATHS = new Set([
  'windows.device_control.usb_storage',
  'mac.device_control.usb_storage',
]);

const DEVICE_POPUP_ENABLED_PATHS = new Set([
  'windows.popup.device_control.enabled',
  'mac.popup.device_control.enabled',
]);

const MALWARE_BOOLEAN_FIELDS = new Set(['blocklist', 'on_write_scan']);

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && Object.prototype.toString.call(value) === '[object Object]';

const childPath = (path: string, key: string): string => (path === '' ? key : `${path}.${key}`);

const collectLeafChanges = (
  fromValue: unknown,
  toValue: unknown,
  path: string
): Array<{ path: string; from: unknown; to: unknown }> => {
  if (Object.is(fromValue, toValue)) {
    return [];
  }

  if (isPlainObject(fromValue) && isPlainObject(toValue)) {
    const keys = new Set([...Object.keys(fromValue), ...Object.keys(toValue)]);
    return [...keys].flatMap((key) =>
      collectLeafChanges(
        Object.hasOwn(fromValue, key) ? fromValue[key] : undefined,
        Object.hasOwn(toValue, key) ? toValue[key] : undefined,
        childPath(path, key)
      )
    );
  }

  if (fromValue === undefined && isPlainObject(toValue)) {
    return Object.keys(toValue).flatMap((key) =>
      collectLeafChanges(undefined, toValue[key], childPath(path, key))
    );
  }

  if (toValue === undefined && isPlainObject(fromValue)) {
    return Object.keys(fromValue).flatMap((key) =>
      collectLeafChanges(fromValue[key], undefined, childPath(path, key))
    );
  }

  return [{ path, from: fromValue, to: toValue }];
};

const hasDevicePopupObject = (policy: PolicyConfig, os: 'windows' | 'mac'): boolean =>
  policy[os].popup.device_control != null;

const assertWritablePath = (path: string): void => {
  const entry = fieldRegistry.getFieldRegistryEntry(path);
  if (entry === undefined || !fieldRegistry.isWritablePath(entry)) {
    throw new PolicyChangePreparationError(
      POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
      nonWritablePathMessage(path)
    );
  }
};

const assertDeviceControlPopupsPresent = (policy: PolicyConfig): void => {
  if (!hasDevicePopupObject(policy, 'windows') || !hasDevicePopupObject(policy, 'mac')) {
    throw new PolicyChangePreparationError(
      POLICY_CHANGE_PREPARATION_ERROR_CODE.unsupported_operation,
      DEVICE_CONTROL_MISSING_POPUP_MESSAGE
    );
  }
};

const validateDirectSetField = (path: string, policy: PolicyConfig): void => {
  if (DEVICE_POPUP_ENABLED_PATHS.has(path)) {
    throw new PolicyChangePreparationError(
      POLICY_CHANGE_PREPARATION_ERROR_CODE.unsupported_operation,
      DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE
    );
  }

  if (DEVICE_CONTROL_ENABLED_PATHS.has(path)) {
    assertDeviceControlPopupsPresent(policy);
  }

  assertWritablePath(path);

  if (get(policy, path) === undefined) {
    throw new PolicyChangePreparationError(
      POLICY_CHANGE_PREPARATION_ERROR_CODE.unknown_current_value,
      unknownCurrentValueMessage(path)
    );
  }
};

const dispatchProtectionEnabled = (
  policy: PolicyConfig,
  protection: PolicyCouplingProtection,
  enabled: boolean
): void => {
  const osList = CARD_OS_LIST[protection];
  policyConfigHelpers.setProtectionModeAndPopup({
    policy,
    protection,
    osList,
    mode: enabled ? ProtectionModes.prevent : ProtectionModes.off,
    syncPopupEnabled: true,
    popupEnabled: enabled,
  });

  if (protection === 'malware') {
    policyConfigHelpers.setMalwareBoolean(policy, 'blocklist', enabled, osList);
    policyConfigHelpers.setMalwareBoolean(policy, 'on_write_scan', enabled, osList);
  }

  if (protection === 'behavior_protection') {
    policyConfigHelpers.setBehaviorReputationService(policy, enabled);
  }
};

const dispatchProtectionLevel = (
  policy: PolicyConfig,
  protection: PolicyCouplingProtection,
  mode: ProtectionModes.detect | ProtectionModes.prevent
): void => {
  policyConfigHelpers.setProtectionModeAndPopup({
    policy,
    protection,
    osList: CARD_OS_LIST[protection],
    mode,
    syncPopupEnabled: true,
    popupEnabled: mode === ProtectionModes.prevent,
  });
};

const dispatchSetField = (policy: PolicyConfig, path: string, value: unknown): void => {
  if (DEVICE_CONTROL_ENABLED_PATHS.has(path)) {
    policyConfigHelpers.setDeviceControlSwitch(policy, value);
    return;
  }

  if (DEVICE_CONTROL_USB_PATHS.has(path)) {
    policyConfigHelpers.setDeviceControlUsbStorage(policy, value);
    return;
  }

  if (path === 'linux.events.session_data') {
    set(policy, path, value);
    policyConfigHelpers.constrainLinuxTtyIo(policy);
    return;
  }

  const segments = path.split('.');
  const [osSegment, section, field, suffix] = segments;

  if (
    segments.length === 4 &&
    osSegment !== undefined &&
    section === 'popup' &&
    field !== undefined &&
    suffix === 'enabled' &&
    field !== 'device_control' &&
    field in CARD_OS_LIST
  ) {
    const protection = field as PolicyCouplingProtection;
    policyConfigHelpers.setPopupEnabled(policy, protection, CARD_OS_LIST[protection], value);
    return;
  }

  if (
    segments.length === 3 &&
    osSegment !== undefined &&
    section === 'malware' &&
    field !== undefined &&
    MALWARE_BOOLEAN_FIELDS.has(field)
  ) {
    policyConfigHelpers.setMalwareBoolean(
      policy,
      field as 'blocklist' | 'on_write_scan',
      value,
      CARD_OS_LIST.malware
    );
    return;
  }

  if (
    segments.length === 3 &&
    section === 'behavior_protection' &&
    field === 'reputation_service'
  ) {
    policyConfigHelpers.setBehaviorReputationService(policy, value);
    return;
  }

  set(policy, path, value);
};

const dispatchOperation = (policy: PolicyConfig, operation: PolicyChangeOperation): void => {
  if (operation.op === 'set_protection_enabled') {
    dispatchProtectionEnabled(policy, operation.protection, operation.enabled);
    return;
  }

  if (operation.op === 'set_protection_level') {
    dispatchProtectionLevel(policy, operation.protection, operation.mode);
    return;
  }

  dispatchSetField(policy, operation.path, operation.value);
};

const originKind = (operation: PolicyChangeOperation, path: string): 'direct' | 'coupled' => {
  if (operation.op === 'set_field') {
    return operation.path === path ? 'direct' : 'coupled';
  }

  return CARD_OS_LIST[operation.protection].some(
    (os) => path === `${os}.${operation.protection}.mode`
  )
    ? 'direct'
    : 'coupled';
};

export const expandChangeSet = (
  operations: readonly PolicyChangeOperation[],
  currentConfig: PolicyConfig
): PreparedPolicyChangeSet => {
  for (const operation of operations) {
    if (operation.op === 'set_field') {
      validateDirectSetField(operation.path, currentConfig);
    }
  }

  const proposedConfig = structuredClone(currentConfig);
  const originByPath = new Map<string, ExplicitPolicyChange['origin']>();

  operations.forEach((operation, operationIndex) => {
    const before = structuredClone(proposedConfig);
    dispatchOperation(proposedConfig, operation);
    for (const change of collectLeafChanges(before, proposedConfig, '')) {
      originByPath.set(change.path, {
        operationIndex,
        op: operation.op,
        kind: originKind(operation, change.path),
      });
    }
  });

  const explicitChanges = collectLeafChanges(currentConfig, proposedConfig, '')
    .filter((change) => !Object.is(change.from, change.to))
    .map((change) => {
      const origin = originByPath.get(change.path);
      if (origin === undefined) {
        throw new PolicyChangePreparationError(
          POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
          nonWritablePathMessage(change.path)
        );
      }
      return {
        path: change.path,
        from: change.from,
        to: change.to,
        origin,
      };
    });

  for (const change of explicitChanges) {
    assertWritablePath(change.path);
  }

  return {
    operations,
    proposedConfig,
    explicitChanges,
  };
};
