/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import moment from 'moment';
import {
  AntivirusRegistrationModes,
  DeviceControlAccessLevel,
  ProtectionModes,
} from '../../../../../../common/endpoint/types';
import {
  getPolicyProtectionsReference,
  POLICY_COUPLING_MALWARE_BOOLEAN_FIELDS,
  type PolicyCouplingMalwareBooleanField,
  type PolicyCouplingProtection,
} from '../../../../../../common/endpoint/models/policy_config_helpers';
import { getControlledArtifactCutoffDate } from '../../../../../../common/endpoint/utils/controlled_artifact_rollout';
import { describePathWritability, getFieldRegistryEntry } from '../field_registry';
import { PolicyChangeRejectedError } from './policy_operation_rejection';

export type SetFieldValueDomain =
  | { readonly type: 'enum'; readonly values: readonly string[] }
  | { readonly type: 'boolean' }
  | {
      readonly type: 'manifest_version';
      readonly keywords: readonly ['latest'];
      readonly earliest: string;
      readonly latest: string;
    }
  | { readonly type: 'string' }
  | { readonly type: 'number' };

const protectionForKeyPath = (path: string): PolicyCouplingProtection | undefined => {
  const [, ...remainder] = path.split('.');
  if (remainder.length === 0) return undefined;
  const keyPath = remainder.join('.');
  return getPolicyProtectionsReference().some(({ keyPath: reference }) => reference === keyPath)
    ? (keyPath.split('.')[0] as PolicyCouplingProtection)
    : undefined;
};

const protectionModeOf = (path: string): PolicyCouplingProtection | undefined => {
  if (!path.endsWith('.mode')) return undefined;
  const protection = protectionForKeyPath(path);
  return protection &&
    ['malware', 'ransomware', 'memory_protection', 'behavior_protection'].includes(protection)
    ? protection
    : undefined;
};

const popupProtectionOf = (path: string): PolicyCouplingProtection | undefined => {
  const parts = path.split('.');
  if (parts.length !== 4 || parts[1] !== 'popup' || parts[3] !== 'enabled') return undefined;
  const protection = parts[2];
  return protection &&
    ['malware', 'ransomware', 'memory_protection', 'behavior_protection'].includes(protection)
    ? (protection as PolicyCouplingProtection)
    : undefined;
};

const malwareBooleanFieldOf = (path: string): PolicyCouplingMalwareBooleanField | undefined => {
  const parts = path.split('.');
  const field = parts.length === 3 && parts[1] === 'malware' ? parts[2] : undefined;
  return POLICY_COUPLING_MALWARE_BOOLEAN_FIELDS.find((candidate) => candidate === field);
};

const deviceControlFieldOf = (path: string): 'enabled' | 'usb_storage' | undefined => {
  const parts = path.split('.');
  if (
    parts.length !== 3 ||
    !['windows', 'mac'].includes(parts[0] ?? '') ||
    parts[1] !== 'device_control'
  ) {
    return undefined;
  }
  return parts[2] === 'enabled' || parts[2] === 'usb_storage' ? parts[2] : undefined;
};

const PROTECTION_MODE_VALUES: readonly string[] = Object.values(ProtectionModes);
const ANTIVIRUS_REGISTRATION_MODE_VALUES: readonly string[] = Object.values(
  AntivirusRegistrationModes
);
const DEVICE_CONTROL_ACCESS_LEVEL_VALUES: readonly string[] =
  Object.values(DeviceControlAccessLevel);

export const getSetFieldValueDomain = (path: string): SetFieldValueDomain | undefined => {
  const writability = describePathWritability(path);
  if (!writability.writable) {
    return undefined;
  }

  if (protectionModeOf(path) !== undefined) {
    return { type: 'enum', values: PROTECTION_MODE_VALUES };
  }

  if (path === 'windows.antivirus_registration.mode') {
    return { type: 'enum', values: ANTIVIRUS_REGISTRATION_MODE_VALUES };
  }

  const deviceField = deviceControlFieldOf(path);
  if (deviceField === 'usb_storage') {
    return { type: 'enum', values: DEVICE_CONTROL_ACCESS_LEVEL_VALUES };
  }
  if (deviceField === 'enabled') {
    return { type: 'boolean' };
  }

  if (
    popupProtectionOf(path) !== undefined ||
    malwareBooleanFieldOf(path) !== undefined ||
    path.endsWith('.behavior_protection.reputation_service') ||
    path === 'linux.events.session_data' ||
    path === 'linux.events.tty_io'
  ) {
    return { type: 'boolean' };
  }

  if (path === 'global_manifest_version') {
    return {
      type: 'manifest_version',
      keywords: ['latest'],
      earliest: getControlledArtifactCutoffDate().format('YYYY-MM-DD'),
      latest: moment.utc().subtract(1, 'day').format('YYYY-MM-DD'),
    };
  }

  const entry = getFieldRegistryEntry(path);
  if (entry?.defaultValue !== undefined) {
    const valueType = typeof entry.defaultValue;
    if (valueType === 'boolean') {
      return { type: 'boolean' };
    }
    if (valueType === 'string') {
      return { type: 'string' };
    }
    if (valueType === 'number') {
      return { type: 'number' };
    }
  }

  return { type: 'string' };
};

const rejectedValue = (path: string): PolicyChangeRejectedError => {
  const acceptedValues = getSetFieldValueDomain(path);
  return new PolicyChangeRejectedError([
    {
      operationIndexes: [],
      path,
      reason: 'invalid_value',
      ...(acceptedValues !== undefined ? { acceptedValues } : {}),
    },
  ]);
};

export type ClassifiedSetFieldValue =
  | {
      readonly kind: 'protection_mode';
      readonly protection: PolicyCouplingProtection;
      readonly value: ProtectionModes;
    }
  | { readonly kind: 'antivirus_registration_mode'; readonly value: AntivirusRegistrationModes }
  | { readonly kind: 'device_control_enabled'; readonly value: boolean }
  | { readonly kind: 'device_control_usb_storage'; readonly value: DeviceControlAccessLevel }
  | {
      readonly kind: 'malware_boolean';
      readonly field: PolicyCouplingMalwareBooleanField;
      readonly value: boolean;
    }
  | { readonly kind: 'behavior_reputation_service'; readonly value: boolean }
  | {
      readonly kind: 'popup_enabled';
      readonly protection: PolicyCouplingProtection;
      readonly value: boolean;
    }
  | { readonly kind: 'linux_session_data'; readonly value: boolean }
  | { readonly kind: 'linux_tty_io'; readonly value: boolean }
  | { readonly kind: 'generic'; readonly value: unknown };

export const classifySetFieldValue = (path: string, value: unknown): ClassifiedSetFieldValue => {
  const domain = getSetFieldValueDomain(path);
  if (domain !== undefined) {
    if (path !== 'global_manifest_version') {
      if (domain.type === 'enum') {
        if (typeof value !== 'string' || !domain.values.includes(value)) {
          throw rejectedValue(path);
        }
      } else if (domain.type === 'boolean') {
        if (typeof value !== 'boolean') {
          throw rejectedValue(path);
        }
      } else if (domain.type === 'string') {
        if (typeof value !== 'string') {
          throw rejectedValue(path);
        }
      } else if (domain.type === 'number') {
        if (typeof value !== 'number') {
          throw rejectedValue(path);
        }
      }
    } else if (typeof value !== 'string') {
      throw rejectedValue(path);
    }
  }

  const protection = protectionModeOf(path);
  if (protection)
    return {
      kind: 'protection_mode',
      protection,
      value: value as ProtectionModes,
    };
  if (path === 'windows.antivirus_registration.mode') {
    return {
      kind: 'antivirus_registration_mode',
      value: value as AntivirusRegistrationModes,
    };
  }
  const deviceField = deviceControlFieldOf(path);
  if (deviceField === 'enabled') return { kind: 'device_control_enabled', value: value as boolean };
  if (deviceField === 'usb_storage') {
    return {
      kind: 'device_control_usb_storage',
      value: value as DeviceControlAccessLevel,
    };
  }
  const popupProtection = popupProtectionOf(path);
  if (popupProtection)
    return {
      kind: 'popup_enabled',
      protection: popupProtection,
      value: value as boolean,
    };
  const malwareField = malwareBooleanFieldOf(path);
  if (malwareField)
    return { kind: 'malware_boolean', field: malwareField, value: value as boolean };
  if (path.endsWith('.behavior_protection.reputation_service')) {
    return { kind: 'behavior_reputation_service', value: value as boolean };
  }
  if (path === 'linux.events.session_data')
    return { kind: 'linux_session_data', value: value as boolean };
  if (path === 'linux.events.tty_io') return { kind: 'linux_tty_io', value: value as boolean };
  const entry = getFieldRegistryEntry(path);
  if (entry?.defaultValue !== undefined && typeof value !== typeof entry.defaultValue) {
    throw rejectedValue(path);
  }
  return { kind: 'generic', value };
};

export const isDeviceControlEnabledPath = (path: string): boolean =>
  deviceControlFieldOf(path) === 'enabled';
export const isDeviceControlUsbPath = (path: string): boolean =>
  deviceControlFieldOf(path) === 'usb_storage';
export const isDevicePopupEnabledPath = (path: string): boolean =>
  /^(windows|mac)\.popup\.device_control\.enabled$/.test(path);
