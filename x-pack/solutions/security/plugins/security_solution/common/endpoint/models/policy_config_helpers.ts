/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { get } from 'lodash';
import { set } from '@kbn/safer-lodash-set';
import {
  DefaultPolicyDeviceNotificationMessage,
  DefaultPolicyNotificationMessage,
  DefaultPolicyRuleNotificationMessage,
} from './policy_config';
import type { PolicyConfig } from '../types';
import {
  PolicyOperatingSystem,
  ProtectionModes,
  AntivirusRegistrationModes,
  DeviceControlAccessLevel,
} from '../types';

interface PolicyProtectionReference {
  keyPath: string;
  osList: PolicyOperatingSystem[];
  enableValue: unknown;
  disableValue: unknown;
}

const allOsValues = [
  PolicyOperatingSystem.mac,
  PolicyOperatingSystem.linux,
  PolicyOperatingSystem.windows,
];

const getPolicyPopupReference = (): Array<{
  keyPath: string;
  osList: PolicyOperatingSystem[];
}> => [
  {
    keyPath: 'popup.malware.message',
    osList: [...allOsValues],
  },
  {
    keyPath: 'popup.memory_protection.message',
    osList: [...allOsValues],
  },
  {
    keyPath: 'popup.behavior_protection.message',
    osList: [...allOsValues],
  },
  {
    keyPath: 'popup.ransomware.message',
    osList: [PolicyOperatingSystem.windows, PolicyOperatingSystem.mac],
  },
  {
    keyPath: 'popup.device_control.message',
    osList: [PolicyOperatingSystem.windows, PolicyOperatingSystem.mac],
  },
];

export const getPolicyProtectionsReference = (): PolicyProtectionReference[] => [
  {
    keyPath: 'malware.mode',
    osList: [...allOsValues],
    disableValue: ProtectionModes.off,
    enableValue: ProtectionModes.prevent,
  },
  {
    keyPath: 'ransomware.mode',
    osList: [PolicyOperatingSystem.windows, PolicyOperatingSystem.mac],
    disableValue: ProtectionModes.off,
    enableValue: ProtectionModes.prevent,
  },
  {
    keyPath: 'memory_protection.mode',
    osList: [...allOsValues],
    disableValue: ProtectionModes.off,
    enableValue: ProtectionModes.prevent,
  },
  {
    keyPath: 'behavior_protection.mode',
    osList: [...allOsValues],
    disableValue: ProtectionModes.off,
    enableValue: ProtectionModes.prevent,
  },
  {
    keyPath: 'attack_surface_reduction.credential_hardening.enabled',
    osList: [PolicyOperatingSystem.windows],
    disableValue: false,
    enableValue: true,
  },
  {
    keyPath: 'antivirus_registration.enabled',
    osList: [PolicyOperatingSystem.windows],
    disableValue: false,
    enableValue: true,
  },
];

/**
 * Returns a copy of the passed `PolicyConfig` with all protections set to disabled.
 *
 * @param policy
 * @returns
 */
export const disableProtections = (policy: PolicyConfig): PolicyConfig => {
  const result = disableCommonProtections(policy);

  return {
    ...result,
    windows: {
      ...result.windows,
      ...getDisabledWindowsSpecificProtections(result),
      popup: {
        ...result.windows.popup,
        ...getDisabledWindowsSpecificPopups(result),
      },
      device_control: {
        ...result.windows.device_control,
        enabled: false,
        usb_storage: DeviceControlAccessLevel.audit,
      },
    },
    mac: {
      ...result.mac,
      ...getDisabledMacSpecificProtections(result),
      device_control: {
        ...result.mac.device_control,
        enabled: false,
        usb_storage: DeviceControlAccessLevel.audit,
      },
      popup: {
        ...result.mac.popup,
        ...getDisabledMacSpecificPopups(result),
        device_control: {
          ...result.mac.popup.device_control,
          enabled: false,
          message: result.mac.popup.device_control?.message || '',
        },
      },
    },
  };
};

const disableCommonProtections = (policy: PolicyConfig) => {
  return Object.keys(policy).reduce<PolicyConfig>((acc, item) => {
    const os = item as keyof PolicyConfig as PolicyOperatingSystem;
    if (!allOsValues.includes(os)) {
      return acc;
    }
    return {
      ...acc,
      [os]: {
        ...policy[os],
        ...getDisabledCommonProtectionsForOS(policy, os),
        popup: {
          ...policy[os].popup,
          ...getDisabledCommonPopupsForOS(policy, os),
        },
      },
    };
  }, policy);
};

const getDisabledCommonProtectionsForOS = (
  policy: PolicyConfig,
  os: PolicyOperatingSystem
): Partial<PolicyConfig['windows']> => ({
  behavior_protection: {
    ...policy[os].behavior_protection,
    mode: ProtectionModes.off,
  },
  memory_protection: {
    ...policy[os].memory_protection,
    mode: ProtectionModes.off,
  },
  malware: {
    ...policy[os].malware,
    blocklist: false,
    on_write_scan: false,
    mode: ProtectionModes.off,
  },
});

const getDisabledCommonPopupsForOS = (policy: PolicyConfig, os: PolicyOperatingSystem) => ({
  behavior_protection: {
    ...policy[os].popup.behavior_protection,
    enabled: false,
  },
  malware: {
    ...policy[os].popup.malware,
    enabled: false,
  },
  memory_protection: {
    ...policy[os].popup.memory_protection,
    enabled: false,
  },
});

const getDisabledWindowsSpecificProtections = (policy: PolicyConfig) => ({
  ransomware: {
    ...policy.windows.ransomware,
    mode: ProtectionModes.off,
  },
  antivirus_registration: {
    ...policy.windows.antivirus_registration,
    mode: AntivirusRegistrationModes.disabled,
    enabled: false,
  },
  attack_surface_reduction: {
    ...policy.windows.attack_surface_reduction,
    credential_hardening: {
      enabled: false,
    },
  },
});

const getDisabledWindowsSpecificPopups = (policy: PolicyConfig) => ({
  ransomware: {
    ...policy.windows.popup.ransomware,
    enabled: false,
  },
  device_control: {
    ...policy.windows.popup.device_control,
    enabled: false,
    message: policy.windows.popup.device_control?.message || '',
  },
});

const getDisabledMacSpecificProtections = (policy: PolicyConfig) => ({
  ransomware: {
    ...policy.mac.ransomware,
    mode: ProtectionModes.off,
  },
});

const getDisabledMacSpecificPopups = (policy: PolicyConfig) => ({
  ransomware: {
    ...policy.mac.popup.ransomware,
    enabled: false,
  },
});

/**
 * Returns the provided with only event collection turned enabled
 * @param policy
 */
export const ensureOnlyEventCollectionIsAllowed = (policy: PolicyConfig): PolicyConfig => {
  const updatedPolicy = disableProtections(policy);

  set(updatedPolicy, 'windows.antivirus_registration.mode', AntivirusRegistrationModes.disabled);
  set(updatedPolicy, 'windows.antivirus_registration.enabled', false);

  return updatedPolicy;
};

/**
 * Checks to see if the provided policy is set to Event Collection only
 */
export const isPolicySetToEventCollectionOnly = (
  policy: PolicyConfig
): { isOnlyCollectingEvents: boolean; message?: string } => {
  const protectionsRef = getPolicyProtectionsReference();
  let message: string | undefined;

  const hasEnabledProtection = protectionsRef.some(({ keyPath, osList, disableValue }) => {
    return osList.some((osValue) => {
      const fullKeyPathForOs = `${osValue}.${keyPath}`;
      const currentValue = get(policy, fullKeyPathForOs);
      const isEnabled = currentValue !== disableValue;

      if (isEnabled) {
        message = `property [${fullKeyPathForOs}] is set to [${currentValue}]`;
      }

      return isEnabled;
    });
  });

  return {
    isOnlyCollectingEvents: !hasEnabledProtection,
    message,
  };
};

export function isBillablePolicy(policy: PolicyConfig) {
  if (!policy.meta.serverless) return false;

  return !isPolicySetToEventCollectionOnly(policy).isOnlyCollectingEvents;
}

const getDefaultPopupMessageForKeyPath = (keyPath: string): string => {
  const family = keyPath.split('.')[1];

  if (family === 'device_control') {
    return DefaultPolicyDeviceNotificationMessage;
  }

  if (family === 'memory_protection' || family === 'behavior_protection') {
    return DefaultPolicyRuleNotificationMessage;
  }

  return DefaultPolicyNotificationMessage;
};

export const checkIfPopupMessagesContainCustomNotifications = (policy: PolicyConfig): boolean => {
  const popupRefs = getPolicyPopupReference();

  return popupRefs.some(({ keyPath, osList }) => {
    return osList.some((osValue) => {
      const fullKeyPathForOs = `${osValue}.${keyPath}`;
      const currentValue = get(policy, fullKeyPathForOs);
      if (currentValue == null || currentValue === '') {
        return false;
      }
      return currentValue !== getDefaultPopupMessageForKeyPath(keyPath);
    });
  });
};

export const resetCustomNotifications = (customNotification?: string): Partial<PolicyConfig> => {
  const popupRefs = getPolicyPopupReference();

  return popupRefs.reduce((acc, { keyPath, osList }) => {
    const message = customNotification ?? getDefaultPopupMessageForKeyPath(keyPath);
    osList.forEach((osValue) => {
      set(acc, `${osValue}.${keyPath}`, message);
    });
    return acc;
  }, {});
};

/**
 * Returns a copy of the passed `PolicyConfig` with device_control fields completely removed
 * from both Windows and Mac OS configurations and their popup settings.
 *
 * @param policy
 * @returns PolicyConfig without device_control fields
 */
export const removeDeviceControl = (policy: PolicyConfig): PolicyConfig => {
  const { device_control: windowsDeviceControl, ...windowsRest } = policy.windows;
  const { device_control: macDeviceControl, ...macRest } = policy.mac;

  const { device_control: windowsPopupDeviceControl, ...windowsPopupRest } = policy.windows.popup;
  const { device_control: macPopupDeviceControl, ...macPopupRest } = policy.mac.popup;

  return {
    ...policy,
    windows: {
      ...windowsRest,
      popup: {
        ...windowsPopupRest,
      },
    },
    mac: {
      ...macRest,
      popup: {
        ...macPopupRest,
      },
    },
  };
};

/**
 * Returns a copy of the passed `PolicyConfig` with Linux DNS events field removed.
 * Used when the linuxDnsEvents feature flag is disabled.
 *
 * @param policy
 * @returns PolicyConfig without Linux dns field
 */
export const removeLinuxDnsEvents = (policy: PolicyConfig): PolicyConfig => {
  const { dns: linuxDns, ...linuxEventsRest } = policy.linux.events;

  return {
    ...policy,
    linux: {
      ...policy.linux,
      events: {
        ...linuxEventsRest,
      },
    },
  };
};

export type PolicyCouplingProtection =
  | 'malware'
  | 'ransomware'
  | 'memory_protection'
  | 'behavior_protection';

export type PolicyCouplingMalwareBooleanField = 'blocklist' | 'on_write_scan';

const isPolicyCouplingOs = (os: string): os is PolicyOperatingSystem =>
  os === PolicyOperatingSystem.windows ||
  os === PolicyOperatingSystem.mac ||
  os === PolicyOperatingSystem.linux;

const forEachCouplingOs = (
  osList: readonly string[],
  write: (os: PolicyOperatingSystem) => void
) => {
  for (const os of osList) {
    if (isPolicyCouplingOs(os)) {
      write(os);
    }
  }
};

export const setProtectionModeAndPopup = ({
  policy,
  protection,
  osList,
  mode,
  syncPopupEnabled,
  popupEnabled,
}: {
  policy: PolicyConfig;
  protection: PolicyCouplingProtection;
  osList: readonly string[];
  mode: ProtectionModes;
  syncPopupEnabled: boolean;
  popupEnabled: boolean;
}): PolicyConfig => {
  forEachCouplingOs(osList, (os) => {
    set(policy, `${os}.${protection}.mode`, mode);
    if (syncPopupEnabled) {
      set(policy, `${os}.popup.${protection}.enabled`, popupEnabled);
    }
  });
  return policy;
};

export const setBehaviorReputationService = (
  policy: PolicyConfig,
  value: unknown
): PolicyConfig => {
  set(policy, 'windows.behavior_protection.reputation_service', value);
  set(policy, 'mac.behavior_protection.reputation_service', value);
  set(policy, 'linux.behavior_protection.reputation_service', value);
  return policy;
};

export const setMalwareBoolean = (
  policy: PolicyConfig,
  field: PolicyCouplingMalwareBooleanField,
  value: unknown,
  osList: readonly string[]
): PolicyConfig => {
  forEachCouplingOs(osList, (os) => {
    set(policy, `${os}.malware.${field}`, value);
  });
  return policy;
};

export const setDeviceControlSwitch = (policy: PolicyConfig, value: unknown): PolicyConfig => {
  if (value === false) {
    policy.windows.device_control = {
      enabled: false,
      usb_storage: DeviceControlAccessLevel.audit,
    };
    policy.windows.popup.device_control = {
      enabled: false,
      message: policy.windows.popup.device_control?.message || '',
    };

    policy.mac.device_control = {
      enabled: false,
      usb_storage: DeviceControlAccessLevel.audit,
    };
    policy.mac.popup.device_control = {
      enabled: false,
      message: policy.mac.popup.device_control?.message || '',
    };

    return policy;
  }

  policy.windows.device_control = {
    enabled: true,
    usb_storage: DeviceControlAccessLevel.deny_all,
  };
  policy.windows.popup = policy.windows.popup || {};
  policy.windows.popup.device_control = {
    enabled: true,
    message: policy.windows.popup.device_control?.message || '',
  };

  policy.mac.device_control = {
    enabled: true,
    usb_storage: DeviceControlAccessLevel.deny_all,
  };
  policy.mac.popup = policy.mac.popup || {};
  policy.mac.popup.device_control = {
    enabled: true,
    message: policy.mac.popup.device_control?.message || '',
  };

  return policy;
};

export const setDeviceControlUsbStorage = (policy: PolicyConfig, value: unknown): PolicyConfig => {
  if (!policy.windows.device_control) {
    set(policy, 'windows.device_control', { enabled: true, usb_storage: value });
  } else {
    set(policy, 'windows.device_control.usb_storage', value);
  }

  if (!policy.mac.device_control) {
    set(policy, 'mac.device_control', { enabled: true, usb_storage: value });
  } else {
    set(policy, 'mac.device_control.usb_storage', value);
  }

  if (value === 'deny_all') {
    if (policy.windows.popup.device_control) {
      policy.windows.popup.device_control.enabled = true;
    }
    if (policy.mac.popup.device_control) {
      policy.mac.popup.device_control.enabled = true;
    }
  } else {
    if (policy.windows.popup.device_control) {
      policy.windows.popup.device_control.enabled = false;
    }
    if (policy.mac.popup.device_control) {
      policy.mac.popup.device_control.enabled = false;
    }
  }

  return policy;
};

export const constrainLinuxTtyIo = (policy: PolicyConfig): PolicyConfig => {
  if (policy.linux.events.session_data === false) {
    policy.linux.events.tty_io = false;
  }
  return policy;
};

export const setPopupEnabled = (
  policy: PolicyConfig,
  protection: PolicyCouplingProtection,
  osList: readonly string[],
  enabled: unknown
): PolicyConfig => {
  forEachCouplingOs(osList, (os) => {
    set(policy, `${os}.popup.${protection}.enabled`, enabled);
  });
  return policy;
};
