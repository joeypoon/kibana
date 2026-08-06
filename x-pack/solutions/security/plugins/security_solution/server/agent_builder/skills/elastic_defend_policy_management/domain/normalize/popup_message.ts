/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  DefaultPolicyDeviceNotificationMessage,
  DefaultPolicyNotificationMessage,
  DefaultPolicyRuleNotificationMessage,
} from '../../../../../../common/endpoint/models/policy_config';
import type { PopupMessageState } from './types';

const DEFAULT_POPUP_MESSAGE_BY_KEY_PATH: Readonly<Record<string, string>> = {
  'popup.malware.message': DefaultPolicyNotificationMessage,
  'popup.ransomware.message': DefaultPolicyNotificationMessage,
  'popup.memory_protection.message': DefaultPolicyRuleNotificationMessage,
  'popup.behavior_protection.message': DefaultPolicyRuleNotificationMessage,
  'popup.device_control.message': DefaultPolicyDeviceNotificationMessage,
};

export const classifyPopupMessage = (
  keyPath: string,
  value: unknown
): PopupMessageState | undefined => {
  const shippedDefault = DEFAULT_POPUP_MESSAGE_BY_KEY_PATH[keyPath];

  if (shippedDefault === undefined) {
    return undefined;
  }

  if (value === '' || value === undefined || value === null || value === shippedDefault) {
    return 'default';
  }

  return 'customized';
};
