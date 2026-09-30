/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { get } from 'lodash';
import { set } from '@kbn/safer-lodash-set';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { ProtectionModes } from '../../../../../../common/endpoint/types';
import {
  getPolicyProtectionsReference,
  POLICY_COUPLING_MALWARE_BOOLEAN_FIELDS,
  type PolicyCouplingProtection,
} from '../../../../../../common/endpoint/models/policy_config_helpers';
import * as helpers from '../../../../../../common/endpoint/models/policy_config_helpers';
import * as fieldRegistry from '../field_registry';
import { policyValuesEqual } from '../policy_value_equality';
import type { ClassifiedSetFieldValue } from './validate_set_field_value';
import {
  classifySetFieldValue,
  isDeviceControlEnabledPath,
  isDeviceControlUsbPath,
} from './validate_set_field_value';
import type {
  ExplicitPolicyChange,
  PolicyChangeOperation,
  PreparedPolicyChangeSet,
} from './policy_change_operation';
import type { PolicyOperationRejection } from './policy_operation_rejection';
import { PolicyChangeRejectedError } from './policy_operation_rejection';

interface Evidence {
  readonly operation: PolicyChangeOperation;
  readonly index: number;
  readonly target: ClassifiedSetFieldValue | undefined;
  readonly patch: Array<{ path: string; from: unknown; to: unknown }>;
  readonly primary: readonly string[];
  readonly semantic: string | undefined;
}

interface OperationValidation {
  readonly rejection?: PolicyOperationRejection;
  readonly target?: ClassifiedSetFieldValue;
}

interface CoupledConflict {
  readonly identity: string;
  readonly first: number;
  readonly second: number;
}

const protectionReference = (protection: PolicyCouplingProtection) =>
  getPolicyProtectionsReference().find(({ keyPath }) => keyPath === `${protection}.mode`);

const pathProtection = (path: string): string | undefined => {
  const reference = getPolicyProtectionsReference().find(({ keyPath, osList }) =>
    osList.some((os) => path === `${os}.${keyPath}`)
  );
  const protection = reference?.keyPath.split('.')[0];
  return protection &&
    ['malware', 'ransomware', 'memory_protection', 'behavior_protection'].includes(protection)
    ? reference?.keyPath
    : undefined;
};

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const leaves = (
  from: unknown,
  to: unknown,
  path = ''
): Array<{ path: string; from: unknown; to: unknown }> => {
  if (policyValuesEqual(from, to)) return [];
  if (isObject(from) && isObject(to)) {
    return [...new Set([...Object.keys(from), ...Object.keys(to)])].flatMap((key) =>
      leaves(from[key], to[key], path ? `${path}.${key}` : key)
    );
  }
  if (isObject(from))
    return Object.keys(from).flatMap((key) =>
      leaves(from[key], undefined, path ? `${path}.${key}` : key)
    );
  if (isObject(to))
    return Object.keys(to).flatMap((key) =>
      leaves(undefined, to[key], path ? `${path}.${key}` : key)
    );
  return [{ path, from, to }];
};

const hasPopup = (policy: PolicyConfig): boolean =>
  policy.windows.popup.device_control != null && policy.mac.popup.device_control != null;

const primaryTargets = (operation: PolicyChangeOperation): readonly string[] => {
  if (operation.op !== 'set_field') {
    const reference = protectionReference(operation.protection);
    return reference ? reference.osList.map((os) => `${os}.${operation.protection}.mode`) : [];
  }
  return [operation.path];
};

const semanticIdentity = (operation: PolicyChangeOperation): string | undefined =>
  operation.op === 'set_field' ? pathProtection(operation.path) : `${operation.protection}.mode`;

const protectionModeIntent = (evidence: Evidence): ProtectionModes | undefined => {
  const { operation, target } = evidence;
  if (operation.op === 'set_protection_enabled') {
    return operation.enabled ? ProtectionModes.prevent : ProtectionModes.off;
  }
  if (operation.op === 'set_protection_level') {
    return operation.mode;
  }
  return target?.kind === 'protection_mode' ? target.value : undefined;
};

const involvesDeviceControl = (evidence: Evidence): boolean =>
  evidence.operation.op === 'set_field' &&
  (isDeviceControlEnabledPath(evidence.operation.path) ||
    isDeviceControlUsbPath(evidence.operation.path));

const dispatch = (
  policy: PolicyConfig,
  operation: PolicyChangeOperation,
  classified?: ClassifiedSetFieldValue
): void => {
  if (operation.op === 'set_protection_enabled' || operation.op === 'set_protection_level') {
    const protection = operation.protection;
    const reference = protectionReference(protection);
    if (!reference) throw new Error(`Unknown protection: ${protection}`);
    const mode =
      operation.op === 'set_protection_enabled'
        ? operation.enabled
          ? ProtectionModes.prevent
          : ProtectionModes.off
        : operation.mode;
    helpers.setProtectionModeAndPopup({
      policy,
      protection,
      osList: reference.osList,
      mode,
      syncPopupEnabled: true,
      popupEnabled: mode === ProtectionModes.prevent,
    });
    if (operation.op === 'set_protection_enabled' && protection === 'malware') {
      for (const field of POLICY_COUPLING_MALWARE_BOOLEAN_FIELDS)
        helpers.setMalwareBoolean(policy, field, operation.enabled, reference.osList);
    }
    if (operation.op === 'set_protection_enabled' && protection === 'behavior_protection')
      helpers.setBehaviorReputationService(policy, mode !== ProtectionModes.off);
    return;
  }
  const target = classified ?? classifySetFieldValue(operation.path, operation.value);
  switch (target.kind) {
    case 'protection_mode': {
      const reference = protectionReference(target.protection);
      if (!reference) throw new Error(`Unknown protection: ${target.protection}`);
      const os = operation.path.split('.')[0];
      const osList = reference.osList.filter((candidate) => candidate === os);
      if (osList.length === 0) {
        set(policy, operation.path, target.value);
        break;
      }
      helpers.setProtectionModeAndPopup({
        policy,
        protection: target.protection,
        osList,
        mode: target.value,
        syncPopupEnabled: false,
        popupEnabled: false,
      });
      break;
    }
    case 'device_control_enabled':
      helpers.setDeviceControlSwitch(policy, target.value);
      break;
    case 'device_control_usb_storage':
      helpers.setDeviceControlUsbStorage(policy, target.value);
      break;
    case 'linux_session_data':
      policy.linux.events.session_data = target.value;
      helpers.constrainLinuxTtyIo(policy);
      break;
    case 'linux_tty_io':
      policy.linux.events.tty_io = target.value;
      break;
    case 'popup_enabled': {
      const reference = protectionReference(target.protection);
      if (reference)
        helpers.setPopupEnabled(policy, target.protection, reference.osList, target.value);
      break;
    }
    case 'malware_boolean': {
      const reference = protectionReference('malware');
      if (reference)
        helpers.setMalwareBoolean(policy, target.field, target.value, reference.osList);
      break;
    }
    case 'behavior_reputation_service':
      helpers.setBehaviorReputationService(policy, target.value);
      break;
    default:
      set(policy, operation.path, operation.value);
  }
};

const validateOperation = (
  operation: PolicyChangeOperation,
  index: number,
  current: PolicyConfig
): OperationValidation => {
  if (operation.op !== 'set_field') return {};
  const writability = fieldRegistry.describePathWritability(operation.path);
  if (!writability.writable) {
    return {
      rejection: { operationIndexes: [index], path: operation.path, reason: writability.reason },
    };
  }
  if (get(current, operation.path) === undefined) {
    return {
      rejection: {
        operationIndexes: [index],
        path: operation.path,
        reason: 'current_value_missing',
      },
    };
  }
  if (isDeviceControlEnabledPath(operation.path) && !hasPopup(current)) {
    return {
      rejection: {
        operationIndexes: [index],
        path: operation.path,
        reason: 'device_control_notifications_uninitialized',
      },
    };
  }
  try {
    return { target: classifySetFieldValue(operation.path, operation.value) };
  } catch (error) {
    if (error instanceof PolicyChangeRejectedError && error.rejections.length > 0) {
      return { rejection: { ...error.rejections[0], operationIndexes: [index] } };
    }
    throw error;
  }
};

const coupledPairConflict = (
  first: Evidence | undefined,
  second: Evidence | undefined
): CoupledConflict | undefined => {
  if (!first || !second) return undefined;
  const sameRequestedPath =
    first.operation.op === 'set_field' &&
    second.operation.op === 'set_field' &&
    first.operation.path === second.operation.path;
  if (sameRequestedPath) return undefined;
  if (first.semantic !== undefined && first.semantic === second.semantic) {
    const firstValue = protectionModeIntent(first);
    const secondValue = protectionModeIntent(second);
    if (
      firstValue !== undefined &&
      secondValue !== undefined &&
      !Object.is(firstValue, secondValue)
    )
      return { identity: first.semantic, first: first.index, second: second.index };
    return undefined;
  }
  if (involvesDeviceControl(first) || involvesDeviceControl(second)) return undefined;
  for (const a of first.patch)
    for (const b of second.patch) {
      const bothCoupled = !first.primary.includes(a.path) && !second.primary.includes(b.path);
      if (a.path === b.path && bothCoupled && !Object.is(a.to, b.to))
        return { identity: a.path, first: first.index, second: second.index };
    }
  return undefined;
};

export const expandChangeSet = (
  operations: readonly PolicyChangeOperation[],
  currentConfig: PolicyConfig
): PreparedPolicyChangeSet => {
  const validations = operations.map((operation, index) =>
    validateOperation(operation, index, currentConfig)
  );
  const passOneRejections = validations.flatMap(({ rejection }) =>
    rejection !== undefined ? [rejection] : []
  );
  if (passOneRejections.length > 0) {
    throw new PolicyChangeRejectedError(passOneRejections);
  }

  const classified = operations.map((operation, index) => ({
    operation,
    target: validations[index].target,
  }));

  const proposal = structuredClone(currentConfig);
  const origins = new Map<string, ExplicitPolicyChange['origin']>();
  const linuxEventIndexes = new Set<number>();

  const recordOrigins = (
    evidenceOperation: PolicyChangeOperation,
    index: number,
    primary: readonly string[],
    patch: Array<{ path: string; from: unknown; to: unknown }>
  ): void => {
    for (const change of patch) {
      origins.set(change.path, {
        operationIndex: index,
        op: evidenceOperation.op,
        kind: primary.includes(change.path) ? ('direct' as const) : ('coupled' as const),
      });
      if (change.path === 'linux.events.session_data' || change.path === 'linux.events.tty_io') {
        linuxEventIndexes.add(index);
      }
    }
  };

  const evidence: Evidence[] = classified.map(({ operation, target }, index) => {
    const before = structuredClone(proposal);
    dispatch(proposal, operation, target);
    const patch = leaves(before, proposal);
    const primary = primaryTargets(operation);
    recordOrigins(operation, index, primary, patch);
    return { operation, index, target, patch, primary, semantic: semanticIdentity(operation) };
  });

  const latestExactPathIndex = new Map<string, number>();
  for (const item of evidence) {
    if (item.operation.op === 'set_field')
      latestExactPathIndex.set(item.operation.path, item.index);
  }
  const participants = evidence.filter(
    (item) =>
      item.operation.op !== 'set_field' ||
      latestExactPathIndex.get(item.operation.path) === item.index
  );

  const coupledConflicts = new Map<string, number[]>();
  for (let left = 0; left < participants.length; left++)
    for (let right = left + 1; right < participants.length; right++) {
      const conflict = coupledPairConflict(participants[left], participants[right]);
      if (conflict !== undefined) {
        const indexes = coupledConflicts.get(conflict.identity) ?? [];
        if (!indexes.includes(conflict.first)) indexes.push(conflict.first);
        if (!indexes.includes(conflict.second)) indexes.push(conflict.second);
        coupledConflicts.set(conflict.identity, indexes);
      }
    }
  if (coupledConflicts.size > 0) {
    throw new PolicyChangeRejectedError(
      [...coupledConflicts.entries()].map(([identity, operationIndexes]) => ({
        operationIndexes,
        path: identity,
        reason: 'conflicting_operations' as const,
      }))
    );
  }

  const intents = new Map<
    string,
    {
      operation: Extract<PolicyChangeOperation, { op: 'set_field' }>;
      target: ClassifiedSetFieldValue;
      index: number;
    }
  >();
  classified.forEach(({ operation, target }, index) => {
    if (operation.op !== 'set_field' || target === undefined) return;
    intents.set(operation.path, { operation, target, index });
  });

  let converged = false;
  for (let pass = 0; pass <= intents.size && !converged; pass++) {
    converged = true;
    for (const [path, intent] of intents) {
      const satisfied = policyValuesEqual(get(proposal, path), intent.operation.value);
      if (!satisfied) {
        converged = false;
        const before = structuredClone(proposal);
        dispatch(proposal, intent.operation, intent.target);
        recordOrigins(
          intent.operation,
          intent.index,
          [intent.operation.path],
          leaves(before, proposal)
        );
      }
    }
  }
  const unsatisfiedIntents = [...intents.values()].filter(
    (intent) => !policyValuesEqual(get(proposal, intent.operation.path), intent.operation.value)
  );
  if (unsatisfiedIntents.length > 0) {
    throw new PolicyChangeRejectedError(
      unsatisfiedIntents.map((intent) => ({
        operationIndexes: [intent.index],
        path: intent.operation.path,
        reason: 'conflicting_operations' as const,
      }))
    );
  }

  if (proposal.linux.events.session_data === false && proposal.linux.events.tty_io === true) {
    throw new PolicyChangeRejectedError([
      {
        operationIndexes: [...linuxEventIndexes],
        path: 'linux.events.tty_io',
        reason: 'invalid_combination' as const,
      },
    ]);
  }

  const explicitChanges = leaves(currentConfig, proposal).map((change) => {
    const origin = origins.get(change.path);
    if (!origin) {
      throw new Error(`Expanded policy change has no recorded origin: ${change.path}`);
    }
    return { ...change, origin };
  });

  return {
    operations,
    preparedOperations: evidence.map(({ operation, index, patch, primary, semantic }) => ({
      requested: operation,
      originIndex: index,
      primaryTargets: primary,
      ...(semantic ? { semanticIdentity: semantic } : {}),
      observedPatch: patch,
    })),
    proposedConfig: proposal,
    explicitChanges,
  };
};
