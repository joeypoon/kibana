/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { hashPolicyConfig } from '../domain/hash_policy_config';
import type { NormalizedPolicyConfig } from '../domain/normalized_policy_config';
import { normalize } from '../domain/normalize';
import type { HasAtLeast } from './access_context';

const DEFAULT_PAGE = 1;
const DEFAULT_PER_PAGE = 20;
const MAX_PER_PAGE = 50;
const LIST_STRING_CAP = 512;

export type PolicyPosture = Readonly<{
  windowsProtectionModes: Readonly<{
    malware: string;
    ransomware: string;
    memoryThreat: string;
    behavior: string;
  }>;
  macProtectionModes: Readonly<{
    malware: string;
    behavior: string;
  }>;
  linuxProtectionModes: Readonly<{
    malware: string;
    behavior: string;
  }>;
  globalTelemetryEnabled: boolean;
}>;

export type ListPolicyItem = Readonly<{
  id: string;
  name: string;
  description: string;
  revision: number;
  version: string;
  updatedAt?: string;
  packageVersion?: string;
  name_string_truncated?: true;
  description_string_truncated?: true;
  normalizedHash: string;
  posture: PolicyPosture;
}>;

export type ListPoliciesDto = Readonly<{
  population: 'endpoint_package_policies';
  page: number;
  per_page: number;
  items: readonly ListPolicyItem[];
  value_total: number;
  has_more: boolean;
  invalid_policy_count: number;
}>;

const toBoundedPage = (value: number): number => {
  const page = Math.trunc(value);
  return Number.isInteger(page) && page >= 1 ? page : DEFAULT_PAGE;
};

const toBoundedPerPage = (value: number): number => {
  const perPage = Math.trunc(value);
  if (!Number.isInteger(perPage) || perPage < 1) {
    return DEFAULT_PER_PAGE;
  }

  return Math.min(perPage, MAX_PER_PAGE);
};

const capListString = (value: string): Readonly<{ text: string; truncated: boolean }> => {
  if (value.length <= LIST_STRING_CAP) {
    return { text: value, truncated: false };
  }

  return { text: value.slice(0, LIST_STRING_CAP), truncated: true };
};

const toCompactPosture = (config: NormalizedPolicyConfig): PolicyPosture => ({
  windowsProtectionModes: {
    malware: config.windows.malware.mode,
    ransomware: config.windows.ransomware.mode,
    memoryThreat: config.windows.memory_protection.mode,
    behavior: config.windows.behavior_protection.mode,
  },
  macProtectionModes: {
    malware: config.mac.malware.mode,
    behavior: config.mac.behavior_protection.mode,
  },
  linuxProtectionModes: {
    malware: config.linux.malware.mode,
    behavior: config.linux.behavior_protection.mode,
  },
  globalTelemetryEnabled: config.global_telemetry_enabled,
});

const toListPolicyItem = (row: PackagePolicy): ListPolicyItem | undefined => {
  try {
    const endpointInput = row.inputs.find((input) => input.type === 'endpoint');
    const policyValue = endpointInput?.config?.policy?.value;
    const { version } = row;

    if (policyValue == null || typeof version !== 'string' || version.length === 0) {
      return undefined;
    }

    const normalizedConfig = normalize(policyValue);
    const { text: name, truncated: nameTruncated } = capListString(row.name);
    const { text: description, truncated: descriptionTruncated } = capListString(
      row.description ?? ''
    );

    return {
      id: row.id,
      name,
      description,
      revision: row.revision,
      version,
      ...(row.updated_at !== undefined ? { updatedAt: row.updated_at } : {}),
      ...(row.package?.version !== undefined ? { packageVersion: row.package.version } : {}),
      ...(nameTruncated ? { name_string_truncated: true } : {}),
      ...(descriptionTruncated ? { description_string_truncated: true } : {}),
      normalizedHash: hashPolicyConfig(normalizedConfig),
      posture: toCompactPosture(normalizedConfig),
    };
  } catch {
    return undefined;
  }
};

export const listEndpointPolicies = async (
  access: HasAtLeast<'policy_read'>,
  args: Readonly<{ page: number; perPage: number }>
): Promise<ListPoliciesDto> => {
  const page = toBoundedPage(args.page);
  const perPage = toBoundedPerPage(args.perPage);
  const { items: rows, total } = await access.fleet.packagePolicy.list(access.fleet.getSoClient(), {
    kuery: access.fleet.endpointPolicyKuery,
    page,
    perPage,
    spaceId: access.spaceId,
  });

  const items: ListPolicyItem[] = [];
  let invalidPolicyCount = 0;

  for (const row of rows) {
    const item = toListPolicyItem(row);
    if (item === undefined) {
      invalidPolicyCount += 1;
    } else {
      items.push(item);
    }
  }

  return {
    population: 'endpoint_package_policies',
    page,
    per_page: perPage,
    items,
    value_total: total,
    has_more: page * perPage < total,
    invalid_policy_count: invalidPolicyCount,
  };
};
