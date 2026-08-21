/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { escapeKuery } from '@kbn/es-query';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { PACKAGE_POLICY_SAVED_OBJECT_TYPE } from '@kbn/fleet-plugin/common';
import type { PolicyConfig } from '../../../../../common/endpoint/types';
import { hashPolicyConfig } from '../domain/hash_policy_config';
import type { NormalizedPolicyConfig } from '../domain/normalized_policy_config';
import { normalize } from '../domain/normalize';
import type { HasAtLeast } from './access_context';
import {
  InvalidEndpointPolicyError,
  PolicyAmbiguousNameError,
  PolicyNotFoundError,
} from './policy_errors';
import { getPackagePolicyById, isRecognizedLookupMiss } from './policy_lookup';

const NAME_LOOKUP_PAGE = 1;
const NAME_LOOKUP_PER_PAGE = 11;

export type PolicyIdentity = Readonly<{
  id: string;
  name: string;
  description: string;
  revision: number;
  version: string;
  updatedAt?: string;
  updatedBy?: string;
  packageVersion?: string;
}>;

export type EndpointPolicyRead = Readonly<{
  policy: PolicyIdentity;
  storedConfig: PolicyConfig;
  normalizedConfig: NormalizedPolicyConfig;
  normalizedHash: string;
}>;

const ensureResolvedInCurrentSpace = async (
  access: HasAtLeast<'policy_read'>,
  policyId: string,
  identifier: string
): Promise<void> => {
  try {
    await access.fleet.ensureInCurrentSpace({ integrationPolicyIds: [policyId] });
  } catch (error) {
    if (error instanceof Error && isRecognizedLookupMiss(error)) {
      throw new PolicyNotFoundError(identifier);
    }

    throw error;
  }
};

const toEndpointPolicyRead = (resolved: PackagePolicy): EndpointPolicyRead => {
  const endpointInput = resolved.inputs.find((input) => input.type === 'endpoint');
  const policyValue = endpointInput?.config?.policy?.value;
  const { version } = resolved;

  if (policyValue == null || typeof version !== 'string' || version.length === 0) {
    throw new InvalidEndpointPolicyError(resolved.id);
  }

  let normalizedConfig: NormalizedPolicyConfig;
  try {
    normalizedConfig = normalize(policyValue);
  } catch (error) {
    if (error instanceof TypeError) {
      throw new InvalidEndpointPolicyError(resolved.id);
    }

    throw error;
  }

  return {
    policy: {
      id: resolved.id,
      name: resolved.name,
      description: resolved.description ?? '',
      revision: resolved.revision,
      version,
      ...(resolved.updated_at !== undefined ? { updatedAt: resolved.updated_at } : {}),
      ...(resolved.updated_by !== undefined ? { updatedBy: resolved.updated_by } : {}),
      ...(resolved.package?.version !== undefined
        ? { packageVersion: resolved.package.version }
        : {}),
    },
    storedConfig: policyValue,
    normalizedConfig,
    normalizedHash: hashPolicyConfig(normalizedConfig),
  };
};

const finishResolvedPolicy = async (
  access: HasAtLeast<'policy_read'>,
  resolved: PackagePolicy,
  identifier: string
): Promise<EndpointPolicyRead> => {
  await ensureResolvedInCurrentSpace(access, resolved.id, identifier);
  return toEndpointPolicyRead(resolved);
};

const getByExactEndpointName = async (
  access: HasAtLeast<'policy_read'>,
  identifier: string
): Promise<EndpointPolicyRead> => {
  const nameClause = `${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name:"${escapeKuery(identifier)}"`;
  const kuery = `${access.fleet.endpointPolicyKuery} AND ${nameClause}`;
  const { items, total } = await access.fleet.packagePolicy.list(access.fleet.getSoClient(), {
    kuery,
    page: NAME_LOOKUP_PAGE,
    perPage: NAME_LOOKUP_PER_PAGE,
    spaceId: access.spaceId,
  });

  if (items.length === 0) {
    throw new PolicyNotFoundError(identifier);
  }

  if (items.length > 1) {
    throw new PolicyAmbiguousNameError(
      items.map(({ id, name }) => ({ id, name })),
      Math.max(total, items.length)
    );
  }

  const [match] = items;
  if (match == null) {
    throw new PolicyNotFoundError(identifier);
  }

  return finishResolvedPolicy(access, match, identifier);
};

export const getEndpointPolicy = async (
  access: HasAtLeast<'policy_read'>,
  args: Readonly<{ idOrName: string }>
): Promise<EndpointPolicyRead> => {
  const identifier = args.idOrName.trim();
  const byId = await getPackagePolicyById(access, identifier);

  if (byId !== undefined) {
    if (byId.package?.name !== 'endpoint') {
      throw new PolicyNotFoundError(identifier);
    }

    return finishResolvedPolicy(access, byId, identifier);
  }

  return getByExactEndpointName(access, identifier);
};
