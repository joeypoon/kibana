/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export type {
  CreatePolicyReadSavedObjectsClientOptions,
  PolicyReadSavedObjectsService,
} from './policy_read_client';
export { createPolicyReadSavedObjectsClient } from './policy_read_client';

export type {
  PolicyReadAuthorization,
  PolicyReadAuthorizationDenied,
  PolicyReadAuthorizationDependencies,
  PolicyReadAuthorizationGranted,
} from './authorize_policy_read';
export { authorizePolicyRead } from './authorize_policy_read';

export {
  createMissingPrivilegeDenial,
  createNotFoundDenial,
  POLICY_READ_PRIVILEGE_NAMES,
} from './policy_read_denial';

export { buildDefendKuery, normalizePolicySearch, POLICY_SEARCH_MAX_LENGTH } from './defend_kuery';

export type {
  DefendPolicyRead,
  PolicyReadOutcome,
  PolicyReadPackagePolicyService,
  ReadDefendPolicyOptions,
} from './read_defend_policy_management';
export { readDefendPolicy } from './read_defend_policy_management';

export type {
  DefendPolicyInventory,
  ReadDefendPolicyInventoryOptions,
} from './inventory_traversal';
export { readDefendPolicyInventory } from './inventory_traversal';

export type {
  PolicyConfigDerivations,
  PolicyInventoryIdentity,
  PolicyRegistryResolve,
} from './to_policy_snapshot';
export {
  DefendPolicyInputNotFoundError,
  isDefendPackagePolicy,
  PolicyRegistryVersionUnknownError,
  toPolicyInventoryIdentity,
  toPolicySnapshot,
} from './to_policy_snapshot';
export { isPolicyNotFoundError } from './policy_read_errors';
export type { BuildScopeDisclosureOptions } from './scope_disclosure';
export {
  buildScopeDisclosure,
  createFleetAgentsPrivilegeDisclosure,
  createRegistryCoverageDisclosure,
  createResultLimitDisclosure,
  createUpstreamFailureDisclosure,
  describeScope,
} from './scope_disclosure';
