/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyReadDenial } from '../../domain/read/types';

export const SECURITY_POLICY_MANAGEMENT_READ_PRIVILEGE =
  'Security > Elastic Defend Policy Management: Read';

export const FLEET_AGENT_POLICIES_READ_PRIVILEGE = 'Fleet > Agent policies: Read';

export const FLEET_INTEGRATIONS_READ_PRIVILEGE = 'Fleet > Integrations: Read';

export const FLEET_POLICY_READ_PRIVILEGE = `${FLEET_AGENT_POLICIES_READ_PRIVILEGE} and ${FLEET_INTEGRATIONS_READ_PRIVILEGE}`;

export const POLICY_READ_PRIVILEGE_NAMES: readonly string[] = [
  SECURITY_POLICY_MANAGEMENT_READ_PRIVILEGE,
  FLEET_POLICY_READ_PRIVILEGE,
];

export const createMissingPrivilegeDenial = ({
  securityPolicyManagementRead = false,
  fleetAgentPoliciesRead = false,
  fleetIntegrationsRead = false,
}: {
  readonly securityPolicyManagementRead?: boolean;
  readonly fleetAgentPoliciesRead?: boolean;
  readonly fleetIntegrationsRead?: boolean;
} = {}): PolicyReadDenial => ({
  reason: 'missing_privilege',
  message:
    'You do not have permission to read Elastic Defend policies. No policy information was retrieved.',
  needAny: [
    ...(securityPolicyManagementRead ? [] : [SECURITY_POLICY_MANAGEMENT_READ_PRIVILEGE]),
    ...(!fleetAgentPoliciesRead && !fleetIntegrationsRead
      ? [FLEET_POLICY_READ_PRIVILEGE]
      : !fleetAgentPoliciesRead
      ? [FLEET_AGENT_POLICIES_READ_PRIVILEGE]
      : !fleetIntegrationsRead
      ? [FLEET_INTEGRATIONS_READ_PRIVILEGE]
      : []),
  ],
});

export const createNotFoundDenial = (policyId: string): PolicyReadDenial => ({
  reason: 'not_found',
  message: `No Elastic Defend policy was found for id [${policyId}] among the policies you can access.`,
});
