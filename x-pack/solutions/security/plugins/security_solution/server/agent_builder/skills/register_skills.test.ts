/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { loggerMock } from '@kbn/logging-mocks';
import { agentBuilderMocks } from '@kbn/agent-builder-plugin/server/mocks';
import { isAllowedBuiltinSkill } from '@kbn/agent-builder-server/allow_lists';
import {
  allowedExperimentalValues,
  type ExperimentalFeatures,
} from '../../../common/experimental_features';
import type { EntityAnalyticsRoutesDeps } from '../../lib/entity_analytics/types';
import { createMockEndpointAppContext } from '../../endpoint/mocks';
import {
  ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID,
  createElasticDefendPolicyManagementSkill,
} from './elastic_defend_policy_management';
import { registerSkills } from './register_skills';

jest.mock('./elastic_defend_policy_management', () => ({
  ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID: 'elastic-defend-policy-management',
  createElasticDefendPolicyManagementSkill: jest.fn(() => ({
    id: 'elastic-defend-policy-management',
  })),
}));

describe('registerSkills', () => {
  const mockLogger = loggerMock.create();
  const mockAgentBuilder = agentBuilderMocks.createSetup();
  const mockGetStartServices = jest.fn() as EntityAnalyticsRoutesDeps['getStartServices'];
  const mockMl = {} as EntityAnalyticsRoutesDeps['ml'];
  const endpointAppContextService = createMockEndpointAppContext().service;

  const baseOpts = {
    agentBuilder: mockAgentBuilder,
    getStartServices: mockGetStartServices,
    kibanaVersion: '9.0.0',
    logger: mockLogger,
    ml: mockMl,
    options: {
      endpointAppContextService,
    },
  };

  const registerWithFeatures = async (
    experimentalFeatures: ExperimentalFeatures
  ): Promise<string[]> => {
    await registerSkills({ ...baseOpts, experimentalFeatures });
    return mockAgentBuilder.skills.register.mock.calls.map(([skill]) => skill.id);
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('keeps elasticDefendPolicyManagementSkill disabled by default', () => {
    expect(allowedExperimentalValues.elasticDefendPolicyManagementSkill).toBe(false);
  });

  it('registers elastic-defend-policy-management with the exact service instance when the flag is enabled', async () => {
    const registeredIds = await registerWithFeatures({
      ...allowedExperimentalValues,
      elasticDefendPolicyManagementSkill: true,
    });

    expect(createElasticDefendPolicyManagementSkill).toHaveBeenCalledTimes(1);
    expect(createElasticDefendPolicyManagementSkill).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices: mockGetStartServices,
    });
    expect(
      jest.mocked(createElasticDefendPolicyManagementSkill).mock.calls[0][0]
        .endpointAppContextService
    ).toBe(endpointAppContextService);
    expect(
      jest.mocked(createElasticDefendPolicyManagementSkill).mock.calls[0][0].getStartServices
    ).toBe(mockGetStartServices);
    expect(registeredIds).toContain(ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID);
    expect(mockAgentBuilder.skills.register).toHaveBeenCalledWith(
      expect.objectContaining({ id: ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID })
    );
  });

  it('does not register elastic-defend-policy-management when the flag is disabled', async () => {
    const registeredIds = await registerWithFeatures({
      ...allowedExperimentalValues,
      elasticDefendPolicyManagementSkill: false,
    });

    expect(createElasticDefendPolicyManagementSkill).not.toHaveBeenCalled();
    expect(registeredIds).not.toContain(ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID);
    expect(mockAgentBuilder.skills.register).not.toHaveBeenCalledWith(
      expect.objectContaining({ id: ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID })
    );
  });

  it('registers only skills whose ids are in the agent-builder allow-list', async () => {
    const registeredIds = await registerWithFeatures({
      ...allowedExperimentalValues,
      elasticDefendPolicyManagementSkill: true,
    });

    expect(registeredIds.length).toBeGreaterThan(0);
    registeredIds.forEach((id) => {
      expect(isAllowedBuiltinSkill(id)).toBe(true);
    });
  });
});
