/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { loggingSystemMock } from '@kbn/core/server/mocks';
import type { MockedLogger } from '@kbn/logging-mocks';
import type { AgentClient } from '@kbn/fleet-plugin/server';
import { createMockAgentClient } from '@kbn/fleet-plugin/server/mocks';
import type { GetAgentStatusResponse } from '@kbn/fleet-plugin/common/types';
import type { PolicyReadPrivilegeBasis } from '../../../domain/read/types';
import { classifyPolicyUse } from '../../../domain/unused';
import type { AssignmentEvidenceInputPolicy } from './collect_assignment_evidence';
import { collectAssignmentEvidence } from './collect_assignment_evidence';

type AgentStatusResults = GetAgentStatusResponse['results'];

const agentStatus = (overrides: Partial<AgentStatusResults> = {}): AgentStatusResults => ({
  events: 0,
  online: 0,
  error: 0,
  offline: 0,
  other: 0,
  updating: 0,
  inactive: 0,
  unenrolled: 0,
  all: 0,
  active: 0,
  ...overrides,
});

const fullPrivileges: PolicyReadPrivilegeBasis = {
  securityPolicyManagementRead: true,
  fleetIntegrationPoliciesRead: true,
  fleetAgentsRead: true,
};

const policy = (id: string, policyIds: string[]): AssignmentEvidenceInputPolicy => ({
  id,
  policy_ids: policyIds,
});

describe('collectAssignmentEvidence', () => {
  let agentClient: jest.Mocked<AgentClient>;
  let getAgentClient: jest.Mock<AgentClient, []>;
  let logger: MockedLogger;

  beforeEach(() => {
    agentClient = createMockAgentClient();
    getAgentClient = jest.fn(() => agentClient);
    logger = loggingSystemMock.createLogger();
  });

  describe('when `fleet.readAgents` is absent', () => {
    const withoutAgentsRead: PolicyReadPrivilegeBasis = {
      ...fullPrivileges,
      fleetAgentsRead: false,
    };

    it('never calls the agent service at all', async () => {
      await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a']), policy('pkg-2', ['ap-b'])],
        privilegeBasis: withoutAgentsRead,
        getAgentClient,
        logger,
      });

      expect(getAgentClient).not.toHaveBeenCalled();
      expect(agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
      expect(agentClient.listAgents).not.toHaveBeenCalled();
      expect(agentClient.getByIds).not.toHaveBeenCalled();
      expect(agentClient.getAgent).not.toHaveBeenCalled();
    });

    it('emits `privilege_absent` with no count, while still reporting the assignment', async () => {
      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a', 'ap-b'])],
        privilegeBasis: withoutAgentsRead,
        getAgentClient,
        logger,
      });

      expect(results).toHaveLength(1);
      expect(results[0].status).toBe('privilege_absent');
      expect(results[0].agentCount).toBeUndefined();
      expect('agentCount' in results[0]).toBe(false);
      expect(results[0].agentPolicyIds).toEqual(['ap-a', 'ap-b']);
      expect(results[0].detail).toContain('fleet.readAgents');
    });

    it('emits `privilege_absent` even for an unassigned policy, keeping the invariant absolute', async () => {
      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', [])],
        privilegeBasis: withoutAgentsRead,
        getAgentClient,
        logger,
      });

      expect(results[0].status).toBe('privilege_absent');
      expect(results[0].agentCount).toBeUndefined();
    });
  });

  describe('agent-policy id deduplication', () => {
    beforeEach(() => {
      agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(
        agentStatus({ online: 2, all: 2, active: 2 })
      );
    });

    it('collapses ids repeated within one package policy into a single lookup', async () => {
      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a', 'ap-a', 'ap-a'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
      expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledWith('ap-a');
      expect(results[0].agentPolicyIds).toEqual(['ap-a']);
      expect(results[0].agentCount).toBe(2);
    });

    it('collapses version-specific variants onto their base agent-policy id', async () => {
      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a', 'ap-a#9.2', 'ap-a#9.3'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
      expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledWith('ap-a');
      expect(results[0].agentPolicyIds).toEqual(['ap-a']);
      expect(results[0].agentCount).toBe(2);
    });

    it('reuses one lookup across several package policies sharing a reusable agent policy', async () => {
      const results = await collectAssignmentEvidence({
        policies: [
          policy('pkg-1', ['ap-shared']),
          policy('pkg-2', ['ap-shared']),
          policy('pkg-3', ['ap-shared', 'ap-other']),
        ],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(2);
      expect(agentClient.getAgentStatusForAgentPolicy.mock.calls.map(([id]) => id)).toEqual([
        'ap-other',
        'ap-shared',
      ]);
      expect(results.map(({ agentCount }) => agentCount)).toEqual([2, 2, 4]);
    });
  });

  describe('counting', () => {
    it('sums enrolled agents across every distinct agent policy of a package policy', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockImplementation(async (agentPolicyId) =>
        agentPolicyId === 'ap-a'
          ? agentStatus({ online: 3, all: 3, active: 3 })
          : agentStatus({ online: 5, all: 5, active: 5 })
      );

      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a', 'ap-b'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(results[0].status).toBe('counted');
      expect(results[0].agentCount).toBe(8);
    });

    it('counts offline and inactive agents as enrolled, so a quiet fleet is not reported as unused', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(
        agentStatus({ offline: 4, inactive: 6, all: 10, active: 4 })
      );

      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(results[0].agentCount).toBe(10);
      expect(classifyPolicyUse(results[0], ['ap-a']).state).toBe('in_use');
    });

    it('excludes unenrolled agents from the count', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(
        agentStatus({ unenrolled: 7, all: 7, active: 0 })
      );

      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(results[0].agentCount).toBe(0);
      expect(classifyPolicyUse(results[0], ['ap-a']).state).toBe('likely_unused_no_agents');
    });

    it('derives a zero for an unassigned policy from the empty assignment, not from Fleet', async () => {
      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', [])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
      expect(results[0].status).toBe('counted');
      expect(results[0].agentCount).toBe(0);
      expect(results[0].detail).toContain('not a Fleet-reported number');
    });
  });

  describe('incomplete lookups', () => {
    it('reports `lookup_incomplete` with a detail when the agent-policy bound cuts the lookup short', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(
        agentStatus({ online: 1, all: 1, active: 1 })
      );

      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a', 'ap-b', 'ap-c'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
        maxAgentPolicyLookups: 2,
      });

      expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(2);
      expect(results[0].status).toBe('lookup_incomplete');
      expect(results[0].agentCount).toBeUndefined();
      expect(results[0].detail).toContain('ap-c');
      expect(results[0].detail).toContain('bound of 2');
      expect(classifyPolicyUse(results[0], ['ap-a', 'ap-b', 'ap-c']).state).toBe('undetermined');
    });

    it('never reports the partial sum it already had when the bound was hit', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(
        agentStatus({ online: 100, all: 100, active: 100 })
      );

      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a', 'ap-b'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
        maxAgentPolicyLookups: 1,
      });

      expect(results[0].agentCount).toBeUndefined();
      expect(results[0].detail).not.toContain('100');
    });

    it('reports `lookup_incomplete` for the affected policy when one agent-policy lookup throws', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockImplementation(async (agentPolicyId) => {
        if (agentPolicyId === 'ap-broken') {
          throw new Error('agent status request timed out');
        }
        return agentStatus({ online: 2, all: 2, active: 2 });
      });

      const results = await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-ok']), policy('pkg-2', ['ap-ok', 'ap-broken'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(results[0].status).toBe('counted');
      expect(results[0].agentCount).toBe(2);
      expect(results[1].status).toBe('lookup_incomplete');
      expect(results[1].agentCount).toBeUndefined();
      expect(results[1].detail).toContain('ap-broken');
      expect(results[1].detail).toContain('agent status request timed out');
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('ap-broken'));
    });

    it('retries nothing and calls a failing agent policy exactly once, even across policies', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockRejectedValue(new Error('boom'));

      await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a']), policy('pkg-2', ['ap-a'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
    });
  });

  describe('forbidden evidence sources', () => {
    it('never reads a synthetic `agents` field off the policy it was handed', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(
        agentStatus({ online: 5, all: 5, active: 5 })
      );

      const withSyntheticZero = {
        id: 'pkg-1',
        policy_ids: ['ap-a'],
        agents: 0,
      } as unknown as AssignmentEvidenceInputPolicy;

      const results = await collectAssignmentEvidence({
        policies: [withSyntheticZero],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(results[0].agentCount).toBe(5);
    });

    it('uses only the Fleet agent-status primitive; no other agent API is touched', async () => {
      agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(
        agentStatus({ online: 1, all: 1, active: 1 })
      );

      await collectAssignmentEvidence({
        policies: [policy('pkg-1', ['ap-a'])],
        privilegeBasis: fullPrivileges,
        getAgentClient,
        logger,
      });

      expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalled();
      expect(agentClient.listAgents).not.toHaveBeenCalled();
      expect(agentClient.getByIds).not.toHaveBeenCalled();
      expect(agentClient.getAgentStatusById).not.toHaveBeenCalled();
    });
  });

  it('returns one evidence record per input policy, in input order', async () => {
    agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(
      agentStatus({ online: 1, all: 1, active: 1 })
    );

    const results = await collectAssignmentEvidence({
      policies: [policy('pkg-3', ['ap-a']), policy('pkg-1', []), policy('pkg-2', ['ap-b'])],
      privilegeBasis: fullPrivileges,
      getAgentClient,
      logger,
    });

    expect(results.map(({ policyId }) => policyId)).toEqual(['pkg-3', 'pkg-1', 'pkg-2']);
  });

  it('returns an empty result set without obtaining an agent client when given no policies', async () => {
    const results = await collectAssignmentEvidence({
      policies: [],
      privilegeBasis: fullPrivileges,
      getAgentClient,
      logger,
    });

    expect(results).toEqual([]);
    expect(agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
  });
});
