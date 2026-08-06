/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AgentClient } from '@kbn/fleet-plugin/server';
import { createMockAgentClient } from '@kbn/fleet-plugin/server/mocks';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';

import { fetchAffectedPopulation, MAX_AFFECTED_POPULATION_LOOKUPS } from './affected_population';

const buildStatus = (active: number) => ({
  events: 0,
  online: active,
  error: 0,
  offline: 0,
  other: 0,
  updating: 0,
  inactive: 0,
  unenrolled: 0,
  all: active,
  active,
});

describe('fetchAffectedPopulation', () => {
  const logger = loggingSystemMock.createLogger();
  let agentClient: jest.Mocked<AgentClient>;
  let getAgentClient: jest.Mock<AgentClient, []>;

  beforeEach(() => {
    agentClient = createMockAgentClient() as jest.Mocked<AgentClient>;
    getAgentClient = jest.fn(() => agentClient);
  });

  it('counts active agents across every assigned agent policy', async () => {
    agentClient.getAgentStatusForAgentPolicy
      .mockResolvedValueOnce(buildStatus(12))
      .mockResolvedValueOnce(buildStatus(30));

    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: ['agent-policy-1', 'agent-policy-2'],
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(result).toEqual({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: ['agent-policy-1', 'agent-policy-2'],
      status: 'counted',
      agentCount: 42,
      detail:
        'Counted agents currently active in Fleet agent enrollment records across 2 assigned agent policies (inactive and unenrolled agents are excluded).',
    });
  });

  it('names the exclusion its count applies, so it cannot be confused with the estate count', async () => {
    agentClient.getAgentStatusForAgentPolicy.mockResolvedValue({
      ...buildStatus(4),
      inactive: 5,
      unenrolled: 2,
      all: 11,
    });

    const assignmentEvidence = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: ['agent-policy-1'],
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(assignmentEvidence.agentCount).toBe(4);
    expect(assignmentEvidence.detail).toContain('currently active');
    expect(assignmentEvidence.detail).toContain('inactive and unenrolled agents are excluded');
  });

  it('deduplicates repeated agent policy ids so they are not double counted', async () => {
    agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(buildStatus(5));

    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: ['agent-policy-1', 'agent-policy-1'],
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
    expect(getAgentClient).toHaveBeenCalledTimes(1);
    expect(result.agentPolicyIds).toEqual(['agent-policy-1']);
    expect(result.agentCount).toBe(5);
  });

  it('collapses a base agent-policy id and its version-suffixed variants into one lookup', async () => {
    agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(buildStatus(7));

    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: ['agent-policy-1', 'agent-policy-1#9.2', 'agent-policy-1#9.3'],
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
    expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledWith('agent-policy-1');
    expect(result.agentPolicyIds).toEqual(['agent-policy-1']);
    expect(result.status).toBe('counted');
    expect(result.agentCount).toBe(7);
  });

  it('counts when the distinct-base-id lookup set is exactly at the bound', async () => {
    agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(buildStatus(1));

    const agentPolicyIds = Array.from(
      { length: MAX_AFFECTED_POPULATION_LOOKUPS },
      (_, index) => `agent-policy-${index}`
    );

    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds,
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(
      MAX_AFFECTED_POPULATION_LOOKUPS
    );
    expect(result.status).toBe('counted');
    expect(result.agentCount).toBe(MAX_AFFECTED_POPULATION_LOOKUPS);
  });

  it('returns lookup_incomplete with no calls or partial count when distinct base ids exceed the bound', async () => {
    const agentPolicyIds = Array.from(
      { length: MAX_AFFECTED_POPULATION_LOOKUPS + 1 },
      (_, index) => `agent-policy-${index}`
    );

    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds,
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(getAgentClient).not.toHaveBeenCalled();
    expect(agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(result.status).toBe('lookup_incomplete');
    expect(result.agentCount).toBeUndefined();
    expect(result.agentPolicyIds).toHaveLength(MAX_AFFECTED_POPULATION_LOOKUPS + 1);
    expect(result.detail).toContain(String(MAX_AFFECTED_POPULATION_LOOKUPS));
  });

  it('still withholds the lookup for overflowed assignments when the privilege is absent', async () => {
    const agentPolicyIds = Array.from(
      { length: MAX_AFFECTED_POPULATION_LOOKUPS + 1 },
      (_, index) => `agent-policy-${index}`
    );

    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds,
      canReadFleetAgents: false,
      getAgentClient,
      logger,
    });

    expect(getAgentClient).not.toHaveBeenCalled();
    expect(result.status).toBe('privilege_absent');
    expect(result.agentCount).toBeUndefined();
  });

  it('reports an undetermined population and performs NO agent lookup without the privilege', async () => {
    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: ['agent-policy-1'],
      canReadFleetAgents: false,
      getAgentClient,
      logger,
    });

    expect(agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(getAgentClient).not.toHaveBeenCalled();
    expect(result.status).toBe('privilege_absent');
    expect(result.agentCount).toBeUndefined();
    expect(result.detail).toContain('Agents: Read');
  });

  it('answers unassigned from the package policy without an agent lookup', async () => {
    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: [],
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(agentClient.getAgentStatusForAgentPolicy).not.toHaveBeenCalled();
    expect(getAgentClient).not.toHaveBeenCalled();
    expect(result).toEqual({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: [],
      status: 'counted',
      agentCount: 0,
      detail:
        'Read from the Fleet package policy: it is not assigned to any agent policy, so no agent lookup was needed.',
    });
  });

  it('does not need the privilege to answer unassigned', async () => {
    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: [],
      canReadFleetAgents: false,
      getAgentClient,
      logger,
    });

    expect(result.status).toBe('counted');
    expect(result.agentCount).toBe(0);
    expect(getAgentClient).not.toHaveBeenCalled();
  });

  it('reports lookup_incomplete with no partial total when a lookup fails', async () => {
    agentClient.getAgentStatusForAgentPolicy
      .mockResolvedValueOnce(buildStatus(12))
      .mockRejectedValueOnce(new Error('es unavailable'));

    const result = await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: ['agent-policy-1', 'agent-policy-2'],
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(result.status).toBe('lookup_incomplete');
    expect(result.agentCount).toBeUndefined();
    expect(result.detail).toContain('agent-policy-2');
  });

  it('reads only Fleet agent enrollment data, never endpoint telemetry or metadata', async () => {
    agentClient.getAgentStatusForAgentPolicy.mockResolvedValue(buildStatus(3));

    await fetchAffectedPopulation({
      policyId: 'endpoint-policy-1',
      agentPolicyIds: ['agent-policy-1'],
      canReadFleetAgents: true,
      getAgentClient,
      logger,
    });

    expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
    expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledWith('agent-policy-1');
    expect(agentClient.listAgents).not.toHaveBeenCalled();
    expect(agentClient.getByIds).not.toHaveBeenCalled();
    expect(agentClient.getAgent).not.toHaveBeenCalled();
  });
});
