/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Client } from '@elastic/elasticsearch';
import {
  cleanupForensicData,
  cleanupPolicyManagementSeededData,
  cleanupTroubleshootingData,
  FORENSIC_AGENT_ID_PREFIX,
  POLICY_MANAGEMENT_AGENT_ID_PREFIX,
  TROUBLESHOOTING_AGENT_ID_PREFIX,
} from './cleanup';

describe('policy management cleanup', () => {
  it('keeps eval agent id prefixes disjoint including the reserved policy-management prefix', () => {
    const prefixes = [
      TROUBLESHOOTING_AGENT_ID_PREFIX,
      FORENSIC_AGENT_ID_PREFIX,
      POLICY_MANAGEMENT_AGENT_ID_PREFIX,
    ];

    expect(POLICY_MANAGEMENT_AGENT_ID_PREFIX).toBe('eval-agent-pm-');

    for (const left of prefixes) {
      for (const right of prefixes.filter((prefix) => prefix !== left)) {
        expect(left.startsWith(right)).toBe(false);
      }
    }
  });

  it('does not pass the reserved policy-management agent prefix to telemetry cleanup', async () => {
    const esClient = {
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;
    const internalEsClient = {
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;

    await cleanupTroubleshootingData({ esClient, internalEsClient });
    await cleanupForensicData({ esClient, internalEsClient });

    const usedPrefixes = [...(esClient.deleteByQuery as jest.Mock).mock.calls].map(
      (call) => call[0].query.prefix['agent.id']
    );

    expect(usedPrefixes).toEqual(
      expect.arrayContaining([TROUBLESHOOTING_AGENT_ID_PREFIX, FORENSIC_AGENT_ID_PREFIX])
    );
    expect(usedPrefixes).not.toContain(POLICY_MANAGEMENT_AGENT_ID_PREFIX);
    expect(
      (esClient.deleteByQuery as jest.Mock).mock.calls.some(
        (call) => call[0].index === '.integration_knowledge'
      )
    ).toBe(false);
  });

  it('deletes policy-management seeded docs by the reserved eval-agent-pm- prefix', async () => {
    const esClient = {
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;
    const internalEsClient = {
      deleteByQuery: jest.fn().mockResolvedValue({}),
    } as unknown as Client;

    await cleanupPolicyManagementSeededData({ esClient, internalEsClient });

    const usedPrefixes = [
      ...(esClient.deleteByQuery as jest.Mock).mock.calls,
      ...(internalEsClient.deleteByQuery as jest.Mock).mock.calls,
    ].map((call) => call[0].query.prefix['agent.id']);

    expect(usedPrefixes.length).toBeGreaterThan(0);
    expect(new Set(usedPrefixes)).toEqual(new Set([POLICY_MANAGEMENT_AGENT_ID_PREFIX]));
    expect(usedPrefixes).not.toContain(TROUBLESHOOTING_AGENT_ID_PREFIX);
    expect(usedPrefixes).not.toContain(FORENSIC_AGENT_ID_PREFIX);
    expect(
      (esClient.deleteByQuery as jest.Mock).mock.calls.some(
        (call) => call[0].index === '.integration_knowledge'
      )
    ).toBe(false);
  });
});
