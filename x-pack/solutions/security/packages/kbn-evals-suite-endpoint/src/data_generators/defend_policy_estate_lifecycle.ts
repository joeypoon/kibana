/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Client } from '@elastic/elasticsearch';
import { agentBuilderDefaultAgentId } from '@kbn/agent-builder-common';
import type { KbnClient } from '@kbn/test';
import type { ToolingLog } from '@kbn/tooling-log';
import type {
  DefendPolicyFixture,
  DefendPolicyFixtureKeyPath,
  IndexedDefendPolicyFixtureEstate,
} from './defend_policy_fixture_estate';
import {
  DEFEND_POLICY_FIXTURE_PACKAGE_VERSION,
  deleteIndexedDefendPolicyFixtureEstate,
  indexDefendPolicyFixtureEstate,
} from './defend_policy_fixture_estate';
import { cleanupPolicyManagementApplyStateData } from './cleanup';
import { buildApplyStateLagAgentIdPrefix } from './defend_policy_apply_state_hosts';
import { evaluate } from '../evaluate';
import { waitForEndpointPackage } from './endpoint_data';

export interface DefendPolicyEstateTeardownClients {
  readonly esClient: Client;
  readonly internalEsClient: Client;
}

export {
  DEFEND_POLICY_DEFAULTS_VS_NEAR_DUPLICATE_KEY_PATHS as DEFAULTS_VS_NEAR_DUPLICATE_KEY_PATHS,
  nearDuplicateBlocklistOverride,
  nearDuplicateConfigFromStoredDefaults,
  nearDuplicateIntervalOverride,
} from './defend_policy_fixture_estate';

export const DEFAULTS_GLOBAL_MANIFEST_VERSION = 'latest';

export const EXPECTED_REVISION = {
  allDefaults: 1,
  overridden: 2,
} as const;

export interface DefendPolicyEstateHandle {
  readonly estate: IndexedDefendPolicyFixtureEstate;
  readonly shortRun: string;
  readonly allDefaults: DefendPolicyFixture;
  readonly exactDuplicate: DefendPolicyFixture;
  readonly nearDuplicate: DefendPolicyFixture;
  readonly unassigned: DefendPolicyFixture;
  readonly assignedZeroAgents: DefendPolicyFixture;
  readonly explicitAdvanced: DefendPolicyFixture;
  readonly secondarySpace?: DefendPolicyFixture;
  readonly pinnedManifest: DefendPolicyFixture;
  readonly all: readonly DefendPolicyFixture[];
}

export const setupDefendPolicyEstate = async ({
  kbnClient,
  log,
  secondarySpaceId,
}: {
  kbnClient: KbnClient;
  log: ToolingLog;
  secondarySpaceId?: string;
}): Promise<DefendPolicyEstateHandle> => {
  let estate: IndexedDefendPolicyFixtureEstate | undefined;

  try {
    estate = await indexDefendPolicyFixtureEstate({
      kbnClient,
      endpointPackageVersion: DEFEND_POLICY_FIXTURE_PACKAGE_VERSION,
      log,
      secondarySpaceId,
    });

    const {
      allDefaults,
      exactDuplicate,
      nearDuplicate,
      unassigned,
      assignedZeroAgents,
      explicitAdvanced,
      secondarySpace,
      pinnedManifest,
    } = estate.fixtures;

    const missing = Object.entries({
      allDefaults,
      exactDuplicate,
      nearDuplicate,
      unassigned,
      assignedZeroAgents,
      explicitAdvanced,
      pinnedManifest,
    })
      .filter(([, fixture]) => fixture === undefined)
      .map(([label]) => label);
    if (
      missing.length > 0 ||
      !allDefaults ||
      !exactDuplicate ||
      !nearDuplicate ||
      !unassigned ||
      !assignedZeroAgents ||
      !explicitAdvanced ||
      !pinnedManifest
    ) {
      throw new Error(
        `Defend policy fixture estate is incomplete — missing ${
          missing.join(', ') || 'unknown fixtures'
        }.`
      );
    }

    if (unassigned.agentPolicyIds.length !== 0) {
      throw new Error(
        `unassigned must be UNASSIGNED for the likely-unused scenarios, but it has ${unassigned.agentPolicyIds.length} agent policy assignment(s).`
      );
    }

    const all = [
      allDefaults,
      exactDuplicate,
      nearDuplicate,
      unassigned,
      assignedZeroAgents,
      explicitAdvanced,
      ...(secondarySpace ? [secondarySpace] : []),
      pinnedManifest,
    ];

    log.info(
      `[elastic-defend-policy-management eval] estate ready at package ${
        estate.endpointPackageVersion
      }: ${all.length} policies (secondarySpace ${secondarySpace ? 'present' : 'absent'})`
    );

    return {
      estate,
      shortRun: estate.shortRun,
      allDefaults,
      exactDuplicate,
      nearDuplicate,
      unassigned,
      assignedZeroAgents,
      explicitAdvanced,
      secondarySpace,
      pinnedManifest,
      all,
    };
  } catch (error) {
    if (estate) {
      try {
        await deleteIndexedDefendPolicyFixtureEstate(kbnClient, estate);
      } catch (cleanupError) {
        log.error(cleanupError instanceof Error ? cleanupError : String(cleanupError));
      }
    }
    throw error;
  }
};

export const teardownDefendPolicyEstate = async (
  kbnClient: KbnClient,
  handle: DefendPolicyEstateHandle | undefined,
  clients?: DefendPolicyEstateTeardownClients
): Promise<void> => {
  if (!handle) return;

  if (!clients) {
    throw new Error(
      'teardownDefendPolicyEstate requires esClient and internalEsClient for run-scoped apply-state cleanup'
    );
  }

  await cleanupPolicyManagementApplyStateData(
    clients,
    buildApplyStateLagAgentIdPrefix(handle.shortRun)
  );
  await deleteIndexedDefendPolicyFixtureEstate(kbnClient, handle.estate);
};

type DefendPolicyEstateGetter = (setupFailureMessage: string) => DefendPolicyEstateHandle;

export const registerDefendPolicyEstateLifecycle = (): DefendPolicyEstateGetter => {
  let handle: DefendPolicyEstateHandle | undefined;

  evaluate.beforeAll(async ({ kbnClient, esClient, agentBuilderClient, log }) => {
    await waitForEndpointPackage(kbnClient, esClient, log);
    handle = await setupDefendPolicyEstate({ kbnClient, log });

    try {
      await agentBuilderClient.converse({ agentId: agentBuilderDefaultAgentId, input: 'hello' });
    } catch (e) {
      log.warning(`Warmup failed: ${e}`);
    }
  });

  evaluate.afterAll(async ({ kbnClient, esClient, internalEsClient }) => {
    const estate = handle;
    handle = undefined;

    await teardownDefendPolicyEstate(kbnClient, estate, { esClient, internalEsClient });
  });

  return (setupFailureMessage) => {
    if (!handle) throw new Error(setupFailureMessage);
    return handle;
  };
};

export const assignedFixturePolicyIds = (handle: DefendPolicyEstateHandle): string[] =>
  handle.all
    .filter(({ agentPolicyIds }) => agentPolicyIds.length > 0)
    .map(({ packagePolicyId }) => packagePolicyId);

export const fixtureLeafValue = (
  fixture: DefendPolicyFixture,
  { keyPath, os }: DefendPolicyFixtureKeyPath
): unknown => {
  const fullPath = os ? `${os}.${keyPath}` : keyPath;
  let cursor: unknown = fixture.config;
  for (const segment of fullPath.split('.')) {
    if (typeof cursor !== 'object' || cursor === null) return undefined;
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return cursor;
};

export const negateStoredBoolean = (before: unknown): boolean => {
  if (typeof before !== 'boolean') {
    throw new Error(
      `assess-impact needs a boolean leaf to negate, but the stored config has ${JSON.stringify(
        before
      )}.`
    );
  }
  return !before;
};

export interface AssessImpactExpectation {
  readonly afterValue: boolean;
  readonly requestedDirection: 'on' | 'off';
  readonly requestedEffect: 'enabling' | 'disabling';
  readonly question: string;
  readonly criterion: string;
}

export const deriveAssessImpactExpectation = (
  before: unknown,
  policyName: string
): AssessImpactExpectation => {
  const afterValue = negateStoredBoolean(before);
  const requestedDirection = afterValue ? 'on' : 'off';
  const requestedEffect = afterValue ? 'enabling' : 'disabling';

  return {
    afterValue,
    requestedDirection,
    requestedEffect,
    question:
      `What would happen if I turned the Windows malware blocklist ${requestedDirection} in the ` +
      `Elastic Defend policy named "${policyName}"?`,
    criterion:
      `Grounds the ${requestedEffect} of the Windows malware blocklist in the assessment ` +
      "tool's computed facts (before/after leaf, validators, and any documentation it returned) " +
      'rather than inventing a security consequence',
  };
};
