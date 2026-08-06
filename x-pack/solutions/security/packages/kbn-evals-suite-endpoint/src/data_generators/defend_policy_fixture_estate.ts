/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KbnClient } from '@kbn/test';
import type { ToolingLog } from '@kbn/tooling-log';
import { set } from '@kbn/safer-lodash-set';
import { cloneDeep, get } from 'lodash';
import type {
  CreatePackagePolicyRequest,
  CreatePackagePolicyResponse,
  UpdatePackagePolicyResponse,
} from '@kbn/fleet-plugin/common';
import {
  AGENT_POLICY_API_ROUTES,
  API_VERSIONS,
  PACKAGE_POLICY_API_ROUTES,
  packagePolicyRouteService,
} from '@kbn/fleet-plugin/common';
import {
  PolicyOperatingSystem,
  type PolicyConfig,
  type PolicyData,
} from '@kbn/security-solution-plugin/common/endpoint/types';
import {
  deleteIndexedFleetEndpointPolicies,
  indexFleetEndpointPolicy,
  type IndexedFleetEndpointPolicyResponse,
} from '@kbn/security-solution-plugin/common/endpoint/data_loaders/index_fleet_endpoint_policy';
import {
  RETRYABLE_TRANSIENT_ERRORS,
  retryOnError,
} from '@kbn/security-solution-plugin/common/endpoint/data_loaders/utils';
import { catchHttpErrorFormatAndThrow } from '@kbn/security-solution-plugin/common/endpoint/format_http_error';
import { policyFactory as policyConfigFactory } from '@kbn/security-solution-plugin/common/endpoint/models/policy_config';
import { getPolicyDataForUpdate } from '@kbn/security-solution-plugin/common/endpoint/service/policy/get_policy_data_for_update';

export const DEFEND_POLICY_FIXTURE_PACKAGE_VERSION = '9.4.0';

export type DefendPolicyFixtureLabel =
  | 'allDefaults'
  | 'exactDuplicate'
  | 'nearDuplicate'
  | 'unassigned'
  | 'assignedZeroAgents'
  | 'explicitAdvanced'
  | 'secondarySpace'
  | 'pinnedManifest';

export interface DefendPolicyFixtureKeyPath {
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
}

export const DEFEND_POLICY_DEFAULTS_VS_NEAR_DUPLICATE_KEY_PATHS: readonly DefendPolicyFixtureKeyPath[] =
  [
    { keyPath: 'malware.blocklist', os: PolicyOperatingSystem.windows },
    { keyPath: 'advanced.artifacts.global.interval', os: PolicyOperatingSystem.windows },
  ];

export const DEFEND_POLICY_EXPLICIT_ADVANCED_KEY_PATHS: readonly DefendPolicyFixtureKeyPath[] = [
  { keyPath: 'advanced.malware.quarantine', os: PolicyOperatingSystem.windows },
  { keyPath: 'advanced.elasticsearch.delay', os: PolicyOperatingSystem.windows },
  { keyPath: 'advanced.agent.connection_delay', os: PolicyOperatingSystem.linux },
  { keyPath: 'advanced.events.image_load.dll_hijack_detection', os: PolicyOperatingSystem.windows },
];

export const DEFEND_POLICY_VERSION_UNAVAILABLE_ADVANCED_KEY_PATH: DefendPolicyFixtureKeyPath = {
  keyPath: 'advanced.events.image_load.dll_hijack_detection',
  os: PolicyOperatingSystem.windows,
};

export const DEFEND_POLICY_PINNED_GLOBAL_MANIFEST_VERSION = '2025-06-03';

export interface DefendPolicyFixture {
  readonly label: DefendPolicyFixtureLabel;
  readonly name: string;
  readonly packagePolicyId: string;
  readonly agentPolicyIds: string[];
  readonly revision: number;
  readonly version?: string;
  readonly config: PolicyConfig;
  readonly spaceIds?: string[];
}

export interface IndexedDefendPolicyFixtureSpaceGroup {
  readonly requestSpaceId?: string;
  readonly indexedPolicies: IndexedFleetEndpointPolicyResponse;
}

export interface IndexedDefendPolicyFixtureEstate {
  readonly endpointPackageVersion: string;
  readonly shortRun: string;
  readonly fixtures: Partial<Record<DefendPolicyFixtureLabel, DefendPolicyFixture>>;
  readonly indexedPolicies: IndexedFleetEndpointPolicyResponse;
  readonly indexedPoliciesByRequestSpace: readonly IndexedDefendPolicyFixtureSpaceGroup[];
}

export interface IndexDefendPolicyFixtureEstateOptions {
  kbnClient: KbnClient;
  endpointPackageVersion: string;
  log?: ToolingLog;
  secondarySpaceId?: string;
  shortRun?: string;
}

export const createDefendPolicyFixtureShortRun = (): string => {
  let token = '';

  while (token.length < 12) {
    token += Math.random().toString(36).slice(2);
  }

  return token.slice(0, 12);
};

export const fleetPackagePolicyName = (base: string, shortRun: string): string =>
  `${base} · ${shortRun}`;

const applyKeyPaths = (
  config: PolicyConfig,
  values: ReadonlyArray<readonly [DefendPolicyFixtureKeyPath, unknown]>
): PolicyConfig => {
  for (const [{ keyPath, os }, value] of values) {
    set(config, os ? `${os}.${keyPath}` : keyPath, value);
  }

  return config;
};

const readKeyPath = (config: PolicyConfig, { keyPath, os }: DefendPolicyFixtureKeyPath): unknown =>
  get(config, os ? `${os}.${keyPath}` : keyPath);

const NEAR_DUPLICATE_INTERVAL_SECONDS = 7200;
const NEAR_DUPLICATE_INTERVAL_ALTERNATE_SECONDS = 3600;

export const nearDuplicateBlocklistOverride = (storedBlocklist: unknown): boolean => {
  if (typeof storedBlocklist !== 'boolean') {
    throw new Error(
      `nearDuplicate needs a boolean leaf to negate, but the stored config has ${JSON.stringify(
        storedBlocklist
      )}.`
    );
  }

  return !storedBlocklist;
};

export const nearDuplicateIntervalOverride = (storedInterval: unknown): number =>
  storedInterval === NEAR_DUPLICATE_INTERVAL_SECONDS
    ? NEAR_DUPLICATE_INTERVAL_ALTERNATE_SECONDS
    : NEAR_DUPLICATE_INTERVAL_SECONDS;

export const nearDuplicateConfigFromStoredDefaults = (
  storedDefaults: PolicyConfig
): PolicyConfig => {
  const [blocklistPath, intervalPath] = DEFEND_POLICY_DEFAULTS_VS_NEAR_DUPLICATE_KEY_PATHS;

  return applyKeyPaths(cloneDeep(storedDefaults), [
    [blocklistPath, nearDuplicateBlocklistOverride(readKeyPath(storedDefaults, blocklistPath))],
    [intervalPath, nearDuplicateIntervalOverride(readKeyPath(storedDefaults, intervalPath))],
  ]);
};

enum TimeoutsInMS {
  TEN_SECONDS = 10 * 1000,
  FIVE_MINUTES = 5 * 60 * 1000,
}

const withFleetRequestSpace = (kbnClient: KbnClient, requestSpaceId?: string): KbnClient => {
  if (!requestSpaceId) {
    return kbnClient;
  }

  const prefix = `/s/${requestSpaceId}`;

  return new Proxy(kbnClient, {
    get(target, prop, receiver) {
      if (prop === 'request') {
        const request = target.request.bind(target);

        const requestWithSpace: KbnClient['request'] = async (params) => {
          const { path } = params;

          return request({
            ...params,
            path: path.startsWith('/s/') ? path : `${prefix}${path}`,
          });
        };

        return requestWithSpace;
      }

      return Reflect.get(target, prop, receiver);
    },
  }) as KbnClient;
};

interface FleetCreatedItem {
  readonly id: string;
}

interface FleetCreateResponse {
  readonly data?: {
    readonly item?: FleetCreatedItem;
  };
}

const requestSpaceFromPath = (path: string): { spaceKey: string; requestSpaceId?: string } => {
  if (!path.startsWith('/s/')) {
    return { spaceKey: '' };
  }

  const requestSpaceId = path.split('/')[2];
  return { spaceKey: requestSpaceId, requestSpaceId };
};

const ensureJournalGroup = (
  journal: Map<string, IndexedDefendPolicyFixtureSpaceGroup>,
  path: string
): IndexedDefendPolicyFixtureSpaceGroup => {
  const { spaceKey, requestSpaceId } = requestSpaceFromPath(path);
  const existing = journal.get(spaceKey);

  if (existing) {
    return existing;
  }

  const group: IndexedDefendPolicyFixtureSpaceGroup = {
    ...(requestSpaceId === undefined ? {} : { requestSpaceId }),
    indexedPolicies: { integrationPolicies: [], agentPolicies: [] },
  };
  journal.set(spaceKey, group);
  return group;
};

const withSuccessfulCreateJournal = (
  kbnClient: KbnClient,
  journal: Map<string, IndexedDefendPolicyFixtureSpaceGroup>
): KbnClient =>
  new Proxy(kbnClient, {
    get(target, prop, receiver) {
      if (prop === 'request') {
        const request = target.request.bind(target);

        const requestWithJournal: KbnClient['request'] = async <T>(
          params: Parameters<KbnClient['request']>[0]
        ) => {
          const response = await request<T>(params);
          const { path, method } = params;

          if (method === 'POST') {
            const item = (response as FleetCreateResponse).data?.item;

            if (item) {
              const group = ensureJournalGroup(journal, path);

              if (path.endsWith(AGENT_POLICY_API_ROUTES.CREATE_PATTERN)) {
                group.indexedPolicies.agentPolicies.push(
                  item as IndexedFleetEndpointPolicyResponse['agentPolicies'][number]
                );
              } else if (path.endsWith(PACKAGE_POLICY_API_ROUTES.CREATE_PATTERN)) {
                group.indexedPolicies.integrationPolicies.push(item as PolicyData);
              }
            }
          }

          return response;
        };

        return requestWithJournal;
      }

      return Reflect.get(target, prop, receiver);
    },
  }) as KbnClient;

const estateFromCreateJournal = (
  endpointPackageVersion: string,
  shortRun: string,
  journal: Map<string, IndexedDefendPolicyFixtureSpaceGroup>
): IndexedDefendPolicyFixtureEstate => {
  const indexedPoliciesByRequestSpace = [...journal.values()];

  return {
    endpointPackageVersion,
    shortRun,
    fixtures: {},
    indexedPolicies: {
      integrationPolicies: indexedPoliciesByRequestSpace.flatMap(
        ({ indexedPolicies }) => indexedPolicies.integrationPolicies
      ),
      agentPolicies: indexedPoliciesByRequestSpace.flatMap(
        ({ indexedPolicies }) => indexedPolicies.agentPolicies
      ),
    },
    indexedPoliciesByRequestSpace,
  };
};

const applyPolicyConfigOverride = async (
  kbnClient: KbnClient,
  createdPolicy: PolicyData,
  override: (config: PolicyConfig) => PolicyConfig,
  log?: ToolingLog
): Promise<PolicyData> => {
  const configuredPolicy = getPolicyDataForUpdate(createdPolicy);
  configuredPolicy.inputs[0].config.policy.value = override(
    configuredPolicy.inputs[0].config.policy.value
  );

  log?.debug(`Applying policy config override to integration policy: ${createdPolicy.name}`);

  const updatedPolicy = (
    await kbnClient
      .request<UpdatePackagePolicyResponse>({
        path: packagePolicyRouteService.getUpdatePath(createdPolicy.id),
        method: 'PUT',
        body: configuredPolicy,
        headers: {
          'elastic-api-version': API_VERSIONS.public.v1,
        },
      })
      .catch(catchHttpErrorFormatAndThrow)
      .then((res) => res.data)
  ).item as PolicyData;

  log?.verbose(`Integration policy configured:`, JSON.stringify(updatedPolicy, null, 2));

  return updatedPolicy;
};

const indexUnassignedEndpointPolicy = async (
  kbnClient: KbnClient,
  policyName: string,
  endpointPackageVersion: string,
  log?: ToolingLog
): Promise<IndexedFleetEndpointPolicyResponse> => {
  const newPackagePolicyData: Omit<CreatePackagePolicyRequest['body'], 'policy_ids'> = {
    name: policyName,
    description: 'Protect the worlds data',
    enabled: true,
    inputs: [
      {
        type: 'endpoint',
        enabled: true,
        streams: [],
        config: {
          policy: {
            value: policyConfigFactory(),
          },
        },
      },
    ],
    namespace: 'default',
    package: {
      name: 'endpoint',
      title: 'Elastic Defend',
      version: endpointPackageVersion,
    },
  };

  const createPackagePolicy = async (): Promise<CreatePackagePolicyResponse> =>
    kbnClient
      .request<CreatePackagePolicyResponse>({
        path: PACKAGE_POLICY_API_ROUTES.CREATE_PATTERN,
        method: 'POST',
        body: newPackagePolicyData,
        headers: {
          'elastic-api-version': API_VERSIONS.public.v1,
        },
      })
      .catch(catchHttpErrorFormatAndThrow)
      .then((res) => res.data);

  const started = new Date();
  const hasTimedOut = (): boolean => {
    const elapsedTime = Date.now() - started.getTime();
    return elapsedTime > TimeoutsInMS.FIVE_MINUTES;
  };

  let packagePolicy: CreatePackagePolicyResponse | undefined;
  log?.debug(`Creating integration policy with name: ${policyName}`);

  while (!packagePolicy && !hasTimedOut()) {
    packagePolicy = await retryOnError(
      async () => createPackagePolicy(),
      [...RETRYABLE_TRANSIENT_ERRORS, 'resource_not_found_exception'],
      log
    );

    if (!packagePolicy) {
      await new Promise((resolve) => setTimeout(resolve, TimeoutsInMS.TEN_SECONDS));
    }
  }

  if (!packagePolicy) {
    throw new Error(`Create package policy failed`);
  }

  log?.verbose(`Integration policy created:`, JSON.stringify(packagePolicy, null, 2));

  return {
    integrationPolicies: [packagePolicy.item as PolicyData],
    agentPolicies: [],
  };
};

export const deleteIndexedDefendPolicyFixtureEstate = async (
  kbnClient: KbnClient,
  estate: IndexedDefendPolicyFixtureEstate
): Promise<void> => {
  for (const { requestSpaceId, indexedPolicies } of estate.indexedPoliciesByRequestSpace) {
    await deleteIndexedFleetEndpointPolicies(
      withFleetRequestSpace(kbnClient, requestSpaceId),
      indexedPolicies
    );
  }
};

export const indexDefendPolicyFixtureEstate = async ({
  kbnClient,
  endpointPackageVersion,
  log,
  secondarySpaceId,
  shortRun: injectedShortRun,
}: IndexDefendPolicyFixtureEstateOptions): Promise<IndexedDefendPolicyFixtureEstate> => {
  const shortRun = injectedShortRun ?? createDefendPolicyFixtureShortRun();
  const fixtures: Partial<Record<DefendPolicyFixtureLabel, DefendPolicyFixture>> = {};
  const indexedPolicies: IndexedFleetEndpointPolicyResponse = {
    integrationPolicies: [],
    agentPolicies: [],
  };
  const byRequestSpace = new Map<string, IndexedDefendPolicyFixtureSpaceGroup>();
  const rollbackJournal = new Map<string, IndexedDefendPolicyFixtureSpaceGroup>();
  const journaledClient = withSuccessfulCreateJournal(kbnClient, rollbackJournal);

  const createFixture = async (
    label: DefendPolicyFixtureLabel,
    baseName: string,
    {
      override,
      unassigned,
      spaceId,
    }: {
      override?: (config: PolicyConfig) => PolicyConfig;
      unassigned?: boolean;
      spaceId?: string;
    } = {}
  ): Promise<DefendPolicyFixture> => {
    const name = fleetPackagePolicyName(baseName, shortRun);
    log?.debug(`Creating Defend policy fixture [${label}]: ${name}`);

    const client = withFleetRequestSpace(journaledClient, spaceId);
    let indexed: IndexedFleetEndpointPolicyResponse;

    if (unassigned) {
      indexed = await indexUnassignedEndpointPolicy(client, name, endpointPackageVersion, log);
    } else {
      indexed = await indexFleetEndpointPolicy(
        client,
        name,
        endpointPackageVersion,
        `Agent policy for ${name}`,
        log,
        spaceId ? [spaceId] : undefined
      );

      if (override) {
        const updated = await applyPolicyConfigOverride(
          client,
          indexed.integrationPolicies[0],
          override,
          log
        );
        indexed = {
          agentPolicies: indexed.agentPolicies,
          integrationPolicies: [updated],
        };
      }
    }

    indexedPolicies.integrationPolicies.push(...indexed.integrationPolicies);
    indexedPolicies.agentPolicies.push(...indexed.agentPolicies);

    const spaceKey = spaceId ?? '';
    let group = byRequestSpace.get(spaceKey);

    if (group === undefined) {
      group = {
        ...(spaceId === undefined ? {} : { requestSpaceId: spaceId }),
        indexedPolicies: { integrationPolicies: [], agentPolicies: [] },
      };
      byRequestSpace.set(spaceKey, group);
    }

    group.indexedPolicies.integrationPolicies.push(...indexed.integrationPolicies);
    group.indexedPolicies.agentPolicies.push(...indexed.agentPolicies);

    const [packagePolicy] = indexed.integrationPolicies;

    const fixture: DefendPolicyFixture = {
      label,
      name: packagePolicy.name,
      packagePolicyId: packagePolicy.id,
      agentPolicyIds: packagePolicy.policy_ids ?? [],
      revision: packagePolicy.revision,
      version: packagePolicy.version,
      config: packagePolicy.inputs[0].config.policy.value,
      spaceIds: packagePolicy.spaceIds,
    };

    fixtures[label] = fixture;

    return fixture;
  };

  let completed = false;

  try {
    const allDefaults = await createFixture('allDefaults', 'All Defaults');

    await createFixture('exactDuplicate', 'Exact Duplicate Of All Defaults', {
      override: () => cloneDeep(allDefaults.config),
    });

    await createFixture('nearDuplicate', 'Near Duplicate Of All Defaults', {
      override: () => nearDuplicateConfigFromStoredDefaults(allDefaults.config),
    });

    await createFixture('unassigned', 'Unassigned', { unassigned: true });

    await createFixture('assignedZeroAgents', 'Assigned Zero Agents');

    await createFixture('explicitAdvanced', 'Explicit Advanced Settings', {
      override: () =>
        applyKeyPaths(cloneDeep(allDefaults.config), [
          [DEFEND_POLICY_EXPLICIT_ADVANCED_KEY_PATHS[0], false],
          [DEFEND_POLICY_EXPLICIT_ADVANCED_KEY_PATHS[1], 300],
          [DEFEND_POLICY_EXPLICIT_ADVANCED_KEY_PATHS[2], 120],
          [DEFEND_POLICY_EXPLICIT_ADVANCED_KEY_PATHS[3], false],
        ]),
    });

    if (secondarySpaceId) {
      await createFixture('secondarySpace', 'Secondary Space', { spaceId: secondarySpaceId });
    } else {
      log?.debug(
        'No `secondarySpaceId` supplied - skipping Defend policy fixture [secondarySpace]'
      );
    }

    await createFixture('pinnedManifest', 'Pinned Protection Updates', {
      override: () => ({
        ...cloneDeep(allDefaults.config),
        global_manifest_version: DEFEND_POLICY_PINNED_GLOBAL_MANIFEST_VERSION,
      }),
    });

    completed = true;

    return {
      endpointPackageVersion,
      shortRun,
      fixtures,
      indexedPolicies,
      indexedPoliciesByRequestSpace: [...byRequestSpace.values()],
    };
  } finally {
    if (!completed) {
      try {
        await deleteIndexedDefendPolicyFixtureEstate(
          kbnClient,
          estateFromCreateJournal(endpointPackageVersion, shortRun, rollbackJournal)
        );
      } catch (cleanupError) {
        log?.error(cleanupError instanceof Error ? cleanupError : String(cleanupError));
      }
    }
  }
};
