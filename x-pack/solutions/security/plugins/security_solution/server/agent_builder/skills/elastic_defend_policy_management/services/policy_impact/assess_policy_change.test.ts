/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cloneDeep } from 'lodash';
import { Subject } from 'rxjs';
import type { ILicense } from '@kbn/licensing-types';
import { licenseMock } from '@kbn/licensing-plugin/common/licensing.mock';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import type { AgentClient, PackagePolicyClient } from '@kbn/fleet-plugin/server';
import {
  createMockAgentClient,
  createPackagePolicyServiceMock,
} from '@kbn/fleet-plugin/server/mocks';
import type { NewPackagePolicyInput } from '@kbn/fleet-plugin/common';
import {
  ALL_PRODUCT_FEATURE_KEYS,
  ProductFeatureSecurityKey,
} from '@kbn/security-solution-features/keys';

import { LicenseService } from '../../../../../../common/license';
import { allowedExperimentalValues } from '../../../../../../common';
import {
  DeviceControlAccessLevel,
  PolicyOperatingSystem,
  ProtectionModes,
} from '../../../../../../common/endpoint/types';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import type { PolicyChangeProposal } from '../../domain/impact/types';
import { ADVISORY_NOT_APPLIED_STATEMENT, META_PERSIST_REWRITES_UNKNOWN } from '../../domain/impact';
import type { AssignmentEvidence } from '../../domain/read/types';
import { buildTestRegistry, buildTestSnapshot } from '../../domain/impact/test_fixtures';
import { createProductFeaturesServiceMock } from '../../../../../lib/product_features_service/mocks';
import type { ProductFeaturesService } from '../../../../../lib/product_features_service';
import { assessPolicyChange } from './assess_policy_change';
import { fetchAffectedPopulation } from './affected_population';
import * as composeValidators from './compose_validators';

const PROHIBITED_PACKAGE_POLICY_METHODS = [
  'create',
  'bulkCreate',
  'update',
  'bulkUpdate',
  'delete',
  'upgrade',
  'bulkUpgrade',
  'rollback',
  'restoreRollback',
  'cleanupRollbackSavedObjects',
  'removeOutputFromAll',
  'runExternalCallbacks',
  'inspect',
] as const;

const buildInputs = (config: PolicyConfig): NewPackagePolicyInput[] => [
  { type: 'system', enabled: true, streams: [] },
  {
    type: 'endpoint',
    enabled: true,
    streams: [],
    config: {
      artifact_manifest: { value: { artifacts: {}, manifest_version: '1', schema_version: 'v1' } },
      policy: { value: config },
    },
  },
];

const COUNTED_POPULATION: AssignmentEvidence = {
  policyId: 'endpoint-policy-1',
  agentPolicyIds: ['agent-policy-1'],
  status: 'counted',
  agentCount: 17,
};

describe('assessPolicyChange', () => {
  const registry = buildTestRegistry();
  const logger = loggingSystemMock.createLogger();
  const Enterprise = licenseMock.createLicense({ license: { type: 'enterprise', uid: 'uid' } });
  const Gold = licenseMock.createLicense({ license: { type: 'gold', mode: 'gold', uid: 'uid' } });

  let licenseEmitter: Subject<ILicense>;
  let licenseService: LicenseService;
  let productFeaturesService: ProductFeaturesService;
  let packagePolicyService: jest.Mocked<PackagePolicyClient>;
  let agentClient: jest.Mocked<AgentClient>;

  beforeEach(() => {
    licenseEmitter = new Subject();
    licenseService = new LicenseService();
    licenseService.start(licenseEmitter);
    licenseEmitter.next(Enterprise);
    productFeaturesService = createProductFeaturesServiceMock();
    packagePolicyService = createPackagePolicyServiceMock();
    agentClient = createMockAgentClient() as jest.Mocked<AgentClient>;
  });

  afterEach(() => {
    licenseService.stop();
  });

  const buildProposal = (
    operations: PolicyChangeProposal['operations'],
    identity?: PolicyChangeProposal['identity']
  ): PolicyChangeProposal => ({
    policyId: 'endpoint-policy-1',
    identity: identity ?? { revision: 4, version: 'WzEyMyw0NV0=' },
    operations,
  });

  it('echoes the canonical proposal back byte-for-byte and marks the result unapplied', () => {
    const snapshot = buildTestSnapshot();
    const proposal = buildProposal([
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        expectedCurrentValue: ProtectionModes.prevent,
        proposedValue: ProtectionModes.detect,
      },
      { keyPath: 'events.file', os: PolicyOperatingSystem.linux, proposedValue: false },
    ]);
    const proposalSerialized = JSON.stringify(proposal);

    const result = assessPolicyChange({
      proposal,
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    expect(JSON.stringify(result.assessment.proposal)).toEqual(proposalSerialized);
    expect(result.assessment.proposal).toBe(proposal);
    expect(result.assessment.applied).toBe(false);
    expect(result.assessment.assessedIdentity).toEqual(snapshot.identity);
  });

  it('leaves the source config provably unmutated after a full assessment', () => {
    const snapshot = buildTestSnapshot();
    const sourceBefore = cloneDeep(snapshot.config);

    const result = assessPolicyChange({
      proposal: buildProposal([
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.off,
        },
        { keyPath: 'global_manifest_version', proposedValue: '2026-01-02' },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    expect(snapshot.config).toEqual(sourceBefore);
    expect(snapshot.config.windows.malware.mode).toBe(ProtectionModes.prevent);
    expect(snapshot.config.global_manifest_version).toBe('latest');
    expect(result.assessment.diffs).toEqual([
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        before: ProtectionModes.prevent,
        after: ProtectionModes.off,
        defaultValue: ProtectionModes.prevent,
        type: 'enum',
        enumValues: [ProtectionModes.detect, ProtectionModes.prevent, ProtectionModes.off],
      },
      {
        keyPath: 'global_manifest_version',
        os: undefined,
        before: 'latest',
        after: '2026-01-02',
        defaultValue: 'latest',
        type: 'string',
      },
      {
        keyPath: 'antivirus_registration.enabled',
        os: PolicyOperatingSystem.windows,
        before: true,
        after: false,
        defaultValue: false,
        type: 'boolean',
      },
    ]);
  });

  it('reports a passing and a failing validator, preserving the failing message verbatim', () => {
    const snapshot = buildTestSnapshot();

    const passing = assessPolicyChange({
      proposal: buildProposal([
        { keyPath: 'events.file', os: PolicyOperatingSystem.linux, proposedValue: false },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in passing) {
      throw new Error(`expected an assessment, got: ${passing.rejection.message}`);
    }

    expect(passing.assessment.validatorOutcomes).toEqual([
      { validator: 'package_policy', passed: true },
      { validator: 'license', passed: true },
      { validator: 'product_features', passed: true },
    ]);

    licenseEmitter.next(Gold);

    const failingSnapshot = buildTestSnapshot();
    failingSnapshot.config.windows.device_control = {
      enabled: true,
      usb_storage: DeviceControlAccessLevel.deny_all,
    };

    const failing = assessPolicyChange({
      proposal: buildProposal([
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.detect,
        },
      ]),
      snapshot: failingSnapshot,
      registry,
      inputs: buildInputs(failingSnapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in failing) {
      throw new Error(`expected an assessment, got: ${failing.rejection.message}`);
    }

    expect(
      failing.assessment.validatorOutcomes.find(({ validator }) => validator === 'license')
    ).toEqual({
      validator: 'license',
      passed: false,
      message: 'Gold license does not support this action. Please upgrade your license.',
    });

    expect(failing.assessment.validatorOutcomes).toHaveLength(3);

    expect(
      failing.assessment.verifiedConfigurationEffects.some((effect) =>
        effect.includes('Gold license does not support this action. Please upgrade your license.')
      )
    ).toBe(true);
  });

  it('rejects a stale revision, reports the current identity, and assesses nothing', () => {
    const snapshot = buildTestSnapshot({ revision: 11 });

    const result = assessPolicyChange({
      proposal: buildProposal(
        [
          {
            keyPath: 'malware.mode',
            os: PolicyOperatingSystem.windows,
            proposedValue: ProtectionModes.off,
          },
        ],
        { revision: 4, version: snapshot.identity.version }
      ),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if (!('rejection' in result)) {
      throw new Error('expected a stale_snapshot rejection');
    }

    expect(result.rejection.reason).toBe('stale_snapshot');
    expect(result.rejection.currentIdentity).toEqual(snapshot.identity);
    expect('assessment' in result).toBe(false);
  });

  it.each([
    [
      'unknown_key_path',
      { keyPath: 'malware.not_a_field', os: PolicyOperatingSystem.windows, proposedValue: true },
    ],
    [
      'not_applicable_for_os',
      {
        keyPath: 'antivirus_registration.enabled',
        os: PolicyOperatingSystem.linux,
        proposedValue: true,
      },
    ],
    [
      'outside_version_window',
      {
        keyPath: 'advanced.future_setting',
        os: PolicyOperatingSystem.windows,
        proposedValue: 'on',
      },
    ],
    [
      'current_value_mismatch',
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        expectedCurrentValue: ProtectionModes.off,
        proposedValue: ProtectionModes.detect,
      },
    ],
  ])('propagates the %s rejection without assessing anything', (reason, operation) => {
    const snapshot = buildTestSnapshot();

    const result = assessPolicyChange({
      proposal: buildProposal([operation]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if (!('rejection' in result)) {
      throw new Error(`expected a ${reason} rejection`);
    }

    expect(result.rejection.reason).toBe(reason);
    expect('assessment' in result).toBe(false);
  });

  it('separates the three evidence tiers and keeps runtime claims in unknowns only', () => {
    const snapshot = buildTestSnapshot();

    const result = assessPolicyChange({
      proposal: buildProposal([
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.detect,
        },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    const { verifiedConfigurationEffects, likelyPopulationEffects, unknowns } = result.assessment;

    expect(verifiedConfigurationEffects[0]).toBe(ADVISORY_NOT_APPLIED_STATEMENT);
    expect(verifiedConfigurationEffects).toEqual(
      expect.arrayContaining([
        `assessed_identity:${snapshot.identity.id}:${snapshot.identity.revision}:${snapshot.identity.version}`,
        'configuration:changed:2',
        'validator:package_policy:passed',
        'validator:license:passed',
        'validator:product_features:passed',
      ])
    );
    expect(likelyPopulationEffects).toEqual([
      'population:assigned:1',
      'population:active_agents:17',
    ]);
    expect(unknowns).toEqual(
      expect.arrayContaining([
        'runtime:policy_execution_unknown',
        'runtime:application_unknown',
        'runtime:endpoint_availability_unknown',
        'runtime:detection_alert_performance_unknown',
        'runtime:change_timing_unknown',
        'persist:meta_license_cloud_billable_unknown',
      ])
    );

    const outsideUnknowns = [...verifiedConfigurationEffects, ...likelyPopulationEffects]
      .join('\n')
      .toLowerCase();

    for (const term of ['running', 'online', 'checked in', 'in effect', 'will block']) {
      expect(outsideUnknowns).not.toContain(term);
    }
  });

  it('persists nothing: no prohibited Fleet method is reachable from the assessment', async () => {
    const snapshot = buildTestSnapshot();

    agentClient.getAgentStatusForAgentPolicy.mockResolvedValue({
      events: 0,
      online: 17,
      error: 0,
      offline: 0,
      other: 0,
      updating: 0,
      inactive: 0,
      unenrolled: 0,
      all: 17,
      active: 17,
    });

    const population = await fetchAffectedPopulation({
      policyId: snapshot.identity.id,
      agentPolicyIds: snapshot.policyIds,
      canReadFleetAgents: true,
      getAgentClient: () => agentClient,
      logger,
    });

    const assessArgs = {
      proposal: buildProposal([
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.detect,
        },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    };

    const result = assessPolicyChange(assessArgs);

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    expect(result.assessment.applied).toBe(false);

    const collaborators: readonly unknown[] = [...Object.values(assessArgs), agentClient];

    for (const collaborator of collaborators) {
      for (const method of PROHIBITED_PACKAGE_POLICY_METHODS) {
        expect(collaborator).not.toHaveProperty(method);
      }
    }

    for (const method of PROHIBITED_PACKAGE_POLICY_METHODS) {
      expect(packagePolicyService[method]).not.toHaveBeenCalled();
    }

    expect(agentClient.getAgentStatusForAgentPolicy).toHaveBeenCalledTimes(1);
  });

  it('adds the antivirus enabled delta when malware prevent becomes detect', () => {
    const snapshot = buildTestSnapshot();

    const result = assessPolicyChange({
      proposal: buildProposal([
        {
          keyPath: 'malware.mode',
          os: PolicyOperatingSystem.windows,
          proposedValue: ProtectionModes.detect,
        },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    expect(result.assessment.diffs).toEqual([
      {
        keyPath: 'malware.mode',
        os: PolicyOperatingSystem.windows,
        before: ProtectionModes.prevent,
        after: ProtectionModes.detect,
        defaultValue: ProtectionModes.prevent,
        type: 'enum',
        enumValues: [ProtectionModes.detect, ProtectionModes.prevent, ProtectionModes.off],
      },
      {
        keyPath: 'antivirus_registration.enabled',
        os: PolicyOperatingSystem.windows,
        before: true,
        after: false,
        defaultValue: false,
        type: 'boolean',
      },
    ]);
    expect(result.assessment.unknowns).toContain(META_PERSIST_REWRITES_UNKNOWN);
    expect(snapshot.config.windows.antivirus_registration.enabled).toBe(true);
  });

  it('keeps a blocklist-only assessment to exactly one diff', () => {
    const snapshot = buildTestSnapshot();

    const result = assessPolicyChange({
      proposal: buildProposal([
        {
          keyPath: 'malware.blocklist',
          os: PolicyOperatingSystem.windows,
          proposedValue: false,
        },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    expect(result.assessment.diffs).toEqual([
      {
        keyPath: 'malware.blocklist',
        os: PolicyOperatingSystem.windows,
        before: true,
        after: false,
        defaultValue: true,
        type: 'boolean',
      },
    ]);
  });

  it('validates the restored mac ransomware config before persist-gate assignment', () => {
    const snapshot = buildTestSnapshot();
    delete (snapshot.config.mac.ransomware as { mode?: ProtectionModes }).mode;
    const composeSpy = jest.spyOn(composeValidators, 'composePolicyValidators');

    const result = assessPolicyChange({
      proposal: buildProposal([
        { keyPath: 'events.file', os: PolicyOperatingSystem.linux, proposedValue: false },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    expect(composeSpy).toHaveBeenCalledTimes(1);
    expect(composeSpy.mock.calls[0][0].proposedConfig.mac.ransomware.mode).toBe(
      ProtectionModes.off
    );
    expect(snapshot.config.mac.ransomware.mode).toBeUndefined();
    expect(
      result.assessment.diffs.some(
        (diff) => diff.keyPath === 'ransomware.mode' && diff.os === PolicyOperatingSystem.mac
      )
    ).toBe(true);

    composeSpy.mockRestore();
  });

  it('does not turn malware off when both persist gates fire', () => {
    const snapshot = buildTestSnapshot();
    productFeaturesService = createProductFeaturesServiceMock(
      ALL_PRODUCT_FEATURE_KEYS.filter(
        (key) =>
          key !== ProductFeatureSecurityKey.endpointPolicyProtections &&
          key !== ProductFeatureSecurityKey.endpointTrustedDevices
      )
    );

    const result = assessPolicyChange({
      proposal: buildProposal([
        {
          keyPath: 'malware.blocklist',
          os: PolicyOperatingSystem.windows,
          proposedValue: false,
        },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: allowedExperimentalValues,
      logger,
    });

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    expect(
      result.assessment.diffs.find(
        (diff) => diff.keyPath === 'malware.mode' && diff.os === PolicyOperatingSystem.windows
      )
    ).toBeUndefined();
    expect(
      result.assessment.diffs.find(
        (diff) => diff.keyPath === 'malware.blocklist' && diff.os === PolicyOperatingSystem.windows
      )
    ).toEqual(
      expect.objectContaining({
        keyPath: 'malware.blocklist',
        os: PolicyOperatingSystem.windows,
        before: true,
        after: false,
      })
    );
    expect(
      result.assessment.diffs.some(
        (diff) => diff.keyPath === 'device_control.enabled' && diff.after === undefined
      )
    ).toBe(true);
  });

  it('drops device control when trustedDevices experimental state is off', () => {
    const snapshot = buildTestSnapshot();

    const result = assessPolicyChange({
      proposal: buildProposal([
        {
          keyPath: 'malware.blocklist',
          os: PolicyOperatingSystem.windows,
          proposedValue: false,
        },
      ]),
      snapshot,
      registry,
      inputs: buildInputs(snapshot.config),
      population: COUNTED_POPULATION,
      licenseService,
      productFeaturesService,
      experimentalFeatures: { ...allowedExperimentalValues, trustedDevices: false },
      logger,
    });

    if ('rejection' in result) {
      throw new Error(`expected an assessment, got: ${result.rejection.message}`);
    }

    expect(result.assessment.diffs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          keyPath: 'malware.blocklist',
          os: PolicyOperatingSystem.windows,
          after: false,
        }),
        expect.objectContaining({
          keyPath: 'device_control.enabled',
          os: PolicyOperatingSystem.windows,
          after: undefined,
        }),
      ])
    );
    expect(
      result.assessment.diffs.find(
        (diff) => diff.keyPath === 'malware.mode' && diff.after === ProtectionModes.off
      )
    ).toBeUndefined();
  });
});
