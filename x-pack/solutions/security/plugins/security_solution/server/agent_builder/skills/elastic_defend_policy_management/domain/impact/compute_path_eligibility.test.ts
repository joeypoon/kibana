/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { licenseMock } from '@kbn/licensing-plugin/common/licensing.mock';
import type { ILicense } from '@kbn/licensing-types';
import moment from 'moment';
import { policyFactory } from '../../../../../../common/endpoint/models/policy_config';
import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import { DeviceControlAccessLevel, ProtectionModes } from '../../../../../../common/endpoint/types';
import { buildEligibilityContext } from './build_eligibility_context';
import { computePathEligibility } from './compute_path_eligibility';
import { prepareChangeSet } from './prepare_change_set';
import type { EligibilityContext } from './policy_change_operation';

const Gold = licenseMock.createLicense({ license: { type: 'gold', mode: 'gold' } });
const Platinum = licenseMock.createLicense({ license: { type: 'platinum', mode: 'platinum' } });
const Enterprise = licenseMock.createLicense({ license: { type: 'enterprise' } });

const eligibilityContext = (
  proposedConfig: PolicyConfig,
  options: {
    license?: ILicense;
    endpointPolicyProtections?: boolean;
    endpointTrustedDevices?: boolean;
    trustedDevicesExperimental?: boolean;
    endpointProtectionUpdates?: boolean;
    serverless?: boolean;
  } = {}
): EligibilityContext =>
  buildEligibilityContext({
    proposedConfig,
    licenseInformation: options.license ?? Enterprise,
    endpointPolicyProtections: options.endpointPolicyProtections ?? true,
    endpointTrustedDevices: options.endpointTrustedDevices ?? true,
    trustedDevicesExperimental: options.trustedDevicesExperimental ?? true,
    endpointProtectionUpdates: options.endpointProtectionUpdates ?? true,
    serverless: options.serverless ?? false,
  });

const recentManifestDate = (): string => moment.utc().subtract(1, 'day').format('YYYY-MM-DD');

const rawRequest = (changes: unknown, idOrName = 'policy-1'): unknown => ({
  idOrName,
  changes,
});

describe('computePathEligibility', () => {
  it('marks ungated event collection eligible on any license', () => {
    const proposed = policyFactory();
    expect(
      computePathEligibility(
        'linux.events.process',
        eligibilityContext(proposed, { license: Gold })
      )
    ).toEqual({ eligible: true });
    expect(
      computePathEligibility(
        'linux.events.process',
        eligibilityContext(proposed, { license: Platinum })
      )
    ).toEqual({ eligible: true });
    expect(computePathEligibility('linux.events.process', eligibilityContext(proposed))).toEqual({
      eligible: true,
    });
  });

  it('marks platinum protections ineligible on gold while malware mode stays eligible', () => {
    const context = eligibilityContext(policyFactory(), { license: Gold });

    expect(computePathEligibility('windows.ransomware.mode', context)).toEqual({
      eligible: false,
      reason: 'license_below_platinum',
    });
    expect(computePathEligibility('mac.memory_protection.mode', context)).toEqual({
      eligible: false,
      reason: 'license_below_platinum',
    });
    expect(computePathEligibility('linux.behavior_protection.mode', context)).toEqual({
      eligible: false,
      reason: 'license_below_platinum',
    });
    expect(computePathEligibility('windows.popup.ransomware.enabled', context)).toEqual({
      eligible: false,
      reason: 'license_below_platinum',
    });
    expect(
      computePathEligibility(
        'windows.attack_surface_reduction.credential_hardening.enabled',
        context
      )
    ).toEqual({
      eligible: false,
      reason: 'license_below_platinum',
    });
    const disabledMalwarePopup = policyFactory();
    disabledMalwarePopup.windows.popup.malware.enabled = false;
    expect(
      computePathEligibility(
        'windows.popup.malware.enabled',
        eligibilityContext(disabledMalwarePopup, { license: Gold })
      )
    ).toEqual({
      eligible: false,
      reason: 'license_below_platinum',
    });
    expect(computePathEligibility('windows.malware.mode', context)).toEqual({ eligible: true });
    expect(computePathEligibility('windows.antivirus_registration.enabled', context)).toEqual({
      eligible: true,
    });
    expect(computePathEligibility('linux.events.process', context)).toEqual({ eligible: true });
  });

  it('marks device_control and global_manifest_version ineligible on platinum', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = '2024-01-01';
    const context = eligibilityContext(proposed, { license: Platinum });

    expect(computePathEligibility('windows.device_control.enabled', context)).toEqual({
      eligible: false,
      reason: 'license_below_enterprise',
    });
    expect(computePathEligibility('mac.popup.device_control.enabled', context)).toEqual({
      eligible: false,
      reason: 'license_below_enterprise',
    });
    expect(computePathEligibility('global_manifest_version', context)).toEqual({
      eligible: false,
      reason: 'license_below_enterprise',
    });
    expect(computePathEligibility('windows.ransomware.mode', context)).toEqual({ eligible: true });
    expect(computePathEligibility('windows.malware.mode', context)).toEqual({ eligible: true });
    expect(computePathEligibility('linux.events.process', context)).toEqual({ eligible: true });
  });

  it('marks divergent macOS and Linux behavior_protection eligible on platinum', () => {
    const proposed = policyFactory();
    proposed.windows.behavior_protection.mode = ProtectionModes.off;
    proposed.mac.behavior_protection.mode = ProtectionModes.detect;
    proposed.linux.behavior_protection.mode = ProtectionModes.prevent;
    const context = eligibilityContext(proposed, { license: Platinum });

    expect(computePathEligibility('windows.behavior_protection.mode', context)).toEqual({
      eligible: true,
    });
    expect(computePathEligibility('mac.behavior_protection.mode', context)).toEqual({
      eligible: true,
    });
    expect(computePathEligibility('linux.behavior_protection.mode', context)).toEqual({
      eligible: true,
    });
  });

  it('marks divergent macOS and Linux behavior_protection eligible on enterprise', () => {
    const proposed = policyFactory();
    proposed.windows.behavior_protection.mode = ProtectionModes.off;
    proposed.mac.behavior_protection.mode = ProtectionModes.detect;
    proposed.linux.behavior_protection.mode = ProtectionModes.prevent;
    const context = eligibilityContext(proposed);

    expect(computePathEligibility('windows.behavior_protection.mode', context)).toEqual({
      eligible: true,
    });
    expect(computePathEligibility('mac.behavior_protection.mode', context)).toEqual({
      eligible: true,
    });
    expect(computePathEligibility('linux.behavior_protection.mode', context)).toEqual({
      eligible: true,
    });
  });

  it('marks paid paths eligible on enterprise with product features enabled', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = recentManifestDate();
    const context = eligibilityContext(proposed);

    expect(computePathEligibility('windows.ransomware.mode', context)).toEqual({ eligible: true });
    expect(computePathEligibility('windows.device_control.enabled', context)).toEqual({
      eligible: true,
    });
    expect(computePathEligibility('global_manifest_version', context)).toEqual({ eligible: true });
    expect(
      computePathEligibility(
        'windows.attack_surface_reduction.credential_hardening.enabled',
        context
      )
    ).toEqual({ eligible: true });
  });

  it('marks a dated global_manifest_version ineligible when endpointProtectionUpdates is disabled', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = '2024-01-01';
    const context = eligibilityContext(proposed, { endpointProtectionUpdates: false });

    expect(computePathEligibility('global_manifest_version', context)).toEqual({
      eligible: false,
      reason: 'endpoint_protection_updates_disabled',
    });
  });

  it('marks a dated global_manifest_version eligible when endpointProtectionUpdates is enabled', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = recentManifestDate();
    const context = eligibilityContext(proposed, { endpointProtectionUpdates: true });

    expect(computePathEligibility('global_manifest_version', context)).toEqual({ eligible: true });
  });

  it('keeps latest global_manifest_version eligible when endpointProtectionUpdates is disabled', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = 'latest';
    const context = eligibilityContext(proposed, { endpointProtectionUpdates: false });

    expect(computePathEligibility('global_manifest_version', context)).toEqual({ eligible: true });
  });

  it('prefers license_below_enterprise over endpoint_protection_updates_disabled on platinum', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = '2024-01-01';
    const context = eligibilityContext(proposed, {
      license: Platinum,
      endpointProtectionUpdates: false,
    });

    expect(computePathEligibility('global_manifest_version', context)).toEqual({
      eligible: false,
      reason: 'license_below_enterprise',
    });
  });

  it('rejects a global_manifest_version with an invalid date format', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = 'not-a-date';
    const context = eligibilityContext(proposed);

    expect(computePathEligibility('global_manifest_version', context)).toEqual({
      eligible: false,
      reason: 'global_manifest_version_invalid_format',
    });
  });

  it('rejects a global_manifest_version older than the controlled-artifact cutoff', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = '2020-01-01';
    const context = eligibilityContext(proposed);

    expect(computePathEligibility('global_manifest_version', context)).toEqual({
      eligible: false,
      reason: 'global_manifest_version_too_old',
    });
  });

  it('rejects a future global_manifest_version', () => {
    const proposed = policyFactory();
    proposed.global_manifest_version = moment.utc().add(1, 'day').format('YYYY-MM-DD');
    const context = eligibilityContext(proposed);

    expect(computePathEligibility('global_manifest_version', context)).toEqual({
      eligible: false,
      reason: 'global_manifest_version_in_future',
    });
  });

  it('skips license-tier gating in serverless', () => {
    const context = eligibilityContext(policyFactory(), { license: Gold, serverless: true });

    expect(computePathEligibility('windows.ransomware.mode', context)).toEqual({ eligible: true });
    expect(computePathEligibility('windows.malware.mode', context)).toEqual({ eligible: true });
  });

  it('keeps product-feature gating in serverless', () => {
    const context = eligibilityContext(policyFactory(), {
      serverless: true,
      endpointPolicyProtections: false,
    });

    expect(computePathEligibility('windows.malware.mode', context)).toEqual({
      eligible: false,
      reason: 'endpoint_policy_protections_disabled',
    });
    expect(computePathEligibility('linux.events.process', context)).toEqual({ eligible: true });
  });

  it('marks protection paths ineligible when endpointPolicyProtections is disabled', () => {
    const context = eligibilityContext(policyFactory(), {
      endpointPolicyProtections: false,
    });

    expect(computePathEligibility('windows.malware.mode', context)).toEqual({
      eligible: false,
      reason: 'endpoint_policy_protections_disabled',
    });
    expect(computePathEligibility('windows.popup.malware.enabled', context)).toEqual({
      eligible: false,
      reason: 'endpoint_policy_protections_disabled',
    });
    expect(computePathEligibility('linux.events.process', context)).toEqual({ eligible: true });
  });

  it('marks device_control ineligible when trusted devices product feature is disabled', () => {
    const context = eligibilityContext(policyFactory(), { endpointTrustedDevices: false });

    expect(computePathEligibility('windows.device_control.enabled', context)).toEqual({
      eligible: false,
      reason: 'endpoint_trusted_devices_disabled',
    });
    expect(computePathEligibility('mac.popup.device_control.enabled', context)).toEqual({
      eligible: false,
      reason: 'endpoint_trusted_devices_disabled',
    });
    expect(computePathEligibility('windows.malware.mode', context)).toEqual({ eligible: true });
  });

  it('marks device_control ineligible when trustedDevices experimental flag is off', () => {
    const context = eligibilityContext(policyFactory(), { trustedDevicesExperimental: false });

    expect(computePathEligibility('windows.device_control.enabled', context)).toEqual({
      eligible: false,
      reason: 'trusted_devices_experimental_disabled',
    });
    expect(computePathEligibility('windows.malware.mode', context)).toEqual({ eligible: true });
  });

  it('marks platinum usb_storage read_only eligible when device_control is disabled', () => {
    const proposed = policyFactory();
    proposed.windows.device_control = {
      enabled: false,
      usb_storage: DeviceControlAccessLevel.read_only,
    };
    const context = eligibilityContext(proposed, { license: Platinum });

    expect(computePathEligibility('windows.device_control.usb_storage', context)).toEqual({
      eligible: true,
    });
  });

  it('marks gold linux.behavior_protection.reputation_service true eligible', () => {
    const proposed = policyFactory();
    proposed.linux.behavior_protection.reputation_service = true;
    const context = eligibilityContext(proposed, { license: Gold });

    expect(computePathEligibility('linux.behavior_protection.reputation_service', context)).toEqual(
      { eligible: true }
    );
  });

  it('marks usb_storage ineligible when trusted devices product feature is disabled', () => {
    const proposed = policyFactory();
    proposed.windows.device_control = {
      enabled: false,
      usb_storage: DeviceControlAccessLevel.read_only,
    };
    const context = eligibilityContext(proposed, {
      license: Platinum,
      endpointTrustedDevices: false,
    });

    expect(computePathEligibility('windows.device_control.usb_storage', context)).toEqual({
      eligible: false,
      reason: 'endpoint_trusted_devices_disabled',
    });
  });

  it('does not mark coupled malware paths ineligible on enterprise', () => {
    const prepared = prepareChangeSet(
      rawRequest([{ op: 'set_protection_enabled', protection: 'malware', enabled: false }]),
      policyFactory()
    );
    const context = eligibilityContext(prepared.proposedConfig);

    expect(prepared.explicitChanges.length).toBeGreaterThan(0);
    expect(
      prepared.explicitChanges.every(
        (change) => computePathEligibility(change.path, context).eligible
      )
    ).toBe(true);
  });

  it('keeps eligibility per path on a mixed gold change set', () => {
    const prepared = prepareChangeSet(
      rawRequest([
        { op: 'set_protection_level', protection: 'malware', mode: ProtectionModes.prevent },
        { op: 'set_protection_level', protection: 'ransomware', mode: ProtectionModes.prevent },
        {
          op: 'set_field',
          path: 'windows.attack_surface_reduction.credential_hardening.enabled',
          value: true,
        },
        { op: 'set_field', path: 'linux.events.session_data', value: true },
      ]),
      policyFactory()
    );
    const context = eligibilityContext(prepared.proposedConfig, { license: Gold });

    expect(prepared.explicitChanges.length).toBeGreaterThan(0);
    expect(computePathEligibility('windows.malware.mode', context)).toEqual({ eligible: true });
    expect(computePathEligibility('linux.events.session_data', context)).toEqual({
      eligible: true,
    });
    expect(computePathEligibility('windows.ransomware.mode', context)).toEqual({
      eligible: false,
      reason: 'license_below_platinum',
    });
    expect(
      computePathEligibility(
        'windows.attack_surface_reduction.credential_hardening.enabled',
        context
      )
    ).toEqual({
      eligible: false,
      reason: 'license_below_platinum',
    });
  });

  it('keeps eligibility per path when protections are disabled on a mixed enterprise set', () => {
    const current = policyFactory();
    current.windows.malware.mode = ProtectionModes.off;
    const prepared = prepareChangeSet(
      rawRequest([
        { op: 'set_protection_level', protection: 'malware', mode: ProtectionModes.prevent },
        { op: 'set_field', path: 'windows.device_control.enabled', value: false },
      ]),
      current
    );
    const context = eligibilityContext(prepared.proposedConfig, {
      endpointPolicyProtections: false,
    });

    expect(prepared.explicitChanges.length).toBeGreaterThan(0);
    expect(computePathEligibility('windows.malware.mode', context)).toEqual({
      eligible: false,
      reason: 'endpoint_policy_protections_disabled',
    });
    expect(computePathEligibility('windows.device_control.enabled', context)).toEqual({
      eligible: true,
    });
  });
});
