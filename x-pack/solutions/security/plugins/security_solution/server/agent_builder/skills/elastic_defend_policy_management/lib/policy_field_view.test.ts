/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { buildPolicyFieldRegistry } from '../domain/field_registry/generate_field_registry';
import { policyFactory } from '../../../../../common/endpoint/models/policy_config';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../common/endpoint/types';
import type { PolicyConfig } from '../../../../../common/endpoint/types';
import {
  buildPolicyFieldReports,
  selectPolicyFieldReports,
  summarizePolicyFields,
} from './policy_field_view';
import { estimateResultTokens, RESULT_TOKEN_BUDGET } from './bounded_result';

const PACKAGE_VERSION = '9.4.0';
const registry = buildPolicyFieldRegistry({ packageVersion: PACKAGE_VERSION });

const reportsFor = (config: PolicyConfig = policyFactory()) =>
  buildPolicyFieldReports({ config, registry, packageVersion: PACKAGE_VERSION });

const keyOf = ({ keyPath, os }: { keyPath: string; os?: string }): string =>
  `${os ?? 'root'}|${keyPath}`;

const advertisedKeys = (): Set<string> => {
  const keys = new Set<string>();

  for (const field of registry.fields) {
    if (field.configurable) {
      if (field.os.length === 0) {
        keys.add(keyOf({ keyPath: field.keyPath }));
      } else {
        for (const os of field.os) {
          keys.add(keyOf({ keyPath: field.keyPath, os }));
        }
      }
    }
  }

  return keys;
};

describe('buildPolicyFieldReports', () => {
  it('covers every configurable field the registry advertises, not only the stored leaves', () => {
    const advertised = advertisedKeys();
    const reported = new Set(reportsFor().map(keyOf));

    expect([...advertised].filter((key) => !reported.has(key))).toEqual([]);
    expect(advertised.size).toBeGreaterThan(300);
  });

  it('reports logging.file as an observed stored value, not as a possibly-absent feature', () => {
    const loggingFile = reportsFor().filter(({ keyPath }) => keyPath === 'logging.file');

    expect(loggingFile).toHaveLength(3);
    for (const report of loggingFile) {
      expect(report.stored).toBe(true);
      expect(report.indeterminateReasonCode).not.toBe('feature_may_be_absent');
      expect(report.value).toBeDefined();
    }
  });

  it('treats every unstored key on a full-featured policy as advanced', () => {
    const unstored = reportsFor().filter((report) => !report.stored);

    expect(unstored.length).toBeGreaterThan(200);
    expect([...new Set(unstored.map((report) => report.category))]).toEqual(['advanced']);
  });

  it('never reports a non-configurable field as configuration the user chose', () => {
    const leaked = reportsFor().filter(
      ({ keyPath, category }) => category === 'meta' || keyPath.startsWith('meta.')
    );

    expect(leaked).toEqual([]);
  });

  it('scopes every reported field to an OS the registry actually lists it for', () => {
    const allowedOsByKeyPath = new Map<string, Set<string>>();

    for (const field of registry.fields) {
      const existing = allowedOsByKeyPath.get(field.keyPath) ?? new Set<string>();
      for (const os of field.os) existing.add(os);
      allowedOsByKeyPath.set(field.keyPath, existing);
    }

    const misscoped = reportsFor().filter(
      ({ keyPath, os }) => os !== undefined && allowedOsByKeyPath.get(keyPath)?.has(os) !== true
    );

    expect(misscoped).toEqual([]);
  });

  it('marks an authored value explicit and an untouched value default', () => {
    const config = policyFactory();
    config.windows.malware.blocklist = false;

    const reports = reportsFor(config);

    expect(
      reports.find(
        (report) =>
          report.keyPath === 'malware.blocklist' && report.os === PolicyOperatingSystem.windows
      )
    ).toMatchObject({ state: 'explicit', value: false, stored: true });
    expect(
      reports.find(
        (report) => report.keyPath === 'malware.mode' && report.os === PolicyOperatingSystem.mac
      )
    ).toMatchObject({ state: 'default', stored: true });
  });

  it('reports an unstored advanced option as its shipped default rather than omitting it', () => {
    const connectionDelay = reportsFor().find(
      (report) =>
        report.keyPath === 'advanced.agent.connection_delay' &&
        report.os === PolicyOperatingSystem.windows
    );

    expect(connectionDelay).toMatchObject({ stored: false, state: 'default' });
    expect(connectionDelay?.value).toBe(connectionDelay?.defaultValue);
  });

  describe('absence is not treated as "default" outside the advanced surface', () => {
    it('reports a stripped non-advanced feature as indeterminate, not as its default', () => {
      const config = policyFactory();
      const { device_control: removedWindows, ...windowsRest } = config.windows;
      const { device_control: removedMac, ...macRest } = config.mac;
      const stripped: PolicyConfig = {
        ...config,
        windows: windowsRest as PolicyConfig['windows'],
        mac: macRest as PolicyConfig['mac'],
      };

      const deviceControl = buildPolicyFieldReports({
        config: stripped,
        registry,
        packageVersion: PACKAGE_VERSION,
      }).filter(({ keyPath }) => keyPath.startsWith('device_control.'));

      expect(deviceControl.length).toBeGreaterThan(0);
      for (const report of deviceControl) {
        expect(report).toMatchObject({
          stored: false,
          state: 'indeterminate',
          indeterminateReasonCode: 'feature_may_be_absent',
        });
        expect(report.value).toBeUndefined();
        expect(report.indeterminateReason).toContain('license');
      }
    });

    it('reports a stripped linux events key as indeterminate rather than defaulted', () => {
      const config = policyFactory();
      const { dns: removedDns, ...linuxEvents } = config.linux.events;
      const stripped: PolicyConfig = {
        ...config,
        linux: { ...config.linux, events: linuxEvents as PolicyConfig['linux']['events'] },
      };

      const dnsReport = buildPolicyFieldReports({
        config: stripped,
        registry,
        packageVersion: PACKAGE_VERSION,
      }).find(
        (report) => report.keyPath === 'events.dns' && report.os === PolicyOperatingSystem.linux
      );

      expect(dnsReport).toMatchObject({
        stored: false,
        state: 'indeterminate',
        indeterminateReasonCode: 'feature_may_be_absent',
      });
    });
  });

  it('reports an unstored advanced field with no recoverable default as indeterminate, with a reason', () => {
    const indeterminate = reportsFor().filter(
      (report) => !report.stored && report.state === 'indeterminate'
    );

    expect(indeterminate.length).toBeGreaterThan(0);
    for (const report of indeterminate) {
      expect(report.value).toBeUndefined();
      expect(report.indeterminateReason ?? '').not.toHaveLength(0);
      expect(report.indeterminateReasonCode).toBeDefined();
    }
  });

  it('gives EVERY indeterminate field a reason code, stored leaves included', () => {
    const indeterminate = reportsFor().filter(({ state }) => state === 'indeterminate');

    expect(indeterminate.length).toBeGreaterThan(0);
    expect(indeterminate.some(({ stored }) => stored)).toBe(true);
    expect(indeterminate.some(({ stored }) => !stored)).toBe(true);

    expect(
      indeterminate
        .filter(({ indeterminateReasonCode }) => indeterminateReasonCode === undefined)
        .map(({ os, keyPath }) => `${os ?? 'root'}|${keyPath}`)
    ).toEqual([]);
  });

  it('never carries a reason or code on a field whose state IS decided', () => {
    const decided = reportsFor().filter(({ state }) => state !== 'indeterminate');

    expect(decided.length).toBeGreaterThan(0);
    expect(
      decided.filter(
        ({ indeterminateReason, indeterminateReasonCode }) =>
          indeterminateReason !== undefined || indeterminateReasonCode !== undefined
      )
    ).toEqual([]);
  });

  it('carries the annotator\u2019s prose alongside the code on a stored indeterminate leaf', () => {
    const storedIndeterminate = reportsFor().filter(
      ({ state, stored }) => state === 'indeterminate' && stored
    );

    expect(storedIndeterminate.length).toBeGreaterThan(0);
    for (const report of storedIndeterminate) {
      expect(report.indeterminateReason ?? '').not.toHaveLength(0);
    }
  });

  it('reports applicability per field, splitting supported from version-unavailable', () => {
    const applicabilities = new Set(reportsFor().map((report) => report.applicability));

    expect(applicabilities.has('applicable')).toBe(true);
    expect(applicabilities.has('version_unavailable')).toBe(true);
  });

  it('orders explicit settings ahead of defaults so a trimmed list keeps what the user chose', () => {
    const config = policyFactory();
    config.windows.malware.blocklist = false;
    config.linux.malware.mode = ProtectionModes.off;

    const reports = reportsFor(config);
    const firstDefaultIndex = reports.findIndex((report) => report.state === 'default');
    const lastExplicitIndex = reports.reduce(
      (last, report, index) => (report.state === 'explicit' ? index : last),
      -1
    );

    expect(lastExplicitIndex).toBeGreaterThanOrEqual(0);
    expect(lastExplicitIndex).toBeLessThan(firstDefaultIndex);
  });

  describe('leaves the registry has no definition for', () => {
    const withUnknownAdvancedKeys = (): PolicyConfig => {
      const config = policyFactory();

      config.windows.advanced = {
        ...config.windows.advanced,
        smoke_infl_key_0: 'x'.repeat(40),
      };
      config.linux.advanced = {
        ...config.linux.advanced,
        future_9_9_knob: { nested: 7 },
      } as PolicyConfig['linux']['advanced'];

      return config;
    };

    it('reports a stored key the registry does not advertise, with its real value', () => {
      const reports = reportsFor(withUnknownAdvancedKeys());
      const windowsKey = reports.find(
        ({ keyPath, os }) =>
          keyPath === 'advanced.smoke_infl_key_0' && os === PolicyOperatingSystem.windows
      );

      expect(windowsKey).toMatchObject({
        unrecognized: true,
        stored: true,
        state: 'explicit',
        value: 'x'.repeat(40),
        applicability: 'unknown',
      });
      expect(windowsKey?.defaultValue).toBeUndefined();
      expect(windowsKey?.category).toBeUndefined();
      expect(windowsKey?.type).toBeUndefined();
      expect(windowsKey?.indeterminateReasonCode).toBeUndefined();
    });

    it('descends into an unknown nested object rather than reporting the container', () => {
      const reports = reportsFor(withUnknownAdvancedKeys()).filter(
        ({ unrecognized, os }) => unrecognized === true && os === PolicyOperatingSystem.linux
      );

      expect(reports).toEqual([
        expect.objectContaining({ keyPath: 'advanced.future_9_9_knob.nested', value: 7 }),
      ]);
    });

    it('recognises the whole factory policy, so the marker is never noise', () => {
      expect(reportsFor().filter(({ unrecognized }) => unrecognized === true)).toEqual([]);
    });

    it('keeps excluded-by-construction and meta keys out, while logging.file stays visible', () => {
      const config = policyFactory();
      config.windows.logging.file = 'debug';
      const withArtifacts = {
        ...config,
        windows: {
          ...config.windows,
          artifact_manifest: { value: { artifacts: { 'endpoint-blah': 'abc' } } },
        },
      } as PolicyConfig;

      const reports = buildPolicyFieldReports({
        config: withArtifacts,
        registry,
        packageVersion: PACKAGE_VERSION,
      });

      expect(reports.filter(({ keyPath }) => keyPath.startsWith('artifact_manifest'))).toEqual([]);
      expect(reports.filter(({ keyPath }) => keyPath.startsWith('meta'))).toEqual([]);

      const loggingFile = reports.filter(({ keyPath }) => keyPath === 'logging.file');

      expect(loggingFile).toHaveLength(3);
      expect(loggingFile.every(({ unrecognized }) => unrecognized === undefined)).toBe(true);
      expect(loggingFile.find(({ os }) => os === PolicyOperatingSystem.windows)?.value).toBe(
        'debug'
      );
    });

    it('does not call a registry field stored on the wrong OS unrecognized', () => {
      const config = policyFactory();
      const stored = {
        ...config,
        linux: { ...config.linux, antivirus_registration: { enabled: true } },
      } as PolicyConfig;

      const reports = buildPolicyFieldReports({
        config: stored,
        registry,
        packageVersion: PACKAGE_VERSION,
      });

      expect(
        reports.filter(
          ({ keyPath, os, unrecognized }) =>
            keyPath === 'antivirus_registration.enabled' &&
            os === PolicyOperatingSystem.linux &&
            unrecognized === true
        )
      ).toEqual([]);
    });

    it('sorts unrecognized leaves with the explicit settings, ahead of every shipped default', () => {
      const reports = reportsFor(withUnknownAdvancedKeys());
      const firstIndeterminateIndex = reports.findIndex(({ state }) => state === 'indeterminate');
      const unrecognizedIndexes = reports
        .map(({ unrecognized }, index) => (unrecognized === true ? index : -1))
        .filter((index) => index >= 0);

      expect(unrecognizedIndexes).toHaveLength(2);
      expect(firstIndeterminateIndex).toBeGreaterThan(0);
      for (const index of unrecognizedIndexes) {
        expect(index).toBeLessThan(firstIndeterminateIndex);
      }
    });

    it('counts unrecognized leaves in the summary instead of undercounting the surface', () => {
      const baseline = summarizePolicyFields(reportsFor());
      const summary = summarizePolicyFields(reportsFor(withUnknownAdvancedKeys()));

      expect(summary.unrecognized).toBe(2);
      expect(summary.total).toBe(baseline.total + 2);
      expect(summary.explicit).toBe(baseline.explicit + 2);
      expect(summary.explicit + summary.default + summary.indeterminate).toBe(summary.total);
      expect(summary.notStored).toBe(baseline.notStored);
    });
  });
});

describe('summarizePolicyFields', () => {
  it('counts states and applicability so a bounded result still describes the whole surface', () => {
    const config = policyFactory();
    config.windows.malware.blocklist = false;

    const reports = reportsFor(config);
    const summary = summarizePolicyFields(reports);

    expect(summary.total).toBe(reports.length);
    expect(summary.explicit + summary.default + summary.indeterminate).toBe(reports.length);
    expect(summary.explicit).toBeGreaterThan(0);
    expect(summary.notStored).toBeGreaterThan(0);
    expect(summary.versionUnavailable).toBeGreaterThan(0);
  });

  it('summary alone stays far inside the budget, so a trimmed read can still report the shape', () => {
    expect(estimateResultTokens(summarizePolicyFields(reportsFor()))).toBeLessThan(
      RESULT_TOKEN_BUDGET / 10
    );
  });
});

describe('selectPolicyFieldReports', () => {
  const withUnknownAdvancedKeys = (): PolicyConfig => {
    const config = policyFactory();

    config.windows.advanced = {
      ...config.windows.advanced,
      smoke_infl_key_0: 'x'.repeat(40),
    };

    return config;
  };

  it('keeps every report for all, including unstored advertised rows', () => {
    const reports = reportsFor();
    const selected = selectPolicyFieldReports({ reports, settingsFilter: 'all' });

    expect(selected).toHaveLength(reports.length);
    expect(selected.some((report) => !report.stored)).toBe(true);
  });

  it('keeps only stored rows when stored is unselected', () => {
    const reports = reportsFor();
    const selected = selectPolicyFieldReports({ reports, settingsFilter: 'stored' });

    expect(selected.length).toBeGreaterThan(0);
    expect(selected.every((report) => report.stored)).toBe(true);
    expect(selected.some((report) => !report.stored)).toBe(false);
    expect(
      selected.some(
        (report) =>
          report.keyPath === 'advanced.agent.connection_delay' &&
          report.os === PolicyOperatingSystem.windows
      )
    ).toBe(false);
  });

  it('still includes unknown stored leaves on an unselected stored filter', () => {
    const reports = reportsFor(withUnknownAdvancedKeys());
    const selected = selectPolicyFieldReports({ reports, settingsFilter: 'stored' });

    expect(selected.every((report) => report.stored)).toBe(true);
    expect(
      selected.find(
        (report) =>
          report.keyPath === 'advanced.smoke_infl_key_0' &&
          report.os === PolicyOperatingSystem.windows
      )
    ).toMatchObject({ unrecognized: true, stored: true, state: 'explicit' });
  });

  it('keeps unstored advertised rows that match a stored keyPaths selection', () => {
    const reports = reportsFor();
    const selected = selectPolicyFieldReports({
      reports,
      settingsFilter: 'stored',
      keyPaths: ['advanced.agent.connection_delay'],
    });

    expect(selected.length).toBeGreaterThan(0);
    expect(selected.every((report) => report.keyPath === 'advanced.agent.connection_delay')).toBe(
      true
    );
    expect(selected.find((report) => report.os === PolicyOperatingSystem.windows)).toMatchObject({
      stored: false,
      state: 'default',
    });
  });

  it('keeps unstored advertised rows that match a stored advanced category selection', () => {
    const reports = reportsFor();
    const selected = selectPolicyFieldReports({
      reports,
      settingsFilter: 'stored',
      category: 'advanced',
    });

    expect(selected.length).toBeGreaterThan(0);
    expect(selected.every((report) => report.category === 'advanced')).toBe(true);
    expect(selected.some((report) => !report.stored)).toBe(true);
  });

  it('keeps only explicit rows, including unrecognized stored leaves', () => {
    const reports = reportsFor(withUnknownAdvancedKeys());
    const selected = selectPolicyFieldReports({ reports, settingsFilter: 'explicit_only' });

    expect(selected.length).toBeGreaterThan(0);
    expect(selected.every((report) => report.state === 'explicit')).toBe(true);
    expect(
      selected.find(
        (report) =>
          report.keyPath === 'advanced.smoke_infl_key_0' &&
          report.os === PolicyOperatingSystem.windows
      )
    ).toMatchObject({ unrecognized: true, stored: true });
  });

  it('does not intersect stored when all is combined with a popup category', () => {
    const reports = reportsFor();
    const selected = selectPolicyFieldReports({
      reports,
      settingsFilter: 'all',
      category: 'popup',
    });

    expect(selected).toEqual(reports.filter((report) => report.category === 'popup'));
  });

  it('does not drop unstored rows when all is combined with an advanced category', () => {
    const reports = reportsFor();
    const selected = selectPolicyFieldReports({
      reports,
      settingsFilter: 'all',
      category: 'advanced',
    });

    expect(selected).toEqual(reports.filter((report) => report.category === 'advanced'));
    expect(selected.some((report) => !report.stored)).toBe(true);
  });
});
