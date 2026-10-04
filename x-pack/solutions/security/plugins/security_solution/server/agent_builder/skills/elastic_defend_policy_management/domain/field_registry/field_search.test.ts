/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  POLICY_EVENT_COLLECTION_LABELS,
  POLICY_PROTECTION_UPDATES_LABEL,
} from '../../../../../../common/endpoint/models/policy_settings_ui_labels';
import { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import { getFieldRegistryEntry } from './derive_field_registry';
import {
  searchPolicyFields,
  type PolicyFieldSearchHit,
  type PolicyFieldSearchResult,
} from './field_search';

const settingKey = (path: string): string => {
  const [first, ...rest] = path.split('.');
  if (
    first !== undefined &&
    rest.length > 0 &&
    (Object.values(PolicyOperatingSystem) as string[]).includes(first)
  ) {
    return rest.join('.');
  }
  return path;
};

interface SearchCase {
  readonly query: string;
  readonly osFilter?: readonly PolicyOperatingSystem[];
  readonly candidatesTruncated: boolean;
  readonly resultsTruncated?: boolean;
  readonly onlyResults?: boolean;
  readonly settings?: readonly string[];
}

const SEARCH_CASES: readonly SearchCase[] = [
  {
    query: 'event collection API',
    candidatesTruncated: false,
    settings: ['events.credential_access'],
  },
  {
    query: 'credential hardening',
    candidatesTruncated: false,
    settings: ['attack_surface_reduction.credential_hardening.enabled'],
  },
  {
    query: 'blocklist',
    candidatesTruncated: false,
    settings: ['malware.blocklist'],
  },
  {
    query: 'protection updates',
    candidatesTruncated: false,
    resultsTruncated: true,
    settings: ['global_manifest_version'],
  },
  {
    query: 'Windows DNS',
    osFilter: [PolicyOperatingSystem.windows],
    candidatesTruncated: false,
    onlyResults: true,
    settings: ['events.dns'],
  },
  {
    query: 'credential',
    candidatesTruncated: false,
    settings: ['attack_surface_reduction.credential_hardening.enabled', 'events.credential_access'],
  },
  {
    query: 'device control',
    candidatesTruncated: false,
    settings: ['device_control.enabled', 'device_control.usb_storage'],
  },
  {
    query: 'event collection',
    candidatesTruncated: true,
    resultsTruncated: true,
  },
];

const topWritableHits = (result: PolicyFieldSearchResult): readonly PolicyFieldSearchHit[] => {
  let topScore = 0;
  for (const hit of result.results) {
    if (hit.writable && hit.score > topScore) {
      topScore = hit.score;
    }
  }
  return result.results.filter((hit) => hit.writable && hit.score === topScore);
};

describe('searchPolicyFields', () => {
  it('ranks queries into candidate settings, OS filters, and truncation flags', () => {
    for (const row of SEARCH_CASES) {
      const result = searchPolicyFields(row.query);
      const hits = topWritableHits(result);
      const observed = {
        osFilter: result.osFilter ?? null,
        candidatesTruncated: result.candidates_truncated,
        resultsTruncated: result.results_truncated,
        settings:
          row.settings === undefined
            ? null
            : [...new Set(hits.map((hit) => settingKey(hit.path)))].sort(),
      };
      expect(observed).toEqual({
        osFilter: row.osFilter ?? null,
        candidatesTruncated: row.candidatesTruncated,
        resultsTruncated:
          row.resultsTruncated ?? (row.onlyResults === true ? false : observed.resultsTruncated),
        settings: row.settings === undefined ? null : [...row.settings].sort(),
      });
    }
  });

  it('links POLICY_EVENT_COLLECTION_LABELS and POLICY_PROTECTION_UPDATES_LABEL to registry entries', () => {
    for (const os of ['windows', 'mac', 'linux'] as const) {
      for (const { field } of POLICY_EVENT_COLLECTION_LABELS[os]) {
        expect(getFieldRegistryEntry(`${os}.events.${field}`)?.path).toBe(`${os}.events.${field}`);
      }
    }
    expect(getFieldRegistryEntry(POLICY_PROTECTION_UPDATES_LABEL.path)?.path).toBe(
      POLICY_PROTECTION_UPDATES_LABEL.path
    );
  });
});
