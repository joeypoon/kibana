/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import type { StartServicesAccessor } from '@kbn/core/server';
import { z } from '@kbn/zod/v4';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import type { FieldRegistryEntry } from '../domain/field_registry';
import {
  getFieldRegistryEntry,
  getOsLessRemainderEntries,
  getProtectionKeyPathEntries,
} from '../domain/field_registry';
import { createPolicyTool } from './create_policy_tool';

export const GET_POLICY_FIELD_REFERENCE_TOOL_ID =
  'security.policy_management.get_policy_field_reference';

const PATH_MAX_LENGTH = 256;

export const getPolicyFieldReferenceSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .max(PATH_MAX_LENGTH)
      .describe(
        'Exact policy path (e.g. linux.events.dns), an OS-less protection keyPath (e.g. malware.mode), or an OS-less remainder after one supported OS segment (e.g. behavior_protection.reputation_service).'
      ),
  })
  .strict();

export type FieldReferenceDocumentationAvailability = 'absent' | 'present';

export type FieldReferenceLongFormGuidance = 'not_retrieved_by_this_tool';

export interface PresentedFieldReferenceEntry {
  readonly documentationAvailability: FieldReferenceDocumentationAvailability;
  readonly entry: FieldRegistryEntry;
}

export interface ExactFieldReferenceResult {
  readonly found: true;
  readonly match: 'exact';
  readonly path: string;
  readonly documentationAvailability: FieldReferenceDocumentationAvailability;
  readonly longFormGuidance: FieldReferenceLongFormGuidance;
  readonly entry: FieldRegistryEntry;
}

export interface ProtectionKeyFieldReferenceResult {
  readonly found: true;
  readonly match: 'protection_key_path';
  readonly path: string;
  readonly longFormGuidance: FieldReferenceLongFormGuidance;
  readonly entries: readonly PresentedFieldReferenceEntry[];
}

export interface OsLessRemainderFieldReferenceResult {
  readonly found: true;
  readonly match: 'os_less_remainder';
  readonly path: string;
  readonly longFormGuidance: FieldReferenceLongFormGuidance;
  readonly entries: readonly PresentedFieldReferenceEntry[];
}

export interface UnknownFieldReferenceResult {
  readonly found: false;
  readonly match: 'none';
  readonly path: string;
  readonly reason: 'unknown_path';
}

export type FieldReferenceResult =
  | ExactFieldReferenceResult
  | ProtectionKeyFieldReferenceResult
  | OsLessRemainderFieldReferenceResult
  | UnknownFieldReferenceResult;

const documentationAvailabilityOf = (
  entry: FieldRegistryEntry
): FieldReferenceDocumentationAvailability =>
  entry.documentation !== undefined && entry.documentation.length > 0 ? 'present' : 'absent';

const presentFieldReferenceEntry = (entry: FieldRegistryEntry): PresentedFieldReferenceEntry => ({
  documentationAvailability: documentationAvailabilityOf(entry),
  entry,
});

const lookupFieldReference = (path: string): FieldReferenceResult => {
  const exact = getFieldRegistryEntry(path);
  if (exact !== undefined) {
    return {
      found: true,
      match: 'exact',
      path,
      documentationAvailability: documentationAvailabilityOf(exact),
      longFormGuidance: 'not_retrieved_by_this_tool',
      entry: exact,
    };
  }

  const protectionEntries = getProtectionKeyPathEntries(path);
  if (protectionEntries.length > 0) {
    return {
      found: true,
      match: 'protection_key_path',
      path,
      longFormGuidance: 'not_retrieved_by_this_tool',
      entries: protectionEntries.map(presentFieldReferenceEntry),
    };
  }

  const remainderEntries = getOsLessRemainderEntries(path);
  if (remainderEntries.length > 0) {
    return {
      found: true,
      match: 'os_less_remainder',
      path,
      longFormGuidance: 'not_retrieved_by_this_tool',
      entries: remainderEntries.map(presentFieldReferenceEntry),
    };
  }

  return { found: false, match: 'none', path, reason: 'unknown_path' };
};

export const createGetPolicyFieldReferenceTool = ({
  endpointAppContextService,
  getStartServices,
}: {
  endpointAppContextService: EndpointAppContextService;
  getStartServices: StartServicesAccessor;
}): BuiltinSkillBoundedTool<typeof getPolicyFieldReferenceSchema> =>
  createPolicyTool({
    endpointAppContextService,
    getStartServices,
    id: GET_POLICY_FIELD_REFERENCE_TOOL_ID,
    description:
      'Look up a single Elastic Defend policy setting by exact path, OS-less protection key, or OS-less remainder. ' +
      'Lookup order is exact path, then protection key, then OS-less remainder. ' +
      'OS-less remainder matching strips exactly one leading supported-OS segment and compares the complete remainder. ' +
      'Returns derived registry facts when found, including os_less_remainder expansions, or a successful unknown_path miss. ' +
      'Found results set `documentationAvailability` to present or absent and `longFormGuidance` to not_retrieved_by_this_tool. ' +
      '`longFormGuidance` means this tool did not retrieve long-form guidance; it is not unavailable after Integration Knowledge retrieval. ' +
      'Restate `entry.documentation` only when `documentationAvailability` is present. ' +
      'Does not read or write live policies.',
    schema: getPolicyFieldReferenceSchema,
    level: 'policy_read',
    run: ({ path }: z.infer<typeof getPolicyFieldReferenceSchema>) => ({
      ...lookupFieldReference(path),
    }),
  });
