/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import { z } from '@kbn/zod/v4';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import {
  getPolicyFieldReferenceParamsSchema,
  type FieldReferenceResult,
} from '../services/field_reference';
import { createPolicyTool } from './create_policy_tool';

export type {
  ExactFieldReferenceResult,
  FieldReferenceDocumentationAvailability,
  FieldReferenceLongFormGuidance,
  FieldReferenceResult,
  FieldReferenceSearchHit,
  FieldReferenceWritabilityFacts,
  GetPolicyFieldReferenceParams,
  GetPolicyFieldReferenceSelector,
  OsLessRemainderFieldReferenceResult,
  PresentedFieldReferenceEntry,
  ProtectionKeyFieldReferenceResult,
  SearchFieldReferenceResult,
  UnknownFieldReferenceResult,
} from '../services/field_reference';

export const GET_POLICY_FIELD_REFERENCE_TOOL_ID =
  'security.policy_management.get_policy_field_reference';

const fieldReferencePathSelectorSchema = z
  .object({
    path: getPolicyFieldReferenceParamsSchema.shape.path
      .unwrap()
      .describe(
        'Exact registry path, protection key, or supported OS-less remainder, such as linux.events.dns, malware.mode, or behavior_protection.reputation_service. UI setting words belong in a query selector; never invent a path from memory. Valid: {"selector":{"path":"windows.events.dns"}}. Do not send null, an empty string, or placeholder text.'
      ),
  })
  .strict();

const fieldReferenceQuerySelectorSchema = z
  .object({
    query: getPolicyFieldReferenceParamsSchema.shape.query
      .unwrap()
      .describe(
        'Words naming a setting the way the policy UI names it, such as credential hardening, event collection API, blocklist, or protection updates, excluding the desired value or state. Exact paths and keys belong in a path selector. A word naming a supported OS (windows, mac, macos, linux) filters results to that OS instead of scoring. Valid: {"selector":{"query":"credential hardening"}}. Do not send null, an empty string, or placeholder text.'
      ),
  })
  .strict();

export const getPolicyFieldReferenceSchema = z
  .object({
    selector: z
      .union([fieldReferencePathSelectorSchema, fieldReferenceQuerySelectorSchema])
      .describe(
        'Exactly one selector object. {"selector":{"path":"windows.events.dns"}} selects an exact registry path, protection key, or supported OS-less remainder; {"selector":{"query":"credential hardening"}} selects words naming a setting. The selector object carries exactly one required property. Invalid: {"path":"windows.events.dns"}, {"selector":{"path":"windows.events.dns","query":"credential hardening"}}, and {"selector":{}}. Do not send path or query at the root, both properties in one selector, null, an empty string, or placeholder text.'
      ),
  })
  .strict();

export const createGetPolicyFieldReferenceTool = ({
  endpointAppContextService,
}: {
  endpointAppContextService: EndpointAppContextService;
}): BuiltinSkillBoundedTool<typeof getPolicyFieldReferenceSchema> =>
  createPolicyTool({
    endpointAppContextService,
    id: GET_POLICY_FIELD_REFERENCE_TOOL_ID,
    description:
      'Look up Elastic Defend policy settings. Pass exactly one required selector object. ' +
      '{"selector":{"path":"windows.events.dns"}}: an exact registry path, protection key, or supported OS-less remainder; UI setting words belong in query, and never invent a path from memory. ' +
      '{"selector":{"query":"credential hardening"}}: words naming a setting, not the desired value or state; exact paths and keys belong in path. ' +
      'The selector object carries exactly one property. Invalid: {"path":"windows.events.dns"} and {"selector":{"path":"windows.events.dns","query":"credential hardening"}}. Do not send path or query at the root, both properties in one selector, null, an empty string, or placeholder text. ' +
      'For on/off or Detect/Prevent requests that target a whole protection family itself (Malware, Ransomware, Memory threat, Malicious behavior) use set_protection_enabled or set_protection_level instead of this tool, and when the user names an exact API path or a protection key use path first; query resolves wording those routes cannot, including a child setting of a protection family such as a blocklist or an on-write scan. ' +
      'Path lookup order is exact path (e.g. linux.events.dns), then protection keyPath (e.g. malware.mode), then OS-less remainder after one supported-OS segment (e.g. behavior_protection.reputation_service); a wrong-OS exact path stays an unknown_path miss. ' +
      'Query matches lowercased registry path words and shared UI-label words, split on non-alphanumerics with a trailing s stemmed from words longer than three characters and stopwords dropped; a query word naming a supported OS (windows, mac, macos, linux) filters results to that OS instead of scoring. ' +
      'Query score is the count of distinct matched query tokens, zero-score entries are excluded, and ties order writable before not writable, label matches before path-only matches, then registry order. ' +
      'At most 10 result paths are returned: results_total is the full match count and results_truncated is true when more paths matched. ' +
      'The candidate set is every writable match at the highest writable score, computed over all matches before the result cap; candidates_truncated is true when a candidate path is not among the returned results, in which case do not select a path and ask for a more specific setting name. ' +
      'Every found entry reports writable and, when false, not_writable_reason (unknown_path, derived_setting, advanced_setting, not_user_editable, coupled_only); writable entries report acceptedValues, the values that path accepts: enum values, boolean, string, number, or a manifest_version window with the latest keyword and bounded dates. ' +
      'When the user request includes an explicit setting value, invoke only this tool first and wait for its returned acceptedValues to validate that value before issuing any list_policies, get_policy, compare_policies, or assess_policy_change calls; never batch policy reads in parallel with field reference. ' +
      'Path lookup results, including exact path, protection-key, and OS-less remainder expansions, set `documentationAvailability` to present or absent and `longFormGuidance` to not_retrieved_by_this_tool. Query results do not include those fields or `entry.documentation`. ' +
      '`longFormGuidance` means this tool did not retrieve long-form guidance; it is not unavailable after Integration Knowledge retrieval. ' +
      'On path lookup results, restate `entry.documentation` only when `documentationAvailability` is present. ' +
      "`entry.defaultValue` is the argument-less factory default, not this deployment's environment-specific default; " +
      'a returned baseline config overrides it for cloud- or telemetry-dependent values. ' +
      'Does not read or write live policies.',
    schema: getPolicyFieldReferenceSchema,
    run: async (params: z.infer<typeof getPolicyFieldReferenceSchema>, service) => {
      const result: FieldReferenceResult = await service.getPolicyFieldReference(params.selector);
      return { ...result };
    },
  });
