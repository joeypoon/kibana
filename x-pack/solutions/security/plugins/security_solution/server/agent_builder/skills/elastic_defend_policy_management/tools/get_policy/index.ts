/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType } from '@kbn/agent-builder-common/tools';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import {
  PolicyRegistryVersionUnknownError,
  buildScopeDisclosure,
  readDefendPolicy,
} from '../../services/policy_read';
import {
  boundList,
  MAX_DOCUMENTATION_CHARS,
  MAX_EXEMPLAR_STRING_CHARS,
  MAX_POLICY_DESCRIPTION_CHARS,
  MAX_SETTING_STRING_CHARS,
  truncateBoundedString,
  truncateBoundedValue,
} from '../../lib/bounded_result';
import type {
  IndeterminateReasonCode,
  PolicyDetailSettingsFilter,
  PolicyFieldReport,
  PolicyFieldSummary,
} from '../../lib/policy_field_view';
import {
  buildPolicyFieldReports,
  selectPolicyFieldReports,
  summarizePolicyFields,
} from '../../lib/policy_field_view';
import {
  createPolicyConfigDerivations,
  resolvePolicyFieldRegistry,
} from '../../lib/policy_registry_cache';
import type { DefendPolicyManagementSkillDeps } from '../../deps';
import { resolvePolicyServices } from '../../deps';
import {
  CONFIGURED_NOT_APPLIED_STATEMENT,
  DEFEND_POLICY_MANAGEMENT_ERROR,
  UNTRUSTED_FIELD_DATA_STATEMENT,
  toScopeDisclosurePayload,
  toolDenial,
  toolError,
  toolException,
  toolSuccess,
} from '../../lib/tool_results';
import {
  policyCategorySelectionInput,
  policyIdInput,
  policyKeyPathsSelectionInput,
} from '../schemas';

export const GET_DEFEND_POLICY_TOOL_ID = 'security.get_defend_policy';

const MAX_REPORTED_SETTINGS = 400;

export const MAX_AGENT_POLICY_ID_EXEMPLARS = 5;

const AGENT_POLICY_ASSIGNMENT_ENVELOPE_TOKENS = 120;

const READ_ENVELOPE_TOKENS = 1_800 + AGENT_POLICY_ASSIGNMENT_ENVELOPE_TOKENS;

const toAgentPolicyAssignmentEnvelope = (
  policyIds: readonly string[]
): {
  readonly agent_policy_id_count: number;
  readonly agent_policy_id_exemplars: readonly string[];
} => ({
  agent_policy_id_count: policyIds.length,
  agent_policy_id_exemplars: policyIds
    .slice(0, MAX_AGENT_POLICY_ID_EXEMPLARS)
    .map((id) => truncateBoundedString(id, MAX_EXEMPLAR_STRING_CHARS)),
});

const buildGetPolicyContinuation = ({
  settingsFilter,
  keyPaths,
  category,
}: {
  readonly settingsFilter: PolicyDetailSettingsFilter;
  readonly keyPaths?: readonly string[];
  readonly category?: string;
}): string => {
  const selectionActive = keyPaths !== undefined || category !== undefined;

  if (selectionActive) {
    const kept: string[] = [];
    if (settingsFilter === 'explicit_only') {
      kept.push('`settingsFilter: "explicit_only"`');
    }
    if (keyPaths !== undefined) {
      kept.push('the same `keyPaths`');
    }
    if (category !== undefined) {
      kept.push(`\`category: "${category}"\``);
    }

    return (
      `Call this tool again while keeping ${kept.join(
        ' and '
      )}. Do not omit \`keyPaths\` or \`category\` — dropping them changes which settings are in scope and ` +
      `turns off per-setting documentation. Narrow further with fewer \`keyPaths\` if this selection is ` +
      `still too large.`
    );
  }

  if (settingsFilter === 'explicit_only') {
    return (
      'Omitted settings are still among those deliberately changed from default; calling again with ' +
      '`settingsFilter: "explicit_only"` alone will not recover them. Narrow with `keyPaths` or ' +
      '`category` while keeping `settingsFilter: "explicit_only"` to see the rest.'
    );
  }

  return (
    'Call this tool again with `settingsFilter: "explicit_only"` to see just the settings that ' +
    'were deliberately changed from their defaults.'
  );
};

const INDETERMINATE_REASON_LEGEND: Readonly<Record<IndeterminateReasonCode, string>> = {
  license_gated_default_unrecoverable:
    'The field is license-gated and the policy does not record the license tier in effect when it ' +
    'was created, so the correct default variant cannot be reproduced and no explicit-vs-default ' +
    'claim is made.',
  creation_input_unrecoverable:
    "The setting's shipped default depends on deployment state captured when the policy was " +
    'created — the license tier, whether the deployment was on Elastic Cloud, or the cluster ' +
    'telemetry opt-in — and the policy does not record it, so the default cannot be reproduced.',
  no_recoverable_default:
    'No default value for the setting is recoverable from any in-repo source, so the effective ' +
    'value cannot be stated.',
  registry_default_missing:
    'The policy schema names a source for this default but carries no default value, so the stored ' +
    'value cannot be compared against one.',
  feature_may_be_absent:
    'The policy schema advertises this setting but the policy does not store it, and for this ' +
    'category that does NOT mean it is at its default: the feature may have been removed from ' +
    'the policy by the license tier or a feature flag. The effective value cannot be stated.',
};

const getDefendPolicySchema = z
  .object({
    policyId: policyIdInput.describe(
      'The Elastic Defend policy id (package policy id). Obtain it from ' +
        '`security.get_defend_policy_inventory`; this tool does not resolve names.'
    ),
    settingsFilter: z
      .enum(['stored', 'all', 'explicit_only'])
      .default('stored')
      .describe(
        'Which settings to return. "stored" (default, including when omitted) reports fields ' +
          'present on the policy document plus unknown stored leaves. "all" reports every setting ' +
          'the policy schema advertises, including inferred unstored defaults marked stored: false. ' +
          '"explicit_only" reports just the settings deliberately changed from default. `keyPaths` ' +
          'or `category` still return matching advertised unstored settings (with documentation) ' +
          'even when the filter is "stored".'
      ),
    keyPaths: policyKeyPathsSelectionInput
      .optional()
      .describe(
        'Select settings by exact registry key path (within an OS branch, e.g. "malware.mode", or ' +
          'policy-root, e.g. "global_telemetry_enabled"); every OS branch carrying the path is ' +
          'returned. Selecting is what turns on per-setting `documentation`, `type`, and ' +
          '`enumValues`. Take paths from an earlier result — a path that names nothing is reported ' +
          'in `key_paths_not_found`, never guessed at.'
      ),
    category: policyCategorySelectionInput
      .optional()
      .describe(
        'Select settings by category (e.g. "protection", "events", "advanced"). Like `keyPaths`, ' +
          'selecting turns on per-setting `documentation`, `type`, and `enumValues`. Combines with ' +
          '`keyPaths` (a setting must match both) and with `settingsFilter`.'
      ),
  })
  .strict();

interface SettingPayload {
  readonly keyPath: string;
  readonly os?: string;
  readonly value: unknown;
  readonly defaultValue?: unknown;
  readonly state: PolicyFieldReport['state'];
  readonly applicability?: PolicyFieldReport['applicability'];
  readonly category?: PolicyFieldReport['category'];
  readonly stored?: false;
  readonly unrecognized?: true;
  readonly indeterminateReasonCode?: IndeterminateReasonCode;
  readonly type?: string;
  readonly enumValues?: readonly string[];
  readonly enum_values_unavailable?: true;
  readonly documentation?: string;
  readonly documentation_unavailable?: true;
  readonly indeterminateReason?: string;
}

const toSettingPayload = (
  report: PolicyFieldReport,
  { enrich }: { enrich: boolean }
): SettingPayload => {
  const {
    keyPath,
    os,
    value,
    defaultValue,
    state,
    applicability,
    category,
    stored,
    unrecognized,
    indeterminateReason,
    indeterminateReasonCode,
  } = report;

  return {
    keyPath,
    ...(os === undefined ? {} : { os }),
    value: truncateBoundedValue(value, MAX_SETTING_STRING_CHARS),
    ...(state === 'explicit' && defaultValue !== undefined
      ? { defaultValue: truncateBoundedValue(defaultValue, MAX_SETTING_STRING_CHARS) }
      : {}),
    state,
    ...(applicability === 'applicable' ? {} : { applicability }),
    ...(category === undefined ? {} : { category }),
    ...(stored ? {} : { stored: false }),
    ...(unrecognized === true ? { unrecognized: true } : {}),
    ...(indeterminateReasonCode === undefined ? {} : { indeterminateReasonCode }),
    ...(state === 'indeterminate' &&
    indeterminateReasonCode === undefined &&
    indeterminateReason !== undefined
      ? { indeterminateReason }
      : {}),
    ...(enrich ? enrichmentFields(report) : {}),
  };
};

const enrichmentFields = (
  report: PolicyFieldReport
): Pick<
  SettingPayload,
  'type' | 'enumValues' | 'enum_values_unavailable' | 'documentation' | 'documentation_unavailable'
> => {
  if (report.unrecognized === true) {
    return { type: 'unknown', documentation_unavailable: true };
  }

  return {
    type: report.type,
    ...(report.type === 'enum'
      ? report.enumValues === undefined
        ? { enum_values_unavailable: true as const }
        : { enumValues: report.enumValues }
      : report.enumValues === undefined
      ? {}
      : { enumValues: report.enumValues }),
    ...(report.documentation === undefined
      ? { documentation_unavailable: true as const }
      : {
          documentation: truncateBoundedString(report.documentation, MAX_DOCUMENTATION_CHARS),
        }),
  };
};

export const createGetDefendPolicyTool = (
  deps: DefendPolicyManagementSkillDeps
): BuiltinSkillBoundedTool<typeof getDefendPolicySchema> => ({
  id: GET_DEFEND_POLICY_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Get the configured settings of ONE Elastic Defend policy by id: protection modes, event ' +
    'collection, popups, advanced options, plus which values were deliberately set versus left at ' +
    "their shipped default, and whether each is supported by the policy's package version. Defaults " +
    'to fields stored on the policy document; pass `settingsFilter: "all"` for the advertised ' +
    'schema including inferred unstored defaults, or select with `keyPaths` or `category` to include ' +
    "matching advertised unstored settings and each selected setting's documentation, value type, " +
    'and allowed enum values. Also returns revision, saved-object version, and provenance for ' +
    'citation. Use after `security.get_defend_policy_inventory` gives you the id. Read-only. Returns ' +
    'CONFIGURED policy and cannot confirm what any endpoint is running. For comparing two policies ' +
    'or estate-wide duplicate/unused analysis use `security.analyze_defend_policy_estate`.',
  schema: getDefendPolicySchema,
  handler: async ({ policyId, settingsFilter = 'stored', keyPaths, category }, { request }) => {
    try {
      const resolved = await resolvePolicyServices({ deps, request });
      if (!resolved.ok) {
        return toolDenial(resolved.denial);
      }

      const services = resolved.value;
      const outcome = await readDefendPolicy({
        packagePolicyService: services.packagePolicyService,
        privilegeBasis: services.privilegeBasis,
        derivations: createPolicyConfigDerivations({ referenceVersion: deps.kibanaVersion }),
        spaceId: services.spaceId,
        getSoClient: services.getSoClient,
        policyId,
      });

      if (!outcome.ok) {
        return toolDenial(outcome.denial);
      }

      const { snapshot, privilegeBasis } = outcome.value;
      const { identity, name, description, packageVersion, provenance, config, configHash } =
        snapshot;
      const registry = resolvePolicyFieldRegistry(packageVersion, {
        referenceVersion: deps.kibanaVersion,
      });

      if ('status' in registry) {
        return registryCoverageError({
          policyId,
          requestedVersion: registry.requestedVersion,
          nearestKnownVersion: registry.nearestKnownVersion,
        });
      }

      const allReports = buildPolicyFieldReports({ config, registry, packageVersion });
      const summary = summarizePolicyFields(allReports);

      const selectionRequested = keyPaths !== undefined || category !== undefined;
      const selected = selectPolicyFieldReports({
        reports: allReports,
        settingsFilter,
        keyPaths,
        category,
      });
      const hasInferredSelected = selected.some((report) => !report.stored);

      const keyPathsNotFound =
        keyPaths === undefined
          ? []
          : keyPaths.filter(
              (requested) => !allReports.some((report) => report.keyPath === requested)
            );

      const settingsSummary = {
        ...summary,
        unknown:
          summary.total - summary.applicable - summary.versionUnavailable - summary.unsupported,
      };

      const bounded = boundList({
        items: selected.map((report) => toSettingPayload(report, { enrich: selectionRequested })),
        maxItems: MAX_REPORTED_SETTINGS,
        envelopeTokens: READ_ENVELOPE_TOKENS,
        itemLabel: 'settings',
        continuation: buildGetPolicyContinuation({ settingsFilter, keyPaths, category }),
      });

      return toolSuccess(
        {
          message: buildReadMessage({
            name,
            identity,
            summary,
            returned: bounded.returned,
            selectedCount: selected.length,
            settingsFilter,
            hasInferredSelected,
            selectionRequested,
            truncationNotice: bounded.truncationNotice,
          }),
          policy: {
            identity: {
              id: identity.id,
              revision: identity.revision,
              ...(identity.version === undefined ? {} : { version: identity.version }),
              updatedAt: identity.updatedAt,
            },
            name,
            ...(description === undefined
              ? {}
              : {
                  description: truncateBoundedString(description, MAX_POLICY_DESCRIPTION_CHARS),
                }),
            package_version: packageVersion,
            ...toAgentPolicyAssignmentEnvelope(snapshot.policyIds),
            provenance: {
              createdAt: provenance.createdAt,
              createdBy: provenance.createdBy,
              updatedAt: provenance.updatedAt,
              updatedBy: provenance.updatedBy,
            },
            config_hash: configHash,
            global_manifest_version: config.global_manifest_version,
            global_telemetry_enabled: config.global_telemetry_enabled,
          },
          settings: bounded.items,
          settings_summary: settingsSummary,
          settings_returned: bounded.returned,
          settings_matching_filter: selected.length,
          settings_truncated: bounded.truncated,
          ...(bounded.truncationNotice === undefined
            ? {}
            : { settings_truncation_notice: bounded.truncationNotice }),
          settings_filter: settingsFilter,
          ...(selectionRequested
            ? {
                settings_selection: {
                  ...(keyPaths === undefined ? {} : { keyPaths: [...keyPaths] }),
                  ...(category === undefined ? {} : { category }),
                },
              }
            : {}),
          ...(keyPathsNotFound.length === 0 ? {} : { key_paths_not_found: keyPathsNotFound }),
          scope_disclosure: toScopeDisclosurePayload(
            buildScopeDisclosure({ privilegeBasis, returned: 1, total: 1 })
          ),
          protection_updates_pin_note:
            '`global_manifest_version` is the protection-updates pin. It is its own dimension, not a ' +
            'protection setting: two policies differing only in this pin have identical protection ' +
            'configuration.',
          settings_legend: {
            state_explicit: 'Deliberately set to a value different from the shipped default.',
            state_default: 'Holds the shipped default.',
            state_indeterminate:
              'The shipped default could not be reproduced, so NO explicit-vs-default claim is made. ' +
              'Report it as undetermined and give the reason: look up the record\u2019s ' +
              '`indeterminateReasonCode` in `indeterminate_reason_legend`, or use its ' +
              '`indeterminateReason` if it carries one instead. Every indeterminate setting carries ' +
              'one of the two; never resolve one yourself.',
            absent_applicability:
              'An omitted `applicability` means `applicable`: the setting is supported by this policy ' +
              'package version. Any other value is stated explicitly.',
            applicability_unknown:
              'The registry has no support window for this field, so applicability could not be ' +
              'determined. This is NOT evidence that the setting is unsupported.',
            absent_stored:
              'An omitted `stored` means the value was READ from the policy document. `stored: false` ' +
              'means the document does not carry this setting and the value shown is INFERRED from the ' +
              'shipped default — never present it as an observed value.',
            absent_default_value:
              'A `defaultValue` is carried only on an explicitly-set setting, where it is the value the ' +
              'setting was changed away from.',
            unrecognized_setting:
              '`unrecognized: true` means this setting IS stored on the policy but this build has no ' +
              'field definition for it \u2014 typically because the cluster runs a newer Elastic Defend ' +
              'package than the schema snapshot used here, or the key was written through the API. The ' +
              '`value` is read from the policy document and is real; report it as configured. Its ' +
              '`state` is `explicit` because its presence in the document is what proves it was ' +
              'authored. No `defaultValue`, `category`, or support window exists for it, so none is ' +
              'given \u2014 never invent one, and never state what the setting does or whether the ' +
              'value is advisable.',
            absent_category:
              'A `category` is absent only on an `unrecognized` setting, where no field definition ' +
              'exists to read one from.',
            selection_enrichment:
              '`documentation`, `type`, and `enumValues` appear on a setting ONLY when a `keyPaths` ' +
              'or `category` selection was requested. Their absence from other results is the ' +
              'contract, not missing data. When `documentation` is present, paraphrase ONLY that ' +
              'text when explaining the setting.',
            documentation_unavailable:
              '`documentation_unavailable: true` means this build holds NO authoritative ' +
              'documentation for the setting. State that plainly — never invent an explanation of ' +
              'what the setting does.',
            enum_values_unavailable:
              '`enum_values_unavailable: true` means the setting is an enum but this build has no ' +
              'record of its allowed values. Never invent them.',
            type_unknown:
              '`type: "unknown"` means this build has no field definition recording the value type. ' +
              'The `value` is still read from the policy document and is real.',
          },
          indeterminate_reason_legend: INDETERMINATE_REASON_LEGEND,
          configured_not_applied: CONFIGURED_NOT_APPLIED_STATEMENT,
          untrusted_field_data: UNTRUSTED_FIELD_DATA_STATEMENT,
        },
        { logger: deps.logger, toolId: GET_DEFEND_POLICY_TOOL_ID }
      );
    } catch (error) {
      if (error instanceof PolicyRegistryVersionUnknownError) {
        return registryCoverageError({
          policyId,
          requestedVersion: error.detail.requestedVersion,
          nearestKnownVersion: error.detail.nearestKnownVersion,
        });
      }

      return toolException(error, {
        logger: deps.logger,
        toolId: GET_DEFEND_POLICY_TOOL_ID,
        operation: `reading Elastic Defend policy [${policyId}]`,
      });
    }
  },
});

const registryCoverageError = ({
  policyId,
  requestedVersion,
  nearestKnownVersion,
}: {
  policyId: string;
  requestedVersion: string;
  nearestKnownVersion: string | undefined;
}) =>
  toolError({
    message:
      `This policy is on Elastic Defend package version ${requestedVersion}, which this feature has ` +
      `no policy field definitions for, so its settings cannot be described.${
        nearestKnownVersion === undefined
          ? ''
          : ` The nearest version with definitions is ${nearestKnownVersion}.`
      } Its settings were NOT read from a different version's schema, because defaults and supported ` +
      `settings genuinely change between versions and doing so would produce confidently wrong ` +
      `answers. Report the package version above so support for it can be added.`,
    error: DEFEND_POLICY_MANAGEMENT_ERROR.unknownError,
    metadata: {
      registry_version_unknown: true,
      requested_version: requestedVersion,
      ...(nearestKnownVersion === undefined ? {} : { nearest_known_version: nearestKnownVersion }),
      policy_id: policyId,
    },
  });

interface ReadMessageOptions {
  readonly name: string;
  readonly identity: { readonly id: string; readonly revision: number; readonly version?: string };
  readonly summary: PolicyFieldSummary;
  readonly returned: number;
  readonly selectedCount: number;
  readonly settingsFilter: PolicyDetailSettingsFilter;
  readonly hasInferredSelected: boolean;
  readonly selectionRequested: boolean;
  readonly truncationNotice?: string;
}

const buildReadMessage = ({
  name,
  identity,
  summary,
  returned,
  selectedCount,
  settingsFilter,
  hasInferredSelected,
  selectionRequested,
  truncationNotice,
}: ReadMessageOptions): string => {
  const cited = `Elastic Defend policy ${JSON.stringify(name)} (id ${identity.id}) at revision ${
    identity.revision
  }${identity.version === undefined ? '' : `, saved-object version ${identity.version}`}.`;

  let counts: string;
  if (settingsFilter === 'explicit_only') {
    counts = `${selectedCount} of ${summary.total} settings were deliberately changed from their shipped default; returning ${returned}.`;
  } else if (settingsFilter === 'stored' && !hasInferredSelected && !selectionRequested) {
    counts = `${selectedCount} of ${summary.total} settings are stored on the document; returning ${returned}.`;
  } else {
    counts = `${summary.total} settings: ${summary.explicit} explicitly set, ${summary.default} at their shipped default, ${summary.indeterminate} undetermined. Returning ${returned}.`;
  }

  let inferred: string | undefined;
  if (summary.notStored === 0) {
    inferred = undefined;
  } else if (hasInferredSelected) {
    inferred = `${summary.notStored} settings are not stored on the policy; their values are inferred from the shipped defaults and are marked \`stored: false\`.`;
  } else {
    inferred = `${summary.notStored} settings are not stored on the policy and are omitted from this result; pass \`settingsFilter: "all"\` or select them with \`keyPaths\` or \`category\` to inspect inferred advertised defaults.`;
  }

  const unsupported =
    summary.versionUnavailable + summary.unsupported === 0
      ? undefined
      : `${
          summary.versionUnavailable + summary.unsupported
        } settings are not supported by this policy's package version and are marked accordingly.`;

  const unrecognized =
    summary.unrecognized === 0
      ? undefined
      : `${summary.unrecognized} settings are stored on the policy but have no field definition in this build \u2014 their values are real and are reported, marked \`unrecognized: true\`, with no default, category, or support window available for them.`;

  return [cited, counts, inferred, unsupported, unrecognized, truncationNotice]
    .filter((part): part is string => part !== undefined)
    .join(' ');
};
