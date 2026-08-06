/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType } from '@kbn/agent-builder-common/tools';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import { allowedExperimentalValues } from '../../../../../../common';
import { PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import type {
  PolicyChangeLeafDiff,
  PolicyChangeOperation,
  PolicyChangeProposal,
} from '../../domain/impact/types';
import { ADVISORY_NOT_APPLIED_STATEMENT, MAX_CHANGE_OPERATIONS } from '../../domain/impact';
import {
  PolicyRegistryVersionUnknownError,
  buildScopeDisclosure,
  readDefendPolicy,
} from '../../services/policy_read';
import { assessPolicyChange, fetchAffectedPopulation } from '../../services/policy_impact';
import {
  createPolicyConfigDerivations,
  resolvePolicyFieldRegistry,
} from '../../lib/policy_registry_cache';
import type { DefendPolicyManagementSkillDeps } from '../../deps';
import { resolvePolicyServices } from '../../deps';
import {
  MAX_ASSESS_DOCUMENTATION_CHARS,
  MAX_ASSESS_STRING_CHARS,
  truncateBoundedString,
  truncateBoundedValue,
} from '../../lib/bounded_result';
import {
  CONFIGURED_NOT_APPLIED_STATEMENT,
  DEFEND_POLICY_MANAGEMENT_ERROR,
  toScopeDisclosurePayload,
  toolDenial,
  toolError,
  toolException,
  toolSuccess,
} from '../../lib/tool_results';
import { policyIdInput } from '../schemas';

export const ASSESS_DEFEND_POLICY_CHANGE_TOOL_ID = 'security.assess_defend_policy_change';

const MAX_SAVED_OBJECT_VERSION_LENGTH = 256;
const MAX_KEY_PATH_LENGTH = 256;

const MAX_PROPOSED_STRING_LENGTH = 4096;

const boundAssessValue = (value: unknown): unknown =>
  truncateBoundedValue(value, MAX_ASSESS_STRING_CHARS);

const boundAssessOperation = ({
  expectedCurrentValue,
  proposedValue,
  ...operation
}: PolicyChangeOperation): PolicyChangeOperation => ({
  ...operation,
  ...(expectedCurrentValue === undefined
    ? {}
    : { expectedCurrentValue: boundAssessValue(expectedCurrentValue) }),
  proposedValue: boundAssessValue(proposedValue),
});

const boundAssessProposal = (proposal: PolicyChangeProposal): PolicyChangeProposal => ({
  ...proposal,
  operations: proposal.operations.map(boundAssessOperation),
});

const boundAssessDiff = ({
  before,
  after,
  defaultValue,
  documentation,
  ...diff
}: PolicyChangeLeafDiff): PolicyChangeLeafDiff => ({
  ...diff,
  before: boundAssessValue(before),
  after: boundAssessValue(after),
  ...(defaultValue === undefined ? {} : { defaultValue: boundAssessValue(defaultValue) }),
  ...(documentation === undefined
    ? {}
    : { documentation: truncateBoundedString(documentation, MAX_ASSESS_DOCUMENTATION_CHARS) }),
});

const proposedValueSchema = z.union([
  z.boolean(),
  z.number(),
  z.string().max(MAX_PROPOSED_STRING_LENGTH),
  z.null(),
]);

const changeOperationSchema = z
  .object({
    keyPath: z
      .string()
      .min(1)
      .max(MAX_KEY_PATH_LENGTH)
      .describe(
        'The setting to change, as the registry key path WITHIN an OS branch (e.g. ' +
          '"malware.blocklist", "advanced.agent.connection_delay") with `os` naming the branch. A ' +
          'policy-root setting (e.g. "global_telemetry_enabled") omits `os`. Take the exact key path ' +
          'from a `security.get_defend_policy` result — never guess one.'
      ),
    os: z
      .enum([PolicyOperatingSystem.windows, PolicyOperatingSystem.mac, PolicyOperatingSystem.linux])
      .optional()
      .describe(
        'Which OS branch the setting belongs to. REQUIRED for OS-scoped settings, omitted for ' +
          'policy-root settings. A wrong OS is refused rather than guessed.'
      ),
    expectedCurrentValue: proposedValueSchema
      .optional()
      .describe(
        'The value you believe the policy currently holds. When supplied and it does not match, the ' +
          'proposal is REFUSED rather than assessed — supply it to guard against reasoning from a ' +
          'stale reading.'
      ),
    proposedValue: proposedValueSchema.describe('The value to assess changing this setting to.'),
  })
  .strict();

const assessDefendPolicyChangeSchema = z
  .object({
    policyId: policyIdInput.describe('The Elastic Defend policy id the change would apply to.'),
    revision: z
      .number()
      .int()
      .min(0)
      .describe(
        'The policy revision this proposal was built against, from a ' +
          '`security.get_defend_policy` result. A proposal against a revision that is no longer ' +
          'current is REFUSED, so nothing is assessed against a configuration that has since changed.'
      ),
    version: z
      .string()
      .min(1)
      .max(MAX_SAVED_OBJECT_VERSION_LENGTH)
      .optional()
      .describe(
        'The saved-object version from the same read. Optional but strongly preferred: it is the ' +
          'stronger staleness check, and a mismatch is decisive.'
      ),
    operations: z
      .array(changeOperationSchema)
      .min(1)
      .max(MAX_CHANGE_OPERATIONS)
      .describe(
        `The changes to assess, one per setting (max ${MAX_CHANGE_OPERATIONS}). Translate the user's ` +
          'words into these typed operations; the assessment echoes back exactly what it evaluated ' +
          'so the user can confirm the translation was faithful.'
      ),
  })
  .strict();

export const createAssessDefendPolicyChangeTool = (
  deps: DefendPolicyManagementSkillDeps
): BuiltinSkillBoundedTool<typeof assessDefendPolicyChangeSchema> => ({
  id: ASSESS_DEFEND_POLICY_CHANGE_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Assess what WOULD happen if specified Elastic Defend policy settings were changed — an ' +
    'advisory "what if" that applies nothing. Returns the canonical proposal it evaluated (echoed ' +
    'back so the user can confirm it matches their request), before/after diffs per setting, the ' +
    'three Elastic Defend validator outcomes, the Fleet-assigned agent population, and what cannot ' +
    'be known. Use for "what would happen if I turned X off" and impact questions. This tool CANNOT ' +
    'and DOES NOT apply changes: for an actual change, direct the user to the Elastic Defend policy ' +
    'UI. A proposal built against a stale revision is refused with the current revision reported.',
  schema: assessDefendPolicyChangeSchema,
  handler: async ({ policyId, revision, version, operations }, { request }) => {
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

      const { snapshot, inputs, privilegeBasis } = outcome.value;
      const registry = resolvePolicyFieldRegistry(snapshot.packageVersion, {
        referenceVersion: deps.kibanaVersion,
      });

      if ('status' in registry) {
        return toolError({
          message:
            `This policy is on Elastic Defend package version ${registry.requestedVersion}, which ` +
            `this feature has no field definitions for, so a change to it cannot be assessed.${
              registry.nearestKnownVersion === undefined
                ? ''
                : ` The nearest known version is ${registry.nearestKnownVersion}.`
            } Nothing was assessed and nothing was changed.`,
          error: DEFEND_POLICY_MANAGEMENT_ERROR.unknownError,
          metadata: {
            registry_version_unknown: true,
            requested_version: registry.requestedVersion,
          },
        });
      }

      const proposal: PolicyChangeProposal = {
        policyId,
        identity: { revision, ...(version === undefined ? {} : { version }) },
        operations,
      };

      const population = await fetchAffectedPopulation({
        policyId,
        agentPolicyIds: snapshot.policyIds,
        canReadFleetAgents: privilegeBasis.fleetAgentsRead,
        getAgentClient: services.getAgentClient,
        logger: deps.logger,
      });

      const result = assessPolicyChange({
        proposal,
        snapshot,
        registry,
        inputs,
        population,
        licenseService: deps.endpointAppContextService.getLicenseService(),
        productFeaturesService: deps.productFeaturesService,
        experimentalFeatures:
          deps.endpointAppContextService.experimentalFeatures ?? allowedExperimentalValues,
        logger: deps.logger,
      });

      const scopeDisclosure = toScopeDisclosurePayload(
        buildScopeDisclosure({ privilegeBasis, returned: 1, total: 1 })
      );

      if ('rejection' in result) {
        const { rejection } = result;

        return toolSuccess(
          {
            message: `The proposal was REFUSED and nothing was assessed. ${rejection.message} This assessment is advisory only; nothing was applied.`,
            assessed: false,
            applied: false,
            configured_not_applied: CONFIGURED_NOT_APPLIED_STATEMENT,
            advisory_statement: ADVISORY_NOT_APPLIED_STATEMENT,
            scope_disclosure: scopeDisclosure,
            rejection: {
              reason: rejection.reason,
              message: rejection.message,
              ...(rejection.keyPath === undefined ? {} : { keyPath: rejection.keyPath }),
              ...(rejection.os === undefined ? {} : { os: rejection.os }),
              ...(rejection.currentIdentity === undefined
                ? {}
                : { currentIdentity: rejection.currentIdentity }),
            },
            proposal_submitted: boundAssessProposal(proposal),
          },
          { logger: deps.logger, toolId: ASSESS_DEFEND_POLICY_CHANGE_TOOL_ID }
        );
      }

      const { assessment } = result;

      return toolSuccess(
        {
          message: buildAssessmentMessage(assessment.diffs.length, assessment.assessedIdentity),
          assessed: true,
          applied: assessment.applied,
          validatorOutcomes: assessment.validatorOutcomes,
          advisory_statement: ADVISORY_NOT_APPLIED_STATEMENT,
          configured_not_applied: CONFIGURED_NOT_APPLIED_STATEMENT,
          scope_disclosure: scopeDisclosure,
          how_to_actually_apply:
            'This skill cannot apply changes and has no tool that can. To make this change, the user ' +
            'must edit the policy themselves in the Elastic Defend policy UI (Security > Manage > ' +
            'Policies).',
          assessedIdentity: assessment.assessedIdentity,
          diffs: assessment.diffs.map(boundAssessDiff),
          verifiedConfigurationEffects: assessment.verifiedConfigurationEffects,
          likelyPopulationEffects: assessment.likelyPopulationEffects,
          unknowns: assessment.unknowns,
          proposal: boundAssessProposal(assessment.proposal),
        },
        { logger: deps.logger, toolId: ASSESS_DEFEND_POLICY_CHANGE_TOOL_ID }
      );
    } catch (error) {
      if (error instanceof PolicyRegistryVersionUnknownError) {
        return toolError({
          message:
            `This policy is on Elastic Defend package version ${error.detail.requestedVersion}, ` +
            `which this feature has no policy field definitions for, so a change to it cannot be ` +
            `assessed.${
              error.detail.nearestKnownVersion === undefined
                ? ''
                : ` The nearest known version is ${error.detail.nearestKnownVersion}.`
            } Nothing was assessed and nothing was changed.`,
          error: DEFEND_POLICY_MANAGEMENT_ERROR.unknownError,
          metadata: {
            registry_version_unknown: true,
            requested_version: error.detail.requestedVersion,
          },
        });
      }

      return toolException(error, {
        logger: deps.logger,
        toolId: ASSESS_DEFEND_POLICY_CHANGE_TOOL_ID,
        operation: `assessing a hypothetical change to Elastic Defend policy [${policyId}]`,
      });
    }
  },
});

const buildAssessmentMessage = (
  diffCount: number,
  identity: { id: string; revision: number; version?: string }
): string => {
  const cited = `Advisory assessment against policy [${identity.id}] at revision ${
    identity.revision
  }${identity.version === undefined ? '' : ` (saved-object version ${identity.version})`}.`;

  const diffs =
    diffCount === 0
      ? 'The proposal would change no stored configuration value: every proposed value already matches what the policy stores.'
      : `The proposal would change ${diffCount} stored configuration ${
          diffCount === 1 ? 'value' : 'values'
        }.`;

  return `${cited} ${diffs} This assessment is advisory only; nothing was applied.`;
};
