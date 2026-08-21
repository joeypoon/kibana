/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { agentBuilderDefaultAgentId, platformCoreTools } from '@kbn/agent-builder-common';
import { tags } from '@kbn/scout';
import { evaluate } from '../../src/evaluate';
import { waitForEndpointPackage } from '../../src/data_generators/endpoint_data';
import { cleanupPolicyManagementSeededData } from '../../src/data_generators/cleanup';
import {
  cleanupPolicyManagementEstatePolicies,
  cleanupPolicyManagementLeftoverFleetPolicies,
  cleanupPolicyManagementPackagePolicy,
  EVAL_PM_FLEET_AGENT_POLICY_NAMES,
  EVAL_PM_FLEET_PACKAGE_POLICY_NAMES,
  EVAL_PM_PACKAGE_POLICY_NAME,
  seedPolicyManagementEstatePolicies,
  seedPolicyManagementPackagePolicy,
} from '../../src/data_generators/policy_management_package_policy';
import type {
  IndexedFleetEndpointPolicyResponse,
  SeededPolicyManagementEstatePolicies,
} from '../../src/data_generators/policy_management_package_policy';
import {
  cleanupPolicyManagementApplyState,
  EVAL_PM_APPLY_STATE_AGENT_POLICY_NAME,
  EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME,
  seedPolicyManagementApplyState,
  type SeededPolicyManagementApplyState,
} from '../../src/data_generators/policy_management_apply_state';
import {
  POLICY_MANAGEMENT_ASSESS_POLICY_CHANGE_TOOL_ID,
  POLICY_MANAGEMENT_COMPARE_POLICIES_TOOL_ID,
  POLICY_MANAGEMENT_GET_POLICY_APPLY_STATE_TOOL_ID,
  POLICY_MANAGEMENT_GET_POLICY_FIELD_REFERENCE_TOOL_ID,
  POLICY_MANAGEMENT_GET_POLICY_TOOL_ID,
  POLICY_MANAGEMENT_LIST_POLICIES_TOOL_ID,
} from '../../src/policy_management_tool_usage_evaluator';

let seededPackagePolicy: IndexedFleetEndpointPolicyResponse | undefined;
let seededEstate: SeededPolicyManagementEstatePolicies | undefined;
let seededApplyState: SeededPolicyManagementApplyState | undefined;

evaluate.describe(
  'Elastic Defend policy_management grounding',
  { tag: tags.stateful.classic },
  () => {
    evaluate.beforeAll(
      async ({ kbnClient, esClient, internalEsClient, agentBuilderClient, log }) => {
        await waitForEndpointPackage(kbnClient, esClient, log);
        await cleanupPolicyManagementLeftoverFleetPolicies({
          kbnClient,
          log,
          packagePolicyNames: [
            ...EVAL_PM_FLEET_PACKAGE_POLICY_NAMES,
            EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME,
          ],
          agentPolicyNames: [
            ...EVAL_PM_FLEET_AGENT_POLICY_NAMES,
            EVAL_PM_APPLY_STATE_AGENT_POLICY_NAME,
          ],
        });
        await cleanupPolicyManagementSeededData({ esClient, internalEsClient });

        const seeded = await seedPolicyManagementPackagePolicy({ kbnClient, log });
        seededPackagePolicy = seeded.indexed;
        seededEstate = await seedPolicyManagementEstatePolicies({
          kbnClient,
          internalEsClient,
          log,
        });
        seededApplyState = await seedPolicyManagementApplyState({
          kbnClient,
          esClient,
          internalEsClient,
          log,
        });

        try {
          await agentBuilderClient.converse({
            agentId: agentBuilderDefaultAgentId,
            input: 'hello',
          });
        } catch (e) {
          log.warning(`Warmup failed: ${e}`);
        }
      }
    );

    evaluate.afterAll(async ({ kbnClient, esClient, internalEsClient, log }) => {
      const cleanupErrors: unknown[] = [];

      try {
        if (seededApplyState) {
          await cleanupPolicyManagementApplyState({
            kbnClient,
            esClient,
            internalEsClient,
            seeded: seededApplyState,
          });
        }
      } catch (error) {
        cleanupErrors.push(error);
      }

      try {
        if (seededEstate) {
          await cleanupPolicyManagementEstatePolicies({
            kbnClient,
            internalEsClient,
            seeded: seededEstate,
          });
        }
      } catch (error) {
        cleanupErrors.push(error);
      }

      try {
        if (seededPackagePolicy) {
          await cleanupPolicyManagementPackagePolicy({
            kbnClient,
            indexed: seededPackagePolicy,
          });
        }
      } catch (error) {
        cleanupErrors.push(error);
      }

      try {
        await cleanupPolicyManagementSeededData({ esClient, internalEsClient });
      } catch (error) {
        cleanupErrors.push(error);
      }

      for (const error of cleanupErrors) {
        log.warning(`policy_management cleanup failed: ${error}`);
      }
    });

    evaluate('OS setting explanation and tuning', async ({ evaluatePolicyManagementDataset }) => {
      await evaluatePolicyManagementDataset({
        dataset: {
          name: 'security: policy-management-os-tuning',
          description:
            'identify Linux event collection settings in the live policy and state their visibility tradeoffs from retrieved tuning guidance.',
          examples: [
            {
              input: {
                question: `Review the Elastic Defend policy named ${EVAL_PM_PACKAGE_POLICY_NAME}. Which Linux event collection settings in this policy control how much telemetry it forwards, and what visibility do I lose if I turn each one off?`,
              },
              output: {
                criteria: [
                  'Reports the current value of each setting it names.',
                  'Names only settings that the field reference confirms exist.',
                  'States the visibility or volume tradeoff of each named setting from retrieved guidance.',
                  'Does not present host setup, artifacts, or deployment roles as policy settings.',
                ],
                required_tools: [
                  POLICY_MANAGEMENT_GET_POLICY_TOOL_ID,
                  POLICY_MANAGEMENT_GET_POLICY_FIELD_REFERENCE_TOOL_ID,
                  platformCoreTools.integrationKnowledge,
                ],
              },
            },
          ],
        },
      });
    });

    evaluate('estate drift and cleanup', async ({ evaluatePolicyManagementDataset }) => {
      await evaluatePolicyManagementDataset({
        dataset: {
          name: 'security: policy-management-estate-cleanup',
          description:
            'distinguish live configuration drift, normalized duplicates, and unused policies from enrolled-agent evidence.',
          examples: [
            {
              input: {
                question:
                  'Compare all Elastic Defend policies in this space. Identify configuration drift, duplicate policies, and unused policies.',
              },
              output: {
                criteria: [
                  'Reports the substantive configuration differences accurately.',
                  'Identifies duplicates only from equal normalized configurations.',
                  'Classifies unused policies only from enrolled-agent evidence, or reports usage as undetermined.',
                  'Keeps drift, duplicate, and unused classifications distinct and performs no write.',
                ],
                required_tools: [
                  POLICY_MANAGEMENT_LIST_POLICIES_TOOL_ID,
                  POLICY_MANAGEMENT_COMPARE_POLICIES_TOOL_ID,
                ],
                forbidden_tools: [POLICY_MANAGEMENT_ASSESS_POLICY_CHANGE_TOOL_ID],
              },
            },
          ],
        },
      });
    });

    evaluate('pre-save detect-to-prevent rollout', async ({ evaluatePolicyManagementDataset }) => {
      await evaluatePolicyManagementDataset({
        dataset: {
          name: 'security: policy-management-detect-to-prevent-rollout',
          description:
            'assess a live malware detect-to-prevent change and stage assignment without applying a write.',
          examples: [
            {
              input: {
                question: `Before changing anything, assess moving malware protection on ${EVAL_PM_PACKAGE_POLICY_NAME} from its current state to prevent. Then give me a staged detect-to-prevent rollout plan that limits operational disruption.`,
              },
              output: {
                criteria: [
                  'Every fact it states about the proposed change and its blast radius matches the assess result.',
                  'Uses detect before prevent and treats observed evidence as qualitative rather than a readiness guarantee.',
                  'Stages assignment through separate policies or host cohorts, with hold or rollback on adverse evidence.',
                  'Applies no change and invents no counts, thresholds, percentages, schedules, or readiness verdicts.',
                ],
                required_tools: [
                  POLICY_MANAGEMENT_ASSESS_POLICY_CHANGE_TOOL_ID,
                  platformCoreTools.integrationKnowledge,
                ],
                forbidden_tools: [POLICY_MANAGEMENT_GET_POLICY_APPLY_STATE_TOOL_ID],
              },
            },
          ],
        },
      });
    });

    evaluate('assigned versus applied protection', async ({ evaluatePolicyManagementDataset }) => {
      await evaluatePolicyManagementDataset({
        dataset: {
          name: 'security: policy-management-assigned-vs-applied',
          description:
            'report the two apply-state populations as separate counts without inferring cause or per-host state.',
          examples: [
            {
              input: {
                question: `For the Elastic Defend policy named ${EVAL_PM_APPLY_STATE_PACKAGE_POLICY_NAME}, how many endpoints are still running an older revision of it, and how many reported an unsuccessful policy response at the current revision?`,
              },
              output: {
                criteria: [
                  'Keeps the out-of-date and policy-response-failure counts and their sources distinct.',
                  'Does not add the two counts or their overflow fields together.',
                  'Reports every count it states exactly as the tool returned it.',
                  'Does not infer a cause, a health verdict, or per-host state.',
                ],
                required_tools: [POLICY_MANAGEMENT_GET_POLICY_APPLY_STATE_TOOL_ID],
              },
            },
          ],
        },
      });
    });
  }
);
