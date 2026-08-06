/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { tags } from '@kbn/scout';
import { evaluate } from '../../src/evaluate';
import type { DefendPolicyManagementDatasetExample } from '../../src/evaluate_defend_policy_management_dataset';
import { registerDefendPolicyEstateLifecycle } from '../../src/data_generators/defend_policy_estate_lifecycle';

evaluate.describe(
  'Elastic Defend Policy Management — estate analysis',
  { tag: tags.stateful.classic },
  () => {
    const getEstate = registerDefendPolicyEstateLifecycle();

    evaluate('compare-leaves — comparison', async ({ evaluateDefendPolicyManagementDataset }) => {
      const handle = getEstate('compare-leaves: fixture estate was not built');
      const { allDefaults, nearDuplicate } = handle;

      const examples: DefendPolicyManagementDatasetExample[] = [
        {
          input: {
            question: `Compare the Elastic Defend policies "${allDefaults.name}" and "${nearDuplicate.name}" and tell me exactly how they differ.`,
          },
          output: {
            criteria: [
              'States which settings differ and what each policy has for them, rather than only saying that they differ',
              'Does not invent differences beyond the ones it reports from the comparison',
              'Names which operating system each difference applies to',
            ],
          },
          metadata: {
            scenario_id: 'compare-leaves',
            left_policy_id: allDefaults.packagePolicyId,
            right_policy_id: nearDuplicate.packagePolicyId,
          },
        },
      ];

      await evaluateDefendPolicyManagementDataset({
        dataset: {
          name: 'security: elastic-defend-policy-management-compare',
          description:
            'compare-leaves. A two-policy comparison must select estate analysis and report the known differing key paths with correct per-OS attribution.',
          examples,
        },
      });
    });

    evaluate(
      'exact-duplicates / unused — duplicates and unused',
      async ({ evaluateDefendPolicyManagementDataset }) => {
        const handle = getEstate('exact-duplicates: fixture estate was not built');
        const { allDefaults, exactDuplicate, unassigned, assignedZeroAgents } = handle;

        const examples: DefendPolicyManagementDatasetExample[] = [
          {
            input: {
              question:
                'Do any of my Elastic Defend policies have the same settings as each other?',
            },
            output: {
              criteria: [
                'Explains what makes the grouped policies redundant (identical configuration) rather than just naming them',
                'Frames the finding as configuration equivalence, and does not tell the user to delete anything',
              ],
            },
            metadata: {
              scenario_id: 'exact-duplicates',
              exact_group: [allDefaults.packagePolicyId, exactDuplicate.packagePolicyId],
            },
          },
          {
            input: { question: 'Which of my Elastic Defend policies are unused?' },
            output: {
              criteria: [
                'Labels the findings as likely or probable rather than asserting the policies are definitively unused',
                'Names the evidence behind each finding (no assignment, or no enrolled agents) instead of asserting it bare',
                'Distinguishes the unassigned policy from the assigned-but-agentless one',
                'Does not recommend deleting or cleaning up any policy',
              ],
            },
            metadata: {
              scenario_id: 'unused',
              unassigned_policy_id: unassigned.packagePolicyId,
              zero_agent_policy_id: assignedZeroAgents.packagePolicyId,
            },
          },
        ];

        await evaluateDefendPolicyManagementDataset({
          dataset: {
            name: 'security: elastic-defend-policy-management-estate',
            description:
              'exact-duplicates and unused. Estate analysis must group allDefaults/exactDuplicate as exact duplicates and classify unassigned and assignedZeroAgents as unused without recommending deletion.',
            examples,
          },
        });
      }
    );
  }
);
