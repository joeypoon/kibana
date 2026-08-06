/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { tags } from '@kbn/scout';
import { evaluate } from '../../src/evaluate';
import type { DefendPolicyManagementDatasetExample } from '../../src/evaluate_defend_policy_management_dataset';
import {
  DEFAULTS_VS_NEAR_DUPLICATE_KEY_PATHS,
  deriveAssessImpactExpectation,
  fixtureLeafValue,
  registerDefendPolicyEstateLifecycle,
} from '../../src/data_generators/defend_policy_estate_lifecycle';

const CHANGE_KEY_PATH = DEFAULTS_VS_NEAR_DUPLICATE_KEY_PATHS[0];

evaluate.describe(
  'Elastic Defend Policy Management — change impact',
  { tag: tags.stateful.classic },
  () => {
    const getEstate = registerDefendPolicyEstateLifecycle();

    evaluate(
      'assess-impact / assess-stale — advisory assessment',
      async ({ evaluateDefendPolicyManagementDataset }) => {
        const handle = getEstate('assess-impact: fixture estate was not built');
        const { allDefaults, nearDuplicate } = handle;

        const beforeValue = fixtureLeafValue(allDefaults, CHANGE_KEY_PATH);
        const impactExpectation = deriveAssessImpactExpectation(beforeValue, allDefaults.name);

        const staleBeforeValue = fixtureLeafValue(nearDuplicate, CHANGE_KEY_PATH);
        const staleExpectation = deriveAssessImpactExpectation(
          staleBeforeValue,
          nearDuplicate.name
        );
        const staleRevision = nearDuplicate.revision - 1;

        const examples: DefendPolicyManagementDatasetExample[] = [
          {
            input: {
              question: impactExpectation.question,
            },
            output: {
              criteria: [
                impactExpectation.criterion,
                'Separates what is certain from the configuration change from what it cannot know about endpoints in the field',
                'Makes clear the change has not been applied and would need to be made deliberately',
              ],
            },
            metadata: {
              scenario_id: 'assess-impact',
              policy_id: allDefaults.packagePolicyId,
              key_path: CHANGE_KEY_PATH.keyPath,
              os: CHANGE_KEY_PATH.os,
              current_revision: allDefaults.revision,
            },
          },
          {
            input: {
              question:
                `I'm still on revision ${staleRevision} of the Elastic Defend policy named ` +
                `"${nearDuplicate.name}". What would happen if I turned the Windows malware ` +
                `blocklist ${staleExpectation.requestedDirection}?`,
            },
            output: {
              criteria: [
                'Rejects the proposed change because the supplied revision is stale, rather than assessing it against the current policy',
                'The answer itself states the current policy identity so the caller can re-assess against the live document',
              ],
            },
            metadata: {
              scenario_id: 'assess-stale',
              policy_id: nearDuplicate.packagePolicyId,
              stale_revision: staleRevision,
              current_revision: nearDuplicate.revision,
            },
          },
        ];

        await evaluateDefendPolicyManagementDataset({
          dataset: {
            name: 'security: elastic-defend-policy-management-impact',
            description:
              'assess-impact and assess-stale. A hypothetical change must be assessed advisorily with the canonical typed proposal echoed back. A proposal against a stale revision must be rejected with the current identity reported.',
            examples,
          },
        });
      }
    );
  }
);
