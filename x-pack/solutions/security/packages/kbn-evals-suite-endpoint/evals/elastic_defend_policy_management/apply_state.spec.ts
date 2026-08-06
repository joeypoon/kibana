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
import {
  registerApplyStateLagHostCleanup,
  registerApplyStateLagHostSetup,
} from '../../src/data_generators/defend_policy_apply_state_hosts';

evaluate.describe(
  'Elastic Defend Policy Management — assigned-versus-applied summary',
  { tag: tags.stateful.classic },
  () => {
    registerApplyStateLagHostCleanup();
    const getEstate = registerDefendPolicyEstateLifecycle();
    registerApplyStateLagHostSetup(getEstate);

    evaluate(
      'apply-state-lag — apply-state summary',
      async ({ evaluateDefendPolicyManagementDataset }) => {
        getEstate('apply-state-lag: fixture estate was not built');

        const examples: DefendPolicyManagementDatasetExample[] = [
          {
            input: {
              question:
                'Are my Elastic Defend endpoints behind on their assigned policy across the fleet?',
            },
            output: {
              criteria: [
                'Reports fleet-wide assigned-versus-applied counts and that some endpoints are behind on revision. Naming a bounded exemplar as an example of lag is allowed. The answer must not turn the summary into a host-by-host diagnosis.',
                'Does not claim or imply which specific settings any endpoint is running, enforcing, or applying; describes assigned-versus-applied revision and/or identity lag only',
                "Does not diagnose a named host's policy-response, artifacts, or health from this fleet-wide summary. Citing a bounded exemplar hostname as an example of lag is allowed. If per-host follow-up is mentioned, it is routed away from this summary rather than performed here",
              ],
            },
            metadata: { scenario_id: 'apply-state-lag' },
          },
        ];

        await evaluateDefendPolicyManagementDataset({
          dataset: {
            name: 'security: elastic-defend-policy-management-apply-state',
            description:
              'apply-state-lag. The estate includes a host behind on revision. Fleet-wide rollout lag must select the assigned-versus-applied summary and report aggregate revision/identity lag rather than diagnosing a named host.',
            examples,
          },
        });
      }
    );
  }
);
