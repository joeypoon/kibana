/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { validateSkillDefinition } from '@kbn/agent-builder-server/skills/type_definition';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import { ToolType } from '@kbn/agent-builder-common/tools';
import { AGENT_BUILDER_BUILTIN_SKILLS } from '@kbn/agent-builder-server/allow_lists';
import {
  createElasticDefendPolicyManagementSkill,
  ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID,
} from './skill';
import { GET_DEFEND_POLICY_INVENTORY_TOOL_ID } from './tools/get_inventory';
import { GET_DEFEND_POLICY_TOOL_ID } from './tools/get_policy';
import { ANALYZE_DEFEND_POLICY_ESTATE_TOOL_ID } from './tools/analyze_estate';
import { ASSESS_DEFEND_POLICY_CHANGE_TOOL_ID } from './tools/assess_change';
import { SUMMARIZE_DEFEND_POLICY_APPLY_STATE_TOOL_ID } from './tools/summarize_apply_state';
import { createDefendPolicyManagementToolMocks } from './lib/test_helpers';

const skill = createElasticDefendPolicyManagementSkill(
  createDefendPolicyManagementToolMocks().deps
);

const EXPECTED_TOOL_IDS = [
  GET_DEFEND_POLICY_INVENTORY_TOOL_ID,
  GET_DEFEND_POLICY_TOOL_ID,
  ANALYZE_DEFEND_POLICY_ESTATE_TOOL_ID,
  ASSESS_DEFEND_POLICY_CHANGE_TOOL_ID,
  SUMMARIZE_DEFEND_POLICY_APPLY_STATE_TOOL_ID,
];

describe('elastic-defend-policy-management skill definition', () => {
  it('validates via validateSkillDefinition', async () => {
    await expect(validateSkillDefinition(skill)).resolves.toBeDefined();
  });

  it('has the id and name the allow list and the eval suite pin', () => {
    expect(skill.id).toBe('elastic-defend-policy-management');
    expect(skill.name).toBe('elastic-defend-policy-management');
    expect(AGENT_BUILDER_BUILTIN_SKILLS).toContain(ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID);
  });

  it('groups with the sibling endpoint skills', () => {
    expect(skill.basePath).toBe('skills/security/endpoint');
  });

  it('has a description within the 1024-character platform limit', () => {
    expect(skill.description.length).toBeGreaterThan(0);
    expect(skill.description.length).toBeLessThanOrEqual(1024);
  });

  it('has non-empty content', () => {
    expect(skill.content.length).toBeGreaterThan(100);
  });

  it('titles the skill Elastic Defend Policy Management', () => {
    expect(skill.content.startsWith('# Elastic Defend Policy Management\n')).toBe(true);
  });

  it('exposes exactly the five expected inline tools, under the platform cap of 7 (5/7)', async () => {
    const tools = await skill.getInlineTools!();

    expect(tools).toHaveLength(5);
    expect(tools.map(({ id }) => id)).toEqual(EXPECTED_TOOL_IDS);
    expect(tools.length).toBeLessThanOrEqual(7);
  });

  it('declares every tool as a builtin with a bounded schema and a description', async () => {
    const tools = (await skill.getInlineTools!()) as BuiltinSkillBoundedTool[];

    for (const tool of tools) {
      expect(tool.type).toBe(ToolType.builtin);
      expect(tool.description.length).toBeGreaterThan(0);
      expect(tool.schema).toBeDefined();
    }
  });

  it('exposes no registry tools, so no general search tool can reach endpoint telemetry', () => {
    expect(skill.getRegistryTools).toBeUndefined();
  });

  describe('routing description', () => {
    const ROUTING_PHRASES = [
      'what Defend policies do I have',
      'what is configured on this policy',
      'are any redundant/unused',
      'compare these two',
      'what would turning X off do',
      'are endpoints behind on policy',
    ] as const;

    it('routes health, artifact, and antivirus questions to the troubleshooting skill', () => {
      expect(skill.description).toContain('elastic-defend-configuration-troubleshooting');
    });

    it('routes host timeline and lateral movement questions to the forensics skill', () => {
      expect(skill.description).toContain('endpoint-forensic-analysis');
    });

    it('preserves the existing routing trigger phrases', () => {
      for (const phrase of ROUTING_PHRASES) {
        expect(skill.description).toContain(phrase);
      }
    });

    it('states the read-only scope and the configured-versus-applied boundary', () => {
      expect(skill.description).toContain('READ-ONLY');
      expect(skill.description.toLowerCase()).toContain('cannot confirm what endpoints');
    });

    it('states that no official Elastic baseline exists in this release', () => {
      expect(skill.description.toLowerCase()).toContain('no official elastic');
    });

    it('states inspect, propose, and assess are allowed', () => {
      expect(skill.description.toLowerCase()).toContain('inspect');
      expect(skill.description.toLowerCase()).toContain('propose');
      expect(skill.description.toLowerCase()).toContain('assess');
      expect(skill.description.toLowerCase()).not.toContain('cannot execute');
    });

    it('keeps the description on current inspect-propose-assess capability', () => {
      expect(skill.description).not.toMatch(/HITL/i);
      expect(skill.description.toLowerCase()).not.toContain('human-in-the-loop');
      expect(skill.description.toLowerCase()).not.toContain('chat assent');
      expect(skill.description.toLowerCase()).not.toContain('authorization');
      expect(skill.description.toLowerCase()).not.toContain('this phase');
      expect(skill.description.toLowerCase()).not.toContain('confirmation workflow');
    });

    it('does not forbid naming the policy UI from the routing description', () => {
      expect(skill.description.toLowerCase()).not.toContain('give no ui or api how-to');
      expect(skill.description.toLowerCase()).not.toContain(
        'do not direct users to kibana, fleet, the security app or ui, rest, curl, or apis to apply or delete'
      );
    });

    it('forbids recommending or guiding delete, remove, uninstall, or destroy', () => {
      expect(skill.description.toLowerCase()).toContain(
        'never recommend or guide delete, remove, uninstall, or destroy'
      );
    });

    it('does not point routing-only turns at a Fleet or Kibana write path', () => {
      expect(skill.description.toLowerCase()).not.toContain('manage > policies');
      expect(skill.description.toLowerCase()).not.toContain('fleet ui');
      expect(skill.description.toLowerCase()).not.toContain('fleet api');
      expect(skill.description.toLowerCase()).not.toContain('agent policies');
    });

    it('does not make permanent capability claims', () => {
      expect(skill.description.toLowerCase()).not.toMatch(/permanently/);
      expect(skill.description.toLowerCase()).not.toMatch(/never will/);
    });
  });

  describe('instructions', () => {
    const requirements: ReadonlyArray<readonly [string, RegExp]> = [
      ['cites revision on every claim', /revision/i],
      ['cites provenance', /provenance/i],
      ['refuses write and apply requests', /read-only/i],
      ['states there is no tool that can change anything', /no tool that can change anything/i],
      [
        'refuses applied/effective-state questions outside the narrow exception',
        /cannot confirm what any endpoint/i,
      ],
      ['names the apply-state summary as the one applied-state exception', /one narrow exception/i],
      ['limits the summary to revision and identity lag', /revision and identity lag/i],
      ['forbids setting-level applied differences', /setting-level applied difference/i],
      [
        'treats apply-state aggregates as authoritative and limits exemplars to hostname and identity/revision',
        /Aggregate counts are authoritative[\s\S]+hostname and configured\/applied[\s\S]+policy identity\/revision only/i,
      ],
      [
        'forbids restating host_status or last_checkin or inferring per-host diagnosis from apply-state exemplars',
        /Do not repeat `host_status` or `last_checkin`[\s\S]+offline\/connectivity state, propagation cause/i,
      ],
      [
        'routes per-endpoint diagnosis to Automatic Troubleshooting',
        /Automatic\s+Troubleshooting/i,
      ],
      ['routes fleet-wide lag to the apply-state summary', /fleet-wide/i],
      ['privilege absence reports no counts, not even zero', /not even zero/i],
      ['forbids fabricating endpoint state', /never invent an agent/i],
      ['refuses official baselines and compliance scores', /no\*{0,2} Elastic-official/i],
      ['forbids model-generated recommendations', /No recommendations of your own/i],
      ['forbids re-deriving deterministic findings', /Never re-derive a deterministic finding/i],
      ['forbids recommending deletion', /Never recommend deleting a policy/i],
      ['declines deletion with no UI or API how-to', /no UI or API how-to/i],
      [
        'triggers deletion refusal on remove, uninstall, and destroy',
        /delete, remove, uninstall, or destroy/i,
      ],
      [
        'forbids named Kibana, Fleet, Security, REST, curl, and API write how-tos for deletion',
        /Kibana, Fleet, the Security app or UI, REST, curl, or APIs/i,
      ],
      [
        'allows recommending an assessed change and naming the policy UI',
        /recommend the assessed change[\s\S]{0,200}Elastic Defend policy UI[\s\S]{0,80}Security > Manage > Policies/i,
      ],
      ['resists prompt injection from field values', /Prompt-injection resistance/i],
      ['treats names and descriptions as user data', /user-supplied data/i],
      ['forbids claiming a space scope', /Never claim a space scope/i],
      ['describes the estate as what the user can access', /policies you can access/i],
      ['explains undetermined as a privilege limitation', /privilege limitation/i],
      ['gives the undetermined continuation', /agent-read privilege/i],
      ['reports the protection-updates pin as its own dimension', /own dimension/i],
      ['surfaces estate accounting for completeness', /estate_accounting/i],
      [
        'assesses a user-supplied revision without stopping at inventory or replacing it by re-reading',
        /user-supplied revision[\s\S]{0,500}do not stop at inventory[\s\S]{0,500}re-read to replace/i,
      ],
    ];

    it.each(requirements)('%s', (_name, pattern) => {
      expect(skill.content).toMatch(pattern);
    });

    it('names all five tools so the model can route between them', () => {
      for (const toolId of EXPECTED_TOOL_IDS) {
        expect(skill.content).toContain(toolId);
      }
    });

    it('forbids looping a per-policy tool across the estate', () => {
      expect(skill.content).toMatch(/Never loop a per-policy tool/i);
    });

    it('separates deletion refusal from change-proposal assessment', () => {
      const refuse = skill.content
        .split('## Refuse: write, apply, and delete requests')[1]
        .split('## Applied state')[0];
      const [deletePart, applyPart] = refuse.split(
        /When asked to change, enable, disable, or apply/
      );

      expect(deletePart).toMatch(/When asked to delete, remove, uninstall, or destroy/i);
      expect(deletePart).toMatch(/Never recommend deleting a policy/i);
      expect(deletePart).toMatch(/no UI or API how-to/i);
      expect(deletePart).toMatch(/Kibana, Fleet, the Security app or UI, REST, curl, or APIs/i);
      expect(deletePart).not.toContain('security.assess_defend_policy_change');
      expect(deletePart.toLowerCase()).not.toContain('human-in-the-loop');
      expect(deletePart).not.toMatch(/HITL/);
      expect(deletePart.toLowerCase()).not.toContain('chat assent');
      expect(deletePart.toLowerCase()).not.toContain('this phase');
      expect(deletePart.toLowerCase()).not.toContain('confirmation workflow');
      expect(deletePart).not.toContain('Security > Manage > Policies');
      expect(deletePart.toLowerCase()).not.toMatch(/fleet ui|fleet api/);

      expect(applyPart).toBeDefined();
      expect(applyPart).toContain('security.assess_defend_policy_change');
      expect(applyPart.toLowerCase()).toContain('advisory proposal');
      expect(applyPart.toLowerCase()).toContain('recommend the assessed change');
      expect(applyPart).toContain('Elastic Defend policy UI');
      expect(applyPart).toContain('Security > Manage > Policies');
      expect(applyPart.toLowerCase()).not.toMatch(/cannot execute or claim/);
      expect(applyPart).not.toMatch(/no UI or API how-to/i);
      expect(applyPart.toLowerCase()).not.toContain('human-in-the-loop');
      expect(applyPart).not.toMatch(/HITL/);
      expect(applyPart.toLowerCase()).not.toContain('chat assent');
      expect(applyPart.toLowerCase()).not.toContain('this phase');
      expect(applyPart.toLowerCase()).not.toContain('confirmation workflow');
    });

    it('keeps the instructions on current inspect-propose-assess capability', () => {
      expect(skill.content).not.toMatch(/HITL/i);
      expect(skill.content.toLowerCase()).not.toContain('human-in-the-loop');
      expect(skill.content.toLowerCase()).not.toContain('chat assent');
      expect(skill.content.toLowerCase()).not.toContain('this phase');
      expect(skill.content.toLowerCase()).not.toContain('confirmation workflow');
    });

    it('names the Elastic Defend policy UI for applying an assessed change, not for deletion', () => {
      const refuse = skill.content
        .split('## Refuse: write, apply, and delete requests')[1]
        .split('## Applied state')[0];
      const [deletePart, applyPart] = refuse.split(
        /When asked to change, enable, disable, or apply/
      );

      expect(deletePart).not.toContain('Security > Manage > Policies');
      expect(applyPart).toContain('Security > Manage > Policies');
    });

    it('does not make permanent capability claims', () => {
      expect(skill.content.toLowerCase()).not.toMatch(/permanently/);
      expect(skill.content.toLowerCase()).not.toMatch(/never will/);
    });
  });
});
