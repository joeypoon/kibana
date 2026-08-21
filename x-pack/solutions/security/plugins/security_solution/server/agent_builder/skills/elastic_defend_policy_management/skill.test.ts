/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { platformCoreTools } from '@kbn/agent-builder-common';
import { isAllowedBuiltinSkill } from '@kbn/agent-builder-server/allow_lists';
import { validateSkillDefinition } from '@kbn/agent-builder-server/skills/type_definition';
import { createMockEndpointAppContext } from '../../../endpoint/mocks';
import { COMPARE_POLICIES_TOOL_ID, createComparePoliciesTool } from './tools/compare_policies';
import { GET_POLICY_TOOL_ID, createGetPolicyTool } from './tools/get_policy';
import {
  GET_POLICY_APPLY_STATE_TOOL_ID,
  createGetPolicyApplyStateTool,
} from './tools/get_policy_apply_state_tool';
import {
  GET_POLICY_FIELD_REFERENCE_TOOL_ID,
  createGetPolicyFieldReferenceTool,
} from './tools/get_policy_field_reference';
import {
  ASSESS_POLICY_CHANGE_TOOL_ID,
  createAssessPolicyChangeTool,
} from './tools/assess_policy_change';
import { LIST_POLICIES_TOOL_ID, createListPoliciesTool } from './tools/list_policies';
import {
  ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID,
  createElasticDefendPolicyManagementSkill,
} from './skill';
import * as skillModule from './skill';

jest.mock(
  './tools/get_policy_field_reference',
  () => ({
    GET_POLICY_FIELD_REFERENCE_TOOL_ID: 'security.policy_management.get_policy_field_reference',
    createGetPolicyFieldReferenceTool: jest.fn((deps: unknown) => ({
      id: 'security.policy_management.get_policy_field_reference',
      ...((deps ?? {}) as object),
    })),
  }),
  { virtual: true }
);

jest.mock(
  './tools/list_policies',
  () => ({
    LIST_POLICIES_TOOL_ID: 'security.policy_management.list_policies',
    createListPoliciesTool: jest.fn((deps: unknown) => ({
      id: 'security.policy_management.list_policies',
      ...((deps ?? {}) as object),
    })),
  }),
  { virtual: true }
);

jest.mock(
  './tools/get_policy',
  () => ({
    GET_POLICY_TOOL_ID: 'security.policy_management.get_policy',
    createGetPolicyTool: jest.fn((deps: unknown) => ({
      id: 'security.policy_management.get_policy',
      ...((deps ?? {}) as object),
    })),
  }),
  { virtual: true }
);

jest.mock(
  './tools/compare_policies',
  () => ({
    COMPARE_POLICIES_TOOL_ID: 'security.policy_management.compare_policies',
    createComparePoliciesTool: jest.fn((deps: unknown) => ({
      id: 'security.policy_management.compare_policies',
      ...((deps ?? {}) as object),
    })),
  }),
  { virtual: true }
);

jest.mock(
  './tools/get_policy_apply_state_tool',
  () => ({
    GET_POLICY_APPLY_STATE_TOOL_ID: 'security.policy_management.get_policy_apply_state',
    createGetPolicyApplyStateTool: jest.fn((deps: unknown) => ({
      id: 'security.policy_management.get_policy_apply_state',
      ...((deps ?? {}) as object),
    })),
  }),
  { virtual: true }
);

jest.mock(
  './tools/assess_policy_change',
  () => ({
    ASSESS_POLICY_CHANGE_TOOL_ID: 'security.policy_management.assess_policy_change',
    createAssessPolicyChangeTool: jest.fn((deps: unknown) => ({
      id: 'security.policy_management.assess_policy_change',
      ...((deps ?? {}) as object),
    })),
  }),
  { virtual: true }
);

const OS_FIELD_PATH = /\b(?:windows|mac|linux)\.[a-z0-9_.]+/i;
const TYPE_FACET = /type:\s*policy_management|type\s+facet|filter by type/i;
const WRITE_TOOL = /apply_policy_change|applyPolicyChange/;
const NAMED_PRESET =
  /\b(?:EDR\s*Complete|EDRComplete|EDR\s*Essential|EDREssential|NGAV|DataCollection)\b/;
const HIDDEN_APPLY =
  /(?:this skill (?:will |can )?apply|call the apply|write the policy|I will (?:now )?apply)/i;

const INLINE_TOOL_IDS = [
  GET_POLICY_FIELD_REFERENCE_TOOL_ID,
  LIST_POLICIES_TOOL_ID,
  GET_POLICY_TOOL_ID,
  COMPARE_POLICIES_TOOL_ID,
  GET_POLICY_APPLY_STATE_TOOL_ID,
  ASSESS_POLICY_CHANGE_TOOL_ID,
] as const;

const createSkill = () => {
  const endpointAppContextService = createMockEndpointAppContext().service;
  const getStartServices = jest.fn();
  return {
    endpointAppContextService,
    getStartServices,
    skill: createElasticDefendPolicyManagementSkill({
      endpointAppContextService,
      getStartServices,
    }),
  };
};

describe('createElasticDefendPolicyManagementSkill', () => {
  beforeEach(() => {
    jest.mocked(createGetPolicyFieldReferenceTool).mockClear();
    jest.mocked(createListPoliciesTool).mockClear();
    jest.mocked(createGetPolicyTool).mockClear();
    jest.mocked(createComparePoliciesTool).mockClear();
    jest.mocked(createGetPolicyApplyStateTool).mockClear();
    jest.mocked(createAssessPolicyChangeTool).mockClear();
  });

  it('does not export a static skill', () => {
    expect(skillModule).not.toHaveProperty('elasticDefendPolicyManagementSkill');
    expect(skillModule).toHaveProperty('createElasticDefendPolicyManagementSkill');
  });

  it('uses an allow-listed built-in skill id', () => {
    expect(isAllowedBuiltinSkill(ELASTIC_DEFEND_POLICY_MANAGEMENT_SKILL_ID)).toBe(true);
  });

  it('uses the planned identifiers', () => {
    const { skill } = createSkill();
    expect(skill.id).toBe('elastic-defend-policy-management');
    expect(skill.name).toBe('elastic-defend-policy-management');
    expect(skill.basePath).toBe('skills/security/endpoint');
  });

  it('exposes only integration knowledge and search registry tools', () => {
    const { skill } = createSkill();
    const registryTools = skill.getRegistryTools?.() ?? [];
    expect(registryTools).toEqual([
      platformCoreTools.integrationKnowledge,
      platformCoreTools.search,
    ]);
  });

  it('defines exactly six inline tools and injects the same service instance', async () => {
    const { skill, endpointAppContextService, getStartServices } = createSkill();
    const inlineTools = await skill.getInlineTools?.();

    expect(inlineTools).toHaveLength(6);
    expect(inlineTools?.map((tool) => tool.id)).toEqual([...INLINE_TOOL_IDS]);

    expect(createGetPolicyFieldReferenceTool).toHaveBeenCalledTimes(1);
    expect(createGetPolicyFieldReferenceTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
    });
    expect(
      jest.mocked(createGetPolicyFieldReferenceTool).mock.calls[0][0].endpointAppContextService
    ).toBe(endpointAppContextService);
    expect(jest.mocked(createGetPolicyFieldReferenceTool).mock.calls[0][0].getStartServices).toBe(
      getStartServices
    );

    expect(createListPoliciesTool).toHaveBeenCalledTimes(1);
    expect(createListPoliciesTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
    });
    expect(jest.mocked(createListPoliciesTool).mock.calls[0][0].endpointAppContextService).toBe(
      endpointAppContextService
    );
    expect(jest.mocked(createListPoliciesTool).mock.calls[0][0].getStartServices).toBe(
      getStartServices
    );

    expect(createGetPolicyTool).toHaveBeenCalledTimes(1);
    expect(createGetPolicyTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
    });
    expect(jest.mocked(createGetPolicyTool).mock.calls[0][0].endpointAppContextService).toBe(
      endpointAppContextService
    );
    expect(jest.mocked(createGetPolicyTool).mock.calls[0][0].getStartServices).toBe(
      getStartServices
    );

    expect(createComparePoliciesTool).toHaveBeenCalledTimes(1);
    expect(createComparePoliciesTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
    });
    expect(jest.mocked(createComparePoliciesTool).mock.calls[0][0].endpointAppContextService).toBe(
      endpointAppContextService
    );
    expect(jest.mocked(createComparePoliciesTool).mock.calls[0][0].getStartServices).toBe(
      getStartServices
    );

    expect(createGetPolicyApplyStateTool).toHaveBeenCalledTimes(1);
    expect(createGetPolicyApplyStateTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
    });
    expect(
      jest.mocked(createGetPolicyApplyStateTool).mock.calls[0][0].endpointAppContextService
    ).toBe(endpointAppContextService);
    expect(jest.mocked(createGetPolicyApplyStateTool).mock.calls[0][0].getStartServices).toBe(
      getStartServices
    );

    expect(createAssessPolicyChangeTool).toHaveBeenCalledTimes(1);
    expect(createAssessPolicyChangeTool).toHaveBeenCalledWith({
      endpointAppContextService,
      getStartServices,
    });
    expect(
      jest.mocked(createAssessPolicyChangeTool).mock.calls[0][0].endpointAppContextService
    ).toBe(endpointAppContextService);
    expect(jest.mocked(createAssessPolicyChangeTool).mock.calls[0][0].getStartServices).toBe(
      getStartServices
    );
  });

  it('omits referencedContent', () => {
    const { skill } = createSkill();
    expect(skill.referencedContent).toBeUndefined();
  });

  it('uses a decision-framed description under the selector length limit', () => {
    const { skill } = createSkill();
    const { description, content } = skill;
    expect(description).toContain('deciding what an Elastic Defend policy should be');
    expect(description).toContain('comparing policies');
    expect(description).toContain('assessing the impact of a change');
    expect(description).toContain('planning a rollout');
    expect(description).toContain('Not for diagnosing something that is already broken');
    expect(description).toContain('Not for healthy artifact-object management');
    expect(description).toContain('Trusted Applications');
    expect(description).toContain('Event Filters');
    expect(description).toContain('Endpoint Exceptions');
    expect(description).toContain('blocklists');
    expect(description).toContain('Named-host apply failures');
    expect(description).toContain('protections not blocking what they should');
    expect(description).toContain('unexpected allow-or-block behavior');
    expect(description).toContain('policy or configuration failures');
    expect(description).toContain('elastic-defend-configuration-troubleshooting');
    expect(description).not.toMatch(/diagnose why policies are not applying/i);
    expect(content).toContain('Named-host apply failures');
    expect(content).toContain('protections not blocking what they should');
    expect(content).toContain('unexpected allow-or-block behavior');
    expect(content).toContain('elastic-defend-configuration-troubleshooting');
    expect(description.length).toBeLessThanOrEqual(1024);
  });

  it('recommends baselines from package-policy best-practice guidance without naming unsupported presets or a host-role taxonomy', () => {
    const { skill } = createSkill();
    const { description, content } = skill;
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const whenToUse = flatten(
      content.slice(
        content.indexOf('## When to use this skill'),
        content.indexOf('## When not to use this skill')
      )
    );
    const processOne = flatten(
      content.slice(
        content.indexOf('### 1. Ground in documentation'),
        content.indexOf('### 2. Orient with the policy model')
      )
    );
    expect(description).toContain('recommending or auditing an environment-appropriate baseline');
    expect(description).toContain('comparing policies');
    expect(description).not.toMatch(/official baseline/i);
    expect(whenToUse).toContain('Recommending or auditing an environment-appropriate baseline');
    expect(whenToUse).toContain('Comparing policies');
    expect(processOne).toContain('package-policy best-practice guidance');
    expect(processOne).toContain('protection-family, OS, and protection-mode vocabulary');
    expect(processOne).toContain('setting, OS, and protection-mode tradeoffs');
    expect(processOne).toContain(GET_POLICY_TOOL_ID);
    expect(processOne).toContain(GET_POLICY_FIELD_REFERENCE_TOOL_ID);
    expect(processOne).toContain('when the user named a policy to audit');
    expect(processOne).toContain('guidance is unavailable');
    expect(processOne).not.toContain('role and mode');
    expect(processOne).not.toContain('workstation versus server');
    expect(processOne).not.toContain('Windows servers');
    expect(content).not.toMatch(NAMED_PRESET);
    expect(description.length).toBeLessThanOrEqual(1024);
  });

  it('constructs concrete package-policy Integration Knowledge queries without troubleshooting nouns', () => {
    const { skill } = createSkill();
    const { content } = skill;
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const processOne = flatten(
      content.slice(
        content.indexOf('### 1. Ground in documentation'),
        content.indexOf('### 2. Orient with the policy model')
      )
    );

    expect(processOne).toContain(platformCoreTools.integrationKnowledge);
    expect(processOne).toContain("this turn's user text and live-tool evidence");
    expect(processOne).toContain('one protection family, OS, or workflow per call');
    expect(processOne).toContain('Stay in package-policy nouns');
    expect(processOne).toContain('Do not add troubleshooting nouns');
    expect(processOne).toContain('Trusted Application');
    expect(processOne).toContain('Endpoint Alert Exception');
    expect(processOne).toContain('Event Filter');
    expect(processOne).toContain('false positive');
    expect(processOne).toContain('Full Disk Access');
    expect(processOne).toContain('Adjacent troubleshooting hits');
    expect(processOne).toContain('must not be composed into guidance');
    expect(processOne).not.toContain('elastic-defend-configuration-troubleshooting');
    expect(processOne).toContain('Follow Call integration_knowledge before describing behaviour');
    expect(processOne).toContain('named-setting misses');

    const exampleQueries = [
      'Elastic Defend detect then prevent mode change healthy policy malware ransomware memory protection',
      'Elastic Defend staged rollout pilot canary host cohort separate agent policies phased assignment',
      'Elastic Defend event collection performance tradeoffs indexed volume protection monitoring',
      'Elastic Defend Windows event collection Malicious Behavior Protection file hashing',
      'Elastic Defend macOS event collection DNS event collection VPN clients policy lever',
      'Elastic Defend Linux fanotify event pipeline session lineage terminal I/O',
      'Elastic Defend ransomware protection Windows macOS',
      'Elastic Defend memory threat protection coverage versus scan cost',
    ];
    for (const query of exampleQueries) {
      expect(processOne).toContain(query);
    }

    expect(processOne).not.toContain('Elastic Defend policy configuration best practices');
    expect(processOne).not.toContain('Elastic Defend memory protection advanced settings');
    expect(processOne).not.toContain('Elastic Defend malware protection prevent versus detect');
  });

  it('excludes healthy artifact-object management and prescribes no deployment taxonomy', () => {
    const { skill } = createSkill();
    const { description, content } = skill;
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const whenNotToUse = flatten(
      content.slice(
        content.indexOf('## When not to use this skill'),
        content.indexOf('## Hard rules')
      )
    );
    expect(description).toContain('Not for healthy artifact-object management');
    expect(description).toContain('Trusted Applications');
    expect(description).toContain('Event Filters');
    expect(description).toContain('Endpoint Exceptions');
    expect(description).toContain('blocklists');
    expect(whenNotToUse).toContain('Trusted Applications');
    expect(whenNotToUse).toContain('Event Filters');
    expect(whenNotToUse).toContain('Endpoint Exceptions');
    expect(whenNotToUse).toContain('blocklists');
    expect(whenNotToUse).toContain('outside this skill');
    expect(whenNotToUse).not.toContain('artifact-management skill');
    const adjacentRule = flatten(
      content.slice(
        content.indexOf('### Hand off adjacent domains without prescribing them'),
        content.indexOf('### Never name a setting from memory')
      )
    );
    expect(adjacentRule).toContain(
      'Across every answer, a concise boundary statement in user-facing language is allowed'
    );
    expect(adjacentRule).toContain(
      'You may state that a host prerequisite, artifact object, or broken-host diagnosis is not a package-policy setting'
    );
    expect(adjacentRule).toContain(
      'Do not name an internal skill identifier in an answer to the user'
    );
    expect(adjacentRule).toContain(
      'Do not prescribe MDM or approval steps, host-prerequisite procedures, or artifact-object selection or tradeoff advice'
    );
    const flattenedProse = [flatten(description), flatten(content)].join(' ');
    expect(flattenedProse).not.toMatch(/\bworkstation\b/i);
    expect(flattenedProse).not.toMatch(/\bserver\b/i);
    expect(flattenedProse).not.toMatch(/\bVDI\b/i);
    expect(flattenedProse).not.toMatch(/Kubernetes/i);
    expect(flattenedProse.replaceAll('deployment-role taxonomies', '')).not.toMatch(/\brole\b/i);
  });

  it('routes existence checks for named or dotted settings, including unknown OS-prefixed names', () => {
    const { skill } = createSkill();
    const { description } = skill;
    expect(description).toContain('verifying whether a named or dotted policy setting exists');
    expect(description).toContain('unknown OS-prefixed dotted setting names');
    expect(description).not.toMatch(OS_FIELD_PATH);
  });

  it('includes the five grounding rules', () => {
    const { skill } = createSkill();
    const { content } = skill;
    expect(content).toContain('Never name a setting from memory');
    expect(content).toContain('Call the field-reference tool before asserting a setting exists');
    expect(content).toContain('Call integration_knowledge before describing behaviour');
    expect(content).toContain('Never state a number that did not come from a tool');
    expect(content).toContain('Restate only returned live-read facts');
    expect(content).toContain('Hand off advanced writes to the UI');
    expect(content).not.toMatch(OS_FIELD_PATH);

    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const behaviourRule = flatten(
      content.slice(
        content.indexOf('### Call integration_knowledge before describing behaviour'),
        content.indexOf('### Never state a number that did not come from a tool')
      )
    );
    const processOne = flatten(
      content.slice(
        content.indexOf('### 1. Ground in documentation'),
        content.indexOf('### 2. Orient with the policy model')
      )
    );
    const processTwo = flatten(
      content.slice(
        content.indexOf('### 2. Orient with the policy model'),
        content.indexOf('### 3. Use live list')
      )
    );
    expect(processTwo).toContain('OS policy blocks are independent');
    expect(processTwo).toContain('typed posture');
    expect(processTwo).toContain('untyped and string-valued');
    expect(processTwo).toContain('Cosmetic popup text is not posture');
    expect(processTwo).toContain('require maintained tools or documentation');
    expect(processTwo).toContain('must not be inferred');
    const integrationKnowledgeSelection = content
      .split('\n')
      .find(
        (line) => line.includes('Prefer') && line.includes(platformCoreTools.integrationKnowledge)
      );
    expect(integrationKnowledgeSelection).toBeDefined();
    const guidanceSurfaces = [
      behaviourRule,
      processOne,
      flatten(integrationKnowledgeSelection ?? ''),
    ];
    for (const surface of guidanceSurfaces) {
      expect(surface).toContain('explain-a-setting');
      expect(surface).toContain('detect-to-prevent');
      expect(surface).toContain('staged rollout');
    }
    expect(behaviourRule).toContain('governed by Process 4');
    expect(behaviourRule).toContain('governed by Process 4 and is assess-only');
    expect(behaviourRule).toContain('Validate each behaviour, tradeoff, and recipe sentence');
    expect(behaviourRule).toContain(
      "that turn's assess result, the retrieved integration-knowledge result content, or this skill's own text"
    );
    expect(behaviourRule).toContain(
      'Retrieval that is silent for a named setting is a miss for that claim'
    );
    expect(behaviourRule).toContain(
      'A family-level article that does not support the named-setting claim is a miss'
    );
    expect(behaviourRule).toContain('Omit the claim or state that guidance is unavailable');
    expect(behaviourRule).toContain('When field-reference returns `entry.documentation`');
    expect(behaviourRule).toContain('restate that short registry documentation');
    expect(behaviourRule).toContain('`longFormGuidance: not_retrieved_by_this_tool`');
    expect(behaviourRule).toContain('this tool did not retrieve long-form guidance');
    expect(behaviourRule).toContain('it is not unavailable after Integration Knowledge retrieval');
    expect(behaviourRule).toContain('must not substitute for that retrieval');
    expect(behaviourRule).toContain(
      'Long-form behaviour and tradeoffs still require retrieved Integration Knowledge'
    );
    expect(behaviourRule).not.toContain(
      'Long-form behaviour and tradeoffs still require retrieved Integration Knowledge or a statement that guidance is unavailable'
    );
    expect(behaviourRule).not.toContain('If nothing relevant returns, say guidance is unavailable');
    expect(processOne).toContain('When the question is not an exact proposed-change assessment');
    expect(flatten(integrationKnowledgeSelection ?? '')).toContain(
      'Do not call it for an exact proposed-change assessment'
    );
  });

  it('grounds live-read reports in returned rows without unreturned consequences', () => {
    const { skill } = createSkill();
    const { content } = skill;
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const liveReadRule = flatten(
      content.slice(
        content.indexOf('### Restate only returned live-read facts'),
        content.indexOf('### Hand off advanced writes to the UI')
      )
    );
    const processFour = flatten(
      content.slice(
        content.indexOf('### 4. Assess a proposed change before reporting impact'),
        content.indexOf('### 5. Advanced change request')
      )
    );
    expect(liveReadRule).toContain('get, compare, apply-state, and assess');
    expect(liveReadRule).toContain('identities, rows, paths, and values');
    expect(liveReadRule).toContain(
      'Boolean, mode, and path-name restatements are allowed categories'
    );
    expect(liveReadRule).toContain(
      'A boolean, mode, or path name does not entail its behavioural meaning'
    );
    expect(liveReadRule).toContain(
      'Before answering, remove any provider, other-product, blocking, coverage, warning, eligibility, or other consequence not explicitly returned'
    );
    expect(liveReadRule).not.toContain('returned assessment fields');
    expect(liveReadRule).not.toContain('Windows Security Center');
    expect(liveReadRule).not.toContain('antivirus');
    expect(processFour).toContain('Follow Restate only returned live-read facts');
    expect(processFour).not.toContain(
      'Boolean, mode, and path-name restatements are allowed categories'
    );
    expect(processFour).not.toContain(
      'A boolean, mode, or path name does not entail its behavioural meaning'
    );
    expect(processFour).not.toContain('Before answering, remove any');
    expect(content).not.toMatch(OS_FIELD_PATH);
  });

  it('selects live list, get, compare, apply-state, and assess without stale no-live-policy text or field paths', () => {
    const { skill } = createSkill();
    const { content } = skill;
    expect(content).toContain(GET_POLICY_FIELD_REFERENCE_TOOL_ID);
    expect(content).toContain(
      'When the tool returns `entry.documentation`, restate that short registry documentation'
    );
    expect(content).toContain(LIST_POLICIES_TOOL_ID);
    expect(content).toContain(GET_POLICY_TOOL_ID);
    expect(content).toContain(COMPARE_POLICIES_TOOL_ID);
    expect(content).toContain(GET_POLICY_APPLY_STATE_TOOL_ID);
    expect(content).toContain(ASSESS_POLICY_CHANGE_TOOL_ID);
    const processThreeHeading = content.split('\n').find((line) => line.startsWith('### 3.'));
    expect(processThreeHeading).toBeDefined();
    expect(processThreeHeading).toContain('named a policy');
    expect(processThreeHeading).toContain('explicitly asked to compare');
    expect(processThreeHeading).toContain('explicitly asked for apply-state');
    expect(processThreeHeading).toContain('bounded proposed-change assessment');
    expect(processThreeHeading).not.toContain('needs deployment facts');
    expect(processThreeHeading).not.toContain('asked explicitly');
    expect(processThreeHeading).toContain('asked a used, unused, or undetermined usage question');
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const leadingWhitespace = (line: string) => line.match(/^(\s*)/)?.[1].length ?? 0;
    const toolSelectionText = content.slice(content.indexOf('## Tool selection'));
    const toolSelectionLines = toolSelectionText.split('\n');
    const toolSelection = flatten(toolSelectionText);
    const negativeExample =
      'Move us from detect to prevent safely with a staged rollout across host cohorts.';
    const requestStop = 'If either is absent, request it and stop';
    const sixToolBan =
      'do not call list, get, compare, field-reference, assess, or apply-state to supply the bounds';
    const inferenceBan =
      'Do not adopt the first, sole, or fixture policy, and do not infer a protection family from policy contents.';
    expect(toolSelection).toContain(negativeExample);
    expect(toolSelection).toContain('policy identity and protection family or families');
    expect(toolSelection).toContain(requestStop);
    expect(toolSelection).toContain(sixToolBan);
    expect(toolSelection).toContain(inferenceBan);
    expect(toolSelection).toContain('named policy and malware protection');
    expect(toolSelection).toContain('existing bounded workflow and tool-selection rules apply');
    expect(toolSelectionLines.some((line) => /^- Otherwise\b/.test(line))).toBe(false);
    const negativeIndex = toolSelection.indexOf(negativeExample);
    const requestIndex = toolSelection.indexOf(requestStop);
    const sixToolIndex = toolSelection.indexOf(sixToolBan);
    const inferenceIndex = toolSelection.indexOf(inferenceBan);
    const boundedParentTextIndex = toolSelection.indexOf('When the user named a policy');
    expect(negativeIndex).toBeGreaterThan(-1);
    expect(requestIndex).toBeGreaterThan(negativeIndex);
    expect(sixToolIndex).toBeGreaterThan(requestIndex);
    expect(inferenceIndex).toBeGreaterThan(sixToolIndex);
    expect(boundedParentTextIndex).toBeGreaterThan(inferenceIndex);
    const boundedParents = toolSelectionLines.filter((line) =>
      /^- When the user named a policy/.test(line)
    );
    expect(boundedParents).toHaveLength(1);
    const boundedParent = boundedParents[0];
    expect(boundedParent).toContain('named');
    expect(boundedParent).toContain('compare');
    expect(boundedParent).toContain('apply-state');
    expect(boundedParent).toContain('explain-a-setting');
    expect(boundedParent).toContain('both');
    expect(boundedParent).toContain('guided-workflow bounds');
    expect(boundedParent).toContain('used, unused, or undetermined usage question');
    expect(boundedParent).toContain('estate-wide');
    const boundedParentIndex = toolSelectionLines.findIndex((line) =>
      /^- When the user named a policy/.test(line)
    );
    const parentIndent = leadingWhitespace(toolSelectionLines[boundedParentIndex]);
    const nestedCallIds = [
      GET_POLICY_FIELD_REFERENCE_TOOL_ID,
      LIST_POLICIES_TOOL_ID,
      GET_POLICY_TOOL_ID,
      COMPARE_POLICIES_TOOL_ID,
      GET_POLICY_APPLY_STATE_TOOL_ID,
      ASSESS_POLICY_CHANGE_TOOL_ID,
    ];
    const nestedCallLines = toolSelectionLines.slice(
      boundedParentIndex + 1,
      boundedParentIndex + 7
    );
    expect(nestedCallLines).toHaveLength(6);
    nestedCallLines.forEach((line, index) => {
      expect(leadingWhitespace(line)).toBeGreaterThan(parentIndent);
      expect(line.trimStart().startsWith('- Call `')).toBe(true);
      expect(line).toContain(nestedCallIds[index]);
    });
    expect(nestedCallLines[0]).not.toContain('Follow Restate only returned live-read facts');
    expect(nestedCallLines[0]).toContain(
      'Follow Call integration_knowledge before describing behaviour'
    );
    expect(nestedCallLines[0]).toContain(
      'A `found: false` `unknown_path` result is a fact: that lookup is unknown'
    );
    expect(nestedCallLines[0]).toContain(
      'A found result — including an OS-less remainder or protection-key expansion — is a known setting identity, not a miss'
    );
    expect(nestedCallLines[0]).not.toContain('A miss is a fact: the path is unknown');
    expect(nestedCallLines[1]).not.toContain('Follow Restate only returned live-read facts');
    expect(nestedCallLines[1]).toContain('`includeUsage: true`');
    expect(nestedCallLines[1]).toContain('estate-wide');
    expect(nestedCallLines[2]).toContain('Follow Restate only returned live-read facts');
    expect(nestedCallLines[3]).toContain('Follow Restate only returned live-read facts');
    expect(nestedCallLines[4]).toContain('Follow Restate only returned live-read facts');
    expect(nestedCallLines[4]).toContain(
      'Follow Never state a number that did not come from a tool'
    );
    expect(nestedCallLines[4]).not.toContain('Apply-state is not enrollment');
    expect(nestedCallLines[5]).toContain('Follow Restate only returned live-read facts');
    expect(nestedCallLines[2]).not.toContain(
      'boolean, mode, and path-name restatements are allowed categories'
    );
    const preferLine = toolSelectionLines
      .slice(boundedParentIndex + 7)
      .find(
        (line) => line.includes('Prefer') && line.includes(platformCoreTools.integrationKnowledge)
      );
    expect(preferLine).toBeDefined();
    expect(leadingWhitespace(preferLine ?? '')).toBe(parentIndent);
    expect(toolSelectionLines[boundedParentIndex + 7]).toBe(preferLine);
    const laterSiblings = toolSelectionLines
      .slice(boundedParentIndex + 7)
      .filter((line) => leadingWhitespace(line) === parentIndent && /^- /.test(line));
    const laterSiblingText = laterSiblings.join('\n');
    expect(laterSiblingText).toContain(`Use \`${platformCoreTools.search}\``);
    expect(laterSiblingText).not.toContain('Do not combine those populations');
    expect(laterSiblingText).not.toContain('countEndpoints is not a skill tool');
    expect(laterSiblingText).not.toContain('Writes are unavailable');
    expect(laterSiblingText).not.toContain('Slot 7 is reserved');
    const nestedCallText = nestedCallLines.join('\n');
    expect(nestedCallText).not.toContain(`Use \`${platformCoreTools.search}\``);
    expect(nestedCallText).not.toContain('Do not combine those populations');
    expect(nestedCallText).not.toContain('countEndpoints is not a skill tool');
    expect(nestedCallText).not.toContain('Writes are unavailable');
    expect(nestedCallText).not.toContain('Slot 7 is reserved');
    expect(content).not.toContain('cannot inspect live policies');
    expect(content).not.toContain('no live-policy tools');
    expect(content).not.toContain('this phase has no deployment data');
    expect(content).not.toContain('live policy and estate facts are unavailable');
    expect(content).not.toMatch(OS_FIELD_PATH);
  });

  it('describes apply-state populations and non-additive overflow without origin-only or inferred counts', () => {
    const { skill } = createSkill();
    const { content, description } = skill;
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const whenToUse = flatten(
      content.slice(
        content.indexOf('## When to use this skill'),
        content.indexOf('## When not to use this skill')
      )
    );
    const numberRule = flatten(
      content.slice(
        content.indexOf('### Never state a number that did not come from a tool'),
        content.indexOf('### Restate only returned live-read facts')
      )
    );
    const writeRule = flatten(
      content.slice(
        content.indexOf('### Hand off advanced writes to the UI'),
        content.indexOf('## Process')
      )
    );
    const processThree = flatten(
      content.slice(
        content.indexOf('### 3. Use live list'),
        content.indexOf('### 4. Assess a proposed change')
      )
    );
    expect(description).toContain('assigned-versus-applied apply-state counts');
    expect(description).toContain('Not for diagnosing something that is already broken');
    expect(numberRule).toContain('Apply-state counts come only from the apply-state tool');
    expect(numberRule).toContain(
      'Assert an index or data-stream name, a field name, or a field value such as an event code'
    );
    expect(numberRule).toContain(
      'only when the user supplied it or a tool or retrieved knowledge returned it this turn'
    );
    expect(numberRule).toContain('Do not infer them from get or compare');
    expect(numberRule).toContain('countEndpoints is not a skill tool');
    expect(numberRule).toContain(
      'Enrolled-agent counts come from the assess tool (blast radius) or the list usage mode (per-policy classification)'
    );
    expect(numberRule).toContain(
      'Do not combine enrolled-agent counts with apply-state populations'
    );
    expect(numberRule).toContain('Apply-state is not enrollment');
    expect(numberRule).toContain(
      "Classify used, unused, or undetermined from the list usage mode's enrolled-agent evidence"
    );
    expect(numberRule).toContain('When the tool returns undetermined, say undetermined');
    expect(numberRule).toContain('An item without a returned classification is undetermined');
    expect(numberRule).toContain('Never infer usage from apply-state metadata or a tool error');
    expect(numberRule).toContain('Never fabricate a proposed change to obtain assess');
    expect(whenToUse).not.toContain('countEndpoints is not a skill tool');
    expect(whenToUse).not.toContain('Apply-state counts come only from the apply-state tool');
    expect(whenToUse).not.toContain('Writes are unavailable');
    expect(whenToUse).not.toContain('Slot 7 is reserved');
    expect(writeRule).toContain('Writes are unavailable and must not be inferred');
    expect(writeRule).toContain('no write tool');
    expect(writeRule).toContain('Slot 7 is reserved for a future apply tool');
    expect(processThree).toContain('Follow Hand off advanced writes to the UI');
    expect(processThree).not.toContain('Slot 7 is reserved');
    expect(processThree).toContain(
      `routes to \`${LIST_POLICIES_TOOL_ID}\` with \`includeUsage: true\``
    );
    expect(processThree).toContain('estate-wide');
    expect(content).toContain(
      "readable united endpoint hosts whose canonical assignment id matches this policy's current agent-policy ids on the request-scoped CPS/CCS surface"
    );
    expect(content).toContain('assigned-versus-applied lag');
    expect(content).not.toContain('cannot answer used or unused');
    expect(content).not.toContain('not enrolled-agent usage evidence');
    expect(content).toContain('latest policy responses at the current package revision');
    expect(content).toContain('two non-additive unclassified overflow fields');
    expect(content).toContain('Do not add them');
    expect(content).toContain(
      'Do not treat overflowed hosts as out-of-date or as current failures'
    );
    expect(content).toContain('elastic-defend-configuration-troubleshooting');
    expect(content).toContain(ASSESS_POLICY_CHANGE_TOOL_ID);
    expect(content).not.toContain('no count tool');
    expect(content.toLowerCase()).not.toContain('origin-only');
    expect(content.toLowerCase()).not.toContain('linked-project hosts are not included');
    expect(content.toLowerCase()).not.toContain('remote-cluster hosts are excluded');
    expect(content).not.toMatch(/overflow(?:ed)? hosts are (?:out-of-date|failing)/i);
  });

  it('requires assessment before reporting proposed-change impact and keeps facts-only wording', () => {
    const { skill } = createSkill();
    const { content } = skill;

    expect(content).toContain('Assess a proposed change before reporting impact');
    expect(content).toContain(ASSESS_POLICY_CHANGE_TOOL_ID);
    expect(content).toContain('Required before reporting proposed-change impact');
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const processFour = flatten(
      content.slice(
        content.indexOf('### 4. Assess a proposed change before reporting impact'),
        content.indexOf('### 5. Advanced change request')
      )
    );
    const assessSelection = content
      .split('\n')
      .find(
        (line) =>
          line.includes(`Call \`${ASSESS_POLICY_CHANGE_TOOL_ID}\``) &&
          line.includes('bounded proposed change')
      );
    expect(assessSelection).toBeDefined();
    const flattenedAssessSelection = flatten(assessSelection ?? '');
    const processFive = flatten(
      content.slice(
        content.indexOf('### 5. Advanced change request'),
        content.indexOf('### 6. Guided detect-to-prevent')
      )
    );
    expect(processFour).toContain(`Do not call \`${platformCoreTools.integrationKnowledge}\``);
    expect(processFour).toContain(
      `the assess result is the sole source of report facts. Do not call \`${platformCoreTools.integrationKnowledge}\`, search, or an extra inline tool. Report the required fields accurately.`
    );
    expect(processFour).toContain('Follow Restate only returned live-read facts');
    expect(processFour).not.toContain(
      'boolean, mode, and path-name restatements are allowed categories'
    );
    expect(processFour).not.toContain(
      'provider, other-product, blocking, coverage, warning, eligibility'
    );
    expect(processFour).not.toContain(
      'A boolean, mode, or path name does not entail its behavioural meaning'
    );
    expect(flattenedAssessSelection).toContain(
      `do not call \`${platformCoreTools.integrationKnowledge}\``
    );
    expect(flattenedAssessSelection).toContain(
      'Exact proposed-change reports are governed by Process 4'
    );
    expect(flattenedAssessSelection).toContain('assess-only');
    expect(flattenedAssessSelection).toContain('Required before reporting proposed-change impact');
    expect(flattenedAssessSelection).not.toContain('requestedOperations');
    expect(flattenedAssessSelection).not.toContain('requestedImpact');
    expect(flattenedAssessSelection).not.toContain('normalizedDiff');
    expect(flattenedAssessSelection).not.toContain(
      'Use status.all as the enrolled-agent headline only when'
    );
    expect(flattenedAssessSelection).not.toContain('key-for-key');
    expect(flattenedAssessSelection).not.toContain(
      'Verify every nonzero status value before answering'
    );
    expect(flattenedAssessSelection).not.toContain('all-others-are-zero');
    expect(processFive).toContain('Follow Hand off advanced writes to the UI');
    expect(processFive).not.toContain(
      'Explain, tradeoff, exact key + suggested value from retrieved docs, then hand off to the Elastic Defend policy UI.'
    );
    expect(processFour).toContain('requestedOperations');
    expect(processFour).toContain('requestedImpact');
    expect(processFour).toContain('requested-intent impact');
    expect(processFour).toContain('truthful no-op');
    expect(processFour).toContain('do not substitute expanded or coupled rows');
    expect(processFour).toContain('expandedChanges');
    expect(processFour).toContain('normalizedDiff');
    expect(processFour).toContain('sideEffects');
    expect(processFour).toContain('revision');
    expect(processFour).toContain('version');
    expect(processFour).toContain('population');
    expect(processFour).toContain('source');
    expect(processFour).toContain('status');
    expect(processFour).toContain('status.all');
    expect(processFour).toContain(
      'every `expandedChanges` row with `path`, `from`, `to`, `originKind`, and `eligibility`'
    );
    expect(processFour).toContain('separately from');
    expect(processFour).toContain('policy.id');
    expect(processFour).toContain('policy.name');
    expect(processFour).toContain('policy.revision');
    expect(processFour).toContain('policy.version');
    expect(processFour).toContain('`revision` does not substitute for `version`');
    expect(processFour).toContain('complete numeric `status` map');
    expect(processFour).toContain('Copy every `expandedChanges` row');
    expect(processFour).toContain('key-for-key');
    expect(processFour).toContain('Verify every nonzero status value before answering');
    expect(processFour).toContain('collapse omitted keys into an all-others-are-zero sentence');
    expect(processFour).toContain(
      'Use status.all as the enrolled-agent headline only when that key is present'
    );
    expect(processFour).toContain('say the headline is unavailable');
    expect(processFour).toContain('assess-only');
    expect(processFour).not.toContain(
      'Put integration-knowledge behaviour in a separately labeled section'
    );
    expect(processFour).not.toContain('expanded intent');
    expect(processFour).not.toContain('policy identity and version');
    expect(processFour).toContain('paths, defaults, other-protection states, or');
    expect(processFour).toContain('alert-field claims');
    expect(processFour).toContain(
      'Restate per-path eligibility only as the assess tool computed it'
    );
    expect(processFour).toContain('do not infer eligibility');
    expect(processFour).toContain(
      'Never claim a change is safe, unsafe, recommended, ready to apply, or unchanged since assessment'
    );
    expect(flattenedAssessSelection).not.toContain(
      'Put integration-knowledge behaviour in a separately labeled section'
    );
    expect(flattenedAssessSelection).not.toContain('expanded intent');
    expect(flattenedAssessSelection).not.toContain('policy identity and version');
    const flattenedContent = flatten(content);
    expect(flattenedContent).toContain(
      'Use status.all as the enrolled-agent headline only when that key is present'
    );
    expect(flattenedContent).toContain('say the headline is unavailable');
    expect(flattenedContent).toContain(
      'Restate per-path eligibility only as the assess tool computed it'
    );
    expect(flattenedContent).toContain(
      'Never claim a change is safe, unsafe, recommended, ready to apply, or unchanged since assessment'
    );
    expect(content).toContain('Slot 7 is reserved for a future apply tool');
    const processSix = flatten(
      content.slice(
        content.indexOf('### 6. Guided detect-to-prevent and staged rollout'),
        content.indexOf('## Tool selection')
      )
    );
    const toolSelection = flatten(content.slice(content.indexOf('## Tool selection')));
    expect(toolSelection).toContain('policy identity and protection family or families');
    expect(toolSelection).toContain('If either is absent, request it and stop');
    expect(toolSelection).toContain(
      'do not call list, get, compare, field-reference, assess, or apply-state to supply the bounds'
    );
    expect(toolSelection).toContain(
      'Do not adopt the first, sole, or fixture policy, and do not infer a protection family from policy contents.'
    );
    expect(toolSelection).not.toContain('requestedOperations');
    expect(toolSelection).not.toContain('requestedImpact');
    expect(toolSelection).not.toContain('normalizedDiff');
    expect(toolSelection).not.toContain('key-for-key');
    expect(toolSelection).not.toContain('Verify every nonzero status value before answering');
    expect(toolSelection).not.toContain('all-others-are-zero');
    expect(toolSelection).not.toContain('countEndpoints is not a skill tool');
    expect(toolSelection).not.toContain('Slot 7 is reserved');
    expect(processSix).not.toContain('If either is absent, request it and stop');
    expect(processSix).not.toContain(
      'do not call list, get, compare, field-reference, assess, or apply-state to supply the bounds'
    );
    expect(processSix).not.toContain(
      'Do not adopt the first, sole, or fixture policy, and do not infer a protection family from policy contents.'
    );
    expect(processSix).toContain(platformCoreTools.integrationKnowledge);
    expect(processSix).toContain('detect versus prevent');
    expect(processSix).toContain('staged rollout');
    expect(processSix).toContain('pilot or canary');
    expect(processSix).toContain('host cohort');
    expect(processSix).toContain('separate agent policies');
    expect(processSix).toContain('phased assignment');
    expect(processSix).toContain('Do not add a type filter');
    expect(processSix).toContain('Treat off-topic retrieval as a miss');
    expect(processSix).toContain('grounded guidance is unavailable');
    expect(processSix).toContain('An exact proposed-change assessment is Process 4 only');
    expect(processSix).toContain('no integration-knowledge call, no search, no extra inline tool');
    expect(processSix).toContain('It is assess-only and governed by Process 4');
    expect(processSix).toContain('For a readiness question');
    expect(processSix).toContain(ASSESS_POLICY_CHANGE_TOOL_ID);
    expect(processSix).toContain('eligibility and coupling');
    expect(processSix).toContain('ground qualitative progression in retrieved knowledge');
    expect(processSix).toContain('Apply-state is not a readiness signal');
    expect(processSix).toContain('must not be presented as one');
    expect(processSix).toContain('readiness-only');
    expect(processSix).toContain(`must not call \`${GET_POLICY_APPLY_STATE_TOOL_ID}\``);
    expect(processSix).toContain('must not use apply-state facts');
    expect(processSix).toContain(
      'separately and explicitly asks assigned-versus-applied status in the same request'
    );
    expect(processSix).toContain('distinct phase');
    expect(processSix).toContain('governed by apply-state population rules');
    expect(processSix).toContain('apply-state facts are never readiness evidence');
    expect(processSix).toContain('combined assessment-and-guidance request');
    expect(processSix).toContain('complete Process 4 as a separate assessment phase');
    expect(processSix).toContain('separate guidance phase');
    expect(processSix).toContain('assess `from` is the live current state');
    expect(processSix).toContain(
      'Users execute policy and assignment changes in the Elastic Defend policy UI'
    );
    expect(processSix).toContain('Do not apply a change');
    expect(processSix).toContain('protection-mode transition');
    expect(processSix).toContain('cohort assignment');
    expect(processSix).toContain('artifact freshness');
    expect(processSix).not.toContain('Include pilot, observe, widen, and rollback points.');
    expect(processSix).toContain('Follow Call integration_knowledge before describing behaviour');
    expect(processSix).toContain('claim-level grounding');
    expect(processSix).not.toContain(
      "that turn's assess result, the retrieved integration-knowledge result content, or this skill's own text"
    );
    expect(processSix).not.toContain('Validate each behaviour, tradeoff, and recipe sentence');
    expect(processSix).not.toContain('family-level article');
    expect(processSix).toContain(
      'defaults, counts, percentages, durations, intervals, and artifact or exception-list names'
    );
    expect(processSix).toContain(
      'Never emit field names, paths, apply-state health, or applied-state verdicts. Restate assess-returned eligibility only as the assess tool computed it'
    );
    expect(processSix).toContain('broken-host, missed-check-in, and failed-response diagnosis');
    expect(processSix).not.toContain('elastic-defend-configuration-troubleshooting');
    expect(content).not.toContain('apply_policy_change');
    expect(content).not.toContain(
      'Put integration-knowledge behaviour in a separately labeled section'
    );
    expect(content).not.toContain(
      'When the assess result returns an antivirus registration `enabled` value changing `true` to `false`'
    );
    expect(content).not.toContain('Windows Security Center provider role');
    expect(content).not.toContain('Windows `unprotected` warning');
    expect(content).not.toContain('Include pilot, observe, widen, and rollback points.');
    expect(content).not.toContain(
      'Explain, tradeoff, exact key + suggested value from retrieved docs, then hand off to the Elastic Defend policy UI.'
    );
    expect(content).not.toMatch(OS_FIELD_PATH);
    expect(content).not.toMatch(TYPE_FACET);
    expect(content).not.toMatch(WRITE_TOOL);
    expect(content).not.toMatch(NAMED_PRESET);
    expect(content).not.toMatch(HIDDEN_APPLY);
  });

  it('keeps canonical count, write, and claim-level phrases unique after collapse', () => {
    const { skill } = createSkill();
    const flattened = skill.content.replace(/\s+/g, ' ');
    const once = (phrase: string) => {
      expect(flattened.split(phrase)).toHaveLength(2);
    };
    once('Apply-state counts come only from the apply-state tool');
    once(
      'Enrolled-agent counts come from the assess tool (blast radius) or the list usage mode (per-policy classification)'
    );
    once('Do not infer them from get or compare');
    once('Do not combine enrolled-agent counts with apply-state populations');
    once('countEndpoints is not a skill tool');
    once('Apply-state is not enrollment');
    once(
      "Classify used, unused, or undetermined from the list usage mode's enrolled-agent evidence"
    );
    once('When the tool returns undetermined, say undetermined');
    once('Never infer usage from apply-state metadata or a tool error');
    once('Never fabricate a proposed change to obtain assess');
    once(
      'Assert an index or data-stream name, a field name, or a field value such as an event code'
    );
    once('A readiness-only question must not call');
    once('apply-state facts are never readiness evidence');
    once('Slot 7 is reserved for a future apply tool');
    once('Writes are unavailable and must not be inferred');
    once(
      "that turn's assess result, the retrieved integration-knowledge result content, or this skill's own text"
    );
    once('Validate each behaviour, tradeoff, and recipe sentence');
    once('A family-level article that does not support the named-setting claim is a miss');
    once('A boolean, mode, or path name does not entail its behavioural meaning');
    once(
      'Before answering, remove any provider, other-product, blocking, coverage, warning, eligibility, or other consequence not explicitly returned'
    );
    once('`requestedImpact` is the requested-intent impact');
    once('truthful no-op intent report');
    once('Copy every `expandedChanges` row');
    once('key-for-key');
    once('Verify every nonzero status value before answering');
    once('collapse omitted keys into an all-others-are-zero sentence');
    once('Across every answer, a concise boundary statement in user-facing language is allowed');
    once(
      'Do not prescribe MDM or approval steps, host-prerequisite procedures, or artifact-object selection or tradeoff advice'
    );
    once('A `found: false` `unknown_path` result is a fact: that lookup is unknown');
  });

  it('keeps OS tuning inside package-policy guidance and omits unsupported retrieved claims', () => {
    const { skill } = createSkill();
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const osTuningRule = flatten(
      skill.content.slice(
        skill.content.indexOf('### Keep OS tuning inside package-policy guidance'),
        skill.content.indexOf('### Report apply state as a closed counts-only result')
      )
    );

    expect(osTuningRule).toContain('### Keep OS tuning inside package-policy guidance');
    expect(osTuningRule).toContain(
      'For an OS-tuning or baseline answer, use current-turn Integration Knowledge only for package-policy guidance and use the field-reference result for exact setting existence, defaults, and legal values.'
    );
    expect(osTuningRule).toContain(
      'Do not compose host prerequisites, installation or permission steps, troubleshooting, incident remediation, artifact or exception guidance, or deployment-role taxonomies into the answer.'
    );
    expect(osTuningRule).toContain(
      'A retrieved related-troubleshooting section is routing context, not policy-setting guidance.'
    );
    expect(osTuningRule).toContain(
      'If retrieved sources conflict or do not support a claim, omit the disputed claim and state that grounded guidance is unavailable.'
    );
    expect(osTuningRule).toContain(
      'Keep each OS section to supported settings, values, behavior, and tradeoffs.'
    );
    expect(osTuningRule).not.toContain('reconcile');
    expect(osTuningRule).not.toContain('invent');
  });

  it('reports apply state as a closed counts-only result without host or causal inference', () => {
    const { skill } = createSkill();
    const flatten = (text: string) => text.replace(/\s+/g, ' ');
    const applyStateRule = flatten(
      skill.content.slice(
        skill.content.indexOf('### Report apply state as a closed counts-only result'),
        skill.content.indexOf('## Process')
      )
    );

    expect(applyStateRule).toContain('### Report apply state as a closed counts-only result');
    expect(applyStateRule).toContain(
      'For an apply-state-only request, call `security.policy_management.get_policy_apply_state` once for the user-named policy.'
    );
    expect(applyStateRule).toContain(
      'Do not call list, get, compare, assess, field-reference, Integration Knowledge, or search unless the user explicitly requests a separate workflow.'
    );
    expect(applyStateRule).toContain(
      'If the apply-state call fails, report that apply state is unavailable without substituting another population or tool.'
    );
    expect(applyStateRule).toContain(
      'Treat a successful apply-state result as a closed counts-only report.'
    );
    expect(applyStateRule).toContain(
      'Copy `policy.id`, `policy.name`, `policy.revision`, and `spaceId`.'
    );
    expect(applyStateRule).toContain(
      'Under `out_of_date`, copy `value`, `classified_hosts`, `unclassified_overflow_hosts`, `truncated`, `source`, and `population`.'
    );
    expect(applyStateRule).toContain(
      'Under `current_policy_response_failures`, copy `value`, `classified_hosts`, `upstream_unclassified_hosts`, `response_unclassified_agents`, `truncated`, `source`, and `population`.'
    );
    expect(applyStateRule).toContain('State returned zero values.');
    expect(applyStateRule).toContain(
      'Keep the two populations separate, and do not add their values or unclassified fields.'
    );
    expect(applyStateRule).toContain(
      'Do not identify or characterize individual hosts, infer assigned or applied versions, infer a cause for lag, infer policy health, or substitute enrolled-agent evidence.'
    );
  });

  it('validates successfully via validateSkillDefinition', async () => {
    const { skill } = createSkill();
    await expect(validateSkillDefinition(skill)).resolves.toBeDefined();
  });
});
