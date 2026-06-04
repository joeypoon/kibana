/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { platformCoreTools } from '@kbn/agent-builder-common';

import type { EndpointAppContextService } from '../../../endpoint/endpoint_app_context_services';
import { createMockEndpointAppContext } from '../../../endpoint/mocks';
import { createAutomaticTroubleshootingSkill } from '.';

describe('createAutomaticTroubleshootingSkill', () => {
  let mockEndpointAppContextService: EndpointAppContextService;

  beforeEach(() => {
    mockEndpointAppContextService = createMockEndpointAppContext().service;
  });

  describe('skill definition', () => {
    it('returns a valid skill definition', () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      expect(skill).toBeDefined();
      expect(skill.id).toBe('automatic_troubleshooting');
      expect(skill.name).toBe('elastic-defend-configuration-troubleshooting');
      expect(skill.basePath).toBe('skills/security/endpoint');
      expect(skill.description).toContain(
        'Troubleshoot Elastic Defend endpoint health'
      );
      expect(skill.content).toContain('Elastic Defend Configuration Troubleshooting');
    });

    it('includes available indices in referenced content', () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      expect(skill.referencedContent).toBeDefined();
      expect(skill.referencedContent).toHaveLength(1);
      expect(skill.referencedContent![0].name).toBe('available_indices');
      expect(skill.referencedContent![0].relativePath).toBe('.');
      expect(skill.referencedContent![0].content).toContain('metrics-endpoint.metadata');
    });

    it('includes system instructions in content', () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      expect(skill.content).toContain('Elastic Defend Configuration Troubleshooting');
      expect(skill.content).toContain('When to use this skill');
      expect(skill.content).toContain('Available Indices');
      expect(skill.content).toContain('Troubleshooting Tools');
      expect(skill.content).toContain('Troubleshooting Approach');
      expect(skill.content).toContain('Scoped investigation framework');
      expect(skill.content).toContain('Example integration knowledge queries');
      expect(skill.content).toContain('Constraints');
    });

    it('gates integration knowledge on scoped current-state classification', () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      expect(skill.content).toContain('Complete the framework below before calling');
      expect(skill.content).toContain(
        'Current policy response freshness gate'
      );
      expect(skill.content).toContain('CURRENTLY_HEALTHY');
      expect(skill.content).toContain('CURRENT_POLICY_FAILURE');
      expect(skill.content).toContain('RECOVERED_POLICY_FAILURE');
      expect(skill.content).toContain('NON_POLICY_HEALTH_FAILURE');
      expect(skill.content).toContain('endpoint list visibility');
      expect(skill.content).toContain(
        'compare Fleet agent documents, endpoint metadata current documents, and united metadata documents before concluding the list is empty'
      );
      expect(skill.content).toContain(
        'do not infer a policy, malware, fanotify, kernel, artifact, or configuration root cause unless the newest policy response has a matching current non-success action'
      );
      expect(skill.content).toContain(
        'Report the stopped/missed-checkins finding, recommend restart and diagnostics'
      );
      expect(skill.content).toContain('Target endpoint identity');
      expect(skill.content).toContain(
        'Apply this as a target endpoint gate only when the user names or clearly implies a specific endpoint'
      );
      expect(skill.content).toContain(
        'classify it as a list-wide endpoint visibility investigation instead of asking for an endpoint name'
      );
      expect(skill.content).toContain(
        'All later evidence must match that target identity by host name, endpoint id, Elastic Agent id, or policy id'
      );
      expect(skill.content).toContain(
        'If the target endpoint cannot be found, stop and ask the user to confirm the endpoint name'
      );
      expect(skill.content).toContain(
        'Do not query older warning/error policy response documents until this gate shows the newest relevant policy response is non-success'
      );
      expect(skill.content).toContain(
        'Do not call platform.core.integration_knowledge'
      );
      expect(skill.content).toContain(
        'Current state beats historical warnings'
      );
      expect(skill.content).toContain(
        'do not turn non-fatal warning logs into the answer to "why is this unhealthy?"'
      );
      expect(skill.content).toContain('Currently healthy policy path');
      expect(skill.content).toContain(
        'Is Fleet agent status currently non-healthy, offline, or missing check-ins?'
      );
      expect(skill.content).toContain(
        'Does the newest policy response contain any current warning/error action or non-success configuration?'
      );
      expect(skill.content).toContain(
        'ask for the specific symptom, affected time range, alert/event, or behavior they want investigated'
      );
      expect(skill.content).toContain(
        'Do not search warning/error logs, call platform.core.integration_knowledge, or inspect historical warnings on this path'
      );
      expect(skill.content).toContain(
        'Do not perform broad log searches, call additional investigation tools except automatic_troubleshooting.generate_insight, list non-fatal log warnings, or recommend remediation for unrelated warnings'
      );
      expect(skill.content).toContain(
        'The current-state and newest-policy-response queries satisfy the evidence requirement'
      );
      expect(skill.content).toContain(
        'Endpoint.status: enrolled'
      );
      expect(skill.content).toContain(
        'after that classification, only call automatic_troubleshooting.generate_insight before answering'
      );
      expect(skill.content).toContain(
        'summarize only the current healthy evidence'
      );
      expect(skill.content).toContain(
        'Never make a historical policy warning the root cause of a current unhealthy/degraded question'
      );
      expect(skill.content).toContain(
        'Never use warnings or errors from another host as evidence for the requested endpoint'
      );
      expect(skill.content).toContain(
        'DO filter every search and every conclusion to the target endpoint identity from the user'
      );
      expect(skill.content).toContain(
        'DO skip platform.core.integration_knowledge when the framework classifies the issue as `CURRENTLY_HEALTHY`'
      );
      expect(skill.content).toContain(
        'DO skip platform.core.integration_knowledge when the framework classifies the issue as `RECOVERED_POLICY_FAILURE`'
      );
      expect(skill.content).toContain(
        'NEVER call platform.core.integration_knowledge for historical policy warnings after the scoped investigation framework classifies the issue as `RECOVERED_POLICY_FAILURE`'
      );
      expect(skill.content).toContain(
        'NEVER mine generic warning logs for a root cause after the scoped investigation framework classifies the endpoint as `CURRENTLY_HEALTHY`'
      );
      expect(skill.content).toContain(
        'NEVER list or remediate generic warning logs after the scoped investigation framework classifies the endpoint as `CURRENTLY_HEALTHY`'
      );
      expect(skill.content).toContain(
        'NEVER call platform.core.integration_knowledge or additional warning/error log searches after the scoped investigation framework classifies the endpoint as `CURRENTLY_HEALTHY`'
      );
      expect(skill.content).toContain(
        'NEVER present a root cause for a general unhealthy question when the currently healthy policy path finds no active issue'
      );
      expect(skill.content).toContain(
        'NEVER diagnose a different host, endpoint id, Elastic Agent id, or policy than the target endpoint named by the user'
      );
      expect(skill.content).toContain(
        'NEVER provide a diagnosis for another endpoint after saying the requested endpoint was not found'
      );
      expect(skill.content).toContain(
        "DON'T perform detailed debugging, broad searches, or remediation recommendations before the scoped investigation framework"
      );
    });

    it('includes example integration knowledge queries', () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      expect(skill.content).toContain('download_global_artifacts');
      expect(skill.content).toContain('global_manifest_version');
      expect(skill.content).toContain('agent.build.original');
      expect(skill.content).toContain('download_user_artifacts');
      expect(skill.content).toContain('missed checkins');
      expect(skill.content).toContain('trusted apps');
      expect(skill.content).toContain('nested_objects.limit');
      expect(skill.content).toContain('Failed to open kernel device');
      expect(skill.content).toContain('action.name agent_connectivity');
    });
  });

  describe('getRegistryTools', () => {
    it('returns the correct platform core tools', () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      const allowedTools = skill.getRegistryTools?.();

      expect(allowedTools).toBeDefined();
      expect(allowedTools).toHaveLength(3);
      expect(allowedTools).toContain(platformCoreTools.search);
      expect(allowedTools).toContain(platformCoreTools.getDocumentById);
      expect(allowedTools).toContain(platformCoreTools.integrationKnowledge);
    });
  });

  describe('getInlineTools', () => {
    it('returns four inline tools', () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      const inlineTools = skill.getInlineTools?.();

      expect(inlineTools).toBeDefined();
      expect(inlineTools).toHaveLength(4);
    });

    it('includes get_package_configurations tool', async () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      const inlineTools = await skill.getInlineTools?.();

      const getPackageConfigTool = inlineTools?.find((tool) =>
        tool.id.includes('get_package_configurations')
      );

      expect(getPackageConfigTool).toBeDefined();
      expect(getPackageConfigTool?.description).toContain('Fetches Elastic Defend package');
    });

    it('includes generate_insight tool', async () => {
      const skill = createAutomaticTroubleshootingSkill(mockEndpointAppContextService);

      const inlineTools = await skill.getInlineTools?.();

      const generateInsightTool = inlineTools?.find((tool) => tool.id.includes('generate_insight'));

      expect(generateInsightTool).toBeDefined();
      expect(generateInsightTool?.description).toContain('Generate and store structured');
    });
  });
});
