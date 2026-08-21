/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType, ToolType } from '@kbn/agent-builder-common';
import { isToolResultId } from '@kbn/agent-builder-server';
import type { StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock, loggingSystemMock } from '@kbn/core/server/mocks';
import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { PolicyOperatingSystem, ProtectionModes } from '../../../../../common/endpoint/types';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import { createToolHandlerContext } from '../../../__mocks__/test_helpers';
import { getFieldRegistry, isWritablePath } from '../domain/field_registry';
import {
  DEVICE_CONTROL_MISSING_POPUP_MESSAGE,
  DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE,
  POLICY_CHANGE_SCHEMA_MESSAGE,
  PolicyChangePreparationError,
  assessPolicyChangeParamsSchema,
  assertParameterBounds,
} from '../domain/impact';
import type { AssessPolicyChangeParams, PolicyChangeFact } from '../domain/impact';
import type { AssessPolicyChangeDto } from '../services/assess_change';
import { assessChange } from '../services/assess_change';
import { countEndpoints } from '../services/count_endpoints';
import { PolicyNotFoundError } from '../services/policy_errors';
import { getEndpointPolicy } from '../services/read_policy';
import { classifyPolicyError, POLICY_TOOL_ERROR_MESSAGES } from './create_policy_tool';
import {
  ASSESS_POLICY_CHANGE_TOOL_ID,
  assessPolicyChangeSchema,
  createAssessPolicyChangeTool,
} from './assess_policy_change';
import { estimateGuardedEnvelopeTokens, fitsGuardedEnvelope } from './trim_policy_result';

jest.mock('../services/assess_change', () => ({
  assessChange: jest.fn(),
}));

jest.mock('../services/read_policy', () => ({
  getEndpointPolicy: jest.fn(),
}));

jest.mock('../services/count_endpoints', () => ({
  countEndpoints: jest.fn(),
}));

const SPACE_ID = 'space-marketing';
const getStartServices = jest.fn(async () => [
  { savedObjects: { getScopedClient: jest.fn().mockReturnValue({}) } },
]) as unknown as StartServicesAccessor;
const mockedAssessChange = jest.mocked(assessChange);
const mockedGetEndpointPolicy = jest.mocked(getEndpointPolicy);
const mockedCountEndpoints = jest.mocked(countEndpoints);

const MIXED_STATUS: Readonly<Record<string, number>> = {
  all: 27,
  active: 22,
  online: 14,
  offline: 6,
  updating: 3,
  error: 2,
  inactive: 1,
  unenrolled: 2,
  events: 0,
  other: 1,
  orphaned: 1,
  uninstalled: 1,
  quarantined: 3,
  draining: 4,
};

const VERDICT_PATTERN =
  /\b(?:eligible|ineligible|safe|unsafe|recommended|ready to apply|unchanged since assessment)\b/i;

const EXCLUDED_MESSAGE_PATH = /popup\.device_control\.message/;

const VALID_PARAMS: AssessPolicyChangeParams = {
  idOrName: 'policy-1',
  changes: [{ op: 'set_protection_enabled', protection: 'malware', enabled: true }],
};

const expectToolResultId = (id: string | undefined): void => {
  if (id === undefined) {
    throw new Error('expected tool_result_id');
  }
  expect(isToolResultId(id)).toBe(true);
};

const createFact = (index: number, path = `windows.malware.mode.${index}`): PolicyChangeFact => ({
  path,
  from: 'off',
  to: ProtectionModes.prevent,
  origin: { operationIndex: 0, op: 'set_protection_enabled', kind: 'direct' },
  registry: {
    path,
    os: [PolicyOperatingSystem.windows],
    kind: 'protection',
    tier: 1,
    documentation: 'malware mode',
    source: 'factory',
    userEditable: true,
  },
  eligibility: { eligible: true },
});

const presentPolicyChangeFact = (fact: PolicyChangeFact): Record<string, unknown> => {
  const { kind: originKind, ...origin } = fact.origin;
  const { kind: registryKind, ...registry } = fact.registry;
  return {
    path: fact.path,
    originKind,
    registryKind,
    origin,
    registry,
    eligibility: fact.eligibility,
    from: fact.from,
    to: fact.to,
  };
};

const createDto = (overrides: Partial<AssessPolicyChangeDto> = {}): AssessPolicyChangeDto => ({
  policy: {
    id: 'policy-1',
    name: 'Endpoint Policy',
    revision: 3,
    version: 'WzEsMV0=',
  },
  spaceId: SPACE_ID,
  requestedOperations: VALID_PARAMS.changes,
  requestedImpact: [createFact(0, 'windows.malware.mode')],
  expandedChanges: [createFact(0, 'windows.malware.mode')],
  normalizedDiff: [{ path: 'windows.malware.mode', from: 'off', to: ProtectionModes.prevent }],
  sideEffects: [
    {
      path: 'windows.antivirus_registration.enabled',
      from: false,
      to: true,
      reason: 'derived_field_update',
      registry: {
        path: 'windows.antivirus_registration.enabled',
        os: [PolicyOperatingSystem.windows],
        kind: 'other',
        tier: 1,
        source: 'factory',
      },
    },
  ],
  blastRadius: {
    population: 'enrolled_agents',
    source: 'fleet_status_aggregation',
    status: MIXED_STATUS,
  },
  ...overrides,
});

const createContext = (
  logger: ReturnType<typeof loggingSystemMock.createLogger> = loggingSystemMock.createLogger()
) =>
  createToolHandlerContext(
    httpServerMock.createKibanaRequest(),
    elasticsearchClientMock.createScopedClusterClient(),
    logger,
    { spaceId: SPACE_ID }
  );

const createAuthorizedService = () => {
  const endpointAppContextService = createMockEndpointAppContextService();
  endpointAppContextService.getEndpointAuthz.mockResolvedValue(
    getEndpointAuthzInitialStateMock({
      canReadPolicyManagement: true,
      canReadEndpointList: true,
      canWritePolicyManagement: false,
    })
  );
  return endpointAppContextService;
};

const getResult = async (
  params: { idOrName: string; changes: AssessPolicyChangeParams['changes'] | [] },
  options: {
    endpointAppContextService?: ReturnType<typeof createMockEndpointAppContextService>;
    ctx?: ReturnType<typeof createContext>;
  } = {}
) => {
  const tool = createAssessPolicyChangeTool({
    endpointAppContextService: options.endpointAppContextService ?? createAuthorizedService(),
    getStartServices,
  });
  const result = await tool.handler(params, options.ctx ?? createContext());
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }
  return result.results[0];
};

describe('createAssessPolicyChangeTool', () => {
  beforeEach(() => {
    mockedAssessChange.mockReset();
    mockedGetEndpointPolicy.mockReset();
    mockedCountEndpoints.mockReset();
  });

  it('registers the approved id, estate_read access, schema, and 12000-token budget', () => {
    const tool = createAssessPolicyChangeTool({
      endpointAppContextService: createAuthorizedService(),
      getStartServices,
    });

    expect(tool.id).toBe(ASSESS_POLICY_CHANGE_TOOL_ID);
    expect(tool.id).toBe('security.policy_management.assess_policy_change');
    expect(tool.type).toBe(ToolType.builtin);
    expect(tool.maxResultTokens).toBe(12_000);
    expect(tool.schema).toBe(assessPolicyChangeSchema);
    expect(assessPolicyChangeSchema).toBe(assessPolicyChangeParamsSchema);
  });

  it('bounds the approved schema before any tool IO', () => {
    expect(assessPolicyChangeSchema.parse({ ...VALID_PARAMS, idOrName: '  policy-1  ' })).toEqual(
      VALID_PARAMS
    );
    expect(
      assessPolicyChangeSchema.safeParse({ ...VALID_PARAMS, idOrName: 'a'.repeat(256) }).success
    ).toBe(true);
    expect(
      assessPolicyChangeSchema.safeParse({ ...VALID_PARAMS, idOrName: 'a'.repeat(257) }).success
    ).toBe(false);
    expect(assessPolicyChangeSchema.safeParse({ ...VALID_PARAMS, idOrName: '' }).success).toBe(
      false
    );
    expect(assessPolicyChangeSchema.safeParse({ idOrName: 'policy-1', changes: [] }).success).toBe(
      false
    );
    expect(
      assessPolicyChangeSchema.safeParse({
        idOrName: 'policy-1',
        changes: Array.from({ length: 51 }, () => VALID_PARAMS.changes[0]),
      }).success
    ).toBe(false);
    expect(assessPolicyChangeSchema.safeParse({ ...VALID_PARAMS, extra: true }).success).toBe(
      false
    );
  });

  it('uses facts-only wording and no verdict, eligibility, apply-state, or license fields', () => {
    const tool = createAssessPolicyChangeTool({
      endpointAppContextService: createAuthorizedService(),
      getStartServices,
    });

    expect(tool.description).not.toMatch(VERDICT_PATTERN);
    expect(tool.description).toContain('separate facts');
    expect(tool.description).toContain('status.all');
    expect(tool.description).toContain('Does not write policies');
    expect(tool.description).toContain('per-path eligibility');
  });

  it('forwards factory access and returns DTO fields plus enrolled-agent headline', async () => {
    const dto = createDto();
    const endpointAppContextService = createAuthorizedService();
    const ctx = createContext();
    mockedAssessChange.mockResolvedValue(dto);

    const tool = createAssessPolicyChangeTool({ endpointAppContextService, getStartServices });
    const result = await tool.handler(VALID_PARAMS, ctx);
    if (!('results' in result)) {
      throw new Error('expected a standard tool result');
    }

    expect(mockedAssessChange).toHaveBeenCalledTimes(1);
    expect(mockedAssessChange).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'estate_read',
        spaceId: SPACE_ID,
      }),
      endpointAppContextService,
      VALID_PARAMS
    );
    expect(mockedAssessChange.mock.calls[0][0]).not.toHaveProperty('request');
    expect(mockedGetEndpointPolicy).not.toHaveBeenCalled();
    expect(mockedCountEndpoints).not.toHaveBeenCalled();
    expect(result.results[0].type).toBe(ToolResultType.other);
    expect(result.results[0].data).toEqual({
      policy: dto.policy,
      spaceId: SPACE_ID,
      requestedOperations: dto.requestedOperations,
      requestedImpact: dto.requestedImpact.map(presentPolicyChangeFact),
      expandedChanges: dto.expandedChanges.map(presentPolicyChangeFact),
      normalizedDiff: dto.normalizedDiff,
      sideEffects: dto.sideEffects,
      blastRadius: {
        population: 'enrolled_agents',
        source: 'fleet_status_aggregation',
        status: MIXED_STATUS,
        headline: 27,
      },
    });
    expect(result.results[0].data).not.toHaveProperty('eligible');
    expect(result.results[0].data).not.toHaveProperty('license');
    expect(result.results[0].data).not.toHaveProperty('out_of_date');
    const presentedExpanded = (
      result.results[0].data as {
        expandedChanges: Array<{
          origin: Record<string, unknown>;
          registry: Record<string, unknown>;
        }>;
      }
    ).expandedChanges[0];
    expect(presentedExpanded).toEqual(
      expect.objectContaining({
        originKind: 'direct',
        registryKind: 'protection',
        eligibility: { eligible: true },
      })
    );
    expect(presentedExpanded).not.toHaveProperty('kind');
    expect(presentedExpanded.origin).not.toHaveProperty('kind');
    expect(presentedExpanded.registry).not.toHaveProperty('kind');
  });

  it('carries the registry product feature gate through the tool result', async () => {
    const manifestFact: PolicyChangeFact = {
      ...createFact(0, 'global_manifest_version'),
      registry: {
        ...createFact(0, 'global_manifest_version').registry,
        productFeatureGate: 'endpointProtectionUpdates',
      },
    };
    mockedAssessChange.mockResolvedValue(
      createDto({
        requestedImpact: [manifestFact],
        expandedChanges: [manifestFact],
      })
    );

    const result = await getResult(VALID_PARAMS);
    const presented = result.data as {
      requestedImpact: Array<{ registry: { productFeatureGate?: string } }>;
    };

    expect(result.type).toBe(ToolResultType.other);
    expect(presented.requestedImpact[0]?.registry.productFeatureGate).toBe(
      'endpointProtectionUpdates'
    );
  });

  it('presents an empty requested impact with preserved requested operations on a no-op', async () => {
    mockedAssessChange.mockResolvedValue(
      createDto({
        requestedImpact: [],
        expandedChanges: [],
        normalizedDiff: [],
        sideEffects: [],
      })
    );

    const result = await getResult(VALID_PARAMS);
    const presented = result.data as {
      requestedOperations: unknown[];
      requestedImpact: unknown[];
    } & Record<string, unknown>;

    expect(result.type).toBe(ToolResultType.other);
    expect(presented.requestedOperations).toEqual(VALID_PARAMS.changes);
    expect(presented.requestedImpact).toEqual([]);
    expect(presented).not.toHaveProperty('requested_impact_value_truncated');
    expect(presented).not.toHaveProperty('requested_impact_value_total');
  });

  it('preserves the complete status map and uses status.all as headline only when present', async () => {
    mockedAssessChange.mockResolvedValue(createDto());
    const withAll = await getResult(VALID_PARAMS);
    const withAllData = withAll.data as {
      blastRadius: {
        headline?: number;
        headlineUnavailable?: true;
        status: Record<string, number>;
      };
    };

    expect(withAllData.blastRadius.status).toEqual(MIXED_STATUS);
    expect(withAllData.blastRadius.headline).toBe(MIXED_STATUS.all);
    expect(withAllData.blastRadius).not.toHaveProperty('headlineUnavailable');

    mockedAssessChange.mockResolvedValue(
      createDto({
        blastRadius: {
          population: 'enrolled_agents',
          source: 'fleet_status_aggregation',
          status: { all: 0, online: 0, offline: 0 },
        },
      })
    );
    const zeroAll = await getResult(VALID_PARAMS);
    expect(
      (zeroAll.data as { blastRadius: { headline: number; status: Record<string, number> } })
        .blastRadius
    ).toEqual({
      population: 'enrolled_agents',
      source: 'fleet_status_aggregation',
      status: { all: 0, online: 0, offline: 0 },
      headline: 0,
    });

    const absentStatus = { online: 4, offline: 3, updating: 1, quarantined: 2 };
    mockedAssessChange.mockResolvedValue(
      createDto({
        blastRadius: {
          population: 'enrolled_agents',
          source: 'no_agent_policy_assignments',
          status: absentStatus,
        },
      })
    );
    const withoutAll = await getResult(VALID_PARAMS);
    const withoutAllData = withoutAll.data as {
      blastRadius: {
        headline?: number;
        headlineUnavailable?: true;
        status: Record<string, number>;
      };
    };

    expect(withoutAllData.blastRadius).toEqual({
      population: 'enrolled_agents',
      source: 'no_agent_policy_assignments',
      status: absentStatus,
      headlineUnavailable: true,
    });
    expect(withoutAllData.blastRadius.status).not.toHaveProperty('all');
    expect(withoutAllData.blastRadius).not.toHaveProperty('headline');
    expect(
      Object.values(withoutAllData.blastRadius.status).reduce((sum, value) => sum + value, 0)
    ).toBe(10);
  });

  it('annotates trimmed expanded rows and never filters blastRadius.status', async () => {
    const expandedChanges = Array.from({ length: 80 }, (_, index) => createFact(index));
    const normalizedDiff = expandedChanges.map(({ path, from, to }) => ({ path, from, to }));
    mockedAssessChange.mockResolvedValue(
      createDto({
        expandedChanges,
        normalizedDiff,
      })
    );

    const result = await getResult(VALID_PARAMS);
    const presented = result.data as {
      expandedChanges: unknown[];
      normalizedDiff: unknown[];
      blastRadius: { status: Record<string, number> };
    } & Record<string, unknown>;

    expect(result.type).toBe(ToolResultType.other);
    expect(presented.expandedChanges).toHaveLength(50);
    expect(presented.normalizedDiff).toHaveLength(50);
    expect(presented).toEqual(
      expect.objectContaining({
        expanded_changes_value_truncated: true,
        expanded_changes_value_total: 80,
        normalized_diff_value_truncated: true,
        normalized_diff_value_total: 80,
      })
    );
    expect(presented.blastRadius.status).toEqual(MIXED_STATUS);
    expect(Object.keys(presented.blastRadius.status)).toEqual(Object.keys(MIXED_STATUS));
    expect(fitsGuardedEnvelope(presented, 12_000)).toBe(true);
    expect(estimateGuardedEnvelopeTokens(presented)).toBeLessThanOrEqual(12_000);
  });

  it('annotates trimmed requested impact rows with truthful totals', async () => {
    const requestedImpact = Array.from({ length: 80 }, (_, index) => createFact(index));
    mockedAssessChange.mockResolvedValue(createDto({ requestedImpact }));

    const result = await getResult(VALID_PARAMS);
    const presented = result.data as { requestedImpact: unknown[] } & Record<string, unknown>;

    expect(result.type).toBe(ToolResultType.other);
    expect(presented.requestedImpact).toHaveLength(50);
    expect(presented).toEqual(
      expect.objectContaining({
        requested_impact_value_truncated: true,
        requested_impact_value_total: 80,
      })
    );
    expect(fitsGuardedEnvelope(presented, 12_000)).toBe(true);
  });

  it('fits a bounds-valid large requestedOperations payload under the current budget', async () => {
    const writablePaths = getFieldRegistry()
      .filter(isWritablePath)
      .map((entry) => entry.path)
      .slice(0, 50);
    const firstPath = writablePaths[0];
    expect(writablePaths).toHaveLength(50);
    expect(firstPath).toEqual(expect.any(String));

    const largeValue = Array.from({ length: 20 }, (_, index) => {
      return `item-${String(index).padStart(2, '0')}-${'N'.repeat(40)}`;
    });
    const requestedOperations = writablePaths.map((path) => ({
      op: 'set_field' as const,
      path,
      value: largeValue,
    }));
    const params = { idOrName: 'policy-1', changes: requestedOperations };

    expect(assessPolicyChangeSchema.safeParse(params).success).toBe(true);
    expect(() => assertParameterBounds(params)).not.toThrow();

    const untrimmedEcho = {
      policy: {
        id: 'policy-1',
        name: 'Endpoint Policy',
        revision: 3,
        version: 'WzEsMV0=',
      },
      spaceId: SPACE_ID,
      requestedOperations,
      expandedChanges: [],
      normalizedDiff: [],
      sideEffects: [],
      blastRadius: {
        population: 'enrolled_agents',
        source: 'fleet_status_aggregation',
        status: MIXED_STATUS,
        headline: 27,
      },
    };
    expect(fitsGuardedEnvelope(untrimmedEcho, 12_000)).toBe(false);

    mockedAssessChange.mockResolvedValue(
      createDto({
        requestedOperations,
        expandedChanges: [{ ...createFact(0, firstPath), to: largeValue }],
        normalizedDiff: [{ path: firstPath, from: 'off', to: largeValue }],
      })
    );

    const result = await getResult(params);
    const presented = result.data as {
      policy: { id: string; name: string; revision: number; version: string };
      requestedOperations: Array<{ op: string; path?: string } & Record<string, unknown>>;
      blastRadius: {
        population: string;
        source: string;
        status: Record<string, number>;
        headline?: number;
      };
    } & Record<string, unknown>;

    expect(result.type).toBe(ToolResultType.other);
    expect(fitsGuardedEnvelope(presented, 12_000)).toBe(true);
    expect(estimateGuardedEnvelopeTokens(presented)).toBeLessThanOrEqual(12_000);
    expect(presented.policy).toEqual(
      expect.objectContaining({
        id: 'policy-1',
        name: 'Endpoint Policy',
        revision: 3,
        version: 'WzEsMV0=',
      })
    );
    expect(presented.blastRadius).toEqual(
      expect.objectContaining({
        population: 'enrolled_agents',
        source: 'fleet_status_aggregation',
        status: MIXED_STATUS,
        headline: 27,
      })
    );
    expect(presented.requestedOperations.length).toBeGreaterThan(0);
    expect(presented.requestedOperations.length).toBeLessThanOrEqual(50);

    if (presented.requestedOperations.length < 50) {
      expect(presented.requested_operations_value_truncated).toBe(true);
      expect(presented.requested_operations_value_total).toBe(50);
    } else {
      expect(presented).not.toHaveProperty('requested_operations_value_truncated');
    }

    for (const operation of presented.requestedOperations) {
      expect(operation.op).toBe('set_field');
      expect(writablePaths).toContain(operation.path);
    }
  });

  it('caps oversized policy identity and flags only the cut strings', async () => {
    mockedAssessChange.mockResolvedValue(
      createDto({
        policy: {
          id: 'I'.repeat(600),
          name: 'N'.repeat(600),
          revision: 3,
          version: 'V'.repeat(600),
        },
      })
    );

    const result = await getResult(VALID_PARAMS);
    const presented = result.data as { policy: Record<string, unknown> };

    expect(presented.policy).toEqual({
      id: 'I'.repeat(512),
      id_string_truncated: true,
      name: 'N'.repeat(512),
      name_string_truncated: true,
      revision: 3,
      version: 'V'.repeat(512),
      version_string_truncated: true,
    });
    expect(presented.policy).not.toHaveProperty('description');
  });

  it('refuses estate_read before run and does not call assessChange', async () => {
    const endpointAppContextService = createMockEndpointAppContextService();
    endpointAppContextService.getEndpointAuthz.mockResolvedValue(
      getEndpointAuthzInitialStateMock({
        canReadPolicyManagement: true,
        canReadEndpointList: false,
        canWritePolicyManagement: false,
      })
    );

    const result = await getResult(VALID_PARAMS, { endpointAppContextService });

    expect(mockedAssessChange).not.toHaveBeenCalled();
    expect(result.type).toBe(ToolResultType.error);
    expectToolResultId(result.tool_result_id);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.not_authorized,
      metadata: { error: 'not_authorized' },
    });
    expect(result.data).not.toHaveProperty('stack');
  });

  it('returns existing scoped not-found without internals', async () => {
    mockedAssessChange.mockRejectedValue(new PolicyNotFoundError('missing-policy'));

    const result = await getResult({ ...VALID_PARAMS, idOrName: 'missing-policy' });

    expect(mockedAssessChange).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'estate_read',
        spaceId: SPACE_ID,
      }),
      expect.anything(),
      { ...VALID_PARAMS, idOrName: 'missing-policy' }
    );
    expect(result.type).toBe(ToolResultType.error);
    expectToolResultId(result.tool_result_id);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.not_found,
      metadata: { error: 'not_found' },
    });
    expect(result.data).not.toHaveProperty('stack');
    expect(JSON.stringify(result.data)).not.toMatch(/ECONNREFUSED|stack|canRead|es\.internal/i);
  });

  it('surfaces both device refusals through existing bounded classification without leaking excluded paths', async () => {
    const cases = [
      new PolicyChangePreparationError(
        'unsupported_operation',
        DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE
      ),
      new PolicyChangePreparationError(
        'unsupported_operation',
        DEVICE_CONTROL_MISSING_POPUP_MESSAGE
      ),
    ];

    for (const thrown of cases) {
      expect(classifyPolicyError(thrown)).toBe('unsupported_operation');
      mockedAssessChange.mockRejectedValueOnce(thrown);

      const result = await getResult({
        idOrName: 'policy-1',
        changes: [{ op: 'set_field', path: 'windows.device_control.enabled', value: false }],
      });
      const serialized = JSON.stringify(result.data);

      expect(result.type).toBe(ToolResultType.error);
      expectToolResultId(result.tool_result_id);
      expect(result.data).toEqual({
        message: POLICY_TOOL_ERROR_MESSAGES.unsupported_operation,
        metadata: { error: 'unsupported_operation' },
      });
      expect(serialized).not.toMatch(EXCLUDED_MESSAGE_PATH);
      expect(serialized).not.toContain('popup.device_control.message');
      expect(serialized).not.toContain(thrown.message);
    }
  });

  it('rejects schema failures through assessChange before resolve or count IO', async () => {
    mockedAssessChange.mockImplementation(
      jest.requireActual('../services/assess_change').assessChange
    );

    const result = await getResult({ idOrName: 'policy-1', changes: [] });

    expect(mockedAssessChange).toHaveBeenCalledTimes(1);
    expect(mockedGetEndpointPolicy).not.toHaveBeenCalled();
    expect(mockedCountEndpoints).not.toHaveBeenCalled();
    expect(result.type).toBe(ToolResultType.error);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.invalid_input,
      metadata: { error: 'invalid_input' },
    });
    expect(
      classifyPolicyError(
        new PolicyChangePreparationError('invalid_input', POLICY_CHANGE_SCHEMA_MESSAGE)
      )
    ).toBe('invalid_input');
  });
});
