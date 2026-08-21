/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType, ToolType } from '@kbn/agent-builder-common';
import { isToolResultId } from '@kbn/agent-builder-server';
import type { ToolHandlerContext } from '@kbn/agent-builder-server/tools';
import type { StartServicesAccessor } from '@kbn/core/server';
import { httpServerMock, loggingSystemMock } from '@kbn/core/server/mocks';
import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import { z } from '@kbn/zod/v4';
import { getEndpointAuthzInitialStateMock } from '../../../../../common/endpoint/service/authz/mocks';
import { createMockEndpointAppContextService } from '../../../../endpoint/mocks';
import {
  EndpointAuthorizationError,
  EndpointHttpError,
  NotFoundError as EndpointNotFoundError,
} from '../../../../endpoint/errors';
import { createToolHandlerContext } from '../../../__mocks__/test_helpers';
import {
  DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE,
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  POLICY_CHANGE_SCHEMA_MESSAGE,
  PolicyChangePreparationError,
  nonWritablePathMessage,
  unknownCurrentValueMessage,
} from '../domain/impact';
import type { PolicyAccessContext } from '../services/access_context';
import {
  InvalidEndpointPolicyError,
  PolicyAmbiguousNameError,
  PolicyAuthorizationError,
  PolicyConflictError,
  PolicyNotFoundError,
} from '../services/policy_errors';
import {
  POLICY_TOOL_ERROR_MESSAGES,
  classifyPolicyError,
  createPolicyTool,
} from './create_policy_tool';

const SPACE_ID = 'space-marketing';
const TOOL_ID = 'security.policy_management.test_policy_tool';

const testSchema = z.object({
  idOrName: z.string().min(1).max(256),
});

const createLogger = () => loggingSystemMock.createLogger();

const expectToolResultId = (id: string | undefined): void => {
  if (id === undefined) {
    throw new Error('expected tool_result_id');
  }
  expect(isToolResultId(id)).toBe(true);
};

const createContext = (
  logger: ReturnType<typeof loggingSystemMock.createLogger> = createLogger()
): ToolHandlerContext => {
  const request = httpServerMock.createKibanaRequest();
  return createToolHandlerContext(
    request,
    elasticsearchClientMock.createScopedClusterClient(),
    logger,
    { spaceId: SPACE_ID }
  );
};

const createGetStartServices = (): StartServicesAccessor =>
  jest.fn(async () => [
    { savedObjects: { getScopedClient: jest.fn().mockReturnValue({}) } },
  ]) as unknown as StartServicesAccessor;

const createAuthorizedService = () => {
  const endpointAppContextService = createMockEndpointAppContextService();
  const getStartServices = createGetStartServices();
  const scopedFleet = endpointAppContextService.getInternalFleetServices();
  const callOrder: string[] = [];

  endpointAppContextService.getInternalFleetServices.mockReset();
  endpointAppContextService.getInternalFleetServices.mockImplementation((spaceId?: string) => {
    callOrder.push(`fleet:${spaceId ?? ''}`);
    return scopedFleet;
  });
  endpointAppContextService.getEndpointAuthz.mockImplementation(async () => {
    callOrder.push('authz');
    return getEndpointAuthzInitialStateMock({
      canReadPolicyManagement: true,
      canReadEndpointList: false,
      canWritePolicyManagement: false,
    });
  });

  return { endpointAppContextService, getStartServices, scopedFleet, callOrder };
};

const getHandlerResult = async (
  run: jest.Mock,
  options: {
    logger?: ReturnType<typeof loggingSystemMock.createLogger>;
    refuse?: boolean;
    maxResultTokens?: number;
  } = {}
) => {
  const logger = options.logger ?? createLogger();
  const { endpointAppContextService, getStartServices, scopedFleet, callOrder } =
    createAuthorizedService();
  if (options.refuse) {
    endpointAppContextService.getEndpointAuthz.mockImplementation(async () => {
      callOrder.push('authz');
      return getEndpointAuthzInitialStateMock({
        canReadPolicyManagement: false,
        canReadEndpointList: false,
        canWritePolicyManagement: false,
      });
    });
  }

  const tool = createPolicyTool({
    endpointAppContextService,
    getStartServices,
    id: TOOL_ID,
    description: 'Test policy tool',
    schema: testSchema,
    level: 'policy_read',
    maxResultTokens: options.maxResultTokens,
    run,
  });
  const ctx = createContext(logger);
  const result = await tool.handler({ idOrName: 'policy-1' }, ctx);
  if (!('results' in result)) {
    throw new Error('expected a standard tool result');
  }

  return {
    tool,
    ctx,
    result: result.results[0],
    endpointAppContextService,
    getStartServices,
    scopedFleet,
    callOrder,
    logger,
  };
};

describe('classifyPolicyError', () => {
  it('classifies local authorization, not-found, ambiguous, invalid, and conflict errors', () => {
    expect(classifyPolicyError(new PolicyAuthorizationError())).toBe('not_authorized');
    expect(classifyPolicyError(new PolicyNotFoundError('policy-1'))).toBe('not_found');
    expect(classifyPolicyError(new PolicyAmbiguousNameError([{ id: 'a', name: 'alpha' }], 1))).toBe(
      'ambiguous_name'
    );
    expect(classifyPolicyError(new InvalidEndpointPolicyError('policy-1'))).toBe('invalid_policy');
    expect(classifyPolicyError(new PolicyConflictError())).toBe('conflict');
  });

  it('classifies Endpoint authorization and not-found classes', () => {
    expect(classifyPolicyError(new EndpointAuthorizationError())).toBe('not_authorized');
    expect(classifyPolicyError(new EndpointNotFoundError('missing'))).toBe('not_found');
  });

  it('classifies HTTP 403, 404, and 409 from statusCode, body, output, and getStatusCode', () => {
    const forbidden = new Error('Forbidden');
    (forbidden as Error & { statusCode: number }).statusCode = 403;
    expect(classifyPolicyError(forbidden)).toBe('not_authorized');

    const bodyForbidden = new Error('Forbidden');
    (bodyForbidden as Error & { body: { statusCode: number } }).body = { statusCode: 403 };
    expect(classifyPolicyError(bodyForbidden)).toBe('not_authorized');

    const boomForbidden = new Error('Forbidden');
    (boomForbidden as Error & { output: { statusCode: number } }).output = { statusCode: 403 };
    expect(classifyPolicyError(boomForbidden)).toBe('not_authorized');

    const getterForbidden = new Error('Forbidden');
    (getterForbidden as Error & { getStatusCode: () => number }).getStatusCode = () => 403;
    expect(classifyPolicyError(getterForbidden)).toBe('not_authorized');

    expect(classifyPolicyError(new EndpointHttpError('missing', 404))).toBe('not_found');
    expect(classifyPolicyError(new EndpointHttpError('conflict', 409))).toBe('conflict');
  });

  it('classifies expected PolicyChangePreparationError codes and ignores raw messages', () => {
    const leakyPath = 'linux.advanced.artifacts.global.channel';
    expect(
      classifyPolicyError(
        new PolicyChangePreparationError(
          POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
          nonWritablePathMessage(leakyPath)
        )
      )
    ).toBe('non_writable_path');
    expect(
      classifyPolicyError(
        new PolicyChangePreparationError(
          POLICY_CHANGE_PREPARATION_ERROR_CODE.unsupported_operation,
          DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE
        )
      )
    ).toBe('unsupported_operation');
    expect(
      classifyPolicyError(
        new PolicyChangePreparationError(
          POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input,
          POLICY_CHANGE_SCHEMA_MESSAGE
        )
      )
    ).toBe('invalid_input');
    expect(
      classifyPolicyError(
        new PolicyChangePreparationError(
          POLICY_CHANGE_PREPARATION_ERROR_CODE.unknown_current_value,
          unknownCurrentValueMessage(leakyPath)
        )
      )
    ).toBe('unknown_current_value');
    expect(
      classifyPolicyError(
        new PolicyChangePreparationError('unknown_code' as 'invalid_input', leakyPath)
      )
    ).toBe('unknown_error');
  });

  it('classifies bad requests and unknown faults as unknown_error, never as not_found', () => {
    expect(classifyPolicyError(new EndpointHttpError('bad request', 400))).toBe('unknown_error');
    expect(classifyPolicyError(new EndpointHttpError('server', 500))).toBe('unknown_error');
    expect(classifyPolicyError(new Error('ECONNREFUSED es.internal.local:9200'))).toBe(
      'unknown_error'
    );
    expect(classifyPolicyError('string error')).toBe('unknown_error');
  });
});

describe('createPolicyTool', () => {
  it('creates a builtin tool and forwards optional maxResultTokens', () => {
    const { endpointAppContextService, getStartServices } = createAuthorizedService();
    const tool = createPolicyTool({
      endpointAppContextService,
      getStartServices,
      id: TOOL_ID,
      description: 'Test policy tool',
      schema: testSchema,
      level: 'policy_read',
      maxResultTokens: 8_000,
      run: async () => ({ ok: true }),
    });

    expect(tool.id).toBe(TOOL_ID);
    expect(tool.type).toBe(ToolType.builtin);
    expect(tool.description).toBe('Test policy tool');
    expect(tool.schema).toBe(testSchema);
    expect(tool.maxResultTokens).toBe(8_000);
  });

  it('omits maxResultTokens when the caller does not set a budget', () => {
    const { endpointAppContextService, getStartServices } = createAuthorizedService();
    const tool = createPolicyTool({
      endpointAppContextService,
      getStartServices,
      id: TOOL_ID,
      description: 'Test policy tool',
      schema: testSchema,
      level: 'policy_read',
      run: async () => ({ ok: true }),
    });

    expect(tool.maxResultTokens).toBeUndefined();
  });

  it('refuses before run and does not acquire Fleet services', async () => {
    const run = jest.fn(async () => ({ leaked: true }));
    const { result, endpointAppContextService, getStartServices, callOrder, logger } =
      await getHandlerResult(run, {
        refuse: true,
      });

    expect(run).not.toHaveBeenCalled();
    expect(endpointAppContextService.getInternalFleetServices).not.toHaveBeenCalled();
    expect(getStartServices).not.toHaveBeenCalled();
    expect(callOrder).toEqual(['authz']);
    expect(result.type).toBe(ToolResultType.error);
    expectToolResultId(result.tool_result_id);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.not_authorized,
      metadata: { error: 'not_authorized' },
    });
    expect(result.data).not.toHaveProperty('stack');
    expect(logger.debug).toHaveBeenCalledWith(`Error in ${TOOL_ID}: not_authorized`);
    expect(logger.error).not.toHaveBeenCalled();
  });

  it('forwards the same handler request and spaceId into access before run', async () => {
    const run = jest.fn(
      async (
        _params: z.infer<typeof testSchema>,
        _access: PolicyAccessContext<'policy_read'>,
        _core: { request: ReturnType<typeof httpServerMock.createKibanaRequest> }
      ) => ({
        ok: true,
      })
    );
    const { result, ctx, endpointAppContextService, getStartServices, callOrder } =
      await getHandlerResult(run);

    expect(endpointAppContextService.getEndpointAuthz).toHaveBeenCalledTimes(1);
    expect(endpointAppContextService.getEndpointAuthz).toHaveBeenCalledWith(ctx.request);
    expect(endpointAppContextService.getInternalFleetServices).toHaveBeenCalledTimes(1);
    expect(endpointAppContextService.getInternalFleetServices).toHaveBeenCalledWith(SPACE_ID);
    expect(getStartServices).toHaveBeenCalledTimes(1);
    expect(callOrder).toEqual(['authz', `fleet:${SPACE_ID}`]);
    expect(run).toHaveBeenCalledTimes(1);
    expect(run).toHaveBeenCalledWith(
      { idOrName: 'policy-1' },
      expect.objectContaining({
        level: 'policy_read',
        spaceId: SPACE_ID,
      }),
      { request: ctx.request }
    );
    expect(run.mock.calls[0][2].request).toBe(ctx.request);
    expect(run.mock.calls[0][1]).not.toHaveProperty('request');
    expect(result.type).toBe(ToolResultType.other);
    expectToolResultId(result.tool_result_id);
    expect(result.data).toEqual({ ok: true });
  });

  it.each([
    ['not_authorized', new PolicyAuthorizationError()],
    ['not_found', new PolicyNotFoundError('policy-1')],
    ['invalid_policy', new InvalidEndpointPolicyError('policy-1')],
    ['conflict', new PolicyConflictError()],
    ['not_authorized', new EndpointAuthorizationError()],
    ['not_found', new EndpointNotFoundError('missing')],
  ] as const)(
    'returns a stable %s error result without internals and debug-logs expected faults',
    async (errorClass, thrown) => {
      const logger = createLogger();
      const run = jest.fn(async () => {
        throw thrown;
      });
      const { result } = await getHandlerResult(run, { logger });

      expect(result.type).toBe(ToolResultType.error);
      expectToolResultId(result.tool_result_id);
      expect(result.data).toEqual({
        message: POLICY_TOOL_ERROR_MESSAGES[errorClass],
        metadata: { error: errorClass },
      });
      expect(result.data).not.toHaveProperty('stack');
      expect(JSON.stringify(result.data)).not.toMatch(/ECONNREFUSED|stack|canRead|es\.internal/i);
      expect(logger.debug).toHaveBeenCalledWith(`Error in ${TOOL_ID}: ${errorClass}`);
      expect(logger.error).not.toHaveBeenCalled();
    }
  );

  it('includes bounded ambiguous-name candidates in error metadata', async () => {
    const logger = createLogger();
    const candidates = Array.from({ length: 12 }, (_, index) => ({
      id: `id-${index}`,
      name: `name-${index}`,
      description: 'should not leak',
    }));
    const run = jest.fn(async () => {
      throw new PolicyAmbiguousNameError(candidates, 12);
    });
    const { result } = await getHandlerResult(run, { logger });

    expect(result.type).toBe(ToolResultType.error);
    expectToolResultId(result.tool_result_id);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.ambiguous_name,
      metadata: {
        error: 'ambiguous_name',
        candidates: candidates.slice(0, 10).map(({ id, name }) => ({ id, name })),
        candidates_truncated: true,
        candidates_total: 12,
      },
    });
    expect(JSON.stringify(result.data)).not.toContain('should not leak');
    expect(logger.debug).toHaveBeenCalledWith(`Error in ${TOOL_ID}: ambiguous_name`);
    expect(logger.error).not.toHaveBeenCalled();
  });

  it.each([
    [
      'non_writable_path',
      new PolicyChangePreparationError(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path,
        nonWritablePathMessage('linux.advanced.artifacts.global.channel')
      ),
      ['linux.advanced.artifacts.global.channel', 'Path is not a writable policy field'],
    ],
    [
      'unsupported_operation',
      new PolicyChangePreparationError(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.unsupported_operation,
        DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE
      ),
      ['device_control.enabled', 'popup.device_control', DEVICE_POPUP_ENABLED_UNSUPPORTED_MESSAGE],
    ],
    [
      'invalid_input',
      new PolicyChangePreparationError(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input,
        POLICY_CHANGE_SCHEMA_MESSAGE
      ),
      [POLICY_CHANGE_SCHEMA_MESSAGE],
    ],
    [
      'unknown_current_value',
      new PolicyChangePreparationError(
        POLICY_CHANGE_PREPARATION_ERROR_CODE.unknown_current_value,
        unknownCurrentValueMessage('windows.advanced.malware.mode')
      ),
      ['windows.advanced.malware.mode', 'current value is not present in the live policy'],
    ],
  ] as const)(
    'returns a canned %s refusal without raw preparation text or paths and debug-logs it',
    async (errorClass, thrown, leakedFragments) => {
      const logger = createLogger();
      const run = jest.fn(async () => {
        throw thrown;
      });
      const { result } = await getHandlerResult(run, { logger });
      const serialized = JSON.stringify(result.data);

      expect(result.type).toBe(ToolResultType.error);
      expectToolResultId(result.tool_result_id);
      expect(result.data).toEqual({
        message: POLICY_TOOL_ERROR_MESSAGES[errorClass],
        metadata: { error: errorClass },
      });
      expect(result.data).not.toHaveProperty('stack');
      expect(serialized).not.toContain(thrown.message);
      for (const fragment of leakedFragments) {
        expect(serialized).not.toContain(fragment);
      }
      expect(logger.debug).toHaveBeenCalledWith(`Error in ${TOOL_ID}: ${errorClass}`);
      expect(logger.error).not.toHaveBeenCalled();
    }
  );

  it('error-logs unknown faults and returns a stable non-sensitive message', async () => {
    const logger = createLogger();
    const run = jest.fn(async () => {
      throw new Error('ECONNREFUSED es.internal.local:9200 secret-token');
    });
    const { result } = await getHandlerResult(run, { logger });

    expect(result.type).toBe(ToolResultType.error);
    expectToolResultId(result.tool_result_id);
    expect(result.data).toEqual({
      message: POLICY_TOOL_ERROR_MESSAGES.unknown_error,
      metadata: { error: 'unknown_error' },
    });
    expect(result.data).not.toHaveProperty('stack');
    expect(JSON.stringify(result.data)).not.toContain('ECONNREFUSED');
    expect(JSON.stringify(result.data)).not.toContain('secret-token');
    expect(JSON.stringify(result.data)).not.toContain('es.internal.local');
    expect(logger.error).toHaveBeenCalledWith(
      `Error in ${TOOL_ID}: ECONNREFUSED es.internal.local:9200 secret-token`
    );
    expect(logger.debug).not.toHaveBeenCalled();
  });
});
