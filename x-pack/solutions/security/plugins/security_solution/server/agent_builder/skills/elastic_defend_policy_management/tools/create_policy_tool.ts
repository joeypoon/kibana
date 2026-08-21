/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolType } from '@kbn/agent-builder-common';
import { createErrorResult, createOtherResult } from '@kbn/agent-builder-server';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import type { ToolHandlerContext } from '@kbn/agent-builder-server/tools';
import type { KibanaRequest, StartServicesAccessor } from '@kbn/core/server';
import type { Logger } from '@kbn/logging';
import type { z } from '@kbn/zod/v4';
import type { EndpointAppContextService } from '../../../../endpoint/endpoint_app_context_services';
import {
  EndpointAuthorizationError,
  NotFoundError as EndpointNotFoundError,
} from '../../../../endpoint/errors';
import {
  POLICY_CHANGE_PREPARATION_ERROR_CODE,
  PolicyChangePreparationError,
} from '../domain/impact';
import type { PolicyAccessContext, PolicyAccessLevel } from '../services/access_context';
import { createPolicyAccessContext } from '../services/access_context';
import {
  InvalidEndpointPolicyError,
  PolicyAmbiguousNameError,
  PolicyAuthorizationError,
  PolicyConflictError,
  PolicyNotFoundError,
} from '../services/policy_errors';

export type PolicyToolErrorClass =
  | 'not_authorized'
  | 'not_found'
  | 'ambiguous_name'
  | 'invalid_policy'
  | 'conflict'
  | 'non_writable_path'
  | 'unsupported_operation'
  | 'invalid_input'
  | 'unknown_current_value'
  | 'unknown_error';

export const POLICY_TOOL_ERROR_MESSAGES: Readonly<Record<PolicyToolErrorClass, string>> = {
  not_authorized: 'Not authorized for policy management',
  not_found: 'Endpoint policy not found',
  ambiguous_name: 'Multiple endpoint policies match the given name',
  invalid_policy: 'Selected policy is not a valid endpoint policy',
  conflict: 'Endpoint policy was modified concurrently',
  non_writable_path: 'Requested policy path is not writable',
  unsupported_operation: 'Requested policy change is not supported',
  invalid_input: 'Requested policy change input is invalid',
  unknown_current_value:
    'Requested policy change cannot be assessed because the current policy value is unknown',
  unknown_error: 'Failed to complete the policy management request',
};

interface CreatePolicyToolOptions<
  TSchema extends z.ZodObject<z.ZodRawShape>,
  TLevel extends PolicyAccessLevel,
  TResult extends Record<string, unknown>
> {
  endpointAppContextService: EndpointAppContextService;
  getStartServices: StartServicesAccessor;
  id: string;
  description: string;
  schema: TSchema;
  level: TLevel;
  maxResultTokens?: number;
  run: (
    params: z.infer<TSchema>,
    access: PolicyAccessContext<TLevel>,
    core: { request: KibanaRequest }
  ) => Promise<TResult> | TResult;
}

const getHttpStatusCode = (error: unknown): number | undefined => {
  if (!(error instanceof Error)) {
    return undefined;
  }

  if ('statusCode' in error && typeof error.statusCode === 'number') {
    return error.statusCode;
  }

  if ('body' in error) {
    const statusCode = (error as { body?: { statusCode?: number } }).body?.statusCode;
    if (typeof statusCode === 'number') {
      return statusCode;
    }
  }

  if ('output' in error) {
    const statusCode = (error as { output?: { statusCode?: number } }).output?.statusCode;
    if (typeof statusCode === 'number') {
      return statusCode;
    }
  }

  if (
    'getStatusCode' in error &&
    typeof (error as { getStatusCode: () => number }).getStatusCode === 'function'
  ) {
    const statusCode = (error as { getStatusCode: () => number }).getStatusCode();
    if (typeof statusCode === 'number') {
      return statusCode;
    }
  }

  return undefined;
};

export const classifyPolicyError = (error: unknown): PolicyToolErrorClass => {
  if (error instanceof PolicyAuthorizationError || error instanceof EndpointAuthorizationError) {
    return 'not_authorized';
  }

  if (error instanceof PolicyNotFoundError || error instanceof EndpointNotFoundError) {
    return 'not_found';
  }

  if (error instanceof PolicyAmbiguousNameError) {
    return 'ambiguous_name';
  }

  if (error instanceof InvalidEndpointPolicyError) {
    return 'invalid_policy';
  }

  if (error instanceof PolicyConflictError) {
    return 'conflict';
  }

  if (error instanceof PolicyChangePreparationError) {
    switch (error.code) {
      case POLICY_CHANGE_PREPARATION_ERROR_CODE.non_writable_path:
        return 'non_writable_path';
      case POLICY_CHANGE_PREPARATION_ERROR_CODE.unsupported_operation:
        return 'unsupported_operation';
      case POLICY_CHANGE_PREPARATION_ERROR_CODE.invalid_input:
        return 'invalid_input';
      case POLICY_CHANGE_PREPARATION_ERROR_CODE.unknown_current_value:
        return 'unknown_current_value';
      default:
        return 'unknown_error';
    }
  }

  const statusCode = getHttpStatusCode(error);
  if (statusCode === 403) {
    return 'not_authorized';
  }
  if (statusCode === 404) {
    return 'not_found';
  }
  if (statusCode === 409) {
    return 'conflict';
  }

  return 'unknown_error';
};

const buildErrorMetadata = (
  error: unknown,
  errorClass: PolicyToolErrorClass
): Record<string, unknown> => {
  const metadata: Record<string, unknown> = { error: errorClass };

  if (error instanceof PolicyAmbiguousNameError) {
    metadata.candidates = error.candidates;
    metadata.candidates_truncated = error.candidatesTruncated;
    metadata.candidates_total = error.candidatesTotal;
  }

  return metadata;
};

const toPolicyErrorResult = (error: unknown, logger: Logger, toolId: string) => {
  const errorClass = classifyPolicyError(error);

  if (errorClass === 'unknown_error') {
    logger.error(`Error in ${toolId}: ${error instanceof Error ? error.message : String(error)}`);
  } else {
    logger.debug(`Error in ${toolId}: ${errorClass}`);
  }

  return createErrorResult({
    message: POLICY_TOOL_ERROR_MESSAGES[errorClass],
    metadata: buildErrorMetadata(error, errorClass),
  });
};

export const createPolicyTool = <
  TSchema extends z.ZodObject<z.ZodRawShape>,
  TLevel extends PolicyAccessLevel,
  TResult extends Record<string, unknown>
>({
  endpointAppContextService,
  getStartServices,
  id,
  description,
  schema,
  level,
  maxResultTokens,
  run,
}: CreatePolicyToolOptions<TSchema, TLevel, TResult>): BuiltinSkillBoundedTool<TSchema> => ({
  id,
  type: ToolType.builtin,
  description,
  schema,
  ...(maxResultTokens !== undefined ? { maxResultTokens } : {}),
  handler: async (params: z.infer<TSchema>, ctx: ToolHandlerContext) => {
    try {
      const access = await createPolicyAccessContext(
        endpointAppContextService,
        { request: ctx.request, spaceId: ctx.spaceId },
        level,
        getStartServices
      );
      return { results: [createOtherResult(await run(params, access, { request: ctx.request }))] };
    } catch (error) {
      return { results: [toPolicyErrorResult(error, ctx.logger, id)] };
    }
  },
});
