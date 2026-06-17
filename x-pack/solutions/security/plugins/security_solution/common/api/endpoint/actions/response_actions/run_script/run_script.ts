/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { TypeOf } from '@kbn/config-schema';
import { schema } from '@kbn/config-schema';
import {
  MAX_EXECUTE_COMMAND_LENGTH,
  MAX_FILE_PATH_LENGTH,
  MAX_ID_LENGTH,
  MAX_SCRIPT_COMMAND_LENGTH,
  MAX_SCRIPT_INPUT_LENGTH,
} from '../../../../../endpoint/schema/schema_bounds_constants';
import { BaseActionRequestSchema } from '../../common/base';
import type { DeepMutable } from '../../../../../endpoint/types';

const { parameters, ...restBaseSchema } = BaseActionRequestSchema;
const getNonEmptyString = (fieldName: string, maxLength: number) =>
  schema.string({
    minLength: 1,
    maxLength,
    validate: (value) => {
      if (!value.trim().length) {
        return `${fieldName} cannot be an empty string`;
      }
    },
  });

// CrowdStrike schemas
const CrowdStrikeRunScriptActionRequestParamsSchema = schema.object(
  {
    /**
     * The script to run
     */
    raw: schema.maybe(getNonEmptyString('Raw', MAX_EXECUTE_COMMAND_LENGTH)),
    /**
     * The path to the script on the host to run
     */
    hostPath: schema.maybe(getNonEmptyString('HostPath', MAX_FILE_PATH_LENGTH)),
    /**
     * The path to the script in the cloud to run
     */
    cloudFile: schema.maybe(getNonEmptyString('CloudFile', MAX_FILE_PATH_LENGTH)),
    /**
     * The command line to run
     */
    commandLine: schema.maybe(getNonEmptyString('CommandLine', MAX_SCRIPT_COMMAND_LENGTH)),
    /**
     * The max timeout value before the command is killed. Number represents milliseconds
     */
    timeout: schema.maybe(schema.number({ min: 1 })),
  },
  {
    validate: (params) => {
      if (!params.raw && !params.hostPath && !params.cloudFile) {
        return 'At least one of Raw, HostPath, or CloudFile must be provided';
      }
    },
  }
);

// Microsoft Defender Endpoint schemas
export const MSDefenderEndpointRunScriptActionRequestParamsSchema = schema.object({
  /**
   * The path to the script in the cloud to run
   */
  scriptName: getNonEmptyString('ScriptName', MAX_ID_LENGTH),
  args: schema.maybe(getNonEmptyString('Args', MAX_SCRIPT_INPUT_LENGTH)),
});

const SentinelOneRunScriptActionRequestParamsSchema = schema.object({
  /**
   * The SentinelOne Script ID to be executed
   */
  scriptId: getNonEmptyString('scriptId', MAX_ID_LENGTH),
  /**
   * Any input arguments for the selected script
   */
  scriptInput: schema.maybe(getNonEmptyString('scriptInput', MAX_SCRIPT_INPUT_LENGTH)),
});

const EndpointRunScriptActionRequestParamsSchema = schema.object({
  /**
   * The Script ID to be executed on the host (from the scripts library)
   */
  scriptId: getNonEmptyString('scriptId', MAX_ID_LENGTH),
  /**
   * Any input arguments for the selected script
   */
  scriptInput: schema.maybe(getNonEmptyString('scriptInput', MAX_SCRIPT_INPUT_LENGTH)),

  /**
   * Timeout for executing the script on the host. Value should be in **seconds**.
   */
  timeout: schema.maybe(schema.number({ min: 1 })),
});

export const RunScriptActionRequestSchema = {
  body: schema.object({
    ...restBaseSchema,
    parameters: schema.conditional(
      schema.siblingRef('agent_type'),
      'crowdstrike',
      CrowdStrikeRunScriptActionRequestParamsSchema,
      schema.conditional(
        schema.siblingRef('agent_type'),
        'microsoft_defender_endpoint',
        MSDefenderEndpointRunScriptActionRequestParamsSchema,
        schema.conditional(
          schema.siblingRef('agent_type'),
          'sentinel_one',
          SentinelOneRunScriptActionRequestParamsSchema,
          schema.conditional(
            schema.siblingRef('agent_type'),
            'endpoint',
            EndpointRunScriptActionRequestParamsSchema,
            schema.never()
          )
        )
      )
    ),
  }),
};

type RunScriptActionRequestParameters = DeepMutable<
  TypeOf<typeof RunScriptActionRequestSchema.body>['parameters']
>;

export type MSDefenderRunScriptActionRequestParams = TypeOf<
  typeof MSDefenderEndpointRunScriptActionRequestParamsSchema
>;

export type EndpointRunScriptActionRequestParams = DeepMutable<
  TypeOf<typeof EndpointRunScriptActionRequestParamsSchema>
>;

export type RunScriptActionRequestBody<
  TParams extends RunScriptActionRequestParameters = RunScriptActionRequestParameters
> = Omit<TypeOf<typeof RunScriptActionRequestSchema.body>, 'parameters'> & {
  parameters: TParams;
};

export type SentinelOneRunScriptActionRequestParams = DeepMutable<
  TypeOf<typeof SentinelOneRunScriptActionRequestParamsSchema>
>;
