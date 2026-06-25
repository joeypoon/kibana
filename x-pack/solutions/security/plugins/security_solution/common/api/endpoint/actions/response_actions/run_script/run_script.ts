/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { TypeOf } from '@kbn/config-schema';
import { schema } from '@kbn/config-schema';
import { BaseActionRequestSchema } from '../../common/base';
import type { DeepMutable } from '../../../../../endpoint/types';

const { parameters, ...restBaseSchema } = BaseActionRequestSchema;
const getNonEmptyString = (fieldName: string, maxLength: number, description?: string) =>
  schema.string({
    minLength: 1,
    maxLength,
    ...(description ? { meta: { description } } : {}),
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
    raw: schema.maybe(getNonEmptyString('Raw', 65536, 'Raw script content to run.')),
    /**
     * The path to the script on the host to run
     */
    hostPath: schema.maybe(
      getNonEmptyString('HostPath', 4096, 'Absolute path to a script on the host.')
    ),
    /**
     * The path to the script in the cloud to run
     */
    cloudFile: schema.maybe(
      getNonEmptyString('CloudFile', 4096, 'Name of a script from the cloud file library.')
    ),
    /**
     * The command line to run
     */
    commandLine: schema.maybe(getNonEmptyString('CommandLine', 8192, 'Command line to run.')),
    /**
     * The max timeout value before the command is killed. Number represents milliseconds
     */
    timeout: schema.maybe(
      schema.number({ min: 1, meta: { description: 'Timeout for the script execution.' } })
    ),
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
  scriptName: getNonEmptyString('ScriptName', 256, 'The name of the script to run.'),
  args: schema.maybe(
    getNonEmptyString('Args', 8192, 'Command-line arguments to pass to the script.')
  ),
});

const SentinelOneRunScriptActionRequestParamsSchema = schema.object({
  /**
   * The SentinelOne Script ID to be executed
   */
  scriptId: getNonEmptyString('scriptId', 256, 'The ID of the script to run.'),
  /**
   * Any input arguments for the selected script
   */
  scriptInput: schema.maybe(getNonEmptyString('scriptInput', 8192, 'Script arguments/input.')),
});

const EndpointRunScriptActionRequestParamsSchema = schema.object({
  /**
   * The Script ID to be executed on the host (from the scripts library)
   */
  scriptId: getNonEmptyString('scriptId', 256, 'The ID of the script to run.'),
  /**
   * Any input arguments for the selected script
   */
  scriptInput: schema.maybe(getNonEmptyString('scriptInput', 8192, 'Script arguments/input.')),

  /**
   * Timeout for executing the script on the host. Value should be in **seconds**.
   */
  timeout: schema.maybe(
    schema.number({ min: 1, meta: { description: 'Timeout for the script execution.' } })
  ),
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
