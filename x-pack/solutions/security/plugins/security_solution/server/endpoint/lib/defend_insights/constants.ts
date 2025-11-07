/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { internalNamespaces } from '@kbn/onechat-common/base/namespaces';

const automaticTroubleshootingNamespace = `${internalNamespaces.securitySolution}.automatic_troubleshooting`;
export const AUTOMATIC_TROUBLESHOOTING_AGENT_ID = automaticTroubleshootingNamespace;
export const EXECUTE_QUERY_TOOL_ID = `${automaticTroubleshootingNamespace}.execute_query`;
export const GENERATE_QUERY_TOOL_ID = `${automaticTroubleshootingNamespace}.generate_query`;
export const GET_CONTEXT_TOOL_ID = `${automaticTroubleshootingNamespace}.get_context`;
export const GENERATE_INSIGHT_TOOL_ID = `${automaticTroubleshootingNamespace}.generate_insight`;
