/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { internalNamespaces } from '@kbn/agent-builder-common/base/namespaces';

const automaticTroubleshootingNamespace = `${internalNamespaces.security}.automatic_troubleshooting`;
export const AUTOMATIC_TROUBLESHOOTING_AGENT_ID = automaticTroubleshootingNamespace;
export const GENERATE_SAFE_QUERY_TOOL_ID = `${automaticTroubleshootingNamespace}.generate_safe_query`;
export const EXECUTE_SAFE_QUERY_TOOL_ID = `${automaticTroubleshootingNamespace}.execute_safe_query`;
export const GET_DATA_TOOL_ID = `${automaticTroubleshootingNamespace}.get_data`;
export const GET_CONTEXT_TOOL_ID = `${automaticTroubleshootingNamespace}.get_context`;
export const GENERATE_INSIGHT_TOOL_ID = `${automaticTroubleshootingNamespace}.generate_insight`;
