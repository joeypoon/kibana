/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Fleet agent IDs, action IDs, connector IDs, saved-object IDs. */
export const MAX_ID_LENGTH = 128;

/** ISO datetimes and moment-compatible date strings. */
export const MAX_DATE_STRING_LENGTH = 64;

/** ECS field paths and autocomplete field names. */
export const MAX_FIELD_NAME_LENGTH = 256;

/** Names and short labels. */
export const MAX_NAME_LENGTH = 256;

/** Descriptions and short documentation fields. */
export const MAX_DESCRIPTION_LENGTH = 256;

/** User/admin free text and LLM-generated message text. */
export const MAX_LONG_TEXT_LENGTH = 10_000;

/** URL links. */
export const MAX_URL_LENGTH = 2_048;

/** Kibana security usernames and space IDs. */
export const MAX_USERNAME_LENGTH = 1_024;

/** Kibana space IDs (Spaces API does not enforce a short cap). */
export const MAX_SPACE_ID_LENGTH = 1_024;

/** Autocomplete prefix strings for internal suggestions. */
export const MAX_SUGGESTION_QUERY_LENGTH = 1_024;

/** Workflow insights GET page size guard. */
export const MAX_WORKFLOW_INSIGHTS_PAGE_SIZE = 100;

/** Workflow insights metadata.notes record key count. */
export const MAX_METADATA_NOTES_KEYS = 50;

/** Suggestions fieldMeta record key count. */
export const MAX_FIELD_META_KEYS = 50;

/** Agent Builder generate_insight raw data array item count. */
export const MAX_GENERATE_INSIGHT_DATA_ITEMS = 50;

/** Agent Builder generate_insight serialized data[] payload size. */
export const MAX_GENERATE_INSIGHT_DATA_SERIALIZED_LENGTH = 100_000;

/** Defend insight and workflow insight array sizes. */
export const MAX_INSIGHTS_ARRAY_SIZE = 50;

/** KQL/kuery/filter strings. */
export const MAX_KQL_LENGTH = 10_000;

/** Protection-update notes (alias of long text). */
export const MAX_NOTE_LENGTH = MAX_LONG_TEXT_LENGTH;

/** File paths and executable paths. */
export const MAX_FILE_PATH_LENGTH = 4_096;

/** Public Endpoint execute command payloads. */
export const MAX_EXECUTE_COMMAND_LENGTH = 100_000;

/** Run-script command-line params. */
export const MAX_SCRIPT_COMMAND_LENGTH = 30_000;

/** Script arguments/input. */
export const MAX_SCRIPT_INPUT_LENGTH = 4_096;

/** Process entity/name fields. */
export const MAX_PROCESS_FIELD_LENGTH = 512;

/** Resolver entity IDs and Elasticsearch document IDs. */
export const MAX_RESOLVER_ENTITY_ID_LENGTH = 512;

/** Index pattern strings. */
export const MAX_INDEX_PATTERN_LENGTH = 1_024;

/** ES/KQL-style filter strings. */
export const MAX_FILTER_STRING_LENGTH = 10_000;

/** Known script library tag values. */
export const MAX_SCRIPT_TAG_LENGTH = 32;

/** endpoint_ids[] and agent ID list counts in action request bodies. */
export const MAX_ENDPOINT_IDS = 250;

/** alert_ids[] counts in action request bodies. */
export const MAX_ALERT_IDS = 50;

/** case_ids[] counts in action request bodies. */
export const MAX_CASE_IDS = 50;

/** Suggestions filter array item counts (top-level filters and nested arrays). */
export const MAX_SUGGESTION_FILTER_ARRAY_ITEMS = 50;

/** MD5/SHA1/SHA256 hex digest strings in artifact validators. */
export const MAX_HASH_HEX_LENGTH = 64;

/** Code-signer subject names and trusted-device field values. */
export const MAX_SIGNER_VALUE_LENGTH = 512;

/** Host isolation exception destination.ip values (IPv4 or CIDR). */
export const MAX_HOST_ISOLATION_IP_VALUE_LENGTH = 50;
