/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { QueryDslQueryContainer, SearchRequest } from '@elastic/elasticsearch/lib/api/types';
import { getAllowedFields, isIndexAllowed } from './data_source_metadata';

function filterFieldsInObject(
  obj: Record<string, any>,
  allowedFieldNames: Set<string>
): Record<string, any> {
  const result: Record<string, any> = {};

  for (const [key, value] of Object.entries(obj)) {
    const isQueryClause = [
      'bool',
      'must',
      'should',
      'must_not',
      'filter',
      'match',
      'term',
      'terms',
      'range',
      'exists',
      'prefix',
      'wildcard',
      'regexp',
      'fuzzy',
      'ids',
      'match_all',
      'match_phrase',
      'multi_match',
      'query_string',
      'simple_query_string',
      'nested',
      'has_child',
      'has_parent',
      'parent_id',
      'geo_bounding_box',
      'geo_distance',
      'geo_polygon',
      'geo_shape',
      'more_like_this',
      'script',
      'script_score',
      'percolate',
      'rank_feature',
      'wrapper',
      'distance_feature',
      'pinned',
      'constant_score',
      'dis_max',
      'function_score',
      'boosting',
      'intervals',
      'match_bool_prefix',
      'combined_fields',
      'span_term',
      'span_multi',
      'span_first',
      'span_near',
      'span_or',
      'span_not',
      'span_containing',
      'span_within',
      'field_masking_span',
      'span_field_masking',
    ].includes(key);

    if (isQueryClause) {
      // This is a query clause, process its value recursively
      if (Array.isArray(value)) {
        const filtered = value
          .map((item) => {
            if (typeof item === 'object' && item !== null) {
              return filterFieldsInObject(item, allowedFieldNames);
            }
            return item;
          })
          .filter((item) => {
            // Remove empty objects
            if (typeof item === 'object' && item !== null) {
              return Object.keys(item).length > 0;
            }
            return true;
          });

        if (filtered.length > 0) {
          result[key] = filtered;
        }
      } else if (typeof value === 'object' && value !== null) {
        const filtered = filterFieldsInObject(value, allowedFieldNames);
        if (Object.keys(filtered).length > 0) {
          result[key] = filtered;
        }
      } else {
        result[key] = value;
      }
    } else {
      // This might be a field name - check if it's allowed
      if (allowedFieldNames.has(key)) {
        result[key] = value;
      }
      // If not allowed, skip this field entirely
    }
  }

  return result;
}

/**
 * Filters indices from a query to only include allowlisted indices
 */
function filterIndices(indices: string | string[] | undefined): string[] {
  if (!indices) {
    return [];
  }

  const indexArray = Array.isArray(indices) ? indices : [indices];
  return indexArray.filter((index) => isIndexAllowed(index));
}

/**
 * Filters _source fields to only include allowlisted fields
 */
function filterSourceFields(
  source: boolean | string | string[] | undefined,
  allowedFieldNames: Set<string>
): boolean | string[] | undefined {
  if (typeof source === 'boolean' || source === undefined) {
    return source;
  }

  const sourceArray = Array.isArray(source) ? source : [source];
  const filtered = sourceArray.filter((field) => {
    // Handle wildcard patterns like "field.*"
    if (field.includes('*')) {
      const prefix = field.replace(/\*/g, '');
      return Array.from(allowedFieldNames).some((allowedField) => allowedField.startsWith(prefix));
    }
    return allowedFieldNames.has(field);
  });

  return filtered.length > 0 ? filtered : undefined;
}

/**
 * Cleans an Elasticsearch query by removing non-allowlisted indices and fields
 */
export function cleanQuery(
  query: Partial<SearchRequest>,
  targetIndex: string
): Partial<SearchRequest> {
  const allowedFields = getAllowedFields(targetIndex);
  const allowedFieldNames = new Set(allowedFields.map((f) => f.name));

  const cleanedQuery: Partial<SearchRequest> = {};

  // Filter indices
  if (query.index) {
    const filtered = filterIndices(query.index);
    if (filtered.length > 0) {
      cleanedQuery.index = filtered;
    }
  }

  // Clean the query clause
  if (query.query) {
    const filteredQuery = filterFieldsInObject(
      query.query as Record<string, any>,
      allowedFieldNames
    );
    if (Object.keys(filteredQuery).length > 0) {
      cleanedQuery.query = filteredQuery as QueryDslQueryContainer;
    }
  }

  // Filter _source fields
  if (query._source !== undefined) {
    const filtered = filterSourceFields(query._source, allowedFieldNames);
    if (filtered !== undefined) {
      cleanedQuery._source = filtered;
    }
  }

  // Clean aggregations
  if (query.aggs) {
    const cleanedAggs: Record<string, any> = {};

    for (const [aggName, aggDef] of Object.entries(query.aggs)) {
      if (typeof aggDef === 'object' && aggDef !== null) {
        const cleanedAgg = filterFieldsInObject(aggDef, allowedFieldNames);
        if (Object.keys(cleanedAgg).length > 0) {
          cleanedAggs[aggName] = cleanedAgg;
        }
      }
    }

    if (Object.keys(cleanedAggs).length > 0) {
      cleanedQuery.aggs = cleanedAggs;
    }
  }

  // Clean sort
  if (query.sort) {
    const sortArray = Array.isArray(query.sort) ? query.sort : [query.sort];
    const cleanedSort = sortArray
      .map((sortItem) => {
        if (typeof sortItem === 'object' && sortItem !== null) {
          return filterFieldsInObject(sortItem, allowedFieldNames);
        }
        return sortItem;
      })
      .filter((item) => {
        if (typeof item === 'object' && item !== null) {
          return Object.keys(item).length > 0;
        }
        return true;
      });

    if (cleanedSort.length > 0) {
      cleanedQuery.sort = cleanedSort;
    }
  }

  // Copy over safe parameters that don't contain field references
  const safeParams: Array<keyof SearchRequest> = [
    'size',
    'from',
    'allow_no_indices',
    'ignore_unavailable',
    'track_total_hits',
    'timeout',
  ];

  for (const param of safeParams) {
    if (query[param] !== undefined) {
      (cleanedQuery as any)[param] = query[param];
    }
  }

  return cleanedQuery;
}

/**
 * Extracts the index pattern from an ES|QL query's FROM clause
 *
 * @param query - The ES|QL query string
 * @returns The index pattern, or empty string if not found
 *
 * @example
 * ```typescript
 * extractIndexFromQuery('FROM logs-endpoint.events.file-* | WHERE agent.id == "x"')
 * // Returns: 'logs-endpoint.events.file-*'
 *
 * extractIndexFromQuery('FROM logs-endpoint.* METADATA _id | KEEP agent.id')
 * // Returns: 'logs-endpoint.*'
 * ```
 */
export function extractIndexFromQuery(query: string): string {
  // Match FROM clause with optional METADATA
  // Pattern: FROM <index> [METADATA ...] [| next command]
  const fromMatch = query.match(/FROM\s+([^\s|]+)/i);

  if (fromMatch && fromMatch[1]) {
    return fromMatch[1].trim();
  }

  return '';
}

/**
 * Validates and cleans an ES|QL query to ensure it only accesses allowlisted indices and fields
 *
 * @param query - The ES|QL query string to validate
 * @param targetIndex - The target index pattern to validate against
 * @returns Object with validated query and any validation errors
 *
 * @example
 * ```typescript
 * const result = validateEsqlQuery(
 *   'FROM logs-endpoint.events.file-* | WHERE agent.id == "x" | KEEP agent.id, process.executable',
 *   'logs-endpoint.events.file-default'
 * );
 * if (result.valid) {
 *   // Execute result.query
 * } else {
 *   // Handle result.errors
 * }
 * ```
 */
export function validateEsqlQuery(
  query: string,
  targetIndex: string
): { valid: boolean; query?: string; errors?: string[] } {
  const errors: string[] = [];
  const allowedFields = getAllowedFields(targetIndex);
  const allowedFieldNames = new Set(allowedFields.map((f) => f.name));

  // 1. Extract and validate FROM clause (index pattern)
  const fromMatch = query.match(/FROM\s+([^\s|]+)/i);
  if (!fromMatch) {
    errors.push('Query must include a FROM clause with an index pattern');
    return { valid: false, errors };
  }

  const indexPattern = fromMatch[1].trim();
  if (!isIndexAllowed(indexPattern)) {
    errors.push(
      `Index pattern "${indexPattern}" is not allowlisted. Target index must match: ${targetIndex}`
    );
    return { valid: false, errors };
  }

  // 2. Extract all field references from the query
  // This regex matches field names in various contexts:
  // - WHERE clauses: field == value, field IN (...)
  // - EVAL: field = expression
  // - STATS: BY field, COUNT(field)
  // - SORT: field ASC/DESC
  // - KEEP/DROP: field1, field2
  const fieldReferencePattern = /\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\b/g;
  const potentialFields = new Set<string>();

  // Extract potential field references
  let match;
  while ((match = fieldReferencePattern.exec(query)) !== null) {
    const fieldName = match[1];
    // Skip ES|QL keywords and functions
    const keywords = new Set([
      'FROM',
      'WHERE',
      'EVAL',
      'STATS',
      'SORT',
      'KEEP',
      'DROP',
      'LIMIT',
      'BY',
      'AS',
      'AND',
      'OR',
      'NOT',
      'IN',
      'LIKE',
      'RLIKE',
      'IS',
      'NULL',
      'COUNT',
      'SUM',
      'AVG',
      'MIN',
      'MAX',
      'MEDIAN',
      'PERCENTILE',
      'ASC',
      'DESC',
      'TRUE',
      'FALSE',
      'NOW',
    ]);

    if (!keywords.has(fieldName.toUpperCase())) {
      potentialFields.add(fieldName);
    }
  }

  // 3. Validate that all referenced fields are allowlisted
  const unauthorizedFields: string[] = [];
  for (const field of potentialFields) {
    if (!allowedFieldNames.has(field)) {
      unauthorizedFields.push(field);
    }
  }

  if (unauthorizedFields.length > 0) {
    errors.push(
      `Query references unauthorized fields: ${unauthorizedFields.join(', ')}. ` +
        `Allowed fields: ${Array.from(allowedFieldNames).join(', ')}`
    );
    return { valid: false, errors };
  }

  // 4. Check for wildcards in KEEP clause
  const keepMatch = query.match(/KEEP\s+([^|]*?)(?:\||$)/i);
  if (keepMatch) {
    const keepFields = keepMatch[1].split(',').map((f) => f.trim());
    for (const field of keepFields) {
      if (field.includes('*')) {
        errors.push(
          `Wildcard patterns in KEEP clause are not allowed. Found: "${field}". ` +
            `Please specify fields explicitly from: ${Array.from(allowedFieldNames).join(', ')}`
        );
        return { valid: false, errors };
      }
    }
  }

  // 5. Check for DROP clause (inverse logic - harder to validate)
  if (query.match(/DROP\s+/i)) {
    errors.push(
      'DROP clause is not allowed. Please use KEEP to explicitly specify allowed fields.'
    );
    return { valid: false, errors };
  }

  // 6. If no KEEP clause exists, add one with all allowed fields
  // This prevents implicit return of all fields
  let validatedQuery = query;
  if (!keepMatch) {
    // Find the last pipe or end of query to append KEEP
    const lastPipeIndex = query.lastIndexOf('|');
    const insertPoint = lastPipeIndex !== -1 ? lastPipeIndex + 1 : query.length;

    const keepClause = `\n| KEEP ${Array.from(allowedFieldNames).join(', ')}`;
    validatedQuery =
      query.slice(0, insertPoint).trimEnd() +
      keepClause +
      (lastPipeIndex !== -1 ? query.slice(insertPoint) : '');
  }

  return { valid: true, query: validatedQuery };
}

/**
 * Filters ES|QL query response to only include allowlisted fields
 *
 * @param response - The ES|QL query response with columns and values
 * @param targetIndex - The target index to determine allowed fields
 * @returns Filtered response with only allowlisted columns
 */
export function filterEsqlResponse(
  response: { columns: Array<{ name: string; type: string }>; values: any[][] },
  targetIndex: string
): { columns: Array<{ name: string; type: string }>; values: any[][] } {
  if (!isIndexAllowed(targetIndex)) {
    throw new Error(`Index pattern "${targetIndex}" is not allowlisted.`);
  }

  const allowedFields = getAllowedFields(targetIndex);
  const allowedFieldNames = new Set(allowedFields.map((f) => f.name));

  // Find indices of allowed columns
  const allowedColumnIndices: number[] = [];
  const filteredColumns: Array<{ name: string; type: string }> = [];

  response.columns.forEach((column, index) => {
    if (allowedFieldNames.has(column.name)) {
      allowedColumnIndices.push(index);
      filteredColumns.push(column);
    }
  });

  // Filter values to only include allowed columns
  const filteredValues = response.values.map((row) =>
    allowedColumnIndices.map((index) => row[index])
  );

  return {
    columns: filteredColumns,
    values: filteredValues,
  };
}
