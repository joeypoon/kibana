/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { DocEntry } from '../schema_extractor';
import { extractDocumentation } from '../schema_extractor';
import type { ApiParameter, Block } from '../types';

export function postProcess(parsedFiles: any[]): void {
  const schemasDirPath = path.resolve(__dirname, '..', '..', '..', 'server', 'routes', 'schemas');

  const schemaFiles = fs
    .readdirSync(schemasDirPath)
    .map((filename) => path.resolve(schemasDirPath, filename));

  const schemaDocs = extractDocumentation(schemaFiles);

  parsedFiles.forEach((parsedFile) => {
    // @ts-ignore
    parsedFile.forEach((block: Block) => {
      const {
        local: { schemas },
      } = block;
      if (!schemas || schemas.length === 0) return;

      for (const schema of schemas) {
        const { name: schemaName, group: paramsGroup } = schema;
        const schemaFields = schemaDocs.get(schemaName);

        if (!schemaFields) return;

        updateBlockParameters(schemaFields, block, paramsGroup);
      }
    });
  });
}

/**
 * Extracts schema's doc entries to apidoc parameters
 * @param docEntries
 * @param block
 * @param paramsGroup
 */
function updateBlockParameters(docEntries: DocEntry[], block: Block, paramsGroup: string): void {
  if (!block.local.parameter) {
    block.local.parameter = {};
  }
  if (!block.local.parameter.fields) {
    block.local.parameter.fields = {};
  }

  if (!block.local.parameter.fields![paramsGroup]) {
    block.local.parameter.fields![paramsGroup] = [];
  }
  const collection = block.local.parameter.fields![paramsGroup] as ApiParameter[];

  for (const field of docEntries) {
    collection.push({
      group: paramsGroup,
      type: escapeSpecial(field.type),
      size: undefined,
      allowedValues: undefined,
      optional: !!field.optional,
      field: field.name,
      defaultValue: undefined,
      description: field.documentation,
    });

    if (field.nested) {
      updateBlockParameters(field.nested, block, field.name);
    }
  }
}

/**
 * Escape special character to make sure the markdown table isn't broken
 */
function escapeSpecial(str: string): string {
  return str.replace(/\|/g, '\\|');
}
