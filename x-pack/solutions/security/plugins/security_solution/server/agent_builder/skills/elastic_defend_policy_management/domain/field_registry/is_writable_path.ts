/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FieldRegistryEntry } from './types';

export const isWritablePath = (entry: FieldRegistryEntry): boolean =>
  entry.tier === 1 && entry.userEditable && !entry.isDerived && !entry.excludeFromComparison;
