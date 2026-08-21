/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export type {
  FieldRegistryEntry,
  FieldRegistryKind,
  FieldRegistryProductFeatureGate,
  FieldRegistrySource,
  FieldRegistryTier,
} from './types';
export { DERIVED_PATHS, EXCLUDED_PATHS, isDerivedPath, isExcludedPath } from './tables';
export {
  getFieldRegistry,
  getFieldRegistryEntry,
  getOsLessRemainderEntries,
  getProtectionKeyPathEntries,
} from './derive_field_registry';
export { isWritablePath } from './is_writable_path';
