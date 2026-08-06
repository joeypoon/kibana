/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PolicyFieldRecord } from '../field_registry/types';

export const GLOBAL_TELEMETRY_KEY_PATH = 'global_telemetry_enabled';

export const isExcludedKeyPath = (keyPath: string): boolean => {
  if (keyPath === 'meta' || keyPath.startsWith('meta.')) {
    return true;
  }

  if (keyPath === 'artifact_manifest' || keyPath.startsWith('artifact_manifest.')) {
    return true;
  }

  if (keyPath === 'logging.file') {
    return true;
  }

  return keyPath === 'policy_ids' || keyPath.startsWith('policy_ids.');
};

export const isExcludedFromComparison = ({ keyPath, category }: PolicyFieldRecord): boolean =>
  category === 'meta' || isExcludedKeyPath(keyPath);
