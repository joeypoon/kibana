/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { escapeKuery } from '@kbn/es-query';
import { PACKAGE_POLICY_SAVED_OBJECT_TYPE } from '@kbn/fleet-plugin/common';
import { ENDPOINT_PACKAGE_NAME } from '../../../../../../common/detection_engine/constants';

export const POLICY_SEARCH_MAX_LENGTH = 256;

export const normalizePolicySearch = (search?: string): string | undefined => {
  if (search === undefined) {
    return undefined;
  }

  const trimmed = search.slice(0, POLICY_SEARCH_MAX_LENGTH).trim();
  return trimmed.length === 0 ? undefined : trimmed;
};

export const buildDefendKuery = (search?: string): string => {
  const packageFilter = `${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.package.name: "${ENDPOINT_PACKAGE_NAME}"`;
  const searchTokens = normalizePolicySearch(search)?.split(/\s+/).filter(Boolean);

  if (searchTokens === undefined || searchTokens.length === 0) {
    return packageFilter;
  }

  return [
    packageFilter,
    ...searchTokens.map(
      (token) => `${PACKAGE_POLICY_SAVED_OBJECT_TYPE}.name: *${escapeKuery(token)}*`
    ),
  ].join(' AND ');
};
