/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Run } from 'langsmith/schemas';
import { DefendInsights } from '@kbn/elastic-assistant-common';

export const getDefendInsights = (run: Run): DefendInsights => {
  const runDefendInsights = run.outputs?.insights;

  // NOTE: calls to `parse` throw an error if the Run Input is invalid
  return DefendInsights.parse(runDefendInsights);
};
