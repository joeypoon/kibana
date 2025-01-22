/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Example } from 'langsmith/schemas';
import { DefendInsights } from '@kbn/elastic-assistant-common';

export const getExampleDefendInsights = (example: Example | undefined): DefendInsights => {
  const exampleDefendInsights = example?.outputs?.insights;

  // NOTE: calls to `parse` throw an error if the Example input is invalid
  return DefendInsights.parse(exampleDefendInsights);
};
