/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { DefendInsightsType } from '@kbn/elastic-assistant-plugin/server';

import { DefendInsightType } from '@kbn/elastic-assistant-common';

import { InvalidDefendInsightTypeError } from '../errors';
import { getIncompatibleAntivirusPrompt } from './incompatible_antivirus';

export const getDefendInsightsPrompt = ({
  type,
  events,
}: {
  type: DefendInsightsType;
  events: string[];
}) => {
  if (type === DefendInsightType.enum.incompatible_antivirus) {
    return getIncompatibleAntivirusPrompt({ events });
  }

  throw new InvalidDefendInsightTypeError();
};
