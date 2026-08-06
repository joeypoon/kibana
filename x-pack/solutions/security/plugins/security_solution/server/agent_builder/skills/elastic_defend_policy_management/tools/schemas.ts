/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { normalizePolicySearch, POLICY_SEARCH_MAX_LENGTH } from '../services/policy_read';
import type { PolicyFieldCategory } from '../domain/field_registry/types';

const MAX_POLICY_ID_LENGTH = 256;

const MAX_KEY_PATH_LENGTH = 256;

const MAX_SELECTED_KEY_PATHS = 25;

const POLICY_FIELD_CATEGORY_KEYS: Record<PolicyFieldCategory, null> = {
  advanced: null,
  antivirus_registration: null,
  attack_surface_reduction: null,
  device_control: null,
  events: null,
  global: null,
  logging: null,
  meta: null,
  popup: null,
  protection: null,
};

export const POLICY_FIELD_CATEGORY_OPTIONS = Object.keys(POLICY_FIELD_CATEGORY_KEYS) as [
  PolicyFieldCategory,
  ...PolicyFieldCategory[]
];

export const policyIdInput = z.string().min(1).max(MAX_POLICY_ID_LENGTH);

export const policySearchInput = z
  .string()
  .min(1)
  .max(POLICY_SEARCH_MAX_LENGTH)
  .transform((value) => normalizePolicySearch(value));

export const POLICY_SEARCH_CONTRACT =
  'Matching is LITERAL and CASE-SENSITIVE against the policy NAME only: every whitespace-separated ' +
  'word must appear somewhere in the name, in any order. It is NOT a regular expression and NOT a ' +
  'glob — `*`, `?`, `.` and every other character match only themselves, so a `search` of `*` or ' +
  '`.*` matches only policies whose names literally contain those characters (practically none). ' +
  'To cover every policy the user can access, OMIT this parameter instead of passing a wildcard.';

export const policyKeyPathsSelectionInput = z
  .array(z.string().min(1).max(MAX_KEY_PATH_LENGTH))
  .min(1)
  .max(MAX_SELECTED_KEY_PATHS);

export const policyCategorySelectionInput = z.enum(POLICY_FIELD_CATEGORY_OPTIONS);
