/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const EXCLUDED_PATHS = ['meta.*', '*.popup.*.message'] as const;
export const DERIVED_PATHS = ['windows.antivirus_registration.enabled'] as const;

const POPUP_MESSAGE_PATH = /(?:^|\.)popup\.[^.]+\.message$/;
const DERIVED_PATH_SET: ReadonlySet<string> = new Set(DERIVED_PATHS);

const matchesExcludedRule = (path: string, rule: (typeof EXCLUDED_PATHS)[number]): boolean => {
  switch (rule) {
    case 'meta.*':
      return path === 'meta' || path.startsWith('meta.');
    case '*.popup.*.message':
      return POPUP_MESSAGE_PATH.test(path);
    default: {
      const exhaustive: never = rule;
      throw new Error(`Unsupported excluded path rule: ${exhaustive}`);
    }
  }
};

export const isExcludedPath = (path: string): boolean =>
  EXCLUDED_PATHS.some((rule) => matchesExcludedRule(path, rule));

export const isDerivedPath = (path: string): boolean => DERIVED_PATH_SET.has(path);
