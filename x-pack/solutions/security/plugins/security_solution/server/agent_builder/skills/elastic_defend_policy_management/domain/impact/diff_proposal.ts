/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { get, isEqual } from 'lodash';

import type { PolicyConfig, PolicyOperatingSystem } from '../../../../../../common/endpoint/types';
import {
  COMPARABLE_APPLICABILITY,
  evaluateFieldApplicability,
} from '../field_registry/applicability';
import { isExcludedKeyPath } from '../normalize/exclusions';
import { collectPolicyLeafPaths } from '../normalize/leaf_paths';
import type { PolicyChangeLeafDiff, PolicyChangeProposal } from './types';
import type { ImpactFieldLookup } from './field_lookup';
import { resolveProposedField, splitAbsoluteKeyPath, toAbsoluteKeyPath } from './field_lookup';

interface DiffProposalArgs {
  readonly before: PolicyConfig;
  readonly after: PolicyConfig;
  readonly proposal: PolicyChangeProposal;
  readonly lookup: ImpactFieldLookup;
  readonly packageVersion: string;
}

export const diffProposal = ({
  before,
  after,
  proposal,
  lookup,
  packageVersion,
}: DiffProposalArgs): PolicyChangeLeafDiff[] => {
  const diffs: PolicyChangeLeafDiff[] = [];
  const seen = new Set<string>();

  for (const { keyPath, os } of proposal.operations) {
    const absoluteKeyPath = toAbsoluteKeyPath(keyPath, os);

    if (!seen.has(absoluteKeyPath)) {
      seen.add(absoluteKeyPath);

      const beforeValue = get(before, absoluteKeyPath);
      const afterValue = get(after, absoluteKeyPath);

      if (!isEqual(beforeValue, afterValue)) {
        diffs.push(buildLeafDiff({ keyPath, os, beforeValue, afterValue, lookup, packageVersion }));
      }
    }
  }

  return diffs;
};

interface UnionPersistPreviewDiffsArgs {
  readonly before: PolicyConfig;
  readonly proposed: PolicyConfig;
  readonly persisted: PolicyConfig;
  readonly proposal: PolicyChangeProposal;
  readonly lookup: ImpactFieldLookup;
  readonly packageVersion: string;
}

export const unionPersistPreviewDiffs = ({
  before,
  proposed,
  persisted,
  proposal,
  lookup,
  packageVersion,
}: UnionPersistPreviewDiffsArgs): PolicyChangeLeafDiff[] => {
  const diffs: PolicyChangeLeafDiff[] = [];
  const seen = new Set<string>();

  for (const { keyPath, os } of proposal.operations) {
    const absoluteKeyPath = toAbsoluteKeyPath(keyPath, os);

    if (!seen.has(absoluteKeyPath)) {
      seen.add(absoluteKeyPath);

      const beforeValue = get(before, absoluteKeyPath);
      const afterValue = get(persisted, absoluteKeyPath);

      if (!isEqual(beforeValue, afterValue)) {
        diffs.push(buildLeafDiff({ keyPath, os, beforeValue, afterValue, lookup, packageVersion }));
      }
    }
  }

  const proposedLeaves = collectPolicyLeafPaths(proposed);
  const persistedLeaves = collectPolicyLeafPaths(persisted);
  const silentPaths = [...new Set([...proposedLeaves.keys(), ...persistedLeaves.keys()])]
    .filter((absoluteKeyPath) => !seen.has(absoluteKeyPath) && !isExcludedKeyPath(absoluteKeyPath))
    .sort();

  for (const absoluteKeyPath of silentPaths) {
    const proposedValue = proposedLeaves.get(absoluteKeyPath);
    const persistedValue = persistedLeaves.get(absoluteKeyPath);

    if (!isEqual(proposedValue, persistedValue)) {
      const { keyPath, os } = splitAbsoluteKeyPath(absoluteKeyPath);

      diffs.push(
        buildLeafDiff({
          keyPath,
          os,
          beforeValue: proposedValue,
          afterValue: persistedValue,
          lookup,
          packageVersion,
        })
      );
    }
  }

  return diffs;
};

interface BuildLeafDiffArgs {
  readonly keyPath: string;
  readonly os?: PolicyOperatingSystem;
  readonly beforeValue: unknown;
  readonly afterValue: unknown;
  readonly lookup: ImpactFieldLookup;
  readonly packageVersion: string;
}

const buildLeafDiff = ({
  keyPath,
  os,
  beforeValue,
  afterValue,
  lookup,
  packageVersion,
}: BuildLeafDiffArgs): PolicyChangeLeafDiff => {
  const resolution = resolveProposedField(lookup, keyPath, os);

  if ('failure' in resolution) {
    return { keyPath, os, before: beforeValue, after: afterValue };
  }

  const { field } = resolution;
  const applicability = evaluateFieldApplicability(field, packageVersion);

  const canQuoteDefault =
    field.defaultSource !== 'unknown' &&
    field.default !== undefined &&
    COMPARABLE_APPLICABILITY[applicability] === true;

  const metadata = {
    type: field.type,
    ...(field.enumValues === undefined ? {} : { enumValues: field.enumValues }),
    ...(field.documentation === undefined ? {} : { documentation: field.documentation }),
  };

  return canQuoteDefault
    ? {
        keyPath,
        os,
        before: beforeValue,
        after: afterValue,
        defaultValue: field.default,
        ...metadata,
      }
    : { keyPath, os, before: beforeValue, after: afterValue, ...metadata };
};
