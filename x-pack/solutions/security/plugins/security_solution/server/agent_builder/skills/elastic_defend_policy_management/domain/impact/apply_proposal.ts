/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cloneDeep, get, isEqual } from 'lodash';
import { set } from '@kbn/safer-lodash-set';

import type { PolicyConfig } from '../../../../../../common/endpoint/types';
import {
  COMPARABLE_APPLICABILITY,
  evaluateFieldApplicability,
} from '../field_registry/applicability';
import type { PolicySnapshot } from '../read/types';
import type { PolicyChangeProposal, PolicyChangeRejection } from './types';
import type { ImpactFieldLookup } from './field_lookup';
import { resolveProposedField, toAbsoluteKeyPath } from './field_lookup';

export const MAX_CHANGE_OPERATIONS = 50;

type ApplyChangeProposalResult =
  | { readonly config: PolicyConfig }
  | { readonly rejection: PolicyChangeRejection };

interface ApplyChangeProposalArgs {
  readonly proposal: PolicyChangeProposal;
  readonly snapshot: PolicySnapshot;
  readonly lookup: ImpactFieldLookup;
}

export const applyChangeProposal = ({
  proposal,
  snapshot,
  lookup,
}: ApplyChangeProposalArgs): ApplyChangeProposalResult => {
  const { identity } = snapshot;
  const { operations } = proposal;

  if (proposal.policyId !== identity.id) {
    return {
      rejection: {
        reason: 'identity_mismatch',
        message: `The proposal names policy [${proposal.policyId}] but was assessed against policy [${identity.id}]. Nothing was assessed. Resubmit the proposal against the policy it names.`,
        currentIdentity: identity,
      },
    };
  }

  if (proposal.identity.revision !== identity.revision) {
    return {
      rejection: {
        reason: 'stale_snapshot',
        message: `Policy [${identity.id}] is now at revision ${identity.revision}, but the proposal was built against revision ${proposal.identity.revision}. Nothing was assessed. Re-read the policy and resubmit.`,
        currentIdentity: identity,
      },
    };
  }

  if (identity.version !== undefined && proposal.identity.version === undefined) {
    return {
      rejection: {
        reason: 'stale_snapshot',
        message: `Policy [${identity.id}] was read with saved-object version [${identity.version}], but the proposal does not identify that saved-object version. Nothing was assessed. Re-read the policy and resubmit with the complete snapshot identity.`,
        currentIdentity: identity,
      },
    };
  }

  if (proposal.identity.version !== undefined && proposal.identity.version !== identity.version) {
    return {
      rejection: {
        reason: 'stale_snapshot',
        message: `Policy [${identity.id}] has been written since the proposal was built (saved-object version is now [${identity.version}], the proposal expected [${proposal.identity.version}]). Nothing was assessed. Re-read the policy and resubmit.`,
        currentIdentity: identity,
      },
    };
  }

  if (operations.length > MAX_CHANGE_OPERATIONS) {
    return {
      rejection: {
        reason: 'too_many_operations',
        message: `A proposal may change at most ${MAX_CHANGE_OPERATIONS} settings in one assessment; this one changes ${operations.length}. Split it into smaller proposals so the full assessment can be reported without truncation.`,
      },
    };
  }

  const config = cloneDeep(snapshot.config);

  for (const operation of operations) {
    const { keyPath, os, expectedCurrentValue, proposedValue } = operation;
    const resolution = resolveProposedField(lookup, keyPath, os);

    if ('failure' in resolution) {
      return {
        rejection: {
          reason: resolution.failure,
          message: resolution.detail,
          keyPath,
          os,
        },
      };
    }

    const applicability = evaluateFieldApplicability(resolution.field, snapshot.packageVersion);

    if (COMPARABLE_APPLICABILITY[applicability] !== true) {
      return {
        rejection: {
          reason: 'outside_version_window',
          message:
            applicability === 'unsupported'
              ? `[${keyPath}] is not supported by Elastic Defend package version ${snapshot.packageVersion}; it was supported through ${resolution.field.lastSupportedVersion}.`
              : `[${keyPath}] is not available in Elastic Defend package version ${snapshot.packageVersion}; it was introduced in ${resolution.field.firstSupportedVersion}.`,
          keyPath,
          os,
        },
      };
    }

    const absoluteKeyPath = toAbsoluteKeyPath(keyPath, os);
    const currentValue = get(config, absoluteKeyPath);

    if (expectedCurrentValue !== undefined && !isEqual(currentValue, expectedCurrentValue)) {
      return {
        rejection: {
          reason: 'current_value_mismatch',
          message: `[${absoluteKeyPath}] is currently ${JSON.stringify(
            currentValue
          )}, not the expected ${JSON.stringify(
            expectedCurrentValue
          )}. Nothing was assessed, because the policy is not in the state the proposal assumed.`,
          keyPath,
          os,
        },
      };
    }

    set(config, absoluteKeyPath, proposedValue);
  }

  return { config };
};
