/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/* eslint-disable max-classes-per-file */

const MAX_AMBIGUOUS_NAME_CANDIDATES = 10;

export class PolicyAuthorizationError extends Error {
  constructor() {
    super('Not authorized for policy management');
    this.name = 'PolicyAuthorizationError';
  }
}

export class PolicyNotFoundError extends Error {
  public readonly identifier: string;

  constructor(identifier: string) {
    super('Endpoint policy not found');
    this.name = 'PolicyNotFoundError';
    this.identifier = identifier;
  }
}

export class PolicyAmbiguousNameError extends Error {
  public readonly candidates: ReadonlyArray<Readonly<{ id: string; name: string }>>;
  public readonly candidatesTruncated: boolean;
  public readonly candidatesTotal: number;

  constructor(
    candidates: ReadonlyArray<Readonly<{ id: string; name: string }>>,
    candidatesTotal: number = candidates.length
  ) {
    const bounded = candidates.slice(0, MAX_AMBIGUOUS_NAME_CANDIDATES).map(({ id, name }) => ({
      id,
      name,
    }));
    super('Multiple endpoint policies match the given name');
    this.name = 'PolicyAmbiguousNameError';
    this.candidates = bounded;
    this.candidatesTotal = candidatesTotal;
    this.candidatesTruncated = candidatesTotal > bounded.length;
  }
}

export class InvalidEndpointPolicyError extends Error {
  public readonly policyId: string;

  constructor(policyId: string) {
    super('Selected policy is not a valid endpoint policy');
    this.name = 'InvalidEndpointPolicyError';
    this.policyId = policyId;
  }
}

export class PolicyConflictError extends Error {
  constructor() {
    super('Endpoint policy was modified concurrently');
    this.name = 'PolicyConflictError';
  }
}
