/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { CreateCustomIntegrationNotificationEvent } from '../create/notifications';
import { CreateInitialState } from '../create/types';

type ChildInitialStates = Partial<CreateInitialState>;
export type InitialState = { context?: ChildInitialStates } & WithSelectedMode;

export interface WithSelectedMode {
  mode: Mode;
}

export type Mode = 'create' | 'update';

export type DefaultCustomIntegrationsContext = WithSelectedMode;

export type CustomIntegrationsTypestate =
  | {
      value: 'uninitialized';
      context: DefaultCustomIntegrationsContext;
    }
  | {
      value: 'create' | { create: 'initialized' };
      context: DefaultCustomIntegrationsContext;
    };

export type CustomIntegrationsContext = CustomIntegrationsTypestate['context'];

export type CustomIntegrationsEvent = CreateCustomIntegrationNotificationEvent;
