/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest } from '@kbn/core-http-server';
import type { SavedObjectsClientContract } from '@kbn/core-saved-objects-api-server';
import type { SavedObjectsServiceStart } from '@kbn/core-saved-objects-server';
import { SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';

export type PolicyReadSavedObjectsService = Pick<SavedObjectsServiceStart, 'getScopedClient'>;

export interface CreatePolicyReadSavedObjectsClientOptions {
  readonly savedObjects: PolicyReadSavedObjectsService;
  readonly request: KibanaRequest;
}

export const createPolicyReadSavedObjectsClient = ({
  savedObjects,
  request,
}: CreatePolicyReadSavedObjectsClientOptions): SavedObjectsClientContract =>
  savedObjects.getScopedClient(request, {
    excludedExtensions: [SECURITY_EXTENSION_ID],
  });
