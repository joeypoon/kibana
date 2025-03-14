/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { PresentationUtilPluginStart } from './types';
import { registerExpressionsLanguage } from '.';
import { setStubKibanaServices } from './services/mocks';

const createStartContract = (): PresentationUtilPluginStart => {
  const startContract: PresentationUtilPluginStart = {
    labsService: {
      getProjects: jest.fn(),
      getProject: jest.fn(),
      isProjectEnabled: jest.fn(),
      reset: jest.fn(),
      setProjectStatus: jest.fn(),
    },
    registerExpressionsLanguage,
  };
  return startContract;
};

export const presentationUtilPluginMock = {
  createStartContract,
};

export * from './__stories__/fixtures/flights';
export const setMockedPresentationUtilServices = () => {
  setStubKibanaServices();
};
