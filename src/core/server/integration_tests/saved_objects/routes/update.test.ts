/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import supertest from 'supertest';
import { savedObjectsClientMock } from '@kbn/core-saved-objects-api-server-mocks';
import type { ICoreUsageStatsClient } from '@kbn/core-usage-data-base-server-internal';
import {
  coreUsageStatsClientMock,
  coreUsageDataServiceMock,
} from '@kbn/core-usage-data-server-mocks';
import {
  createHiddenTypeVariants,
  setupServer,
  SetupServerReturn,
} from '@kbn/core-test-helpers-test-utils';
import {
  registerUpdateRoute,
  type InternalSavedObjectsRequestHandlerContext,
} from '@kbn/core-saved-objects-server-internal';
import { loggerMock } from '@kbn/logging-mocks';
import { deprecationMock, setupConfig } from './routes_test_utils';

const testTypes = [
  { name: 'index-pattern', hide: false }, // multi-namespace type
  { name: 'hidden-type', hide: true }, // hidden
  { name: 'hidden-from-http', hide: false, hideFromHttpApis: true },
];

describe('PUT /api/saved_objects/{type}/{id?}', () => {
  let server: SetupServerReturn['server'];
  let createRouter: SetupServerReturn['createRouter'];
  let handlerContext: SetupServerReturn['handlerContext'];
  let savedObjectsClient: ReturnType<typeof savedObjectsClientMock.create>;
  let coreUsageStatsClient: jest.Mocked<ICoreUsageStatsClient>;
  let loggerWarnSpy: jest.SpyInstance;
  let registrationSpy: jest.SpyInstance;

  beforeEach(async () => {
    const clientResponse = {
      id: 'logstash-*',
      title: 'logstash-*',
      type: 'logstash-type',
      attributes: {},
      timeFieldName: '@timestamp',
      notExpandable: true,
      references: [],
    };

    ({ server, createRouter, handlerContext } = await setupServer());
    savedObjectsClient = handlerContext.savedObjects.client;
    savedObjectsClient.update.mockResolvedValue(clientResponse);

    handlerContext.savedObjects.typeRegistry.getType.mockImplementation((typename: string) => {
      return testTypes
        .map((typeDesc) => createHiddenTypeVariants(typeDesc))
        .find((fullTest) => fullTest.name === typename);
    });

    const router = createRouter<InternalSavedObjectsRequestHandlerContext>('/api/saved_objects/');
    coreUsageStatsClient = coreUsageStatsClientMock.create();
    coreUsageStatsClient.incrementSavedObjectsUpdate.mockRejectedValue(new Error('Oh no!')); // intentionally throw this error, which is swallowed, so we can assert that the operation does not fail
    const coreUsageData = coreUsageDataServiceMock.createSetupContract(coreUsageStatsClient);
    const logger = loggerMock.create();
    loggerWarnSpy = jest.spyOn(logger, 'warn').mockImplementation();
    registrationSpy = jest.spyOn(router, 'put');

    const config = setupConfig();
    const access = 'public';
    registerUpdateRoute(router, {
      config,
      coreUsageData,
      logger,
      access,
      deprecationInfo: deprecationMock,
    });

    await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  it('formats successful response and records usage stats', async () => {
    const clientResponse = {
      id: 'logstash-*',
      title: 'logstash-*',
      type: 'logstash-type',
      timeFieldName: '@timestamp',
      notExpandable: true,
      attributes: {},
      references: [],
    };
    savedObjectsClient.update.mockResolvedValue(clientResponse);

    const result = await supertest(server.listener)
      .put('/api/saved_objects/index-pattern/logstash-*')
      .set('x-elastic-internal-origin', 'kibana')
      .send({
        attributes: {
          title: 'Testing',
        },
        references: [],
      })
      .expect(200);

    expect(result.body).toEqual(clientResponse);
    expect(coreUsageStatsClient.incrementSavedObjectsUpdate).toHaveBeenCalledWith({
      request: expect.anything(),
      types: ['index-pattern'],
    });
  });

  it('calls upon savedObjectClient.update', async () => {
    await supertest(server.listener)
      .put('/api/saved_objects/index-pattern/logstash-*')
      .set('x-elastic-internal-origin', 'kibana')
      .send({
        attributes: { title: 'Testing' },
        version: 'foo',
      })
      .expect(200);

    expect(savedObjectsClient.update).toHaveBeenCalledWith(
      'index-pattern',
      'logstash-*',
      { title: 'Testing' },
      { version: 'foo', migrationVersionCompatibility: 'raw' }
    );
  });

  it('returns with status 400 for types hidden from the HTTP APIs', async () => {
    const result = await supertest(server.listener)
      .put('/api/saved_objects/hidden-from-http/hiddenId')
      .set('x-elastic-internal-origin', 'kibana')
      .send({
        attributes: { title: 'does not matter' },
      })
      .expect(400);
    expect(result.body.message).toContain("Unsupported saved object type: 'hidden-from-http'");
  });

  it('logs a warning message when called', async () => {
    await supertest(server.listener)
      .put('/api/saved_objects/index-pattern/logstash-*')
      .set('x-elastic-internal-origin', 'kibana')
      .send({ attributes: { title: 'Logging test' }, version: 'log' })
      .expect(200);
    expect(loggerWarnSpy).toHaveBeenCalledTimes(1);
  });

  it('passes deprecation configuration to the router arguments', async () => {
    await supertest(server.listener)
      .put('/api/saved_objects/index-pattern/logstash-*')
      .set('x-elastic-internal-origin', 'kibana')
      .send({ attributes: { title: 'Logging test' }, version: 'log' })
      .expect(200);
    expect(registrationSpy.mock.calls[0][0]).toMatchObject({
      options: { deprecated: deprecationMock },
    });
  });
});
