/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ENDPOINT_DEFAULT_PAGE, ENDPOINT_DEFAULT_PAGE_SIZE } from '../constants';
import { HostStatus } from '../types';
import { GetMetadataListRequestSchema, GetMetadataRequestSchema } from '../../api/endpoint';
import { MAX_ID_LENGTH } from './schema_bounds_constants';

// NOTE: Even though schemas are kept in common/api/endpoint - we keep tests here, because common/api should import from outside
describe('endpoint metadata schema', () => {
  describe('GetMetadataListRequestSchemaV2', () => {
    const query = GetMetadataListRequestSchema.query;

    it('should return correct query params when valid', () => {
      const queryParams = {
        page: 1,
        pageSize: 20,
        kuery: 'some kuery',
        hostStatuses: [HostStatus.HEALTHY.toString()],
      };
      expect(query.validate(queryParams)).toEqual(queryParams);
    });

    it('should correctly use default values', () => {
      const expected = { page: ENDPOINT_DEFAULT_PAGE, pageSize: ENDPOINT_DEFAULT_PAGE_SIZE };
      expect(query.validate(undefined)).toEqual(expected);
      expect(query.validate({ page: undefined })).toEqual(expected);
      expect(query.validate({ pageSize: undefined })).toEqual(expected);
      expect(query.validate({ page: undefined, pageSize: undefined })).toEqual(expected);
    });

    it('should throw if page param is not a number', () => {
      expect(() => query.validate({ page: 'notanumber' })).toThrowError();
    });

    it('should throw if page param is less than 0', () => {
      expect(() => query.validate({ page: -1 })).toThrowError();
    });

    it('should throw if pageSize param is not a number', () => {
      expect(() => query.validate({ pageSize: 'notanumber' })).toThrowError();
    });

    it('should throw if pageSize param is less than 1', () => {
      expect(() => query.validate({ pageSize: 0 })).toThrowError();
    });

    it('should throw if pageSize param is greater than 10000', () => {
      expect(() => query.validate({ pageSize: 10001 })).toThrowError();
    });

    it('should throw if kuery is not string', () => {
      expect(() => query.validate({ kuery: 123 })).toThrowError();
    });

    it('should work with valid hostStatus', () => {
      const queryParams = { hostStatuses: [HostStatus.HEALTHY, HostStatus.UPDATING] };
      const expected = {
        page: ENDPOINT_DEFAULT_PAGE,
        pageSize: ENDPOINT_DEFAULT_PAGE_SIZE,
        ...queryParams,
      };
      expect(query.validate(queryParams)).toEqual(expected);
    });

    it('should throw if kuery exceeds max length', () => {
      expect(() => query.validate({ kuery: 'a'.repeat(10_001) })).toThrowError();
    });

    it('should accept kuery at max length', () => {
      const kuery = 'a'.repeat(10_000);
      expect(query.validate({ kuery })).toEqual({
        page: ENDPOINT_DEFAULT_PAGE,
        pageSize: ENDPOINT_DEFAULT_PAGE_SIZE,
        kuery,
      });
    });

    it('should throw if invalid hostStatus', () => {
      expect(() =>
        query.validate({ hostStatuses: [HostStatus.UNHEALTHY, 'invalidstatus'] })
      ).toThrowError();
    });
  });

  describe('GetMetadataRequestSchema', () => {
    const params = GetMetadataRequestSchema.params;
    const maxId = 'a'.repeat(MAX_ID_LENGTH);
    const overMaxId = 'a'.repeat(MAX_ID_LENGTH + 1);

    it('should accept id at max length', () => {
      expect(() => params.validate({ id: maxId })).not.toThrow();
    });

    it('should reject id over max length', () => {
      expect(() => params.validate({ id: overMaxId })).toThrow();
    });
  });
});
