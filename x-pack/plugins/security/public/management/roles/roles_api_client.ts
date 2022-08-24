/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { HttpStart } from '@kbn/core/public';

import type { Role, RoleIndexPrivilege } from '../../../common/model';
import { copyRole } from '../../../common/model';
import type { RoleKibanaPrivilege } from '../../../common/model/role';

export class RolesAPIClient {
  constructor(private readonly http: HttpStart) {}

  public async getRoles() {
    return await this.http.get<Role[]>('/api/security/role');
  }

  public async getRole(roleName: string) {
    return await this.http.get<Role>(`/api/security/role/${encodeURIComponent(roleName)}`);
  }

  public async deleteRole(roleName: string) {
    await this.http.delete(`/api/security/role/${encodeURIComponent(roleName)}`);
  }

  public async saveRole({ role, createOnly = false }: { role: Role; createOnly?: boolean }) {
    await this.http.put(`/api/security/role/${encodeURIComponent(role.name)}`, {
      body: JSON.stringify(this.transformRoleForSave(copyRole(role))),
      query: { createOnly },
    });
  }

  private transformRoleForSave(role: Role) {
    // Remove any placeholder index privileges
    const isPlaceholderPrivilege = (indexPrivilege: RoleIndexPrivilege) =>
      indexPrivilege.names.length === 0;
    role.elasticsearch.indices = role.elasticsearch.indices.filter(
      (indexPrivilege) => !isPlaceholderPrivilege(indexPrivilege)
    );

    // Remove any placeholder query entries
    role.elasticsearch.indices.forEach((index) => index.query || delete index.query);

    role.kibana.forEach((kibanaPrivilege: RoleKibanaPrivilege) => {
      // If a base privilege is defined, then do not persist feature privileges
      if (kibanaPrivilege.base.length > 0) {
        kibanaPrivilege.feature = {};
      }

      // TODO remove, for testing - packages will come from roles UI
      const endpointFeatures = kibanaPrivilege.feature?.siem;
      const packages: string[] = [];

      if (endpointFeatures) {
        if (endpointFeatures.includes('endpoint_management_all')) {
          packages.push('endpoint:action:endpoint_management_write');
        } else if (endpointFeatures.includes('endpoint_management_read')) {
          packages.push('endpoint:action:endpoint_management_read');
        }

        if (endpointFeatures.includes('response_actions_management_all')) {
          packages.push('endpoint:action:response_actions_management_write');
        } else if (endpointFeatures.includes('response_actions_management_read')) {
          packages.push('endpoint:action:response_actions_management_read');
        }

        if (endpointFeatures.includes('host_isolation_all')) {
          packages.push('endpoint:action:isolate_hosts');
        }

        if (endpointFeatures.includes('process_operations_all')) {
          packages.push('endpoint:action:process_operations');
        }

        if (endpointFeatures.includes('file_operations_all')) {
          packages.push('endpoint:action:file_operations');
        }
      }

      kibanaPrivilege.packages = packages;
    });

    // @ts-expect-error
    delete role.name;
    delete role.transient_metadata;
    delete role._unrecognized_applications;
    delete role._transform_error;

    return role;
  }
}
