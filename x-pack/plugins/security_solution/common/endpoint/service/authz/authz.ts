/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FleetAuthz } from '@kbn/fleet-plugin/common';
import type { LicenseService } from '../../../license';
import type { EndpointAuthz } from '../../types/authz';
import type { MaybeImmutable } from '../../types';

/**
 * Used by both the server and the UI to generate the Authorization for access to Endpoint related
 * functionality
 *
 * @param licenseService
 * @param fleetAuthz
 * @param userRoles
 */
export const calculateEndpointAuthz = (
  licenseService: LicenseService,
  fleetAuthz: FleetAuthz,
  userRoles: MaybeImmutable<string[]>
): EndpointAuthz => {
  const isPlatinumPlusLicense = licenseService.isPlatinumPlus();
  const isEnterpriseLicense = licenseService.isEnterprise();
  const hasAllEndpointAccess =
    userRoles.includes('superuser') ||
    !!fleetAuthz?.packagePrivileges?.endpoint?.actions?.all?.executePackageAction;
  const hasEndpointManagementAccess =
    hasAllEndpointAccess ||
    !!fleetAuthz?.packagePrivileges?.endpoint?.actions?.endpoint_management_write
      ?.executePackageAction ||
    !!fleetAuthz?.packagePrivileges?.endpoint?.actions?.endpoint_management_read
      ?.executePackageAction;
  const canReadResponseActionsManagement =
    hasAllEndpointAccess ||
    !!fleetAuthz?.packagePrivileges?.endpoint?.actions?.response_actions_management_read
      ?.executePackageAction;
  const canWriteResponseActionsManagement =
    hasAllEndpointAccess ||
    !!fleetAuthz?.packagePrivileges?.endpoint?.actions?.response_actions_management_write
      ?.executePackageAction;
  const canWriteProcessOperations =
    hasAllEndpointAccess ||
    !!fleetAuthz?.packagePrivileges?.endpoint?.actions?.process_operations?.executePackageAction;

  return {
    canAccessFleet: fleetAuthz?.fleet.all ?? userRoles.includes('superuser'),
    canAccessEndpointManagement: hasEndpointManagementAccess,
    canReadResponseActionsManagement:
      (canWriteResponseActionsManagement || canReadResponseActionsManagement) &&
      isEnterpriseLicense,
    canWriteResponseActionsManagement: canWriteResponseActionsManagement && isEnterpriseLicense,
    canCreateArtifactsByPolicy: hasEndpointManagementAccess && isPlatinumPlusLicense,
    // Response Actions
    canIsolateHost:
      isPlatinumPlusLicense &&
      !!fleetAuthz?.packagePrivileges?.endpoint?.actions?.isolate_hosts?.executePackageAction,
    canUnIsolateHost: hasEndpointManagementAccess,
    canKillProcess: canWriteProcessOperations && isEnterpriseLicense,
    canSuspendProcess: canWriteProcessOperations && isEnterpriseLicense,
    canGetRunningProcesses: canWriteProcessOperations && isEnterpriseLicense,
    canAccessResponseConsole: hasEndpointManagementAccess && isEnterpriseLicense,
  };
};

export const getEndpointAuthzInitialState = (): EndpointAuthz => {
  return {
    canAccessFleet: false,
    canAccessEndpointManagement: false,
    canReadResponseActionsManagement: false,
    canWriteResponseActionsManagement: false,
    canCreateArtifactsByPolicy: false,
    canIsolateHost: false,
    canUnIsolateHost: true,
    canKillProcess: false,
    canSuspendProcess: false,
    canGetRunningProcesses: false,
    canAccessResponseConsole: false,
  };
};
