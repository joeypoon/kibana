/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CapabilitiesProvider, KibanaRequest } from '@kbn/core/server';
import type { Capabilities } from '@kbn/core/types';

import { appContextService } from '.';

export const capabilitiesProvider: CapabilitiesProvider = () => {
  return {
    packages: {
      endpoint: {
        managePackagePolicy: false,
        actions: {
          all: {
            executePackageAction: false,
          },
          endpoint_management_write: {
            executePackageAction: false,
          },
          endpoint_management_read: {
            executePackageAction: false,
          },
          response_actions_management_write: {
            executePackageAction: false,
          },
          response_actions_management_read: {
            executePackageAction: false,
          },
          isolate_hosts: {
            executePackageAction: false,
          },
          process_operations: {
            executePackageAction: false,
          },
          file_operations: {
            executePackageAction: false,
          },
        },
        spaces: {
          all: false,
        },
      },
    },
  } as any; // TODO format not compatible with Capabilities
};

export const capabilitiesSwitcher = async (
  request: KibanaRequest,
  uiCapabilities: Capabilities,
  useDefaultCapabilities: boolean
) => {
  if (request.auth.isAuthenticated) {
    const privileges = await appContextService
      .getClusterClient()
      .asScoped(request)
      .asCurrentUser.security.getUserPrivileges();

    const capabilities = privileges.applications
      .filter((app) => app.application === 'kibana-.kibana')
      .map((app) => {
        const packageRes = app.resources.find((res) => res.match('package:[^:]*'));
        let result: any = {};
        if (packageRes) {
          const pkg = packageRes.split(':')[1];
          const hasManagePackagePolicy = app.privileges.includes(
            'feature_integrations.manage_package_policy'
          );
          const spaces = app.resources
            .filter((res) => res.match('space:.*'))
            .map((res) => res.split(':')[1])
            .reduce((acc: any, curr: any) => ({ ...acc, [curr]: true }), {});
          result = {
            ...result,
            [pkg]: {
              managePackagePolicy: hasManagePackagePolicy,
              spaces,
            },
          };
        }
        app.resources
          .filter((res) => res.match('package:.*:action:.*'))
          .forEach((packageActionRes) => {
            if (packageActionRes) {
              const [, pkg, , action] = packageActionRes.split(':');
              const hasExecutePackageAction = app.privileges.includes(
                'feature_integrations.execute_package_action'
              );
              result = {
                ...result,
                [pkg]: {
                  ...result[pkg],
                  actions: {
                    ...result[pkg].actions,
                    [action === '*' ? 'all' : action]: {
                      executePackageAction: hasExecutePackageAction,
                    },
                  },
                },
              };
            }
          });

        return result;
      })
      .reduce((acc, curr) => {
        return { ...acc, ...curr };
      }, {});

    return { packages: capabilities };
  }

  return {};
};
