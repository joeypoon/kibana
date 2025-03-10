/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
// switch is not available on shared-ux-router
// eslint-disable-next-line no-restricted-imports
import { Switch } from 'react-router-dom';

import { Route } from '@kbn/shared-ux-router';

import { InitialAppData } from '../../../common/types';

import { SemanticSearchGuide } from './components/semantic_search_guide/semantic_search_guide';

import { ROOT_PATH } from './routes';

export const EnterpriseSearchSemanticSearch: React.FC<InitialAppData> = () => {
  return (
    <Switch>
      <Route exact path={ROOT_PATH}>
        <SemanticSearchGuide />
      </Route>
    </Switch>
  );
};
