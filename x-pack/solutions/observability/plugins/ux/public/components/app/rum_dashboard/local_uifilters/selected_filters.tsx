/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { Fragment } from 'react';
import { EuiButtonEmpty, EuiFlexGroup, EuiFlexItem } from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import styled from '@emotion/styled';
import { FilterValueLabel } from '@kbn/exploratory-view-plugin/public';
import type { DataView } from '@kbn/data-views-plugin/public';
import { useLegacyUrlParams } from '../../../../context/url_params_context/use_url_params';
import { FiltersUIHook } from '../hooks/use_local_uifilters';
import { SelectedWildcards } from './selected_wildcards';
import { UxLocalUIFilterName } from '../../../../../common/ux_ui_filter';

interface Props {
  indexPattern?: DataView;
  filters: FiltersUIHook['filters'];
  invertFilter: FiltersUIHook['invertFilter'];
  onChange: (name: UxLocalUIFilterName, values: string[]) => void;
  clearValues: () => void;
}

const FilterItem = styled(EuiFlexItem)`
  max-width: 300px;
`;

export function SelectedFilters({
  indexPattern,
  onChange,
  filters,
  invertFilter,
  clearValues,
}: Props) {
  const {
    uxUiFilters,
    urlParams: { searchTerm },
  } = useLegacyUrlParams();
  const { transactionUrl } = uxUiFilters;

  const urlValues = transactionUrl ?? [];

  const hasValues = filters.some((filter) => filter.value?.length > 0);

  return indexPattern && (hasValues || urlValues.length > 0 || searchTerm) ? (
    <EuiFlexGroup alignItems="center" gutterSize="s" wrap>
      <SelectedWildcards indexPattern={indexPattern} />
      {(filters ?? []).map(({ name, title, fieldName, excluded }) => (
        <Fragment key={name}>
          {((uxUiFilters?.[name] ?? []) as string[]).map((value) => (
            <FilterItem key={name + value} grow={false}>
              <FilterValueLabel
                dataView={indexPattern}
                removeFilter={() => {
                  onChange(
                    name,
                    (uxUiFilters?.[name] as string[]).filter((valT) => valT !== value)
                  );
                }}
                invertFilter={({ negate }) => {
                  invertFilter(name, value, negate);
                }}
                field={fieldName}
                value={name === 'transactionUrl' ? formatUrlValue(value) : value}
                negate={!!excluded}
                label={title}
              />
            </FilterItem>
          ))}
        </Fragment>
      ))}

      <EuiFlexItem grow={false}>
        <EuiButtonEmpty
          data-test-subj="uxSelectedFiltersClearFiltersButton"
          size="xs"
          iconType="cross"
          onClick={clearValues}
          data-cy="clearFilters"
        >
          {i18n.translate('xpack.ux.clearFilters', {
            defaultMessage: 'Clear filters',
          })}
        </EuiButtonEmpty>
      </EuiFlexItem>
    </EuiFlexGroup>
  ) : null;
}

function formatUrlValue(val: string) {
  const maxUrlToDisplay = 30;
  const urlLength = val.length;
  if (urlLength < maxUrlToDisplay) {
    return val;
  }
  const urlObj = new URL(val);
  if (urlObj.pathname === '/') {
    return val;
  }
  const domainVal = urlObj.hostname;
  const extraLength = urlLength - maxUrlToDisplay;
  const extraDomain = domainVal.substring(0, extraLength);

  if (urlObj.pathname.length + 7 > maxUrlToDisplay) {
    return val.replace(domainVal, '..');
  }

  return val.replace(extraDomain, '..');
}
