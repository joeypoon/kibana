/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { METADATA_UNITED_INDEX } from '../../../../../../common/endpoint/constants';
import {
  buildUnitedApplyStateFilter,
  UNITED_APPLY_STATE_ASSIGNMENT_FIELD,
} from './united_apply_state_filter';
import {
  APPLY_STATE_AGENT_ID_AGG_NAME,
  APPLY_STATE_AGENT_TERMS_SIZE,
  APPLY_STATE_APPLIED_AGENT_REV_FIELD,
  APPLY_STATE_MISSING_LONG,
  APPLY_STATE_REPORTED_AGENT_REV_FIELD,
  APPLY_STATE_REPORTED_PACKAGE_ID_FIELD,
  APPLY_STATE_REPORTED_PACKAGE_REV_FIELD,
  APPLY_STATE_TUPLE_AGG_NAME,
  APPLY_STATE_TUPLE_TERMS_SIZE,
  APPLY_STATE_UNITED_RUNTIME_MAPPINGS,
  buildUnitedApplyStateSearch,
  evaluateUnitedOutOfDate,
} from './apply_state_united_aggregation';

const PACKAGE_POLICY = { id: 'pkg', revision: 3 };
const CONFIGURED_BY_AGENT_POLICY_ID = {
  base: { id: 'base', revision: 5 },
};

const runtimeScriptSource = (fieldName: string): string => {
  const mapping = APPLY_STATE_UNITED_RUNTIME_MAPPINGS[fieldName];
  const script = mapping && 'script' in mapping ? mapping.script : undefined;
  if (typeof script === 'string') {
    return script;
  }
  if (
    typeof script === 'object' &&
    script !== null &&
    'source' in script &&
    typeof script.source === 'string'
  ) {
    return script.source;
  }
  throw new Error(`missing painless source for ${fieldName}`);
};

describe('buildUnitedApplyStateSearch', () => {
  const search = buildUnitedApplyStateSearch({
    agentPolicyIds: ['base'],
    ccsEnabled: false,
  });

  it('serializes a size-0 united search with five runtime keys and sibling terms', () => {
    expect(search).toEqual({
      index: METADATA_UNITED_INDEX,
      from: 0,
      size: 0,
      track_total_hits: false,
      query: buildUnitedApplyStateFilter(['base']),
      runtime_mappings: APPLY_STATE_UNITED_RUNTIME_MAPPINGS,
      aggregations: {
        [APPLY_STATE_TUPLE_AGG_NAME]: {
          multi_terms: {
            size: APPLY_STATE_TUPLE_TERMS_SIZE,
            terms: [
              { field: UNITED_APPLY_STATE_ASSIGNMENT_FIELD },
              { field: APPLY_STATE_REPORTED_PACKAGE_ID_FIELD },
              { field: APPLY_STATE_REPORTED_AGENT_REV_FIELD },
              { field: APPLY_STATE_REPORTED_PACKAGE_REV_FIELD },
              { field: APPLY_STATE_APPLIED_AGENT_REV_FIELD },
            ],
          },
        },
        [APPLY_STATE_AGENT_ID_AGG_NAME]: {
          terms: {
            field: 'united.endpoint.agent.id',
            size: APPLY_STATE_AGENT_TERMS_SIZE,
          },
        },
      },
    });
    expect(APPLY_STATE_TUPLE_TERMS_SIZE).toBe(1500);
    expect(APPLY_STATE_AGENT_TERMS_SIZE).toBe(1500);
  });

  it('does not call Elasticsearch or address .fleet-agents', () => {
    const serialized = JSON.stringify(search);

    expect(serialized).not.toContain('.fleet-agents');
    expect(search.index).toBe(METADATA_UNITED_INDEX);
  });

  it('keeps cpsSpaceId off the bool and only uses cpsSpaceId for CCS index pairing', () => {
    const ccsOnly = buildUnitedApplyStateSearch({
      agentPolicyIds: ['base'],
      ccsEnabled: true,
    });
    const cpsAndCcs = buildUnitedApplyStateSearch({
      agentPolicyIds: ['base'],
      ccsEnabled: true,
      cpsSpaceId: 'space-b',
    });
    const cpsOnly = buildUnitedApplyStateSearch({
      agentPolicyIds: ['base'],
      ccsEnabled: false,
      cpsSpaceId: 'space-b',
    });

    expect(ccsOnly.index).toBe(`${METADATA_UNITED_INDEX},*:${METADATA_UNITED_INDEX}`);
    expect(cpsAndCcs.index).toBe(METADATA_UNITED_INDEX);
    expect(cpsOnly.index).toBe(METADATA_UNITED_INDEX);
    expect(ccsOnly.query).toEqual(buildUnitedApplyStateFilter(['base']));
    expect(cpsAndCcs.query).toEqual(buildUnitedApplyStateFilter(['base']));
    expect(JSON.stringify(cpsAndCcs.query)).not.toContain('united.agent.namespaces');
  });

  it('does not use the list CPS empty-id remote branch', () => {
    const cpsSearch = buildUnitedApplyStateSearch({
      agentPolicyIds: ['base'],
      ccsEnabled: false,
      cpsSpaceId: 'test-space',
    });
    const serializedQuery = JSON.stringify(cpsSearch.query);

    expect(cpsSearch.query).toEqual(buildUnitedApplyStateFilter(['base']));
    expect(serializedQuery).not.toContain('united.agent.namespaces');
    expect(serializedQuery).not.toContain('_alias:_origin');
    expect(serializedQuery).not.toContain('minimum_should_match');
  });

  it('emits sentinels for every runtime key and never queries unmapped policy_base_id', () => {
    const assignmentScript = runtimeScriptSource(UNITED_APPLY_STATE_ASSIGNMENT_FIELD);
    const reportedIdScript = runtimeScriptSource(APPLY_STATE_REPORTED_PACKAGE_ID_FIELD);
    const reportedAgentRevScript = runtimeScriptSource(APPLY_STATE_REPORTED_AGENT_REV_FIELD);
    const reportedPackageRevScript = runtimeScriptSource(APPLY_STATE_REPORTED_PACKAGE_REV_FIELD);
    const appliedAgentRevScript = runtimeScriptSource(APPLY_STATE_APPLIED_AGENT_REV_FIELD);
    const serializedQuery = JSON.stringify(search.query);

    expect(assignmentScript).toContain('params._source');
    expect(assignmentScript).toContain('policy_base_id');
    expect(assignmentScript).toContain("replaceAll(/#\\d+\\.\\d+$/, m -> '')");
    expect(assignmentScript).toContain("emit('')");
    expect(reportedIdScript).toContain('united.endpoint.Endpoint.policy.applied.id');
    expect(reportedIdScript).toContain("emit('')");
    expect(reportedAgentRevScript).toContain('params._source');
    expect(reportedAgentRevScript).toContain('applied.version');
    expect(reportedAgentRevScript).toContain('emit(-1L)');
    expect(reportedPackageRevScript).toContain('endpoint_policy_version');
    expect(reportedPackageRevScript).toContain('emit(-1L)');
    expect(appliedAgentRevScript).toContain('united.agent.policy_revision_idx');
    expect(appliedAgentRevScript).toContain('emit(-1L)');
    expect(appliedAgentRevScript).not.toContain("doc['united.agent.policy_revision']");
    expect(serializedQuery).not.toContain('applied.id');
    expect(serializedQuery).not.toContain('united.agent.policy_base_id');
    expect(serializedQuery).not.toContain('united.agent.policy_id');
  });

  it('strips only a trailing #major.minor suffix from the assignment policy id', () => {
    const assignmentScript = runtimeScriptSource(UNITED_APPLY_STATE_ASSIGNMENT_FIELD);
    const patternStart = assignmentScript.indexOf('replaceAll(/') + 'replaceAll(/'.length;
    const patternEnd = assignmentScript.indexOf("/, m -> '')", patternStart);
    const suffixPattern = new RegExp(assignmentScript.slice(patternStart, patternEnd));

    expect(patternEnd).toBeGreaterThan(patternStart);
    expect('policy-id#1.0'.replace(suffixPattern, '')).toBe('policy-id');
    expect('eval-agent-policy-id'.replace(suffixPattern, '')).toBe('eval-agent-policy-id');
    expect('policy#123'.replace(suffixPattern, '')).toBe('policy#123');
  });

  it('reuses one integer-normalization helper in all three revision scripts and drops explicit revision casts', () => {
    const reportedAgentRevScript = runtimeScriptSource(APPLY_STATE_REPORTED_AGENT_REV_FIELD);
    const reportedPackageRevScript = runtimeScriptSource(APPLY_STATE_REPORTED_PACKAGE_REV_FIELD);
    const appliedAgentRevScript = runtimeScriptSource(APPLY_STATE_APPLIED_AGENT_REV_FIELD);
    const helper = reportedAgentRevScript.slice(
      0,
      reportedAgentRevScript.indexOf('\ndef source = params._source')
    );

    expect(helper).toContain('long normalizeIntegerRevision(def value)');
    expect(reportedPackageRevScript.startsWith(helper)).toBe(true);
    expect(appliedAgentRevScript.startsWith(helper)).toBe(true);
    expect(reportedAgentRevScript).not.toContain('(long)');
    expect(reportedPackageRevScript).not.toContain('(long)');
    expect(appliedAgentRevScript).not.toContain('(long)');
    expect(reportedAgentRevScript).toContain(
      'emit(normalizeIntegerRevision(source.united.endpoint.Endpoint.policy.applied.version))'
    );
    expect(reportedPackageRevScript).toContain(
      'emit(normalizeIntegerRevision(source.united.endpoint.Endpoint.policy.applied.endpoint_policy_version))'
    );
    expect(appliedAgentRevScript).toContain('emit(normalizeIntegerRevision(revision))');
    expect(appliedAgentRevScript).toContain("doc.containsKey('united.agent.policy_revision_idx')");
    expect(appliedAgentRevScript).toContain("doc['united.agent.policy_revision_idx'].size() > 0");
  });

  it('encodes the integer accept-set so unparseable revisions take the missing sentinel instead of throwing', () => {
    const helper = runtimeScriptSource(APPLY_STATE_REPORTED_AGENT_REV_FIELD).slice(
      0,
      runtimeScriptSource(APPLY_STATE_REPORTED_AGENT_REV_FIELD).indexOf(
        '\ndef source = params._source'
      )
    );

    expect(helper).toContain('if (value == null)');
    expect(helper).toContain('instanceof Number');
    expect(helper).toContain('longValue()');
    expect(helper).toContain('instanceof String');
    expect(helper).toContain('.trim()');
    expect(helper).toContain('trimmed.length() == 0');
    expect(helper).toContain('Long.parseLong(trimmed)');
    expect(helper).toContain('catch (NumberFormatException e)');
    expect(helper.indexOf('instanceof Number')).toBeLessThan(helper.indexOf('Long.parseLong'));
    expect(helper.indexOf('longValue()')).toBeLessThan(helper.indexOf('Long.parseLong'));
    expect(helper).not.toContain('(long)');
    expect(helper.match(/return -1L;/g)).toEqual([
      'return -1L;',
      'return -1L;',
      'return -1L;',
      'return -1L;',
    ]);
  });

  it('does not set missing_bucket or composite paging', () => {
    const serialized = JSON.stringify(search.aggregations);

    expect(serialized).not.toContain('missing_bucket');
    expect(serialized).not.toContain('composite');
    expect(serialized).not.toContain('.fleet-agents');
  });

  it('uses match_none for empty assignment ids without emitting terms: []', () => {
    const emptySearch = buildUnitedApplyStateSearch({
      agentPolicyIds: [],
      ccsEnabled: false,
    });

    expect(emptySearch.query).toEqual({ match_none: {} });
    expect(JSON.stringify(emptySearch.query)).not.toContain('"terms"');
  });
});

describe('evaluateUnitedOutOfDate', () => {
  const evaluate = (
    aggregations: unknown,
    configuredByAgentPolicyId: Readonly<
      Record<string, { id: string; revision: number }>
    > = CONFIGURED_BY_AGENT_POLICY_ID
  ) =>
    evaluateUnitedOutOfDate({
      aggregations,
      packagePolicy: PACKAGE_POLICY,
      configuredByAgentPolicyId,
    });

  it('returns zeros for missing aggregations (index-missing shape)', () => {
    expect(evaluate(undefined)).toEqual({
      outOfDateHosts: 0,
      classifiedHosts: 0,
      overflowHosts: 0,
      agentIds: [],
      agentOverflow: 0,
    });
    expect(evaluate(null)).toEqual({
      outOfDateHosts: 0,
      classifiedHosts: 0,
      overflowHosts: 0,
      agentIds: [],
      agentOverflow: 0,
    });
    expect(evaluate({})).toEqual({
      outOfDateHosts: 0,
      classifiedHosts: 0,
      overflowHosts: 0,
      agentIds: [],
      agentOverflow: 0,
    });
  });

  it('weights in-date and out-of-date tuples separately and keeps overflow unclassified', () => {
    const inDateTuples = Array.from({ length: 8 }, (_, index) => ({
      key: [`base-${index}`, PACKAGE_POLICY.id, 5, 3, 5],
      doc_count: 100,
    }));
    const configured = Object.fromEntries(
      inDateTuples.map((bucket) => [bucket.key[0], { id: String(bucket.key[0]), revision: 5 }])
    );
    const result = evaluate(
      {
        [APPLY_STATE_TUPLE_AGG_NAME]: {
          buckets: [
            ...inDateTuples,
            { key: ['base-0', 'stale-pkg', 5, 3, 5], doc_count: 5 },
            { key: ['base-1', PACKAGE_POLICY.id, 1, 3, 5], doc_count: 5 },
          ],
          sum_other_doc_count: 20,
        },
        [APPLY_STATE_AGENT_ID_AGG_NAME]: {
          buckets: [{ key: 'agent-a', doc_count: 1 }],
          sum_other_doc_count: 7,
        },
      },
      configured
    );

    expect(result).toEqual({
      outOfDateHosts: 10,
      classifiedHosts: 810,
      overflowHosts: 20,
      agentIds: ['agent-a'],
      agentOverflow: 7,
    });
    expect(result).not.toHaveProperty('value_total');
  });

  it('uses the documented 5 / 805 / 20 overflow example without classifying overflow', () => {
    const result = evaluate({
      [APPLY_STATE_TUPLE_AGG_NAME]: {
        buckets: [
          { key: ['base', PACKAGE_POLICY.id, 5, 3, 5], doc_count: 800 },
          { key: ['base', 'stale-pkg', 5, 3, 5], doc_count: 5 },
        ],
        sum_other_doc_count: 20,
      },
      [APPLY_STATE_AGENT_ID_AGG_NAME]: {
        buckets: [],
        sum_other_doc_count: 0,
      },
    });

    expect(result.outOfDateHosts).toBe(5);
    expect(result.classifiedHosts).toBe(805);
    expect(result.overflowHosts).toBe(20);
    expect(result.agentOverflow).toBe(0);
  });

  it('treats a missing reported version sentinel as out-of-date when id is present', () => {
    const result = evaluate({
      [APPLY_STATE_TUPLE_AGG_NAME]: {
        buckets: [
          {
            key: ['base', PACKAGE_POLICY.id, APPLY_STATE_MISSING_LONG, 3, 5],
            doc_count: 4,
          },
        ],
        sum_other_doc_count: 0,
      },
    });

    expect(result).toEqual({
      outOfDateHosts: 4,
      classifiedHosts: 4,
      overflowHosts: 0,
      agentIds: [],
      agentOverflow: 0,
    });
  });

  it('does not pass 0 for a missing reported revision when current revisions are 0', () => {
    const result = evaluateUnitedOutOfDate({
      aggregations: {
        [APPLY_STATE_TUPLE_AGG_NAME]: {
          buckets: [
            {
              key: [
                'base',
                PACKAGE_POLICY.id,
                APPLY_STATE_MISSING_LONG,
                APPLY_STATE_MISSING_LONG,
                APPLY_STATE_MISSING_LONG,
              ],
              doc_count: 2,
            },
          ],
        },
      },
      packagePolicy: { id: PACKAGE_POLICY.id, revision: 0 },
      configuredByAgentPolicyId: { base: { id: 'base', revision: 0 } },
    });

    expect(result.outOfDateHosts).toBe(2);
  });

  it('does not classify an empty reported package id as out-of-date', () => {
    const result = evaluate({
      [APPLY_STATE_TUPLE_AGG_NAME]: {
        buckets: [{ key: ['base', '', 5, 3, 5], doc_count: 9 }],
      },
    });

    expect(result).toEqual({
      outOfDateHosts: 0,
      classifiedHosts: 9,
      overflowHosts: 0,
      agentIds: [],
      agentOverflow: 0,
    });
  });

  it('treats a configured lookup miss as out-of-date when reported id is present', () => {
    const result = evaluate({
      [APPLY_STATE_TUPLE_AGG_NAME]: {
        buckets: [{ key: ['unknown', PACKAGE_POLICY.id, 5, 3, 5], doc_count: 3 }],
      },
    });

    expect(result.outOfDateHosts).toBe(3);
    expect(result.classifiedHosts).toBe(3);
  });

  it('skips malformed tuple buckets instead of throwing', () => {
    const result = evaluate({
      [APPLY_STATE_TUPLE_AGG_NAME]: {
        buckets: [
          { key: ['base', PACKAGE_POLICY.id, 5], doc_count: 2 },
          { key: ['base', PACKAGE_POLICY.id, 5, 3, 5] },
          'not-a-bucket',
          { key: ['base', PACKAGE_POLICY.id, 5, 3, 5], doc_count: 6 },
        ],
        sum_other_doc_count: 11,
      },
      [APPLY_STATE_AGENT_ID_AGG_NAME]: {
        buckets: [{ key: 'agent-1', doc_count: 1 }, { doc_count: 1 }, { key: '', doc_count: 1 }],
        sum_other_doc_count: 4,
      },
    });

    expect(result).toEqual({
      outOfDateHosts: 0,
      classifiedHosts: 6,
      overflowHosts: 11,
      agentIds: ['agent-1'],
      agentOverflow: 4,
    });
  });

  it('keeps tuple overflow and agent overflow mathematically distinct', () => {
    const result = evaluate({
      [APPLY_STATE_TUPLE_AGG_NAME]: {
        buckets: [{ key: ['base', PACKAGE_POLICY.id, 5, 3, 5], doc_count: 1 }],
        sum_other_doc_count: 20,
      },
      [APPLY_STATE_AGENT_ID_AGG_NAME]: {
        buckets: [],
        sum_other_doc_count: 20,
      },
    });

    expect(result.overflowHosts).toBe(20);
    expect(result.agentOverflow).toBe(20);
  });
});
