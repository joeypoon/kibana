/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import type { ToolHandlerStandardReturn } from '@kbn/agent-builder-server/tools';
import { SECURITY_EXTENSION_ID } from '@kbn/core-saved-objects-server';
import type { PackagePolicy } from '@kbn/fleet-plugin/common';
import { createGetDefendPolicyInventoryTool } from '.';
import { RESULT_TOKEN_BUDGET, estimateResultTokens } from '../../lib/bounded_result';
import { INTERACTIVE_ESTATE_WORK_LIMIT } from '../work_limit';
import type { DefendPolicyManagementToolMocks } from '../../lib/test_helpers';
import {
  createDefendPolicyMock,
  createDefendPolicyManagementToolMocks,
  expectConfiguredNotAppliedIsResultScoped,
  expectReadOnlyAndNoForbiddenReads,
  expectWrappedHandlerWithinPlatformBudget,
} from '../../lib/test_helpers';

const PINNED_PACKAGE_VERSION = '9.4.0';

interface InventoryPayload {
  message: string;
  policies: Array<{
    id: string;
    name: string;
    description?: string;
    revision: number;
    version?: string;
    package_version: string;
    agent_policy_ids: readonly string[];
    updated_at: string;
    updated_by: string;
  }>;
  total: number;
  returned: number;
  truncated: boolean;
  truncation_notice?: string;
  result_budget_notice?: string;
  listing_complete: boolean;
  continuation: string;
  work_limit: number;
  configured_not_applied?: string;
  scope_disclosure: {
    privilege_basis: Record<string, boolean>;
    returned: number;
    total: number;
    space_id?: string;
    partial?: { reason: string; detail: string; continuation: string };
  };
}

interface ErrorPayload {
  message: string;
  metadata?: Record<string, unknown>;
}

describe('security.get_defend_policy_inventory', () => {
  let mocks: DefendPolicyManagementToolMocks;
  let tool: ReturnType<typeof createGetDefendPolicyInventoryTool>;

  const runTool = async (input: Parameters<typeof tool.handler>[0]) =>
    (await tool.handler(input, mocks.context)) as ToolHandlerStandardReturn;

  const defendPolicy = (overrides: Parameters<typeof createDefendPolicyMock>[0] = {}) =>
    createDefendPolicyMock({
      package: { name: 'endpoint', title: 'Elastic Defend', version: PINNED_PACKAGE_VERSION },
      ...overrides,
    });

  const givenEstate = (...pages: PackagePolicy[][]) => {
    mocks.packagePolicyService.fetchAllItems.mockResolvedValue({
      async *[Symbol.asyncIterator]() {
        for (const page of pages) {
          yield page;
        }
      },
    } as unknown as Awaited<ReturnType<typeof mocks.packagePolicyService.fetchAllItems>>);
  };

  beforeEach(() => {
    jest.restoreAllMocks();
    mocks = createDefendPolicyManagementToolMocks();
    tool = createGetDefendPolicyInventoryTool(mocks.deps);
  });

  describe('success', () => {
    it('returns bounded rows with the exact total and the scope disclosure', async () => {
      givenEstate([
        defendPolicy({ id: 'p-1', name: 'Prod' }),
        defendPolicy({ id: 'p-2', name: 'Dev' }),
      ]);

      const result = await runTool({});
      const payload = result.results[0].data as InventoryPayload;

      expect(result.results[0].type).toBe(ToolResultType.other);
      expect(payload.total).toBe(2);
      expect(payload.policies.map(({ id }) => id)).toEqual(['p-1', 'p-2']);
      expect(payload.listing_complete).toBe(true);
      expect(payload.scope_disclosure.privilege_basis).toEqual({
        securityPolicyManagementRead: true,
        fleetIntegrationPoliciesRead: true,
        fleetAgentsRead: true,
      });
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('maps identity fields and does not leak config, hash, inputs, or factory leaf paths', async () => {
      givenEstate([
        defendPolicy({
          id: 'p-1',
          name: 'Prod',
          description: 'Hello',
          revision: 7,
          version: 'Wzg5XQ==',
          updated_at: '2026-03-03T00:00:00.000Z',
          updated_by: 'alice',
          policy_ids: ['ap-1', 'ap-2'],
        }),
      ]);

      const payload = (await runTool({})).results[0].data as InventoryPayload;
      const serialized = JSON.stringify(payload);

      expect(payload.policies[0]).toEqual({
        id: 'p-1',
        name: 'Prod',
        description: 'Hello',
        revision: 7,
        version: 'Wzg5XQ==',
        package_version: PINNED_PACKAGE_VERSION,
        agent_policy_ids: ['ap-1', 'ap-2'],
        updated_at: '2026-03-03T00:00:00.000Z',
        updated_by: 'alice',
      });
      expect(serialized).not.toContain('config_hash');
      expect(serialized).not.toContain('configHash');
      expect(serialized).not.toContain('configNormalized');
      expect(serialized).not.toContain('"inputs"');
      expect(serialized).not.toContain('windows.malware');
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('reads through one Fleet fetchAllItems call with the tokenized Defend kuery', async () => {
      givenEstate([defendPolicy()]);

      await runTool({ search: 'Prod Windows Servers' });

      expect(mocks.packagePolicyService.fetchAllItems).toHaveBeenCalledTimes(1);
      const [soClientArg, options] = mocks.packagePolicyService.fetchAllItems.mock.calls[0];
      expect(soClientArg).toBeDefined();
      expect(options).toMatchObject({ spaceIds: ['default'] });
      expect(options?.kuery).toContain('package.name: "endpoint"');
      expect(options?.kuery).toContain('name: *Prod*');
      expect(options?.kuery).toContain('name: *Windows*');
      expect(options?.kuery).toContain('name: *Servers*');
      expect(options?.kuery?.split(' AND ')).toHaveLength(4);
    });

    it('surfaces an actionable partial disclosure when the traversal was interrupted', async () => {
      mocks.packagePolicyService.fetchAllItems.mockRejectedValue(new Error('Fleet went away'));

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.scope_disclosure.partial).toEqual({
        reason: 'upstream_failure',
        detail: expect.any(String),
        continuation: expect.any(String),
      });
      expect(payload.listing_complete).toBe(false);
      expect(payload.message).toContain('INCOMPLETE');
      expect(payload.message).not.toMatch(/Returning all/);
      expect(payload.message).toContain('examined no');
      expect(payload.message).not.toMatch(/No Elastic Defend policies you can access/);
      expect(payload.message).not.toMatch(/you can access/);
    });

    it('stops at the interactive work limit and accounts for the partial listing honestly', async () => {
      const pages: PackagePolicy[][] = [];
      for (let page = 0; page * 100 < INTERACTIVE_ESTATE_WORK_LIMIT + 100; page += 1) {
        pages.push(
          Array.from({ length: 100 }, (_, index) =>
            defendPolicy({ id: `p-${page * 100 + index}`, name: `P ${page * 100 + index}` })
          )
        );
      }
      givenEstate(...pages);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.work_limit).toBe(INTERACTIVE_ESTATE_WORK_LIMIT);
      expect(payload.scope_disclosure.partial?.reason).toBe('result_limit_reached');
      expect(payload.scope_disclosure.partial?.detail).toContain('work limit');
      expect(payload.scope_disclosure.partial?.detail).not.toContain(
        'policies matching your request'
      );
      expect(payload.scope_disclosure.partial?.continuation).toContain('search');
      expect(payload.listing_complete).toBe(false);
      expect(payload.message).toContain('INCOMPLETE');
      expect(payload.message).not.toMatch(/Returning all/);
      expect(payload.message).toContain('examined');
      expect(payload.message).toContain('before stopping');
      expect(payload.message).not.toMatch(/\b\d+ Elastic Defend policies? you can access/);
      expect(payload.message).not.toMatch(/you can access/);
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('discloses a registry-coverage gap instead of answering from a neighbouring version', async () => {
      givenEstate([
        defendPolicy({ id: 'p-1', name: 'Good' }),
        createDefendPolicyMock({
          id: 'p-bad',
          name: 'Unknown version',
          package: { name: 'endpoint', title: 'Elastic Defend', version: 'unreleased-build' },
        }),
      ]);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.policies.map(({ id }) => id)).toEqual(['p-1']);
      expect(payload.scope_disclosure.partial?.detail).toContain('unreleased-build');
      expect(payload.listing_complete).toBe(false);
    });

    it('claims no space scope when the deployment did not enforce one', async () => {
      givenEstate([defendPolicy()]);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.scope_disclosure).not.toHaveProperty('space_id');
      expect(payload.message).toContain('you can access');
      expect(payload.message).not.toMatch(/space/i);
    });

    it('reports an enforced space only when Fleet stamped one on the returned policies', async () => {
      givenEstate([{ ...defendPolicy(), spaceIds: ['default'] }]);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.scope_disclosure.space_id).toBe('default');
    });
  });

  describe('empty result', () => {
    it('says plainly that no policies matched, and reports zero rather than omitting the total', async () => {
      givenEstate([]);

      const payload = (await runTool({ search: 'nothing-matches' })).results[0]
        .data as InventoryPayload;

      expect(payload.total).toBe(0);
      expect(payload.policies).toEqual([]);
      expect(payload.listing_complete).toBe(true);
      expect(payload.message).toContain('No Elastic Defend policies');
      expect(payload.message).toContain('nothing-matches');
    });
  });

  describe('search guidance', () => {
    it('states the literal, case-sensitive, non-regex search contract in the schema and tool text', () => {
      const searchDescription = tool.schema.shape.search.description ?? '';

      expect(searchDescription).toContain('CASE-SENSITIVE');
      expect(searchDescription).toContain('NOT a regular expression');
      expect(searchDescription).toContain('NOT a glob');
      expect(searchDescription).toContain('`*`');
      expect(searchDescription).toContain('`.*`');
      expect(searchDescription).toContain('OMIT this parameter');
      expect(tool.description).toContain('not regex');
      expect(tool.description).toContain('not glob');
    });

    it('keeps regex/glob-shaped filters literal in the kuery instead of letting them match everything', async () => {
      givenEstate([defendPolicy()]);

      await runTool({ search: '.*' });
      await runTool({ search: '*' });

      const firstKuery = mocks.packagePolicyService.fetchAllItems.mock.calls[0][1]?.kuery;
      const secondKuery = mocks.packagePolicyService.fetchAllItems.mock.calls[1][1]?.kuery;
      expect(firstKuery).toContain('name: *.\\**');
      expect(firstKuery).not.toContain('name: **.**');
      expect(secondKuery).toContain('name: *\\**');
    });

    it('never claims the accessible estate when a name filter is active, even on a complete listing', async () => {
      givenEstate([defendPolicy({ id: 'p-1', name: 'Prod' })]);

      const payload = (await runTool({ search: 'Prod' })).results[0].data as InventoryPayload;

      expect(payload.listing_complete).toBe(true);
      expect(payload.total).toBe(1);
      expect(payload.message).toContain('matching the name filter');
      expect(payload.message).toContain('Returning all 1 matching the filter');
      expect(payload.continuation).toContain('MATCHING the name filter');
      expect(payload.continuation).toContain('Omit `search`');
      expect(payload.continuation).not.toContain('Every policy you can access has been returned');
      expect(JSON.stringify(payload)).not.toContain(
        'Every policy you can access has been returned'
      );
    });

    it('scopes an incomplete filtered listing to the filter and instructs omitting it', async () => {
      const bulky = Array.from({ length: 60 }, (_, index) =>
        defendPolicy({
          id: `p-${index}`,
          name: `Policy ${index} ${'x'.repeat(900)}`,
          description: 'y'.repeat(900),
        })
      );
      givenEstate(bulky);

      const payload = (await runTool({ search: 'Policy' })).results[0].data as InventoryPayload;

      expect(payload.truncated).toBe(true);
      expect(payload.message).toContain('scoped to policies whose names match the filter');
      expect(payload.message).toContain('Omit `search`');
    });

    it.each(['.*', '*'])(
      'explains an empty result for a wildcard-shaped %s filter instead of letting it read as "no policies exist"',
      async (search) => {
        givenEstate([]);

        const payload = (await runTool({ search })).results[0].data as InventoryPayload;

        expect(payload.total).toBe(0);
        expect(payload.message).toContain('No Elastic Defend policies you can access matching');
        expect(payload.message).not.toMatch(/No Elastic Defend policies you can access\./);
        expect(payload.message).toContain('literal, case-sensitive substring filter');
        expect(payload.message).toContain('not a regular expression');
        expect(payload.message).toContain('not a glob');
        expect(payload.message).toContain('omit `search`');
        expect(payload.message).toContain('list every accessible policy');
      }
    );

    it('keeps the exhaustive-listing wording unchanged when no filter is active', async () => {
      givenEstate([
        defendPolicy({ id: 'p-1', name: 'Prod' }),
        defendPolicy({ id: 'p-2', name: 'Dev' }),
      ]);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.continuation).toBe('Every policy you can access has been returned.');
      expect(payload.message).toContain('Returning all 2.');
      expect(payload.message).not.toContain('name filter');
    });

    it('treats a whitespace-only search as unfiltered exhaustive listing', async () => {
      givenEstate([
        defendPolicy({ id: 'p-1', name: 'Prod' }),
        defendPolicy({ id: 'p-2', name: 'Dev' }),
      ]);

      const payload = (await runTool({ search: '   ' })).results[0].data as InventoryPayload;

      expect(payload.continuation).toBe('Every policy you can access has been returned.');
      expect(payload.message).toContain('Returning all 2.');
      expect(payload.message).not.toContain('name filter');
      expect(payload.message).not.toContain('matching the filter');
      const kuery = mocks.packagePolicyService.fetchAllItems.mock.calls[0][1]?.kuery;
      expect(kuery).toContain('package.name: "endpoint"');
      expect(kuery?.includes(' AND ')).toBe(false);
    });
  });

  describe('truncation', () => {
    it('discloses the trim explicitly and keeps `total` at the real count', async () => {
      const bulky = Array.from({ length: 60 }, (_, index) =>
        defendPolicy({
          id: `p-${index}`,
          name: `Policy ${index} ${'x'.repeat(900)}`,
          description: 'y'.repeat(900),
        })
      );

      givenEstate(bulky);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.truncated).toBe(true);
      expect(payload.policies.length).toBeLessThan(bulky.length);
      expect(payload.truncation_notice).toContain(String(bulky.length));
      expect(payload.truncation_notice).toMatch(/search/);
      expect(payload.message).toContain('left out of this result');
      expect(payload.total).toBe(60);
      expect(payload.returned).toBe(payload.policies.length);
    });

    it('never claims the listing is complete on a result it trimmed for size, and offers a way to get the rest', async () => {
      const bulky = Array.from({ length: 60 }, (_, index) =>
        defendPolicy({
          id: `p-${index}`,
          name: `Policy ${index} ${'x'.repeat(900)}`,
          description: 'y'.repeat(900),
        })
      );

      givenEstate(bulky);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.truncated).toBe(true);
      expect(payload.listing_complete).toBe(false);
      expect(payload.message).toContain('INCOMPLETE');
      expect(payload.message).not.toMatch(/Returning all/);
      expect(payload.continuation).not.toContain('Every policy you can access has been returned');
      expect(payload.continuation).toContain('search');
    });

    it('charges the fixed envelope against the token budget, so an assembled result cannot overrun it', async () => {
      const rows = Array.from({ length: 100 }, (_, index) =>
        defendPolicy({
          id: `p-${String(index).padStart(3, '0')}`,
          name: 'n'.repeat(195),
          description: 'd'.repeat(195),
        })
      );

      givenEstate(rows);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      const perRowTokens = estimateResultTokens(payload.policies[0]);
      expect(perRowTokens * rows.length).toBeLessThanOrEqual(RESULT_TOKEN_BUDGET);

      expect(payload.truncated).toBe(true);
      expect(payload.policies.length).toBeLessThan(rows.length);
      expect(estimateResultTokens(payload)).toBeLessThanOrEqual(RESULT_TOKEN_BUDGET);
      expect(payload.result_budget_notice).toBeUndefined();
      expect(mocks.logger.warn).not.toHaveBeenCalled();
    });

    it('still reports a genuinely exhaustive listing as complete', async () => {
      givenEstate([
        defendPolicy({ id: 'p-1', name: 'Prod' }),
        defendPolicy({ id: 'p-2', name: 'Dev' }),
      ]);

      const payload = (await runTool({})).results[0].data as InventoryPayload;

      expect(payload.truncated).toBe(false);
      expect(payload.listing_complete).toBe(true);
      expect(payload.message).toContain('Returning all 2.');
      expect(payload.message).not.toContain('INCOMPLETE');
      expect(payload.continuation).toContain('Every policy you can access has been returned');
    });

    it('keeps an 80k description under the wrapped 20k platform budget without a false empty estate', async () => {
      const oversized = defendPolicy({
        id: 'p-huge',
        name: 'Huge',
        description: 'y'.repeat(80_000),
      });

      givenEstate([oversized]);

      const result = await runTool({});
      const payload = result.results[0].data as InventoryPayload;

      expectWrappedHandlerWithinPlatformBudget(result);
      expect(payload.result_budget_notice).toBeUndefined();
      expect(payload.total).toBe(1);
      expect(payload.policies).toHaveLength(1);
      expect(payload.policies[0].id).toBe('p-huge');
      expect(payload.policies[0].description?.length).toBeLessThan(80_000);
      expect(payload.policies[0].description).toContain('truncated');
      expectConfiguredNotAppliedIsResultScoped(payload);
      expect(mocks.logger.warn).not.toHaveBeenCalled();
    });
  });

  describe('authorization denied', () => {
    const givenCallerHoldingNoPolicyRead = () => {
      mocks.setPrivileges({
        securityPolicyManagementRead: false,
        fleetIntegrationPoliciesRead: false,
      });
    };

    it('returns an error result naming the privileges, without policy metadata', async () => {
      givenCallerHoldingNoPolicyRead();
      givenEstate([defendPolicy()]);

      const result = await runTool({});
      const payload = result.results[0].data as ErrorPayload;

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect(payload.metadata).toMatchObject({ error: 'not_authorized' });
      expect(payload.metadata?.need_any).toEqual([
        'Security > Elastic Defend Policy Management: Read',
        'Fleet > Agent policies: Read and Fleet > Integrations: Read',
      ]);
      expect(Object.keys(payload.metadata ?? {}).sort()).toEqual(['error', 'need_any']);
      expect(JSON.stringify(payload)).not.toMatch(/Defend policy 1|defend-1/);
      expectReadOnlyAndNoForbiddenReads(mocks);
    });

    it('never constructs the security-extension-excluded saved-objects client or reads Fleet', async () => {
      givenCallerHoldingNoPolicyRead();

      await runTool({});

      expect(mocks.savedObjects.getScopedClient).not.toHaveBeenCalled();
      expect(mocks.packagePolicyService.fetchAllItems).not.toHaveBeenCalled();

      mocks.setPrivileges({ securityPolicyManagementRead: true });
      givenEstate([defendPolicy()]);
      await runTool({});

      expect(mocks.savedObjects.getScopedClient).toHaveBeenCalledWith(mocks.request, {
        excludedExtensions: [SECURITY_EXTENSION_ID],
      });
    });
  });

  describe('exception', () => {
    it('reports Fleet being unavailable without throwing', async () => {
      mocks.withoutFleet();

      const result = await runTool({});

      expect(result.results[0].type).toBe(ToolResultType.error);
      expect((result.results[0].data as ErrorPayload).message).toContain('Fleet');
    });
  });

  describe('schema', () => {
    it('bounds the search input and rejects unexpected keys', () => {
      const schema = tool.schema;

      expect(schema.safeParse({ search: 'x'.repeat(257) }).success).toBe(false);
      expect(schema.safeParse({ perPage: 20 }).success).toBe(false);
      expect(schema.safeParse({ cursor: 'abc' }).success).toBe(false);
      expect(schema.safeParse({}).success).toBe(true);
      const whitespace = schema.safeParse({ search: '   ' });
      expect(whitespace.success).toBe(true);
      expect(whitespace.data?.search).toBeUndefined();
    });
  });
});
