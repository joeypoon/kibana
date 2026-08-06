/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';

import { AdvancedPolicySchema } from '../../../../../../common/endpoint/service/policy/field_registry/advanced_policy_schema';
import { parseDocumentedDefault } from './parse_documented_default';

const parse = (documentation: string) => parseDocumentedDefault({ documentation });

describe('parseDocumentedDefault', () => {
  describe('unconditional scalar defaults', () => {
    it('parses a boolean default', () => {
      expect(
        parse('Enable Windows Redirection Guard on Win10/Win11 21H2 and later. Default: true.')
      ).toEqual({ status: 'parsed', value: true, type: 'boolean' });
    });

    it('parses a false boolean default', () => {
      expect(parse('Exclude local network events. Default: false.')).toEqual({
        status: 'parsed',
        value: false,
        type: 'boolean',
      });
    });

    it('parses an integer default', () => {
      expect(
        parse(
          'How long to wait for agent connectivity before sending first policy reply, in seconds. Default: 60.'
        )
      ).toEqual({ status: 'parsed', value: 60, type: 'number' });
    });

    it('parses a URL default without truncating it at its dots', () => {
      expect(
        parse(
          'Modify the base URL from which to download protection artifact updates. Default: https://artifacts.security.elastic.co.'
        )
      ).toEqual({
        status: 'parsed',
        value: 'https://artifacts.security.elastic.co',
        type: 'string',
      });
    });

    it('parses a path default containing a placeholder', () => {
      expect(
        parse(
          'Modify the relative URL from which to download protection artifact manifests. Default: /downloads/endpoint/manifest/artifacts-<version>.zip.'
        )
      ).toEqual({
        status: 'parsed',
        value: '/downloads/endpoint/manifest/artifacts-<version>.zip',
        type: 'string',
      });
    });

    it('parses a numeric default carrying a parenthetical gloss', () => {
      expect(
        parse(
          'Specify a network event deduplication transfer threshold, in bytes. Events for connections exceeding the threshold will always be emitted. A value 0 disables this feature. Default: 1048576 (1MB).'
        )
      ).toEqual({ status: 'parsed', value: 1048576, type: 'number' });
    });

    it('parses a default stated without a colon', () => {
      expect(
        parse(
          'Maximum size of scripts captured by mac.advanced.events.script_capturein bytes. Default 1024.'
        )
      ).toEqual({ status: 'parsed', value: 1024, type: 'number' });
    });

    it('normalises a quoted enum default to the same value as an unquoted one', () => {
      const quoted = parse(
        "Control the threshold that should be used for evaluating malware. Allowed values are 'normal', 'conservative', and 'aggressive'. Default: 'normal'."
      );
      const unquoted = parse(
        "Control the threshold that should be used for evaluating malware. Allowed values are 'normal', 'conservative', and 'aggressive'. Default: normal."
      );

      expect(quoted).toEqual({ status: 'parsed', value: 'normal', type: 'string' });
      expect(quoted).toEqual(unquoted);
    });

    it('tolerates the stray trailing backtick in the shipped firewall_anti_tamper copy', () => {
      expect(
        parse(
          "Enable firewall anti tamper prevention or detection. Tamper protetion must also be enabled. Allowed values are 'prevent', 'detect', and 'off'. Default: prevent`."
        )
      ).toEqual({ status: 'parsed', value: 'prevent', type: 'string' });
    });

    it("parses the literal string value 'default' rather than treating the word as a marker", () => {
      expect(
        parse(
          "Modify the release channel for protection artifact updates. The 'default' is staged rollout, 'rapid' receives candidate artifacts as soon as available, and 'stable' only receives artifact updates after staged rollout has finished. Default: default."
        )
      ).toEqual({ status: 'parsed', value: 'default', type: 'string' });
    });
  });

  describe('mixed behavioural prose', () => {
    it('prefers a trailing explicit statement over a leading "by default" clause', () => {
      expect(
        parse(
          'Control if the fanotify subsystem should ignore unknown filesystems. By default only Elastic-tested filesystems are monitored. If set to false, all filesystems, excluding certain known-benign filesystems, will be monitored. Default: true.'
        )
      ).toEqual({ status: 'parsed', value: true, type: 'boolean' });
    });

    it('does not let a mid-sentence "by default" clause invert the declared value', () => {
      expect(
        parse(
          'Include ancestor process entity IDs in all event types; by default they are only included in alerts and process events. Default: false.'
        )
      ).toEqual({ status: 'parsed', value: false, type: 'boolean' });
    });

    it('does not mistake a narrative use of the lowercase word for a declaration', () => {
      expect(
        parse('Download and use default event filter rules from Elastic. Default: true.')
      ).toEqual({ status: 'parsed', value: true, type: 'boolean' });
    });
  });

  describe('version-conditional prose', () => {
    it('never collapses two version branches into a single scalar', () => {
      const result = parse(
        'Enter the mount namespace of processes when they generate fanotify events. For 9.2 and earlier, default: false. For 9.3 and later, default: true.'
      );

      expect(result).toEqual({
        status: 'version_conditional',
        branches: [
          { boundary: '9.2', direction: 'earlier', value: false, type: 'boolean' },
          { boundary: '9.3', direction: 'later', value: true, type: 'boolean' },
        ],
      });
      expect(result).not.toHaveProperty('value');
    });

    it('models a numeric version-conditional default in both directions', () => {
      expect(
        parse(
          'Maximum number of process ancestry entries to include in process events. For 8.14 and earlier, default: 20. For 8.15 and later, default: 5.'
        )
      ).toEqual({
        status: 'version_conditional',
        branches: [
          { boundary: '8.14', direction: 'earlier', value: 20, type: 'number' },
          { boundary: '8.15', direction: 'later', value: 5, type: 'number' },
        ],
      });
    });

    it('treats a conditional whose branches are not an earlier/later pair as unresolved', () => {
      expect(
        parse('Some field. For 8.14 and later, default: 20. For 8.15 and later, default: 5.')
      ).toEqual({ status: 'unparseable', reason: 'version_conditional_unresolved' });
    });

    it('treats a lone conditional branch as unresolved rather than as the default', () => {
      expect(parse('Some field. For 8.14 and earlier, default: 20.')).toEqual({
        status: 'unparseable',
        reason: 'version_conditional_unresolved',
      });
    });

    it('does not misread "and later" in ordinary prose as a version conditional', () => {
      expect(
        parse('Enable Windows Redirection Guard on Win10/Win11 21H2 and later. Default: true.')
      ).toEqual({ status: 'parsed', value: true, type: 'boolean' });
    });
  });

  describe('refusals', () => {
    it('reports an absent value for "Default: none."', () => {
      expect(
        parse(
          'Override the PEM-encoded public key used to verify the protection artifact manifest signature. Default: none.'
        )
      ).toEqual({ status: 'unparseable', reason: 'value_absent' });
    });

    it('reports a non-scalar value for behavioural default prose', () => {
      expect(
        parse(
          'Keep at least the specified number of gigabytes of free space on the volume where Endpoint is installed. If free space falls below this threshold, certain features, such as response actions that require additional storage space, will no longer function. Default: no limit.'
        )
      ).toEqual({ status: 'unparseable', reason: 'value_not_scalar' });
    });

    it('reports a non-scalar value when the default names a configuration source', () => {
      expect(
        parse(
          "Override the log level configured for logs that are saved to disk and streamed to Elasticsearch. Elastic recommends using Fleet to change this logging setting in most circumstances. Allowed values are 'error', 'warning', 'info', 'debug', and 'trace'. Default: Fleet configuration is used."
        )
      ).toEqual({ status: 'unparseable', reason: 'value_not_scalar' });
    });

    it('reports no default statement when the prose states none', () => {
      expect(parse('Deprecated, do not use.')).toEqual({
        status: 'unparseable',
        reason: 'no_default_statement',
      });
    });

    it('refuses to guess from "by default" prose with no explicit statement', () => {
      expect(
        parse('Monitors filesystems. By default only Elastic-tested ones are monitored.')
      ).toEqual({ status: 'unparseable', reason: 'prose_default_only' });
    });
  });

  describe('non-English locales', () => {
    afterEach(() => {
      i18n.init({ locale: 'en', messages: {} });
    });

    it('names the locale as the cause instead of claiming the schema documents no default', () => {
      const translated =
        '最初のポリシー応答を送信する前にエージェント接続を待機する時間（秒）。デフォルト：60.';

      expect(parse(translated)).toEqual({
        status: 'unparseable',
        reason: 'no_default_statement',
      });

      i18n.init({ locale: 'ja-JP', messages: {} });

      expect(parse(translated)).toEqual({
        status: 'unparseable',
        reason: 'documentation_not_english_source',
      });
    });

    it('never reports no_default_statement or prose_default_only under a translated locale', () => {
      i18n.init({ locale: 'ja-JP', messages: {} });

      for (const { documentation } of AdvancedPolicySchema) {
        const result = parseDocumentedDefault({ documentation });

        if (result.status === 'unparseable') {
          expect(result.reason).not.toBe('no_default_statement');
          expect(result.reason).not.toBe('prose_default_only');
        }
      }
    });

    it('still parses an English-source default that no catalog translated', () => {
      i18n.init({ locale: 'ja-JP', messages: {} });

      expect(parse('Exclude local network events. Default: false.')).toEqual({
        status: 'parsed',
        value: false,
        type: 'boolean',
      });
    });

    it('does not report a regional English variant as a translated locale', () => {
      i18n.init({ locale: 'en-US', messages: {} });

      expect(parse('Deprecated, do not use.')).toEqual({
        status: 'unparseable',
        reason: 'no_default_statement',
      });
    });

    it('reads the locale per call so an init after import is still observed', () => {
      expect(parse('Deprecated, do not use.')).toEqual({
        status: 'unparseable',
        reason: 'no_default_statement',
      });

      i18n.init({ locale: 'de-DE', messages: {} });

      expect(parse('Deprecated, do not use.')).toEqual({
        status: 'unparseable',
        reason: 'documentation_not_english_source',
      });

      i18n.init({ locale: 'en', messages: {} });

      expect(parse('Deprecated, do not use.')).toEqual({
        status: 'unparseable',
        reason: 'no_default_statement',
      });
    });
  });

  describe('over the whole shipped schema', () => {
    it('is deterministic across repeated calls despite the module-level regex state', () => {
      const first = AdvancedPolicySchema.map(({ documentation }) =>
        parseDocumentedDefault({ documentation })
      );
      const second = AdvancedPolicySchema.map(({ documentation }) =>
        parseDocumentedDefault({ documentation })
      );

      expect(second).toEqual(first);
    });

    it('resolves a default or an explicit refusal for every entry, with no silent gaps', () => {
      const byStatus = { parsed: 0, version_conditional: 0, unparseable: 0 };

      for (const { documentation } of AdvancedPolicySchema) {
        byStatus[parseDocumentedDefault({ documentation }).status] += 1;
      }

      expect(byStatus.parsed + byStatus.version_conditional + byStatus.unparseable).toBe(
        AdvancedPolicySchema.length
      );
      expect(byStatus.parsed).toBeGreaterThan(AdvancedPolicySchema.length / 2);
      expect(byStatus.version_conditional).toBeGreaterThan(0);
    });
  });
});
