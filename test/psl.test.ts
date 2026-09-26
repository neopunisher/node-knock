import test from 'node:test';
import assert from 'node:assert/strict';

import {
  knock,
  parsePublicSuffixList,
  loadPublicSuffixList,
  getPublicSuffix,
  getRegistrableDomain,
} from '../src/index.ts';
import type { KnockResolver } from '../src/index.ts';

const notFound = (name: string) =>
  Object.assign(new Error(`queryA ENOTFOUND ${name}`), { code: 'ENOTFOUND' });

function fakeResolver(zone: Record<string, string[]>): KnockResolver & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async resolve4(name) {
      calls.push(name);
      if (name in zone) return zone[name]!;
      throw notFound(name);
    },
    async resolve6(name) {
      calls.push(name);
      throw notFound(name);
    },
  };
}

// A minimal list exercising every rule kind: normal, multi-label, wildcard,
// exception, and a PRIVATE-section entry.
const FIXTURE = [
  '// ===BEGIN ICANN DOMAINS===',
  'com',
  'co.uk',
  'uk',
  '*.ck',
  '!www.ck',
  '// a comment',
  '// ===END ICANN DOMAINS===',
  '// ===BEGIN PRIVATE DOMAINS===',
  'github.io',
  '// ===END PRIVATE DOMAINS===',
  '',
].join('\n');

test('parsePublicSuffixList records rule kind and section', () => {
  const rules = parsePublicSuffixList(FIXTURE);
  assert.deepEqual(rules.get('com'), { exception: false, icann: true });
  assert.deepEqual(rules.get('*.ck'), { exception: false, icann: true });
  assert.deepEqual(rules.get('www.ck'), { exception: true, icann: true });
  assert.deepEqual(rules.get('github.io'), { exception: false, icann: false });
  // Comment lines are skipped, not stored as rules.
  assert.equal(rules.has('a'), false);
});

test('getPublicSuffix applies the PSL matching algorithm', () => {
  const rules = parsePublicSuffixList(FIXTURE);
  assert.equal(getPublicSuffix('example.com', rules), 'com');
  assert.equal(getPublicSuffix('a.b.example.co.uk', rules), 'co.uk');
  assert.equal(getPublicSuffix('foo.ck', rules), 'foo.ck'); // *.ck matches one label
  assert.equal(getPublicSuffix('www.ck', rules), 'ck'); // !www.ck exception wins
  assert.equal(getPublicSuffix('user.github.io', rules), 'github.io');
  assert.equal(getPublicSuffix('host.unknown-tld', rules), 'unknown-tld'); // default rule "*"
});

test('getRegistrableDomain returns the suffix plus one label', () => {
  const rules = parsePublicSuffixList(FIXTURE);
  assert.equal(getRegistrableDomain('www.example.com', rules), 'example.com');
  assert.equal(getRegistrableDomain('a.b.example.co.uk', rules), 'example.co.uk');
  assert.equal(getRegistrableDomain('www.ck', rules), 'www.ck'); // exception makes it registrable
  assert.equal(getRegistrableDomain('foo.ck', rules), null); // foo.ck is itself a public suffix
  assert.equal(getRegistrableDomain('bar.foo.ck', rules), 'bar.foo.ck');
  assert.equal(getRegistrableDomain('host.unknown-tld', rules), 'host.unknown-tld');
  // A bare public suffix has no registrable domain.
  assert.equal(getRegistrableDomain('com', rules), null);
  assert.equal(getRegistrableDomain('co.uk', rules), null);
});

test('icannOnly ignores the PRIVATE section', () => {
  const rules = parsePublicSuffixList(FIXTURE);
  assert.equal(getRegistrableDomain('user.github.io', rules), 'user.github.io');
  // Without the private github.io rule, .io is unknown here → default "*" → github.io.
  assert.equal(getRegistrableDomain('user.github.io', rules, { icannOnly: true }), 'github.io');
});

test('the bundled Public Suffix List loads and resolves real suffixes', async () => {
  const rules = await loadPublicSuffixList();
  assert.ok(rules.size > 5000, `list has ${rules.size} rules`);
  assert.equal(getRegistrableDomain('www.example.com', rules), 'example.com');
  assert.equal(getRegistrableDomain('a.b.example.co.uk', rules), 'example.co.uk');
  assert.equal(getRegistrableDomain('shop.example.github.io', rules), 'example.github.io');
  // Internationalized suffix (公司.cn), matched in the punycode form hostnames use.
  const cn = new URL('http://公司.cn').hostname;
  assert.equal(getRegistrableDomain(`store.${cn}`, rules), `store.${cn}`);
  assert.equal(getRegistrableDomain(cn, rules), null);
});

test('knock reduces the target to its registrable domain', async () => {
  const resolver = fakeResolver({ 'www.example.co.uk': ['192.0.2.1'] });
  const report = await knock('dev.example.co.uk', {
    words: ['www'],
    resolver,
    ct: false,
    wildcardTests: 0,
  });
  assert.equal(report.domain, 'example.co.uk');
  assert.deepEqual(report.results.map((r) => r.name), ['www.example.co.uk']);
  assert.ok(resolver.calls.includes('www.example.co.uk'));
});

test('knock with baseDomainOnly:false scans the exact host', async () => {
  const resolver = fakeResolver({ 'www.dev.example.co.uk': ['192.0.2.1'] });
  const report = await knock('dev.example.co.uk', {
    words: ['www'],
    resolver,
    ct: false,
    wildcardTests: 0,
    baseDomainOnly: false,
  });
  assert.equal(report.domain, 'dev.example.co.uk');
  assert.deepEqual(report.results.map((r) => r.name), ['www.dev.example.co.uk']);
});

test('knock accepts injected PSL rules and honors icannOnly', async () => {
  const rules = parsePublicSuffixList(FIXTURE);
  const resolver = fakeResolver({ 'www.github.io': ['192.0.2.1'] });
  const report = await knock('user.github.io', {
    words: ['www'],
    resolver,
    ct: false,
    wildcardTests: 0,
    psl: rules,
    icannOnly: true,
  });
  assert.equal(report.domain, 'github.io');
  assert.ok(resolver.calls.includes('www.github.io'));
});

test('knock does not mangle an IPv4 target', async () => {
  const resolver = fakeResolver({ 'www.192.0.2.1': ['192.0.2.9'] });
  const report = await knock('192.0.2.1', {
    words: ['www'],
    resolver,
    ct: false,
    wildcardTests: 0,
  });
  assert.equal(report.domain, '192.0.2.1');
});
