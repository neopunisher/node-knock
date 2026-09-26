import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  certSubdomains,
  knock,
  normalizeDomain,
  parseWordlist,
  type KnockResolver,
} from '../src/index.ts';

function nxdomain(): Error {
  return Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
}

/** Resolver double backed by a name -> addresses map; `*` answers everything else. */
function fakeResolver(zone: Record<string, string[]>): KnockResolver & { queries: string[] } {
  const queries: string[] = [];
  const lookup = async (name: string) => {
    queries.push(name);
    const hit = zone[name] ?? zone['*'];
    if (!hit) throw nxdomain();
    return hit;
  };
  return { queries, resolve4: lookup, resolve6: lookup };
}

function fakeFetch(body: unknown, status = 200): typeof fetch {
  return async () => new Response(JSON.stringify(body), { status });
}

test('normalizeDomain strips scheme, path, case and trailing dot', () => {
  assert.equal(normalizeDomain('HTTPS://www.Example.com/path?q=1'), 'www.example.com');
  assert.equal(normalizeDomain('example.com.'), 'example.com');
  assert.equal(normalizeDomain('  example.com:8080 '), 'example.com');
  assert.throws(() => normalizeDomain(''), TypeError);
  assert.throws(() => normalizeDomain('http://[::1]/'), TypeError);
});

test('parseWordlist dedupes, lowercases and skips comments', () => {
  assert.deepEqual(parseWordlist('www\r\nWWW\n\n# comment\n mail \n'), ['www', 'mail']);
});

test('certSubdomains extracts in-scope names from crt.sh output', async () => {
  const names = await certSubdomains('example.com', {
    fetch: fakeFetch([
      { common_name: 'example.com', name_value: 'example.com\nwww.example.com' },
      { common_name: '*.dev.example.com', name_value: '*.dev.example.com\nAPI.example.com.' },
      { common_name: 'evil-example.com', name_value: 'other.org\nbad name.example.com' },
    ]),
  });
  assert.deepEqual(names, ['api.example.com', 'dev.example.com', 'www.example.com']);
});

test('certSubdomains rejects on HTTP errors', async () => {
  await assert.rejects(certSubdomains('example.com', { fetch: fakeFetch([], 503) }), /HTTP 503/);
});

test('knock finds wordlist hits and merges CT sources', async () => {
  const resolver = fakeResolver({
    'www.example.com': ['192.0.2.1'],
    'api.example.com': ['192.0.2.2'],
  });
  const seen: string[] = [];
  const report = await knock('example.com', {
    words: ['www', 'mail'],
    resolver,
    fetch: fakeFetch([{ name_value: 'www.example.com\napi.example.com\nold.example.com' }]),
    onResult: (r) => seen.push(r.name),
  });

  const byName = Object.fromEntries(report.results.map((r) => [r.name, r]));
  assert.deepEqual(Object.keys(byName).sort(), ['api.example.com', 'www.example.com']);
  assert.deepEqual(byName['www.example.com']?.sources, ['wordlist', 'ct']);
  assert.deepEqual(byName['api.example.com']?.sources, ['ct']);
  assert.deepEqual(report.ct.unresolved, ['old.example.com']);
  assert.equal(report.wildcard.detected, false);
  assert.equal(report.stats.found, 2);
  assert.deepEqual(seen.sort(), ['api.example.com', 'www.example.com']);
});

test('knock suppresses wildcard echoes but keeps CT-backed names', async () => {
  const resolver = fakeResolver({ '*': ['198.51.100.9'], 'www.example.com': ['192.0.2.1'] });
  const report = await knock('example.com', {
    words: ['www', 'nope', 'shop'],
    resolver,
    fetch: fakeFetch([{ name_value: 'shop.example.com' }]),
  });
  assert.equal(report.wildcard.detected, true);
  assert.deepEqual(report.wildcard.addresses, ['198.51.100.9']);
  assert.deepEqual(report.results.map((r) => r.name).sort(), ['shop.example.com', 'www.example.com']);
});

test('knock with verify: false reports CT names without DNS', async () => {
  const resolver = fakeResolver({});
  const report = await knock('example.com', {
    words: [],
    verify: false,
    resolver,
    fetch: fakeFetch([{ name_value: 'a.example.com' }]),
  });
  assert.deepEqual(report.results, [{ name: 'a.example.com', addresses: [], sources: ['ct'] }]);
  assert.equal(resolver.queries.length, 0);
});

test('knock records CT failures without aborting the run', async () => {
  const report = await knock('example.com', {
    words: ['www'],
    resolver: fakeResolver({ 'www.example.com': ['192.0.2.1'] }),
    fetch: fakeFetch([], 502),
  });
  assert.match(report.ct.error ?? '', /HTTP 502/);
  assert.equal(report.stats.found, 1);
});

test('knock counts real DNS failures as errors', async () => {
  const resolver: KnockResolver = {
    resolve4: async () => {
      throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
    },
    resolve6: async () => [],
  };
  const report = await knock('example.com', { words: ['www'], ct: false, wildcardTests: 0, resolver });
  assert.equal(report.stats.errors, 1);
  assert.equal(report.stats.found, 0);
});

test('knock rejects when aborted', async () => {
  const controller = new AbortController();
  controller.abort(new Error('stop'));
  await assert.rejects(
    knock('example.com', { words: ['www'], resolver: fakeResolver({}), signal: controller.signal }),
    /stop/,
  );
});

test('knock loads the bundled wordlist by default', async () => {
  const report = await knock('example.com', {
    ct: false,
    wildcardTests: 0,
    resolver: fakeResolver({}),
  });
  assert.ok(report.stats.words > 30000);
});
