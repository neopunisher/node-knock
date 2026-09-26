import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  knock,
  certSubdomains,
  normalizeDomain,
  parseWordlist,
  loadWordlist,
  wordlists,
} from '../src/index.ts';
import type { KnockFetch, KnockResolver } from '../src/index.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

const notFound = (name: string) =>
  Object.assign(new Error(`queryA ENOTFOUND ${name}`), { code: 'ENOTFOUND' });

// Resolver test double: names map to address arrays; everything else is ENOTFOUND.
function fakeResolver(
  zone: Record<string, string[]>,
  { wildcard }: { wildcard?: string[] } = {},
): KnockResolver & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async resolve4(name) {
      calls.push(name);
      if (name in zone) return zone[name]!;
      if (wildcard) return wildcard;
      throw notFound(name);
    },
    async resolve6(name) {
      calls.push(name);
      throw notFound(name);
    },
  };
}

const ctResponse = (entries: unknown): KnockFetch =>
  async () => ({
    ok: true,
    status: 200,
    async json() {
      return entries;
    },
  });

test('normalizeDomain reduces input to a bare hostname', () => {
  assert.equal(normalizeDomain('Example.COM'), 'example.com');
  assert.equal(normalizeDomain('https://www.example.com/some/path?q=1'), 'www.example.com');
  assert.equal(normalizeDomain('example.com.'), 'example.com');
  assert.equal(normalizeDomain('example.com:8080'), 'example.com');
  assert.throws(() => normalizeDomain(''), TypeError);
  assert.throws(() => normalizeDomain('not a domain'), TypeError);
  assert.throws(() => normalizeDomain('[::1]'), TypeError);
});

test('parseWordlist trims, lowercases, dedupes and skips comments', () => {
  const words = parseWordlist('www\nWWW\n  mail \t\n\n# comment\nftp\r\nwww');
  assert.deepEqual(words, ['www', 'mail', 'ftp']);
});

test('bundled wordlists load and are non-trivial', async () => {
  const subs = await loadWordlist(wordlists.subs);
  const org = await loadWordlist(wordlists.org);
  assert.ok(subs.length > 30000, `subs list has ${subs.length} entries`);
  assert.ok(org.length > 1000, `org list has ${org.length} entries`);
  assert.ok(subs.includes('www'));
});

test('knock finds wordlist subdomains and reports stats', async () => {
  const resolver = fakeResolver({
    'www.example.com': ['192.0.2.1'],
    'mail.example.com': ['192.0.2.2', '192.0.2.3'],
  });
  const report = await knock('https://EXAMPLE.com/ignored', {
    words: ['www', 'mail', 'nope'],
    resolver,
    ct: false,
    wildcardTests: 0,
  });
  assert.equal(report.domain, 'example.com');
  assert.deepEqual(
    report.results.map((r) => r.name).sort(),
    ['mail.example.com', 'www.example.com'],
  );
  assert.deepEqual(
    report.results.find((r) => r.name === 'mail.example.com')?.addresses,
    ['192.0.2.2', '192.0.2.3'],
  );
  assert.deepEqual(report.results[0]?.sources, ['wordlist']);
  assert.equal(report.stats.words, 3);
  assert.equal(report.stats.queried, 3);
  assert.equal(report.stats.found, 2);
  assert.equal(report.stats.errors, 0);
  assert.equal(report.wildcard.detected, false);
});

test('knock detects wildcard DNS and suppresses echo answers', async () => {
  const resolver = fakeResolver(
    {
      'www.example.com': ['192.0.2.1', '198.51.100.9'],
      'blah.example.com': ['198.51.100.9'],
    },
    { wildcard: ['198.51.100.9'] },
  );
  const report = await knock('example.com', {
    words: ['www', 'blah'],
    resolver,
    ct: false,
    wildcardTests: 2,
  });
  assert.equal(report.wildcard.detected, true);
  assert.deepEqual(report.wildcard.addresses, ['198.51.100.9']);
  // "www" has an address beyond the wildcard answer; "blah" only echoes it.
  assert.deepEqual(report.results.map((r) => r.name), ['www.example.com']);
});

test('knock streams results through onResult', async () => {
  const resolver = fakeResolver({ 'www.example.com': ['192.0.2.1'] });
  const seen: string[] = [];
  await knock('example.com', {
    words: ['www', 'nope'],
    resolver,
    ct: false,
    wildcardTests: 0,
    onResult: (result) => seen.push(result.name),
  });
  assert.deepEqual(seen, ['www.example.com']);
});

test('knock honors an abort signal', async () => {
  const controller = new AbortController();
  const resolver: KnockResolver = {
    async resolve4() {
      controller.abort();
      return ['192.0.2.1'];
    },
    async resolve6() {
      throw notFound('x');
    },
  };
  await assert.rejects(
    knock('example.com', {
      words: ['a', 'b', 'c', 'd'],
      resolver,
      ct: false,
      wildcardTests: 0,
      concurrency: 1,
      signal: controller.signal,
    }),
    { name: 'AbortError' },
  );
});

test('certSubdomains extracts in-scope names from crt.sh entries', async () => {
  const fetch = ctResponse([
    { common_name: 'www.example.com', name_value: 'www.example.com\nexample.com' },
    { common_name: '*.dev.example.com', name_value: '*.dev.example.com\nAPI.Example.com' },
    { common_name: 'evil.example.org', name_value: 'deep.stage.example.com' },
    { common_name: 'bad name.example.com', name_value: '' },
  ]);
  const names = await certSubdomains('example.com', { fetch });
  assert.deepEqual(
    names,
    ['api.example.com', 'dev.example.com', 'www.example.com', 'deep.stage.example.com'].sort(),
  );
});

test('certSubdomains throws on a non-OK response', async () => {
  const fetch: KnockFetch = async () => ({
    ok: false,
    status: 503,
    async json() {
      return [];
    },
  });
  await assert.rejects(certSubdomains('example.com', { fetch }), /HTTP 503/);
});

test('knock merges CT names, verifies them, and tracks unresolved ones', async () => {
  const resolver = fakeResolver({
    'www.example.com': ['192.0.2.1'],
    'api.example.com': ['192.0.2.4'],
  });
  const fetch = ctResponse([
    {
      common_name: 'api.example.com',
      name_value: 'api.example.com\nwww.example.com\ngone.example.com',
    },
  ]);
  const report = await knock('example.com', {
    words: ['www'],
    resolver,
    fetch,
    wildcardTests: 0,
  });
  const byName = new Map(report.results.map((r) => [r.name, r]));
  assert.deepEqual(byName.get('www.example.com')?.sources.sort(), ['ct', 'wordlist']);
  assert.deepEqual(byName.get('api.example.com')?.sources, ['ct']);
  assert.deepEqual(report.ct.unresolved, ['gone.example.com']);
  assert.equal(report.ct.names, 3);
  assert.equal(report.ct.error, null);
  assert.equal(report.stats.candidates, 3);
});

test('CT names survive wildcard suppression; unverified runs skip DNS', async () => {
  const fetch = ctResponse([{ common_name: 'hidden.example.com', name_value: '' }]);
  const wildcarded = await knock('example.com', {
    words: [],
    resolver: fakeResolver({}, { wildcard: ['198.51.100.9'] }),
    fetch,
    wildcardTests: 0,
  });
  assert.deepEqual(wildcarded.results.map((r) => r.name), ['hidden.example.com']);

  const unverified = await knock('example.com', {
    words: [],
    resolver: fakeResolver({}),
    fetch,
    verify: false,
    wildcardTests: 0,
  });
  assert.deepEqual(unverified.results, [
    { name: 'hidden.example.com', addresses: [], sources: ['ct'] },
  ]);
  assert.equal(unverified.stats.queried, 0);
});

test('a failed CT lookup is reported but does not abort the run', async () => {
  const resolver = fakeResolver({ 'www.example.com': ['192.0.2.1'] });
  const fetch: KnockFetch = async () => {
    throw new Error('network down');
  };
  const report = await knock('example.com', {
    words: ['www'],
    resolver,
    fetch,
    wildcardTests: 0,
  });
  assert.equal(report.ct.error, 'network down');
  assert.equal(report.stats.found, 1);
});

test('CLI: --help and --version work', () => {
  const help = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /Usage/);
  assert.match(help.stdout, /--passive/);

  const { version } = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
  ) as { version: string };
  const versionRun = spawnSync(process.execPath, [CLI, '-V'], { encoding: 'utf8' });
  assert.equal(versionRun.status, 0);
  assert.equal(versionRun.stdout.trim(), version);
});

test('CLI: refuses to run with nothing to do', () => {
  const noDomain = spawnSync(process.execPath, [CLI], { encoding: 'utf8' });
  assert.equal(noDomain.status, 1);
  assert.match(noDomain.stderr, /no domain/);

  const contradiction = spawnSync(
    process.execPath,
    [CLI, '--passive', '--no-ct', 'example.com'],
    { encoding: 'utf8' },
  );
  assert.equal(contradiction.status, 1);
  assert.match(contradiction.stderr, /nothing to do/);
});
