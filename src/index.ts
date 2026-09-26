/**
 * knock — subdomain enumeration via Certificate Transparency logs and
 * wordlist DNS brute forcing, with wildcard DNS detection.
 */
import { Resolver } from 'node:dns/promises';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadPublicSuffixList, getRegistrableDomain } from './psl.ts';
import type { PublicSuffixRules } from './psl.ts';

export type KnockSource = 'wordlist' | 'ct';

export interface KnockWebStatuses {
  https: number | null;
  http: number | null;
}

export interface KnockResult {
  /** Fully qualified hostname, e.g. "www.example.com". */
  name: string;
  /** Addresses the name resolved to (empty for unverified CT names). */
  addresses: string[];
  /** Where the candidate came from. */
  sources: KnockSource[];
  /** HTTP status codes per protocol; only present when `web: true`. */
  web?: KnockWebStatuses;
}

export interface KnockWildcard {
  detected: boolean;
  /** Addresses returned for random non-existent labels. */
  addresses: string[];
}

export interface KnockCtReport {
  enabled: boolean;
  /** Unique in-scope names found in Certificate Transparency logs. */
  names: number;
  /** CT names that no longer resolve (stale or internal-only certificates). */
  unresolved: string[];
  /** Error message when the CT lookup failed; the run continues without it. */
  error: string | null;
}

export interface KnockStats {
  words: number;
  candidates: number;
  queried: number;
  found: number;
  errors: number;
  durationMs: number;
}

export interface KnockReport {
  domain: string;
  wildcard: KnockWildcard;
  ct: KnockCtReport;
  results: KnockResult[];
  stats: KnockStats;
}

/** Minimal resolver surface; satisfied by dns.promises.Resolver or a test double. */
export interface KnockResolver {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
}

/** Minimal fetch surface; satisfied by globalThis.fetch or a test double. */
export type KnockFetch = (
  url: string,
  init: { signal: AbortSignal; headers: Record<string, string> },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface CertSubdomainsOptions {
  /** Request timeout in milliseconds. Default 15000. */
  timeout?: number;
  signal?: AbortSignal;
  /** Injectable fetch implementation, mainly for testing. */
  fetch?: KnockFetch;
}

export interface KnockOptions {
  /** Labels to try. Takes precedence over `wordlist`. Pass [] for passive-only runs. */
  words?: string[];
  /** Path to a wordlist file. Defaults to the bundled `wordlists.subs`. */
  wordlist?: string;
  /** Parallel DNS queries. Default 64. */
  concurrency?: number;
  /** Per-query DNS timeout in milliseconds. Default 5000. */
  timeout?: number;
  /** DNS retry attempts per query. Default 2. */
  tries?: number;
  /** DNS servers to query instead of the system resolvers. */
  servers?: string[];
  /** Address family: 4 (A), 6 (AAAA) or 'any' for both. Default 4. */
  family?: 4 | 6 | 'any';
  /** Random probes used to detect wildcard DNS. 0 disables. Default 3. */
  wildcardTests?: number;
  /** Pull candidates from Certificate Transparency logs. Default true. */
  ct?: boolean;
  /** CT request timeout in milliseconds. Default 15000. */
  ctTimeout?: number;
  /** Resolve CT-discovered names over DNS. Default true. */
  verify?: boolean;
  /** Probe http/https on each found host. Default false. */
  web?: boolean;
  /** Per-request web probe timeout in milliseconds. Default 5000. */
  webTimeout?: number;
  /**
   * Reduce the target to its registrable domain via the Public Suffix List
   * before enumerating (so "dev.example.co.uk" is scanned as "example.co.uk").
   * Default true; set false to enumerate under the exact host given.
   */
  baseDomainOnly?: boolean;
  /**
   * When reducing to the registrable domain, use only the ICANN section of the
   * Public Suffix List, ignoring private suffixes like github.io. Default false.
   */
  icannOnly?: boolean;
  /** Injectable Public Suffix List rules, mainly for testing. */
  psl?: PublicSuffixRules;
  /** Abort the run; knock() rejects with the abort reason. */
  signal?: AbortSignal;
  /** Injectable resolver, mainly for testing. */
  resolver?: KnockResolver;
  /** Injectable fetch implementation used for the CT lookup. */
  fetch?: KnockFetch;
  /** Called with each result as it is discovered. */
  onResult?: (result: KnockResult) => void;
}

/** Absolute paths to the wordlists bundled with the package. */
export const wordlists = {
  subs: fileURLToPath(new URL('../lists/subs.txt', import.meta.url)),
  org: fileURLToPath(new URL('../lists/org.txt', import.meta.url)),
};

// DNS answers that simply mean "nothing there", as opposed to a lookup failure.
const NEGATIVE_CODES = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN']);

const HOSTNAME_PATTERN = /^[a-z0-9_][a-z0-9_.-]*$/;

// Dotted-quad IPv4 literals have no registrable domain; skip PSL reduction.
const IPV4_PATTERN = /^\d{1,3}(?:\.\d{1,3}){3}$/;

type KnockDefaults = Required<
  Pick<
    KnockOptions,
    | 'wordlist'
    | 'concurrency'
    | 'timeout'
    | 'tries'
    | 'family'
    | 'wildcardTests'
    | 'ct'
    | 'ctTimeout'
    | 'verify'
    | 'web'
    | 'webTimeout'
    | 'baseDomainOnly'
    | 'icannOnly'
  >
>;

const defaults: KnockDefaults = {
  wordlist: wordlists.subs,
  concurrency: 64,
  timeout: 5000,
  tries: 2,
  family: 4,
  wildcardTests: 3,
  ct: true,
  ctTimeout: 15000,
  verify: true,
  web: false,
  webTimeout: 5000,
  baseDomainOnly: true,
  icannOnly: false,
};

/**
 * Reduce user input like "HTTPS://www.Example.com/path" to a bare hostname.
 * Throws TypeError when no usable hostname can be extracted.
 */
export function normalizeDomain(input: string): string {
  const raw = String(input ?? '').trim();
  if (raw === '') throw new TypeError('domain is required');
  const url = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    throw new TypeError(`invalid domain: ${raw}`);
  }
  hostname = hostname.toLowerCase().replace(/\.+$/, '');
  if (hostname === '' || hostname.startsWith('[')) {
    throw new TypeError(`invalid domain: ${raw}`);
  }
  return hostname;
}

/** Parse wordlist text into unique, lowercased labels. Blank lines and #comments are skipped. */
export function parseWordlist(text: string): string[] {
  const words = new Set<string>();
  for (const line of String(text).split(/\r?\n/)) {
    const word = line.trim().toLowerCase();
    if (word === '' || word.startsWith('#')) continue;
    words.add(word);
  }
  return [...words];
}

/** Read and parse a wordlist file. */
export async function loadWordlist(path: string): Promise<string[]> {
  return parseWordlist(await readFile(path, 'utf8'));
}

/**
 * Query Certificate Transparency logs (via crt.sh) for names certified under
 * `domain`. Purely passive: one HTTPS request, no DNS traffic to the target.
 * Wildcard entries like "*.dev.example.com" are reported as "dev.example.com".
 * Resolves to a sorted array of hostnames, the apex excluded.
 */
export async function certSubdomains(
  domain: string,
  options: CertSubdomainsOptions = {},
): Promise<string[]> {
  const target = normalizeDomain(domain);
  const { timeout = defaults.ctTimeout, signal, fetch: fetchImpl = globalThis.fetch } = options;
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${target}`)}&output=json`;
  const signals = [AbortSignal.timeout(timeout)];
  if (signal) signals.push(signal);
  const response = await fetchImpl(url, {
    signal: AbortSignal.any(signals),
    headers: { accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`crt.sh responded with HTTP ${response.status}`);
  const entries = await response.json();
  const names = new Set<string>();
  for (const entry of Array.isArray(entries) ? entries : []) {
    const record = entry as { common_name?: unknown; name_value?: unknown };
    const candidates = [record?.common_name, ...String(record?.name_value ?? '').split('\n')];
    for (const candidate of candidates) {
      if (!candidate) continue;
      let name = String(candidate).trim().toLowerCase().replace(/\.+$/, '');
      if (name.startsWith('*.')) name = name.slice(2);
      if (name === target || !name.endsWith(`.${target}`)) continue;
      if (!HOSTNAME_PATTERN.test(name)) continue;
      names.add(name);
    }
  }
  return [...names].sort();
}

function makeResolver({
  timeout,
  tries,
  servers,
}: {
  timeout: number;
  tries: number;
  servers?: string[];
}): KnockResolver {
  const resolver = new Resolver({ timeout, tries });
  if (servers && servers.length > 0) resolver.setServers(servers);
  return resolver;
}

async function lookupName(
  resolver: KnockResolver,
  name: string,
  family: 4 | 6 | 'any',
): Promise<{ addresses: string[]; error: unknown }> {
  const addresses: string[] = [];
  let error: unknown;
  const families: Array<4 | 6> = family === 'any' ? [4, 6] : [family];
  for (const fam of families) {
    try {
      const found = fam === 6 ? await resolver.resolve6(name) : await resolver.resolve4(name);
      addresses.push(...found);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | null)?.code;
      if (!NEGATIVE_CODES.has(code ?? '')) error = err;
    }
  }
  return { addresses, error };
}

// Resolve a few random labels that cannot exist; any answers reveal a wildcard record.
async function detectWildcard(
  resolver: KnockResolver,
  domain: string,
  { tests, family }: { tests: number; family: 4 | 6 | 'any' },
): Promise<Set<string>> {
  const addresses = new Set<string>();
  for (let i = 0; i < tests; i += 1) {
    const name = `knock-${randomBytes(8).toString('hex')}.${domain}`;
    const { addresses: found } = await lookupName(resolver, name, family);
    for (const address of found) addresses.add(address);
  }
  return addresses;
}

async function probeWeb(name: string, timeout: number): Promise<KnockWebStatuses> {
  const statuses: KnockWebStatuses = { https: null, http: null };
  await Promise.all(
    (['https', 'http'] as const).map(async (protocol) => {
      try {
        const response = await fetch(`${protocol}://${name}/`, {
          method: 'HEAD',
          redirect: 'manual',
          signal: AbortSignal.timeout(timeout),
        });
        statuses[protocol] = response.status;
      } catch {
        statuses[protocol] = null;
      }
    }),
  );
  return statuses;
}

async function pool<T>(
  items: T[],
  worker: (item: T) => Promise<void>,
  concurrency: number,
  signal?: AbortSignal,
): Promise<void> {
  let index = 0;
  const size = Math.max(1, Math.min(concurrency, items.length));
  const runners = Array.from({ length: size }, async () => {
    while (index < items.length && !signal?.aborted) {
      const item = items[index]!;
      index += 1;
      await worker(item);
    }
  });
  await Promise.all(runners);
}

/**
 * Enumerate subdomains of `domain`.
 *
 * Two sources feed the candidate set: Certificate Transparency logs
 * (passive, `ct` option) and a wordlist brute force over DNS. Candidates
 * are resolved concurrently; hosts that only echo a wildcard DNS answer are
 * suppressed unless Certificate Transparency vouches for them.
 */
export async function knock(domain: string, options: KnockOptions = {}): Promise<KnockReport> {
  const opts = { ...defaults, ...options };
  let target = normalizeDomain(domain);
  if (opts.baseDomainOnly && !IPV4_PATTERN.test(target)) {
    const rules = opts.psl ?? (await loadPublicSuffixList());
    const base = getRegistrableDomain(target, rules, { icannOnly: opts.icannOnly });
    if (base) target = base;
  }
  const words = opts.words ?? (await loadWordlist(opts.wordlist));
  const resolver = opts.resolver ?? makeResolver(opts);
  const { signal } = opts;
  signal?.throwIfAborted();
  const started = Date.now();

  const ct: KnockCtReport = { enabled: Boolean(opts.ct), names: 0, unresolved: [], error: null };
  const candidates = new Map<string, Set<KnockSource>>();
  for (const word of words) {
    candidates.set(`${word}.${target}`, new Set(['wordlist']));
  }
  if (opts.ct) {
    try {
      const names = await certSubdomains(target, {
        timeout: opts.ctTimeout,
        signal,
        fetch: opts.fetch,
      });
      ct.names = names.length;
      for (const name of names) {
        const sources = candidates.get(name);
        if (sources) sources.add('ct');
        else candidates.set(name, new Set(['ct']));
      }
    } catch (err) {
      if (signal?.aborted) throw err;
      ct.error = err instanceof Error ? err.message : String(err);
    }
  }

  const wildcardAddresses =
    words.length > 0 && opts.wildcardTests > 0
      ? await detectWildcard(resolver, target, { tests: opts.wildcardTests, family: opts.family })
      : new Set<string>();

  const results: KnockResult[] = [];
  let queried = 0;
  let errors = 0;

  await pool(
    [...candidates.entries()],
    async ([name, sources]) => {
      const fromCt = sources.has('ct');
      const emit = async (addresses: string[]) => {
        const result: KnockResult = { name, addresses, sources: [...sources] };
        if (opts.web) result.web = await probeWeb(name, opts.webTimeout);
        results.push(result);
        opts.onResult?.(result);
      };

      if (fromCt && !sources.has('wordlist') && !opts.verify) {
        await emit([]);
        return;
      }

      const { addresses, error } = await lookupName(resolver, name, opts.family);
      queried += 1;
      if (addresses.length === 0) {
        if (error) errors += 1;
        if (fromCt) ct.unresolved.push(name);
        return;
      }
      // A wordlist hit that only mirrors the wildcard answer is not a real
      // discovery; a certificate in the CT logs is evidence on its own.
      if (
        !fromCt &&
        wildcardAddresses.size > 0 &&
        addresses.every((address) => wildcardAddresses.has(address))
      ) {
        return;
      }
      await emit(addresses);
    },
    opts.concurrency,
    signal,
  );

  signal?.throwIfAborted();
  ct.unresolved.sort();

  return {
    domain: target,
    wildcard: { detected: wildcardAddresses.size > 0, addresses: [...wildcardAddresses] },
    ct,
    results,
    stats: {
      words: words.length,
      candidates: candidates.size,
      queried,
      found: results.length,
      errors,
      durationMs: Date.now() - started,
    },
  };
}

export {
  publicSuffixListPath,
  parsePublicSuffixList,
  loadPublicSuffixList,
  getPublicSuffix,
  getRegistrableDomain,
} from './psl.ts';
export type { PublicSuffixRule, PublicSuffixRules, PublicSuffixOptions } from './psl.ts';

export default knock;
