/**
 * Public Suffix List support — reduce a hostname to its registrable domain.
 *
 * Where a name may be registered (`co.uk`, `github.io`, `s3.amazonaws.com`)
 * cannot be inferred from string rules alone, so knock uses the Public Suffix
 * List. The data is vendored in `lists/public_suffix_list.dat`; refresh it with
 * `npm run update-psl`.
 *
 * @see https://github.com/publicsuffix/list/wiki/Format for the rule format and
 *   the matching algorithm implemented in {@link publicSuffixLength}.
 */
import { readFile } from 'node:fs/promises';
import { domainToASCII, fileURLToPath } from 'node:url';

/** Absolute path to the vendored Public Suffix List. */
export const publicSuffixListPath = fileURLToPath(
  new URL('../lists/public_suffix_list.dat', import.meta.url),
);

/** A single Public Suffix List rule. */
export interface PublicSuffixRule {
  /** The rule began with `!`, marking an exception to a wildcard rule. */
  exception: boolean;
  /** From the ICANN section rather than the PRIVATE section of the list. */
  icann: boolean;
}

/** Parsed rule set: punycode rule string (without any leading `!`) → rule. */
export type PublicSuffixRules = Map<string, PublicSuffixRule>;

/** Options shared by the Public Suffix List lookups. */
export interface PublicSuffixOptions {
  /** Ignore the PRIVATE section (github.io, herokuapp.com, …). Default false. */
  icannOnly?: boolean;
}

// Punycode a rule so it matches the ASCII hostnames the WHATWG URL parser
// produces (the list is UTF-8; hostnames come through as xn--…). A leftmost
// `*` wildcard is preserved.
function toAscii(name: string): string {
  if (name === '*') return '*';
  if (name.startsWith('*.')) {
    const rest = domainToASCII(name.slice(2));
    return rest ? `*.${rest}` : name.toLowerCase();
  }
  return domainToASCII(name) || name.toLowerCase();
}

/**
 * Parse Public Suffix List text into a rule map. Each line is read only up to
 * the first whitespace; `//` lines and blanks are skipped. The ICANN/PRIVATE
 * section is tracked from the `===BEGIN …===` markers.
 */
export function parsePublicSuffixList(text: string): PublicSuffixRules {
  const rules: PublicSuffixRules = new Map();
  let icann = true;
  for (const rawLine of String(text).split(/\r?\n/)) {
    if (rawLine.includes('===BEGIN ICANN DOMAINS===')) {
      icann = true;
      continue;
    }
    if (rawLine.includes('===BEGIN PRIVATE DOMAINS===')) {
      icann = false;
      continue;
    }
    const token = rawLine.trim().split(/\s+/)[0] ?? '';
    if (token === '' || token.startsWith('//')) continue;
    const exception = token.startsWith('!');
    rules.set(toAscii(exception ? token.slice(1) : token), { exception, icann });
  }
  return rules;
}

const cache = new Map<string, Promise<PublicSuffixRules>>();

/** Read and parse a Public Suffix List file, memoized per path. */
export function loadPublicSuffixList(
  path: string = publicSuffixListPath,
): Promise<PublicSuffixRules> {
  let pending = cache.get(path);
  if (!pending) {
    pending = readFile(path, 'utf8')
      .then(parsePublicSuffixList)
      .catch((error: unknown) => {
        cache.delete(path);
        throw error;
      });
    cache.set(path, pending);
  }
  return pending;
}

// Number of labels in the public suffix of `labels`, per the PSL algorithm:
// an exception rule prevails over any wildcard/normal rule; otherwise the rule
// with the most labels prevails; with no match the default rule is `*` (one
// label). An exception rule's suffix is one label shorter than the rule.
function publicSuffixLength(
  labels: string[],
  rules: PublicSuffixRules,
  icannOnly: boolean,
): number {
  let best: { exception: boolean; length: number } | null = null;
  for (let i = 0; i < labels.length; i += 1) {
    const length = labels.length - i;
    const exact = labels.slice(i).join('.');
    const wildcard = ['*', ...labels.slice(i + 1)].join('.');
    for (const key of exact === wildcard ? [exact] : [exact, wildcard]) {
      const rule = rules.get(key);
      if (!rule || (icannOnly && !rule.icann)) continue;
      if (
        !best ||
        (rule.exception && !best.exception) ||
        (rule.exception === best.exception && length > best.length)
      ) {
        best = { exception: rule.exception, length };
      }
    }
  }
  if (!best) return 1;
  return best.exception ? best.length - 1 : best.length;
}

function cleanHost(hostname: string): string {
  return String(hostname).toLowerCase().replace(/\.+$/, '');
}

/**
 * The public suffix of `hostname` (e.g. "co.uk", "github.io"), or null when the
 * hostname has fewer labels than the matching rule. `hostname` should already
 * be a bare, lowercased, punycode host as produced by `normalizeDomain`.
 */
export function getPublicSuffix(
  hostname: string,
  rules: PublicSuffixRules,
  options: PublicSuffixOptions = {},
): string | null {
  const host = cleanHost(hostname);
  if (host === '') return null;
  const labels = host.split('.');
  const length = publicSuffixLength(labels, rules, options.icannOnly ?? false);
  if (length > labels.length) return null;
  return labels.slice(labels.length - length).join('.');
}

/**
 * The registrable domain of `hostname` — its public suffix plus one label
 * (e.g. "www.example.co.uk" → "example.co.uk"). Returns null when `hostname` is
 * itself a public suffix (or shorter), i.e. has no registrable domain.
 */
export function getRegistrableDomain(
  hostname: string,
  rules: PublicSuffixRules,
  options: PublicSuffixOptions = {},
): string | null {
  const host = cleanHost(hostname);
  if (host === '') return null;
  const labels = host.split('.');
  const length = publicSuffixLength(labels, rules, options.icannOnly ?? false);
  if (labels.length <= length) return null;
  return labels.slice(labels.length - length - 1).join('.');
}
