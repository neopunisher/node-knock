#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { knock, wordlists } from './index.ts';
import type { KnockOptions, KnockReport, KnockResult, KnockSource } from './index.ts';

const { version } = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { version: string };

const HELP = `knock ${version} — subdomain enumeration

Usage
  knock [options] <domain> [domain ...]

Sources
  Certificate Transparency logs (crt.sh, passive) and a wordlist DNS brute
  force run by default; wildcard DNS answers are detected and filtered.

Options
  -l, --list <path|subs|org>  wordlist file, or a bundled list by name
                              (default: "subs", ~31k entries)
  -p, --passive               skip the wordlist brute force (CT lookup only)
      --no-ct                 skip the Certificate Transparency lookup
      --no-verify             report CT names without resolving them
      --full-host             scan the exact host given, without reducing it
                              to the registrable domain (Public Suffix List)
  -c, --concurrency <n>       parallel DNS queries (default: 64)
  -t, --timeout <ms>          per-query DNS timeout (default: 5000)
  -s, --server <ip>           DNS server to use, repeatable
  -6, --ipv6                  also resolve AAAA records
  -w, --web                   probe http/https on found hosts
  -j, --json                  print the full report as JSON
  -q, --quiet                 hostnames only, no summary
  -h, --help                  show this help
  -V, --version               print the version

Examples
  knock example.com
  knock --passive --json example.com
  knock -l org -s 1.1.1.1 -c 128 example.com

Only scan domains you own or are authorized to assess.`;

function fail(message: string): never {
  process.stderr.write(`knock: ${message}\n`);
  process.exit(1);
}

function parseCliArgs() {
  try {
    return parseArgs({
      allowPositionals: true,
      options: {
        list: { type: 'string', short: 'l' },
        passive: { type: 'boolean', short: 'p', default: false },
        'no-ct': { type: 'boolean', default: false },
        'no-verify': { type: 'boolean', default: false },
        'full-host': { type: 'boolean', default: false },
        concurrency: { type: 'string', short: 'c', default: '64' },
        timeout: { type: 'string', short: 't', default: '5000' },
        server: { type: 'string', short: 's', multiple: true },
        ipv6: { type: 'boolean', short: '6', default: false },
        web: { type: 'boolean', short: 'w', default: false },
        json: { type: 'boolean', short: 'j', default: false },
        quiet: { type: 'boolean', short: 'q', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'V', default: false },
      },
    });
  } catch (error) {
    return fail(error instanceof Error ? error.message : String(error));
  }
}

const { values: flags, positionals: domains } = parseCliArgs();

if (flags.help) {
  console.log(HELP);
  process.exit(0);
}
if (flags.version) {
  console.log(version);
  process.exit(0);
}
if (domains.length === 0) {
  fail('no domain given (try: knock example.com, or --help)');
}

const integer = (name: string, value: string): number => {
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) fail(`--${name} expects a positive integer, got "${value}"`);
  return n;
};

const options: KnockOptions = {
  concurrency: integer('concurrency', flags.concurrency),
  timeout: integer('timeout', flags.timeout),
  servers: flags.server,
  family: flags.ipv6 ? 'any' : 4,
  ct: !flags['no-ct'],
  verify: !flags['no-verify'],
  baseDomainOnly: !flags['full-host'],
  web: flags.web,
};
if (flags.passive) options.words = [];
if (flags.list === 'subs' || flags.list === 'org') options.wordlist = wordlists[flags.list];
else if (flags.list) options.wordlist = flags.list;

if (flags.passive && !options.ct) fail('--passive together with --no-ct leaves nothing to do');

const sourceTag = (sources: KnockSource[]): string =>
  sources.length > 1 ? 'ct+list' : sources[0] === 'ct' ? 'ct' : 'list';

const printResult = (result: KnockResult): void => {
  if (flags.quiet) {
    console.log(result.name);
    return;
  }
  const addresses = result.addresses.length > 0 ? result.addresses.join(' ') : '-';
  const web = result.web
    ? `  https:${result.web.https ?? '-'} http:${result.web.http ?? '-'}`
    : '';
  console.log(`${result.name}  ${addresses}  [${sourceTag(result.sources)}]${web}`);
};

const reports: KnockReport[] = [];
let failed = false;

for (const domain of domains) {
  try {
    const report = await knock(domain, {
      ...options,
      onResult: flags.json ? undefined : printResult,
    });
    reports.push(report);
    if (!flags.json && !flags.quiet) {
      const { stats, wildcard, ct } = report;
      if (wildcard.detected) {
        process.stderr.write(
          `! wildcard DNS on ${report.domain} (${wildcard.addresses.join(', ')}) — matching wordlist hits suppressed\n`,
        );
      }
      if (ct.error) process.stderr.write(`! ct lookup failed: ${ct.error}\n`);
      const ctNote = ct.enabled ? `, ${ct.names} ct names (${ct.unresolved.length} unresolved)` : '';
      process.stderr.write(
        `# ${report.domain}: ${stats.found} found from ${stats.candidates} candidates${ctNote} in ${(stats.durationMs / 1000).toFixed(1)}s\n`,
      );
    }
  } catch (error) {
    failed = true;
    process.stderr.write(`knock: ${domain}: ${error instanceof Error ? error.message : String(error)}\n`);
  }
}

if (flags.json && reports.length > 0) {
  console.log(JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2));
}
process.exitCode = failed ? 1 : 0;
