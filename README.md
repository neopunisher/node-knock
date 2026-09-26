# knock

> Knock, knock. Who's there?

Subdomain enumeration for Node.js. Pulls candidate names from **Certificate
Transparency logs** (passive, via [crt.sh](https://crt.sh)) and a bundled
**31k-entry wordlist** (active DNS brute force), detects wildcard DNS so you
don't drown in false positives, and verifies everything with real lookups.

Zero runtime dependencies. Great for attack-surface audits, pen-test recon,
or checking what a new client actually has exposed.

[![npm version](https://img.shields.io/npm/v/knock.svg)](https://www.npmjs.com/package/knock)
[![CI](https://github.com/neopunisher/node-knock/actions/workflows/ci.yml/badge.svg)](https://github.com/neopunisher/node-knock/actions/workflows/ci.yml)

## Install

```bash
npm install -g knock   # CLI
npm install knock      # library
```

Requires Node.js >= 22.

## CLI

```bash
knock example.com
```

```
www.example.com  93.184.216.34  [ct+list]
api.example.com  203.0.113.10  [ct]
mail.example.com  198.51.100.7  [list]
# example.com: 3 found from 31307 candidates, 18 ct names (2 unresolved) in 41.3s
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `-p, --passive` | Certificate Transparency only — no brute force |
| `--no-ct` | wordlist brute force only |
| `--no-verify` | report CT names without resolving them |
| `--full-host` | scan the exact host given (skip the registrable-domain reduction) |
| `-l, --list <path\|subs\|org>` | custom wordlist, or a bundled one by name |
| `-c, --concurrency <n>` | parallel DNS queries (default 64) |
| `-s, --server <ip>` | DNS server to query (repeatable) |
| `-6, --ipv6` | also resolve AAAA records |
| `-w, --web` | probe http/https on each found host |
| `-j, --json` | full report as JSON |
| `-q, --quiet` | hostnames only (pipe-friendly) |

Found hosts stream to stdout as they resolve; diagnostics go to stderr, so
`knock -q example.com | sort` does what you'd hope.

## Library

```js
import { knock } from 'knock';

const report = await knock('example.com', { concurrency: 128 });

for (const { name, addresses, sources } of report.results) {
  console.log(name, addresses, sources); // 'www.example.com', ['93.184.216.34'], ['ct', 'wordlist']
}
console.log(report.wildcard); // { detected: false, addresses: [] }
console.log(report.ct);       // { enabled: true, names: 18, unresolved: [...], error: null }
console.log(report.stats);    // { words, candidates, queried, found, errors, durationMs }
```

Stream results as they're discovered, or go passive-only:

```js
await knock('example.com', { onResult: (r) => console.log(r.name) });

// Just the Certificate Transparency names, one HTTPS request, no DNS:
import { certSubdomains } from 'knock';
const names = await certSubdomains('example.com');
```

### Options

| Option | Default | Description |
| --- | --- | --- |
| `words` | — | array of labels to try (`[]` for passive-only) |
| `wordlist` | bundled `subs` | path to a wordlist file |
| `ct` | `true` | pull candidates from Certificate Transparency logs |
| `ctTimeout` | `15000` | crt.sh request timeout (ms) |
| `verify` | `true` | resolve CT names over DNS |
| `concurrency` | `64` | parallel DNS queries |
| `timeout` / `tries` | `5000` / `2` | per-query DNS timeout (ms) and retries |
| `servers` | system | DNS servers to query |
| `family` | `4` | `4`, `6`, or `'any'` for A + AAAA |
| `wildcardTests` | `3` | random probes for wildcard detection (`0` disables) |
| `web` / `webTimeout` | `false` / `5000` | probe http/https on found hosts |
| `baseDomainOnly` | `true` | reduce the target to its registrable domain first |
| `icannOnly` | `false` | ignore the PSL's PRIVATE section (github.io, …) |
| `signal` | — | `AbortSignal` to cancel the run |
| `onResult` | — | callback fired per discovery |
| `resolver` / `fetch` / `psl` | built-in | injectable for testing |

The bundled wordlists are exposed as `wordlists.subs` (~31k labels,
popularity-ordered) and `wordlists.org`, and helpers `loadWordlist(path)` /
`parseWordlist(text)` / `normalizeDomain(input)` are exported too. Full
TypeScript types ship with the package.

## How it works

0. **Public Suffix List** — input like `https://deep.www.example.co.uk/x` is
   first reduced to its registrable domain (`example.co.uk`) using a vendored
   [PSL](https://publicsuffix.org) snapshot (refresh with `npm run
   update-psl`), so private suffixes like `github.io` are handled correctly.
   `--full-host` / `baseDomainOnly: false` scans the host exactly as given,
   and the PSL helpers (`getRegistrableDomain`, `getPublicSuffix`,
   `loadPublicSuffixList`) are exported for standalone use.
1. **Certificate Transparency** — every publicly trusted TLS certificate is
   logged; querying the logs for `%.example.com` reveals names that were ever
   certified, including ones DNS brute forcing would never guess. Names that
   no longer resolve are reported in `ct.unresolved` — often the most
   interesting ones.
2. **Wildcard detection** — a few random labels are resolved first; if the
   zone answers for anything, wordlist hits that merely echo the wildcard
   answer are suppressed (CT-sourced names are kept: the certificate is
   evidence on its own).
3. **Brute force** — wordlist labels are resolved through a bounded worker
   pool using `node:dns` directly against your system resolvers (or servers
   you pick with `-s`).

## Development

TypeScript sources live in `src/` and run directly on Node's native type
stripping — `npm test` executes the `.ts` tests with `node --test`, no build
step needed. `npm run build` compiles `dist/` (what actually ships), and
`npm run knock -- example.com` runs the CLI from source.

## Responsible use

DNS brute forcing generates thousands of queries and CT lookups are logged.
Only scan domains you own or are explicitly authorized to assess.

## Publishing

Releases are published to npm from GitHub Actions via
[trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC) — no
long-lived npm tokens — with provenance attestations generated automatically.

## License

MIT © [Carter Cole](https://github.com/neopunisher)
