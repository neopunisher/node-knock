# Changelog

## 1.0.0 (2026)

Complete modernization — a rewrite of the 2014-era `0.1.0`.

### Added
- **Certificate Transparency source**: passive subdomain discovery via crt.sh
  (`certSubdomains()`, on by default in `knock()`), with DNS verification and
  an `unresolved` list for stale/internal certificate names.
- Actual enumeration (the old `lib.js` stopped at normalizing the domain):
  wordlist DNS brute force with a bounded concurrency pool, wildcard DNS
  detection/suppression, optional http/https probing, `AbortSignal` support,
  streaming `onResult` callback, per-run stats.
- Real CLI (`knock <domain>`): `--passive`, `--no-ct`, `--no-verify`,
  `--full-host`, `--list`, `--concurrency`, `--server`, `--ipv6`, `--web`,
  `--json`, `--quiet`.
- Public Suffix List support with a vendored snapshot (`npm run update-psl`):
  targets reduce to their registrable domain by default (what `tldtools` did
  in 0.x), with `getRegistrableDomain` / `getPublicSuffix` /
  `loadPublicSuffixList` exported and `baseDomainOnly` / `icannOnly` / `psl`
  options on `knock()`.
- TypeScript type definitions, `node:test` suite, CI (Node 20/22/24), and npm
  trusted publishing (OIDC) with provenance.

### Changed
- **Breaking**: ESM-only, Node >= 22, and a new API —
  `knock(domain, opts)` returns a Promise of a report instead of taking a
  callback.
- Rewritten in TypeScript (`src/`, compiled to `dist/`; tests run the `.ts`
  sources directly via Node's type stripping).
- Zero runtime dependencies: `request`, `optimist`, `step`, `glob`,
  `tldtools` and the undeclared `underscore` are gone, replaced by
  `node:dns/promises`, `fetch`, `util.parseArgs` and async/await.
- The bundled `subs.txt` / `org.txt` wordlists are unchanged and now exposed
  via the `wordlists` export.
