# AGENTS.md

Guidance for AI coding agents working in this repository. User-facing API
docs for agents live in `llms.txt` (shipped in the npm package); keep it in
sync when the public API, CLI flags or MCP tools change.

## Layout

- `src/index.ts` — library: `knock()`, `certSubdomains()`, wordlist helpers, types.
- `src/psl.ts` — Public Suffix List parsing and lookups (re-exported from index).
- `src/cli.ts` — the `knock` bin. `--mcp` hands off to `src/mcp.ts`.
- `src/mcp.ts` — MCP server over stdio, hand-rolled newline-delimited JSON-RPC.
- `lists/` — bundled wordlists (`subs.txt`, `org.txt`) and the vendored
  `public_suffix_list.dat` (refresh with `npm run update-psl`).
- `test/*.test.ts` — `node:test` suites, run directly from TypeScript.
- `dist/` — build output; gitignored, but it is what ships.

## Commands

```bash
npm test                  # node --test on the .ts sources, no build needed
npm run typecheck         # tsc, no emit
npm run build             # compile src/ -> dist/
npm run knock -- example.com   # run the CLI from source
```

Run `npm run typecheck && npm test` before calling a change done; CI runs
both plus the build on Node 22 and 24.

## Rules

- **Zero runtime dependencies.** Don't add any — that includes the MCP SDK;
  `src/mcp.ts` implements the protocol directly. Dev dependencies are fine.
- Node >= 22, ESM only. Sources use Node's native type stripping, so only
  erasable TypeScript syntax (`erasableSyntaxOnly`): no enums, namespaces or
  parameter properties. Import siblings with the `.ts` extension; the build
  rewrites them to `.js`.
- Tests must not touch the network. Inject the `resolver`, `fetch` and `psl`
  test doubles (see `test/knock.test.ts`); the MCP server takes the same via
  `serveMcp({ knockOptions })`.
- In MCP mode stdout is the protocol channel — never `console.log` from
  library or server code; diagnostics go to stderr.
- New `knock()` options need a default in `defaults`, a README options-table
  row, an `llms.txt` mention, and (if agents should reach it) a property on
  the `knock_enumerate` tool schema.
- User-visible changes get a `CHANGELOG.md` entry.

## Releasing

Publishing is via GitHub release -> `.github/workflows/publish.yml`, which
stages the package through npm trusted publishing (OIDC); a maintainer then
approves it with 2FA. Don't run `npm publish` locally, and keep the pinned
npm version and the `bin` paths (no `./` prefix) as they are.
