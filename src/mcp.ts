/**
 * knock as a Model Context Protocol server over stdio — newline-delimited
 * JSON-RPC 2.0, implemented directly so the package stays dependency-free.
 */
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import type { Readable, Writable } from 'node:stream';
import {
  knock,
  certSubdomains,
  normalizeDomain,
  wordlists,
  loadPublicSuffixList,
  getPublicSuffix,
  getRegistrableDomain,
} from './index.ts';
import type { KnockOptions } from './index.ts';

const { version } = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { version: string };

/** Protocol revisions this server speaks, newest first. */
export const MCP_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

type JsonObject = Record<string, unknown>;
type Id = string | number;

export interface McpServerOptions {
  input?: Readable;
  output?: Writable;
  /** Merged into every knock() / certSubdomains() call, mainly for testing (resolver, fetch, psl). */
  knockOptions?: Pick<KnockOptions, 'resolver' | 'fetch' | 'psl'>;
}

class InvalidParams extends Error {}

const INSTRUCTIONS = `knock enumerates subdomains of a domain using Certificate Transparency logs (passive, via crt.sh) and a wordlist DNS brute force with wildcard detection.
Prefer knock_ct_lookup or knock_enumerate with passive: true for a quick, low-noise look; a full brute force sends ~31k DNS queries and takes roughly 30-90 seconds.
Only enumerate domains the user owns or is authorized to assess.`;

const domainProperty = {
  type: 'string',
  description: 'Domain, hostname or URL, e.g. "example.com" or "https://www.example.co.uk/path".',
};

const TOOLS = [
  {
    name: 'knock_enumerate',
    title: 'Enumerate subdomains',
    description:
      'Find subdomains of a domain. Combines Certificate Transparency logs with a DNS brute force over a bundled wordlist, filters wildcard DNS, and verifies names with real lookups. Input is reduced to its registrable domain first (www.example.co.uk -> example.co.uk) unless fullHost is set. Returns the full report: results (name, addresses, sources), wildcard, ct (including unresolved CT names), and stats. A full run sends ~31k DNS queries; use passive: true for a CT-only lookup.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: domainProperty,
        passive: {
          type: 'boolean',
          description: 'Skip the wordlist brute force; Certificate Transparency only. Default false.',
        },
        ct: { type: 'boolean', description: 'Query Certificate Transparency logs. Default true.' },
        verify: {
          type: 'boolean',
          description: 'Resolve CT-discovered names over DNS. Default true.',
        },
        fullHost: {
          type: 'boolean',
          description: 'Scan the exact host given instead of its registrable domain. Default false.',
        },
        wordlist: {
          type: 'string',
          enum: ['subs', 'org'],
          description: 'Bundled wordlist: "subs" (~31k labels, default) or "org".',
        },
        words: {
          type: 'array',
          items: { type: 'string' },
          description: 'Custom labels to try instead of a bundled wordlist, e.g. ["www", "api"].',
        },
        concurrency: {
          type: 'integer',
          minimum: 1,
          maximum: 512,
          description: 'Parallel DNS queries. Default 64.',
        },
        timeout: {
          type: 'integer',
          minimum: 1,
          description: 'Per-query DNS timeout in milliseconds. Default 5000.',
        },
        servers: {
          type: 'array',
          items: { type: 'string' },
          description: 'DNS server IPs to query instead of the system resolvers.',
        },
        ipv6: { type: 'boolean', description: 'Also resolve AAAA records. Default false.' },
        web: {
          type: 'boolean',
          description: 'Probe http/https on each found host and report status codes. Default false.',
        },
      },
      required: ['domain'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'knock_ct_lookup',
    title: 'Certificate Transparency lookup',
    description:
      'List hostnames under a domain that appear in Certificate Transparency logs (crt.sh). Passive: one HTTPS request to crt.sh, no DNS traffic to the target. Names are not verified and may be stale. The domain is used exactly as given (no registrable-domain reduction).',
    inputSchema: {
      type: 'object',
      properties: {
        domain: domainProperty,
        timeout: {
          type: 'integer',
          minimum: 1,
          description: 'Request timeout in milliseconds. Default 15000.',
        },
      },
      required: ['domain'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'knock_registrable_domain',
    title: 'Registrable domain',
    description:
      'Reduce a hostname or URL to its public suffix and registrable domain using the bundled Public Suffix List, e.g. "a.b.example.co.uk" -> suffix "co.uk", registrable "example.co.uk". Offline; no network access.',
    inputSchema: {
      type: 'object',
      properties: {
        host: domainProperty,
        icannOnly: {
          type: 'boolean',
          description: 'Ignore private suffixes like github.io. Default false.',
        },
      },
      required: ['host'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
];

function optional<T>(
  args: JsonObject,
  key: string,
  check: (value: unknown) => value is T,
  expected: string,
): T | undefined {
  const value = args[key];
  if (value === undefined || value === null) return undefined;
  if (!check(value)) throw new InvalidParams(`"${key}" must be ${expected}`);
  return value;
}

const isBoolean = (v: unknown): v is boolean => typeof v === 'boolean';
const isString = (v: unknown): v is string => typeof v === 'string';
const isPositiveInteger = (v: unknown): v is number => Number.isInteger(v) && (v as number) > 0;
const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every(isString);

function required(args: JsonObject, key: string): string {
  const value = optional(args, key, isString, 'a string');
  if (!value) throw new InvalidParams(`"${key}" is required`);
  return value;
}

/**
 * Serve MCP over stdio (or the given streams). Resolves when the input ends.
 */
export async function serveMcp(options: McpServerOptions = {}): Promise<void> {
  const { input = process.stdin, output = process.stdout, knockOptions = {} } = options;
  const inFlight = new Map<Id, AbortController>();

  const send = (message: JsonObject): void => {
    output.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
  };
  const reply = (id: Id, result: JsonObject) => send({ id, result });
  const replyError = (id: Id | null, code: number, message: string) =>
    send({ id, error: { code, message } });

  const toolResult = (data: JsonObject, summary?: string): JsonObject => ({
    content: [
      ...(summary ? [{ type: 'text', text: summary }] : []),
      { type: 'text', text: JSON.stringify(data) },
    ],
    structuredContent: data,
  });

  async function callTool(
    name: string,
    args: JsonObject,
    signal: AbortSignal,
    progress: (count: number, message: string) => void,
  ): Promise<JsonObject> {
    switch (name) {
      case 'knock_enumerate': {
        const domain = required(args, 'domain');
        const passive = optional(args, 'passive', isBoolean, 'a boolean') ?? false;
        const list = optional(args, 'wordlist', isString, 'a string');
        if (list !== undefined && list !== 'subs' && list !== 'org') {
          throw new InvalidParams('"wordlist" must be "subs" or "org"');
        }
        const run: KnockOptions = {
          ...knockOptions,
          signal,
          ct: optional(args, 'ct', isBoolean, 'a boolean') ?? true,
          verify: optional(args, 'verify', isBoolean, 'a boolean') ?? true,
          baseDomainOnly: !(optional(args, 'fullHost', isBoolean, 'a boolean') ?? false),
          wordlist: wordlists[list ?? 'subs'],
          words: passive ? [] : optional(args, 'words', isStringArray, 'an array of strings'),
          concurrency: Math.min(
            optional(args, 'concurrency', isPositiveInteger, 'a positive integer') ?? 64,
            512,
          ),
          timeout: optional(args, 'timeout', isPositiveInteger, 'a positive integer'),
          servers: optional(args, 'servers', isStringArray, 'an array of strings'),
          family: optional(args, 'ipv6', isBoolean, 'a boolean') ? 'any' : 4,
          web: optional(args, 'web', isBoolean, 'a boolean') ?? false,
        };
        if (passive && !run.ct) throw new InvalidParams('passive with ct: false leaves nothing to do');
        if (run.timeout === undefined) delete run.timeout;
        let found = 0;
        run.onResult = (result) => {
          found += 1;
          progress(found, result.name);
        };
        const report = await knock(domain, run);
        const { stats, wildcard, ct } = report;
        const summary =
          `${report.domain}: ${stats.found} found from ${stats.candidates} candidates` +
          (ct.enabled ? `, ${ct.names} CT names (${ct.unresolved.length} unresolved)` : '') +
          (wildcard.detected ? `, wildcard DNS detected (${wildcard.addresses.join(', ')})` : '') +
          (ct.error ? `, CT lookup failed: ${ct.error}` : '') +
          ` in ${(stats.durationMs / 1000).toFixed(1)}s`;
        return toolResult(report as unknown as JsonObject, summary);
      }
      case 'knock_ct_lookup': {
        const domain = normalizeDomain(required(args, 'domain'));
        const names = await certSubdomains(domain, {
          signal,
          fetch: knockOptions.fetch,
          timeout: optional(args, 'timeout', isPositiveInteger, 'a positive integer'),
        });
        return toolResult({ domain, names }, `${names.length} CT names under ${domain}`);
      }
      case 'knock_registrable_domain': {
        const host = normalizeDomain(required(args, 'host'));
        const icannOnly = optional(args, 'icannOnly', isBoolean, 'a boolean') ?? false;
        const rules = knockOptions.psl ?? (await loadPublicSuffixList());
        return toolResult({
          host,
          publicSuffix: getPublicSuffix(host, rules, { icannOnly }),
          registrableDomain: getRegistrableDomain(host, rules, { icannOnly }),
        });
      }
      default:
        throw new InvalidParams(`unknown tool: ${name}`);
    }
  }

  async function handle(message: JsonObject): Promise<void> {
    const { id, method } = message as { id?: Id; method?: unknown };
    const params = (message.params ?? {}) as JsonObject;
    const isRequest = typeof id === 'string' || typeof id === 'number';

    if (typeof method !== 'string') {
      // Responses to requests we never send; ignore. Malformed requests get an error.
      if (isRequest && !('result' in message || 'error' in message)) {
        replyError(id, -32600, 'invalid request');
      }
      return;
    }

    if (!isRequest) {
      if (method === 'notifications/cancelled') {
        inFlight.get(params.requestId as Id)?.abort(new Error(String(params.reason ?? 'cancelled')));
      }
      return;
    }

    switch (method) {
      case 'initialize': {
        const requested = params.protocolVersion;
        reply(id, {
          protocolVersion:
            typeof requested === 'string' && MCP_PROTOCOL_VERSIONS.includes(requested)
              ? requested
              : MCP_PROTOCOL_VERSIONS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'knock', title: 'knock', version },
          instructions: INSTRUCTIONS,
        });
        return;
      }
      case 'ping':
        reply(id, {});
        return;
      case 'tools/list':
        reply(id, { tools: TOOLS });
        return;
      case 'tools/call': {
        const name = String(params.name ?? '');
        const args = (params.arguments ?? {}) as JsonObject;
        const progressToken = (params._meta as JsonObject | undefined)?.progressToken;
        const controller = new AbortController();
        inFlight.set(id, controller);
        const progress = (count: number, text: string) => {
          if (progressToken === undefined) return;
          send({
            method: 'notifications/progress',
            params: { progressToken, progress: count, message: `found ${text}` },
          });
        };
        try {
          reply(id, await callTool(name, args, controller.signal, progress));
        } catch (error) {
          // A cancelled request gets no response, per the spec.
          if (controller.signal.aborted) return;
          const text = error instanceof Error ? error.message : String(error);
          if (error instanceof InvalidParams && text.startsWith('unknown tool')) {
            replyError(id, -32602, text);
          } else {
            reply(id, { content: [{ type: 'text', text }], isError: true });
          }
        } finally {
          inFlight.delete(id);
        }
        return;
      }
      default:
        replyError(id, -32601, `method not found: ${method}`);
    }
  }

  const lines = createInterface({ input, crlfDelay: Infinity });
  const pending = new Set<Promise<void>>();
  for await (const line of lines) {
    if (line.trim() === '') continue;
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      replyError(null, -32700, 'parse error');
      continue;
    }
    if (typeof message !== 'object' || message === null || Array.isArray(message)) {
      replyError(null, -32600, 'invalid request');
      continue;
    }
    // Requests run concurrently so pings and cancellations stay responsive during a scan.
    const task = handle(message as JsonObject).catch((error: unknown) => {
      process.stderr.write(`knock mcp: ${error instanceof Error ? error.stack : String(error)}\n`);
    });
    pending.add(task);
    void task.finally(() => pending.delete(task));
  }
  for (const controller of inFlight.values()) controller.abort(new Error('input closed'));
  await Promise.allSettled(pending);
}
