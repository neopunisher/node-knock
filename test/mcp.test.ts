import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { createInterface } from 'node:readline';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { serveMcp, MCP_PROTOCOL_VERSIONS } from '../src/mcp.ts';
import type { McpServerOptions } from '../src/mcp.ts';
import { parsePublicSuffixList } from '../src/index.ts';
import type { KnockFetch, KnockResolver } from '../src/index.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

type Message = Record<string, any>;

const notFound = (name: string) =>
  Object.assign(new Error(`queryA ENOTFOUND ${name}`), { code: 'ENOTFOUND' });

const resolver: KnockResolver = {
  async resolve4(name) {
    if (name === 'www.example.com') return ['192.0.2.1'];
    if (name === 'api.example.com') return ['192.0.2.2'];
    throw notFound(name);
  },
  async resolve6(name) {
    throw notFound(name);
  },
};

const fetch: KnockFetch = async () => ({
  ok: true,
  status: 200,
  async json() {
    return [{ common_name: 'api.example.com', name_value: 'api.example.com\n*.old.example.com' }];
  },
});

const psl = parsePublicSuffixList('com\nuk\nco.uk\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n');

// Start an in-process server and return a JSON-RPC client bound to it.
function connect(knockOptions: McpServerOptions['knockOptions'] = { resolver, fetch, psl }) {
  const input = new PassThrough();
  const output = new PassThrough();
  const done = serveMcp({ input, output, knockOptions });
  const received: Message[] = [];
  const waiters: Array<() => void> = [];
  createInterface({ input: output }).on('line', (line) => {
    received.push(JSON.parse(line));
    waiters.splice(0).forEach((wake) => wake());
  });
  let nextId = 1;
  const next = async (match: (m: Message) => boolean): Promise<Message> => {
    for (;;) {
      const index = received.findIndex(match);
      if (index >= 0) return received.splice(index, 1)[0]!;
      await new Promise<void>((resolve) => waiters.push(resolve));
    }
  };
  return {
    raw: (text: string) => input.write(`${text}\n`),
    notify: (method: string, params: Message = {}) =>
      input.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`),
    request(method: string, params: Message = {}) {
      const id = nextId++;
      input.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      return { id, response: next((m) => m.id === id) };
    },
    next,
    async close() {
      input.end();
      await done;
    },
  };
}

test('mcp: initialize negotiates the protocol version', async () => {
  const client = connect();
  const known = await client.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'test', version: '0' },
  }).response;
  assert.equal(known.result.protocolVersion, '2025-06-18');
  assert.equal(known.result.serverInfo.name, 'knock');
  assert.ok(known.result.capabilities.tools);

  const unknown = await client.request('initialize', { protocolVersion: '1999-01-01' }).response;
  assert.equal(unknown.result.protocolVersion, MCP_PROTOCOL_VERSIONS[0]);

  assert.deepEqual((await client.request('ping').response).result, {});
  await client.close();
});

test('mcp: lists tools with input schemas', async () => {
  const client = connect();
  const { result } = await client.request('tools/list').response;
  const names = result.tools.map((tool: Message) => tool.name);
  assert.deepEqual(names, ['knock_enumerate', 'knock_ct_lookup', 'knock_registrable_domain']);
  for (const tool of result.tools) {
    assert.equal(tool.inputSchema.type, 'object');
    assert.ok(tool.description.length > 20);
  }
  await client.close();
});

test('mcp: knock_enumerate returns a structured report and streams progress', async () => {
  const client = connect();
  const { response } = client.request('tools/call', {
    name: 'knock_enumerate',
    arguments: { domain: 'https://www.example.com/x', words: ['www', 'nope'] },
    _meta: { progressToken: 'p1' },
  });
  const { result } = await response;
  assert.equal(result.isError, undefined);
  const report = result.structuredContent;
  assert.equal(report.domain, 'example.com');
  assert.deepEqual(
    report.results.map((r: Message) => r.name).sort(),
    ['api.example.com', 'www.example.com'],
  );
  assert.deepEqual(report.ct.unresolved, ['old.example.com']);
  assert.match(result.content[0].text, /example\.com: 2 found/);
  assert.deepEqual(JSON.parse(result.content[1].text), report);

  const progress = await client.next((m) => m.method === 'notifications/progress');
  assert.equal(progress.params.progressToken, 'p1');
  assert.equal(progress.params.progress, 1);
  await client.close();
});

test('mcp: knock_ct_lookup and knock_registrable_domain', async () => {
  const client = connect();
  const ct = await client.request('tools/call', {
    name: 'knock_ct_lookup',
    arguments: { domain: 'example.com' },
  }).response;
  assert.deepEqual(ct.result.structuredContent, {
    domain: 'example.com',
    names: ['api.example.com', 'old.example.com'],
  });

  const psl = await client.request('tools/call', {
    name: 'knock_registrable_domain',
    arguments: { host: 'a.b.example.co.uk' },
  }).response;
  assert.deepEqual(psl.result.structuredContent, {
    host: 'a.b.example.co.uk',
    publicSuffix: 'co.uk',
    registrableDomain: 'example.co.uk',
  });
  await client.close();
});

test('mcp: bad input becomes a tool error; unknown tools and methods are protocol errors', async () => {
  const client = connect();
  const bad = await client.request('tools/call', {
    name: 'knock_enumerate',
    arguments: { domain: 'example.com', concurrency: 'lots' },
  }).response;
  assert.equal(bad.result.isError, true);
  assert.match(bad.result.content[0].text, /concurrency/);

  const missing = await client.request('tools/call', { name: 'knock_ct_lookup', arguments: {} })
    .response;
  assert.equal(missing.result.isError, true);

  const unknownTool = await client.request('tools/call', { name: 'nope' }).response;
  assert.equal(unknownTool.error.code, -32602);

  const unknownMethod = await client.request('resources/list').response;
  assert.equal(unknownMethod.error.code, -32601);

  client.raw('{not json');
  assert.equal((await client.next((m) => m.id === null)).error.code, -32700);
  await client.close();
});

test('mcp: cancellation aborts a running call without a response', async () => {
  let release!: () => void;
  const stalled: KnockFetch = (_url, { signal }) =>
    new Promise((_resolve, reject) => {
      release = () => reject(signal.reason);
      signal.addEventListener('abort', release);
    });
  const client = connect({ resolver, fetch: stalled, psl });
  const call = client.request('tools/call', {
    name: 'knock_ct_lookup',
    arguments: { domain: 'example.com' },
  });
  await new Promise((resolve) => setImmediate(resolve));
  client.notify('notifications/cancelled', { requestId: call.id, reason: 'user' });
  const after = await client.request('ping').response;
  assert.deepEqual(after.result, {});
  await client.close();
  const leftover = await Promise.race([call.response, Promise.resolve('none')]);
  assert.equal(leftover, 'none');
});

test('CLI: --mcp speaks JSON-RPC on stdout', async () => {
  const child = spawn(process.execPath, [CLI, '--mcp'], { stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = createInterface({ input: child.stdout });
  const first = new Promise<string>((resolve) => lines.once('line', resolve));
  child.stdin.write(
    `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } })}\n`,
  );
  const response = JSON.parse(await first);
  assert.equal(response.id, 1);
  assert.equal(response.result.serverInfo.name, 'knock');
  child.stdin.end();
  const code = await new Promise((resolve) => child.on('close', resolve));
  assert.equal(code, 0);
});
