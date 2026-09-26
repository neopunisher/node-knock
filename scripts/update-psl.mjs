#!/usr/bin/env node
/**
 * Refresh the vendored Public Suffix List (`lists/public_suffix_list.dat`).
 *
 * The list changes continuously; a stale copy makes knock treat newly valid
 * suffixes as ordinary labels. Run `npm run update-psl` periodically and commit
 * the result. See https://publicsuffix.org/learn/.
 */
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const SOURCE = 'https://publicsuffix.org/list/public_suffix_list.dat';
const dest = fileURLToPath(new URL('../lists/public_suffix_list.dat', import.meta.url));

const response = await fetch(SOURCE, { redirect: 'follow', headers: { accept: 'text/plain' } });
if (!response.ok) {
  console.error(`update-psl: ${SOURCE} responded with HTTP ${response.status}`);
  process.exit(1);
}
const text = await response.text();

// Guard against fetching an error page or a truncated file.
if (!text.includes('===BEGIN ICANN DOMAINS===') || !text.includes('===BEGIN PRIVATE DOMAINS===')) {
  console.error('update-psl: downloaded file is missing the ICANN/PRIVATE section markers; not writing');
  process.exit(1);
}

await writeFile(dest, text, 'utf8');
const lines = text.split('\n').length;
console.log(`update-psl: wrote ${dest} (${text.length} bytes, ${lines} lines) on ${new Date().toISOString().slice(0, 10)}`);
