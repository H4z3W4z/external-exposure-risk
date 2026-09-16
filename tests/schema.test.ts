import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Ajv } from 'ajv';
import { analyzeDomain } from '../src/analyze.js';
import { parseInput } from '../src/input.js';
import { normalizeHost } from '../src/providers/shodan.js';
import { parseKev } from '../src/providers/cisa-kev.js';
import { parseEpss } from '../src/providers/epss.js';
import { clock, CVE, NOW, hostRaw, kevRaw, epssRaw, resources } from './helpers.js';
test('Dataset schema accepts full populated and no-data records and rejects unsupported certainty', async () => {
  const schema = JSON.parse(await readFile('.actor/dataset_schema.json', 'utf8'));
  const validate = new Ajv({ strict: true, allowUnionTypes: true }).compile(schema.fields);
  const { metrics } = resources();
  const source = { url: '', fetchedAt: NOW, dataDate: NOW, state: 'fresh' as const, cacheAgeSeconds: 0 };
  const deps = { dns: { resolve: async () => ({ ips: ['8.8.8.8'], warnings: [], partial: false }) },
    shodan: { host: async () => normalizeHost(hostRaw(), '8.8.8.8', NOW, 200), related: async () => ({ ips: [], warnings: [], truncated: false }) },
    kev: { get: async () => ({ entries: parseKev(kevRaw).entries, source, warnings: [] }) },
    epss: { get: async () => ({ entries: parseEpss(epssRaw, [CVE]), sources: { [CVE]: source }, warnings: [] }) }, metrics, now: clock };
  const record = await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), deps);
  assert.ok(validate(record), JSON.stringify(validate.errors));
  const bad = structuredClone(record) as unknown as { priorities: { applicability: string }[] };
  bad.priorities[0].applicability = 'CONFIRMED_VULNERABLE'; assert.equal(validate(bad), false);
  deps.dns.resolve = async () => ({ ips: [], warnings: [], partial: false });
  assert.ok(validate(await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), deps)), JSON.stringify(validate.errors));
});
