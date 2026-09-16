import test from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient, ProviderError } from '../src/http.js';
import { PublicCache } from '../src/cache.js';
import { KevProvider, parseKev } from '../src/providers/cisa-kev.js';
import { EpssProvider } from '../src/providers/epss.js';
import { normalizeHost } from '../src/providers/shodan.js';
import { redact } from '../src/security.js';
import { resources, clock, kevRaw, epssRaw, FakeHttp, CVE, NOW, hostRaw } from './helpers.js';
test('timeouts are bounded, retried twice, counted and sanitized', async () => {
  const { metrics } = resources();
  const fetcher = ((_url: unknown, opts: RequestInit) => new Promise<Response>((_resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('test timed out')), 1000);
    opts.signal!.addEventListener('abort', () => { clearTimeout(timer); reject(new Error('secret-bearing timeout detail')); }, { once: true });
  })) as typeof fetch;
  const http = new HttpClient(metrics, fetcher, async () => {}, 0, 10);
  await assert.rejects(http.get('https://api.shodan.io/?key=secret', 'shodan'), e => e instanceof ProviderError && e.code === 'NETWORK_OR_TIMEOUT' && !e.message.includes('secret'));
  assert.equal(metrics.counts.shodanRequests, 3); assert.equal(metrics.counts.retries, 2);
});
test('permanent HTTP errors and invalid JSON do not cause retry storms', async () => {
  for (const status of [400,401,403,404]) {
    const { metrics } = resources();
    const http = new HttpClient(metrics, (async () => new Response('private body', { status })) as typeof fetch, async () => {}, 0);
    await assert.rejects(http.get('https://api.shodan.io/', 'shodan')); assert.equal(metrics.counts.shodanRequests, 1);
  }
});
test('Retry-After is capped and transient 503 can recover', async () => {
  const { metrics } = resources(); let calls = 0; const sleeps: number[] = [];
  const http = new HttpClient(metrics, (async () => ++calls < 2 ? new Response('', { status: 503, headers: { 'retry-after': '999999' } }) : new Response('{}')) as typeof fetch, async ms => { sleeps.push(ms); }, 0);
  await http.get('https://api.shodan.io/', 'shodan'); assert.deepEqual(sleeps, [30_000]);
});
test('broken persistent cache permits fresh intelligence and records read/write errors', async () => {
  const { metrics } = resources();
  const cache = new PublicCache({ get: async () => { throw new Error('read'); }, set: async () => { throw new Error('write'); } }, metrics, clock);
  const kev = await new KevProvider(new FakeHttp(() => kevRaw), cache, metrics, clock).get();
  const epss = await new EpssProvider(new FakeHttp(() => epssRaw), cache, metrics, clock).get([CVE]);
  assert.equal(kev.source.state, 'fresh'); assert.equal(epss.sources[CVE].state, 'fresh');
  assert.equal(metrics.errors['cache.READ_FAILED'], 2); assert.equal(metrics.errors['cache.WRITE_FAILED'], 2);
});
test('malformed KEV refresh retains valid stale cache instead of replacing it', async () => {
  const { metrics, cache, store } = resources();
  await store.set('KEV-v1', { value: parseKev(kevRaw), fetchedAt: '2026-09-13T00:00:00Z' });
  const result = await new KevProvider(new FakeHttp(() => ({ error: 'bad' })), cache, metrics, clock).get();
  assert.equal(result.source.state, 'stale'); assert.ok(result.entries[CVE]);
});
test('malformed service exclusion is explicitly partial even below the service cap', () => {
  const r = normalizeHost(hostRaw({ data: [{ port: '443' }] }), '8.8.8.8', NOW, 200);
  assert.equal(r.truncated, true); assert.equal(r.asset, null); assert.ok(!r.warnings.join(' ').includes('Service limit'));
});
test('adversarial quote/number secrets cannot corrupt JSON structure', () => {
  assert.deepEqual(redact({ number: 123, message: 'quote " and 123', nested: ['123'] }, ['"', '123']), { number: 123, message: 'quote [REDACTED] and [REDACTED]', nested: ['[REDACTED]'] });
});
