import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeHost, ShodanProvider, associations } from '../src/providers/shodan.js';
import { KevProvider, parseKev } from '../src/providers/cisa-kev.js';
import { EpssProvider, parseEpss } from '../src/providers/epss.js';
import { ProviderError, HttpClient } from '../src/http.js';
import { redact } from '../src/security.js';
import { clock, NOW, CVE, hostRaw, kevRaw, epssRaw, FakeHttp, resources } from './helpers.js';
test('normalizes services, versions, CPE, CVE object/list and UTC Shodan timestamps', () => {
  const r = normalizeHost(hostRaw(), '8.8.8.8', NOW, 200);
  assert.equal(r.asset!.services[0].observedAt, '2026-09-14T12:00:00.000Z');
  assert.equal(r.asset!.services[0].version, '1.2.3');
  assert.deepEqual(associations([CVE, CVE, 'not-a-cve']), [{ cve: CVE, providerVerified: null }]);
  assert.equal(associations({ [CVE]: { verified: false } })[0].providerVerified, false);
  assert.equal(JSON.stringify(r).includes('raw-banner'), false);
});
test('dedup retains latest service and does not move historical CVEs to newer observations', () => {
  const old = hostRaw().data[0]; const recent = { ...old, timestamp: '2026-09-15T00:00:00', vulns: {}, version: '2.0' };
  const a = normalizeHost(hostRaw({ data: [old, recent, recent] }), '8.8.8.8', NOW, 200);
  const b = normalizeHost(hostRaw({ data: [recent, old, recent] }), '8.8.8.8', NOW, 200);
  assert.deepEqual(a, b); assert.equal(a.asset!.services.length, 1); assert.equal(a.asset!.services[0].associations.length, 0);
});
test('equal-time conflict is deterministic, and transport endpoints remain separate', () => {
  const a = hostRaw().data[0], b = { ...a, version: '9' }, c = { ...a, transport: 'udp' };
  const r = normalizeHost(hostRaw({ data: [a, b, c] }), '8.8.8.8', NOW, 200);
  assert.deepEqual(r, normalizeHost(hostRaw({ data: [c, b, a] }), '8.8.8.8', NOW, 200));
  assert.equal(r.asset!.services.length, 2); assert.equal(r.asset!.services[0].conflictingEvidence, true);
});
test('unlocated host CVEs remain host-only and do not duplicate service CVEs', () => {
  const r = normalizeHost(hostRaw({ vulns: [CVE, 'CVE-2024-0002'] }), '8.8.8.8', NOW, 200);
  assert.equal(r.asset!.hostAssociations!.port, null);
  assert.deepEqual(r.asset!.hostAssociations!.associations.map(a => a.cve), ['CVE-2024-0002']);
});
test('missing fields stay null, invalid endpoints excluded, service caps warn', () => {
  const r = normalizeHost(hostRaw({ data: [{ port: 80 }, { port: 443 }, { port: '22' }] }), '8.8.8.8', NOW, 1);
  assert.equal(r.asset!.services[0].product, null); assert.equal(r.asset!.services[0].observedAt, null);
  assert.equal(r.truncated, true); assert.equal(r.warnings.length, 2);
  assert.throws(() => normalizeHost({}, '8.8.8.8', NOW, 2));
});
test('Shodan caches within run, does not persist key or raw response, and handles 404', async () => {
  const { metrics } = resources();
  const http = new FakeHttp(() => hostRaw()); const provider = new ShodanProvider(http, 'test-secret', metrics, clock);
  await provider.host('8.8.8.8', 10); const result = await provider.host('8.8.8.8', 10);
  assert.equal(http.calls.length, 1); assert.equal(metrics.counts.cacheHits, 1);
  assert.equal(JSON.stringify(result).includes('test-secret'), false);
  assert.equal(new URL(http.calls[0].url).searchParams.get('history'), 'false');
  const missing = new ShodanProvider(new FakeHttp(() => { throw new ProviderError('shodan', 'HTTP_404', 404); }), 'x', metrics, clock);
  assert.equal((await missing.host('8.8.8.8', 10)).asset, null);
  await assert.rejects(provider.host('127.0.0.1', 10));
});
test('exhausted auth/rate limits stop further Shodan calls', async () => {
  const { metrics } = resources(); const http = new FakeHttp(() => { throw new ProviderError('shodan', 'RATE_LIMITED', 429); });
  const p = new ShodanProvider(http, 'x', metrics, clock);
  await assert.rejects(p.host('8.8.8.8', 10)); await assert.rejects(p.host('1.1.1.1', 10));
  assert.equal(http.calls.length, 1);
});
test('related hosts require exact domain boundary and first-page truncation is reported', async () => {
  const { metrics } = resources(); const http = new FakeHttp(() => ({ total: 101, matches: [
    { ip_str: '8.8.8.8', hostnames: ['vpn.example.com'] }, { ip_str: '1.1.1.1', hostnames: ['notexample.com'] }, { ip_str: '9.9.9.9', hostnames: ['example.com.evil.org'] }, { ip_str: '127.0.0.1', hostnames: ['example.com'] }] }));
  const r = await new ShodanProvider(http, 'x', metrics).related('example.com');
  assert.deepEqual(r.ips, ['8.8.8.8']); assert.equal(r.truncated, true);
});
test('KEV validates catalog, caches daily, and uses bounded stale fallback', async () => {
  const { metrics, store, cache } = resources(); const http = new FakeHttp(() => kevRaw);
  const first = await new KevProvider(http, cache, metrics, clock).get();
  assert.equal(first.entries[CVE].knownRansomwareCampaignUse, 'Known');
  await new KevProvider(http, cache, metrics, clock).get(); assert.equal(http.calls.length, 1);
  await store.set('KEV-v1', { value: parseKev(kevRaw), fetchedAt: '2026-09-13T00:00:00Z' });
  http.respond = () => { throw new Error('offline'); };
  const stale = await new KevProvider(http, cache, metrics, clock).get(); assert.equal(stale.source.state, 'stale');
  await store.set('KEV-v1', { value: parseKev(kevRaw), fetchedAt: '2026-08-01T00:00:00Z' });
  assert.equal((await new KevProvider(http, cache, metrics, clock).get()).source.state, 'unavailable');
  assert.throws(() => parseKev({ vulnerabilities: [] }));
});
test('bad cache and persistent storage failures do not stop fresh retrieval', async () => {
  const { metrics, store, cache } = resources();
  await store.set('KEV-v1', { value: { entries: { x: {} } }, fetchedAt: NOW });
  assert.equal((await new KevProvider(new FakeHttp(() => kevRaw), cache, metrics, clock).get()).source.state, 'fresh');
});
test('EPSS preserves zero, missing and invalid scores distinctly', () => {
  assert.equal(parseEpss({ status: 'OK', data: [{ ...epssRaw.data[0], epss: '0' }] }, [CVE])[CVE].probability, 0);
  assert.deepEqual(parseEpss({ status: 'OK', data: [] }, [CVE]), {});
  for (const value of ['NaN', '-1', '1.1', '', null, undefined]) assert.throws(() => parseEpss({ status: 'OK', data: [{ ...epssRaw.data[0], epss: value }] }, [CVE]));
  assert.throws(() => parseEpss(epssRaw, ['CVE-2024-9999']));
});
test('EPSS batches only requested unique CVEs, caches, and avoids calls for empty input', async () => {
  const { metrics, cache } = resources(); const http = new FakeHttp(() => epssRaw);
  const p = new EpssProvider(http, cache, metrics, clock);
  assert.deepEqual(await p.get([]), { entries: {}, sources: {}, warnings: [] });
  const r = await p.get([CVE, CVE]); assert.equal(r.entries[CVE].probability, 0.968);
  await p.get([CVE]); assert.equal(http.calls.length, 1);
  await new EpssProvider(http, cache, metrics, clock).get([CVE]); assert.equal(http.calls.length, 1);
});
test('EPSS failure uses bounded fallback, stale scores cannot appear fresh', async () => {
  const { metrics, cache, store } = resources();
  await store.set(`EPSS-v1-${CVE}`, { value: { cve: CVE, probability: 0.99, percentile: 0.999, date: '2026-09-13' }, fetchedAt: '2026-09-13T00:00:00Z' });
  const http = new FakeHttp(() => { throw new Error('offline'); });
  const r = await new EpssProvider(http, cache, metrics, clock).get([CVE, 'CVE-2024-9999']);
  assert.equal(r.sources[CVE].state, 'stale'); assert.equal(r.sources['CVE-2024-9999'].state, 'unavailable');
  const staleData = new FakeHttp(() => ({ status: 'OK', data: [{ ...epssRaw.data[0], date: '2026-01-01' }] }));
  assert.equal((await new EpssProvider(staleData, cache, metrics, clock).get([CVE])).sources[CVE].state, 'stale');
});
test('EPSS batch query lengths stay bounded', async () => {
  const { metrics, cache } = resources(); const http = new FakeHttp(() => ({ status: 'OK', data: [] }));
  const cves = Array.from({ length: 121 }, (_, n) => `CVE-2024-${10000 + n}`);
  await new EpssProvider(http, cache, metrics, clock).get(cves);
  assert.equal(http.calls.length, 3);
  for (const call of http.calls) assert.ok(new URL(call.url).searchParams.get('cve')!.length < 2000);
});
test('HTTP retries 429/5xx and records requests without logging credentials', async () => {
  const { metrics } = resources(); let calls = 0;
  const fetcher = (async () => { calls++; return calls < 3 ? new Response('secret-body', { status: 429 }) : new Response('{"ok":true}'); }) as typeof fetch;
  const http = new HttpClient(metrics, fetcher, async () => {}, 0);
  assert.deepEqual(await http.get('https://api.shodan.io/?key=secret', 'shodan'), { ok: true });
  assert.equal(metrics.counts.shodanRequests, 3); assert.equal(metrics.counts.retries, 2);
  assert.equal(JSON.stringify(metrics.snapshot()).includes('secret'), false);
});
test('HTTP rejects malformed/oversize responses and sanitizes network exceptions', async () => {
  const { metrics } = resources();
  for (const fetcher of [(async () => new Response('bad-json secret')), (async () => { throw new Error('url?key=secret'); }), (async () => new Response('x'.repeat(20_000_001)))]) {
    const http = new HttpClient(metrics, fetcher as typeof fetch, async () => {}, 0);
    await assert.rejects(http.get('https://api.shodan.io/?key=secret', 'shodan'), e => e instanceof ProviderError && !JSON.stringify(e).includes('secret'));
  }
});
test('redacts credentials including encoded values and JSON escapes', () => {
  const secret = 'secret"&/\nvalue';
  const r = redact({ nested: [secret, `url?key=${encodeURIComponent(secret)}`] }, [secret]);
  assert.deepEqual(r, { nested: ['[REDACTED]', 'url?key=[REDACTED]'] });
});
