import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeDomain, type Dependencies } from '../src/analyze.js';
import { parseInput } from '../src/input.js';
import { ShodanProvider } from '../src/providers/shodan.js';
import { KevProvider } from '../src/providers/cisa-kev.js';
import { EpssProvider } from '../src/providers/epss.js';
import { ProviderError } from '../src/http.js';
import { clock, CVE, hostRaw, kevRaw, epssRaw, FakeHttp, resources } from './helpers.js';
function setup() {
  const { metrics, cache } = resources();
  const http = new FakeHttp((_url, provider) => provider === 'shodan' ? hostRaw() : provider === 'kev' ? kevRaw : epssRaw);
  const deps: Dependencies = { dns: { resolve: async () => ({ ips: ['8.8.8.8'], warnings: [], partial: false }) },
    shodan: new ShodanProvider(http, 'test-key', metrics, clock), kev: new KevProvider(http, cache, metrics, clock),
    epss: new EpssProvider(http, cache, metrics, clock), metrics, now: clock };
  return { deps, http };
}
test('domain pipeline gives structured summary, evidence, cost diagnostics and shared-IP deduplication', async () => {
  const { deps, http } = setup(); const input = parseInput({ domains: ['example.com', 'example.org'] });
  const record = await analyzeDomain('example.com', input, deps);
  assert.equal(record.status, 'ok');
  assert.deepEqual(record.summary, { assetsObserved: 1, servicesObserved: 1, cveAssociations: 1, uniqueCves: 1, kevMatches: 1, highEpss: 1, criticalPriority: 0, highPriority: 1 });
  assert.ok(record.humanSummary.includes('Investigate first:'));
  assert.equal(record.priorities[0].evidence.length, 3);
  await analyzeDomain('example.org', input, deps);
  assert.equal(http.calls.length, 3); assert.equal(deps.metrics.counts.domainsAnalyzed, 2);
  assert.equal(deps.metrics.snapshot().cost.actualMarginalCostPerDomainUsd, null);
});
test('repeat runs with identical fixtures/time produce identical records', async () => {
  const input = parseInput({ domain: 'example.com' });
  const a = await analyzeDomain('example.com', input, setup().deps);
  const b = await analyzeDomain('example.com', input, setup().deps);
  assert.deepEqual(a, b);
});
test('no DNS data skips intelligence calls, and reports insufficient evidence', async () => {
  const { deps, http } = setup(); deps.dns.resolve = async () => ({ ips: [], warnings: [], partial: false });
  const r = await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), deps);
  assert.equal(r.status, 'no_data'); assert.equal(http.calls.length, 0);
  assert.match(r.humanSummary, /Insufficient evidence/);
});
test('Shodan failure is a failed assessment, never an empty clean result', async () => {
  const { deps, http } = setup(); http.respond = () => { throw new ProviderError('shodan', 'HTTP_401', 401); };
  const r = await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), deps);
  assert.equal(r.status, 'failed'); assert.equal(r.sources.shodan.state, 'unavailable');
  assert.match(r.warnings.join(' '), /HTTP_401/);
});
test('intel outages retain associations with unknown KEV/EPSS and partial status', async () => {
  const { deps, http } = setup(); http.respond = (_url, p) => { if (p === 'shodan') return hostRaw(); throw new Error('offline'); };
  const r = await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), deps);
  assert.equal(r.status, 'partial'); assert.equal(r.priorities[0].cisaKev, null); assert.equal(r.priorities[0].epss, null);
});
test('IP and CVE limits report incomplete results and do not hide associations', async () => {
  const { deps, http } = setup();
  deps.dns.resolve = async () => ({ ips: ['8.8.8.8','9.9.9.9'], warnings: [], partial: false });
  const raw = hostRaw(); raw.data[0].vulns['CVE-2024-0002'] = { verified: false };
  http.respond = (_url, p) => p === 'shodan' ? raw : p === 'kev' ? kevRaw : epssRaw;
  const r = await analyzeDomain('example.com', parseInput({ domain: 'example.com', maxIpsPerDomain: 1, maxCvesPerDomain: 1 }), deps);
  assert.equal(r.status, 'partial'); assert.equal(r.summary.uniqueCves, 2);
  assert.equal(Object.keys(r.sources.epss).length, 1); assert.equal(r.priorities.find(p => p.cve === CVE)!.cisaKev, true);
  assert.match(r.warnings.join(' '), /IP limit/); assert.match(r.warnings.join(' '), /CVE enrichment limit/);
});
test('stale warnings and service without vulnerabilities still produce exposure evidence', async () => {
  const { deps, http } = setup(); const raw = hostRaw(); raw.data[0].timestamp = '2025-01-01T00:00:00'; raw.data[0].vulns = {};
  http.respond = () => raw;
  const r = await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), deps);
  assert.equal(r.priorities[0].priority, 'INSUFFICIENT_EVIDENCE'); assert.match(r.warnings.join(' '), /stale/);
  assert.equal(http.calls.length, 1);
});
