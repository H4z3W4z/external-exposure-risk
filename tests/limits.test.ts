import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeDomain } from '../src/analyze.js';
import { parseInput } from '../src/input.js';
import { prioritize, sortFindings } from '../src/priority.js';
import { BoundedCache } from '../src/bounded-cache.js';
import { fitRecord, recordBytes, FindingSelection, MAX_RETAINED_FINDINGS } from '../src/output.js';
import { normalizeHost } from '../src/providers/shodan.js';
import { clock, NOW, hostRaw, resources, service, intelligence } from './helpers.js';
async function record() {
  const { metrics } = resources(); const raw = hostRaw(); raw.data[0].vulns = {};
  return analyzeDomain('example.com', parseInput({ domain: 'example.com' }), {
    metrics, now: clock, dns: { resolve: async () => ({ ips: ['8.8.8.8'], warnings: [], partial: false }) },
    shodan: { host: async () => normalizeHost(raw, '8.8.8.8', NOW, 200), related: async () => ({ ips: [], warnings: [], truncated: false }) },
    kev: { get: async () => { throw new Error('Unneeded enrichment'); } }, epss: { get: async () => { throw new Error('Unneeded enrichment'); } },
  });
}
test('weighted LRU remains bounded, refreshes recency, replaces entries and refuses oversized items', () => {
  let evicted = 0; const cache = new BoundedCache<string>(50, 2, () => evicted++);
  cache.set('a','first'); cache.set('b','second'); cache.get('a'); cache.set('c','third');
  assert.equal(cache.has('a'), true); assert.equal(cache.has('b'), false); assert.equal(cache.size, 2);
  cache.set('a','replacement'); assert.equal(cache.get('a'), 'replacement');
  cache.set('huge','x'.repeat(100)); assert.equal(cache.has('huge'), false); assert.ok(cache.bytes <= 50); assert.ok(evicted >= 2);
});
test('bounded finding selection retains globally highest priority independent of arrival order', () => {
  const base = prioritize('example.com', service(), intelligence(), parseInput({ domain: 'example.com' }), NOW)[0];
  const findings = Array.from({ length: 6000 }, (_, n) => ({ ...base, id: String(n).padStart(6,'0'), priority: n === 5999 ? 'HIGH_PRIORITY' as const : 'MEDIUM_PRIORITY' as const }));
  const a = new FindingSelection(), b = new FindingSelection();
  findings.forEach(f => a.add(f)); findings.slice().reverse().forEach(f => b.add(f));
  assert.equal(a.total, 6000); assert.equal(a.finish().length, MAX_RETAINED_FINDINGS);
  assert.equal(a.finish()[0].id, '005999'); assert.deepEqual(a.finish(), b.finish());
  assert.deepEqual(a.finish(), sortFindings(findings).slice(0, MAX_RETAINED_FINDINGS));
});
test('byte ceiling measures UTF-8 exactly, drops duplicate asset detail and keeps finding evidence', async () => {
  const r = await record(); const evidence = structuredClone(r.priorities[0].evidence);
  r.assets[0].organization = '界'.repeat(30_000);
  const result = fitRecord(r, 32_000);
  assert.equal(result.assets.length, 0); assert.equal(result.output!.assetsOmitted, 1);
  assert.equal(result.summary.assetsObserved, 1); assert.equal(result.output!.summaryScope, 'assessed_observations');
  assert.equal(result.status, 'partial'); assert.match(result.humanSummary, /example.com — partial/);
  assert.deepEqual(result.priorities[0].evidence, evidence);
  assert.equal(result.output!.serializedBytes, Buffer.byteLength(JSON.stringify(result)));
  assert.equal(recordBytes(result), result.output!.serializedBytes); assert.ok(result.output!.serializedBytes <= 32_000);
});
test('oversized finding detail is bounded without stripping evidence from retained findings', async () => {
  const r = await record();
  r.priorities = Array.from({ length: 50 }, (_, n) => ({ ...r.priorities[0], id: String(n), evidence: [{ ...r.priorities[0].evidence[0], details: { note: '界'.repeat(2000) } }] }));
  r.output!.findingsAssessed = 50;
  fitRecord(r, 32_000);
  assert.ok(r.priorities.length > 0 && r.priorities.length < 50);
  assert.equal(r.output!.findingsOmitted, 50 - r.priorities.length);
  assert.ok(r.priorities.every(f => f.evidence[0].details.note === '界'.repeat(2000)));
  assert.ok(Buffer.byteLength(JSON.stringify(r)) <= 32_000);
  assert.throws(() => fitRecord(r, 100));
});
test('analysis budgets stop further lookups and disclose unassessed observations', async () => {
  const { metrics } = resources(); let calls = 0;
  const raw = hostRaw();
  raw.data = Array.from({ length: 200 }, (_, i) => ({ ...raw.data[0], port: i + 1, vulns: Object.fromEntries(Array.from({ length: 200 }, (_, n) => [`CVE-2024-${10000+n}`, { verified: true }])) }));
  const intel = intelligence();
  const r = await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), {
    metrics, now: clock, dns: { resolve: async () => ({ ips: ['8.8.8.8','9.9.9.9'], warnings: [], partial: false }) },
    shodan: { host: async () => { calls++; return normalizeHost(raw, '8.8.8.8', NOW, 200); }, related: async () => ({ ips: [], warnings: [], truncated: false }) },
    kev: { get: async () => ({ entries: {}, source: intel.kevSource, warnings: [] }) }, epss: { get: async () => ({ entries: {}, sources: {}, warnings: [] }) },
  });
  assert.equal(calls, 1); assert.equal(r.output!.analysisLimited, true); assert.equal(r.status, 'partial');
  assert.equal(r.summary.cveAssociations, 20_000); assert.equal(r.output!.findingsAssessed, 20_000);
  assert.ok(r.priorities.length <= 2000); assert.match(r.warnings.join(' '), /unassessed/);
});
