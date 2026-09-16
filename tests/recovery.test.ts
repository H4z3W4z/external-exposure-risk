import test from 'node:test';
import assert from 'node:assert/strict';
import { runPortfolio, inputFingerprint, InterruptedRun, type PortfolioSink, type RunState, type CompletedDomain } from '../src/portfolio.js';
import { parseInput } from '../src/input.js';
import { Metrics } from '../src/metrics.js';
import { normalizeHost } from '../src/providers/shodan.js';
import { parseKev } from '../src/providers/cisa-kev.js';
import { parseEpss } from '../src/providers/epss.js';
import { clock, NOW, CVE, hostRaw, kevRaw, epssRaw } from './helpers.js';
import type { Dependencies } from '../src/analyze.js';
function setup() {
  let state: RunState | null = null; const records: CompletedDomain[] = []; let summary = ''; let requests = 0;
  const source = { url: '', fetchedAt: NOW, dataDate: NOW, state: 'fresh' as const, cacheAgeSeconds: 0 };
  const deps = (): Dependencies => ({ now: clock, metrics: new Metrics(), dns: { resolve: async () => ({ ips: ['8.8.8.8'], warnings: [], partial: false }) },
    shodan: { host: async () => { requests++; return normalizeHost(hostRaw(), '8.8.8.8', NOW, 20); }, related: async () => ({ ips: [], warnings: [], truncated: false }) },
    kev: { get: async () => ({ entries: parseKev(kevRaw).entries, source, warnings: [] }) },
    epss: { get: async () => ({ entries: parseEpss(epssRaw, [CVE]), sources: { [CVE]: source }, warnings: [] }) } });
  const sink: PortfolioSink = { state: async () => state, saveState: async s => { state = structuredClone(s); },
    completed: async () => structuredClone(records), push: async r => { records.push(structuredClone(r)); }, summary: async s => { summary = s; } };
  return { deps, sink, records, getSummary: () => summary, getRequests: () => requests };
}
const input = parseInput({ domains: ['a.example.com','b.example.com','c.example.com'] });
test('interruption preserves completed domains and resume skips only committed Dataset rows', async () => {
  const f = setup();
  await assert.rejects(runPortfolio(input, f.deps(), f.sink, [], () => f.records.length === 1), InterruptedRun);
  assert.equal(f.records.length, 1); assert.match(f.getSummary(), /a.example.com/);
  const deps = f.deps(); const r = await runPortfolio(input, deps, f.sink);
  assert.equal(r.completed, 3); assert.equal(r.resumed, 1); assert.equal(f.getRequests(), 3);
  assert.equal(deps.metrics.counts.domainsAnalyzed, 3); assert.equal(deps.metrics.snapshot().usageMayBeIncomplete, true);
  assert.match(f.getSummary(), /c.example.com/);
});
test('write succeeded but acknowledgement/checkpoint failed: restart does not append it again', async () => {
  const f = setup(); const push = f.sink.push; let fail = true;
  f.sink.push = async r => { await push(r); if (fail) { fail = false; throw new Error('lost acknowledgement'); } };
  await assert.rejects(runPortfolio(input, f.deps(), f.sink)); assert.equal(f.records.length, 1);
  await runPortfolio(input, f.deps(), f.sink);
  assert.equal(f.records.length, 3); assert.equal(f.getRequests(), 3);
});
test('write failed before commit: resume reassesses uncommitted domain', async () => {
  const f = setup(); const push = f.sink.push; f.sink.push = async () => { throw new Error('storage unavailable'); };
  await assert.rejects(runPortfolio(input, f.deps(), f.sink)); assert.equal(f.records.length, 0);
  f.sink.push = push; await runPortfolio(input, f.deps(), f.sink);
  assert.equal(f.records.length, 3); assert.equal(f.getRequests(), 4);
});
test('changed input, duplicate rows and unrecognized storage cannot be silently resumed', async () => {
  const f = setup(); await runPortfolio(input, f.deps(), f.sink);
  await assert.rejects(runPortfolio(parseInput({ domain: 'different.example.com' }), f.deps(), f.sink));
  f.records.push(f.records[0]); await assert.rejects(runPortfolio(input, f.deps(), f.sink));
  f.sink.state = async () => null; await assert.rejects(runPortfolio(input, f.deps(), f.sink));
});
test('input fingerprint never depends on credentials, and a finished restart performs no lookups', async () => {
  assert.equal(inputFingerprint({ ...input, shodanApiKey: 'first-secret' }), inputFingerprint({ ...input, shodanApiKey: 'second-secret' }));
  const f = setup(); await runPortfolio(input, f.deps(), f.sink); await runPortfolio(input, f.deps(), f.sink);
  assert.equal(f.getRequests(), 3); assert.equal(f.records.length, 3);
});
