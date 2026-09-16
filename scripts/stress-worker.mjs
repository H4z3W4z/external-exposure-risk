import { writeFile } from 'node:fs/promises';
import { parseInput } from '../dist/input.js';
import { Metrics } from '../dist/metrics.js';
import { HttpClient } from '../dist/http.js';
import { PublicCache, MemoryCache } from '../dist/cache.js';
import { ShodanProvider } from '../dist/providers/shodan.js';
import { KevProvider } from '../dist/providers/cisa-kev.js';
import { EpssProvider } from '../dist/providers/epss.js';
import { runPortfolio } from '../dist/portfolio.js';
import { MAX_RECORD_BYTES, recordBytes } from '../dist/output.js';

const profiles = {
  shared: { domains: 100, ips: 1, services: 20, cves: 10, shared: true, wide: false },
  diverse: { domains: 100, ips: 4, services: 40, cves: 50, shared: false, wide: false },
  oversized: { domains: 2, ips: 2, services: 200, cves: 100, shared: false, wide: true },
  epss_churn: { domains: 6, ips: 1, services: 1, cves: 2000, shared: false, wide: false, uniqueCves: true },
};
const name = process.argv[2]; const profile = profiles[name];
if (!profile) throw new Error('Choose shared, diverse, oversized, or epss_churn.');
const started = performance.now();
const now = () => new Date('2026-09-15T12:00:00Z');
const cves = Array.from({ length: profile.cves }, (_, n) => `CVE-2024-${10000 + n}`);
let wireCalls = 0;
const mockFetch = async url => {
  wireCalls++;
  const u = new URL(url);
  let value;
  if (u.hostname === 'api.shodan.io') {
    const ip = u.pathname.split('/').at(-1);
    const hostCves = profile.uniqueCves ? Array.from({ length: profile.cves }, (_, n) => `CVE-2024-${10000 + Number(ip.split('.')[1]) * 2000 + n}`) : cves;
    value = { ip_str: ip, hostnames: ['synthetic.example.com'], org: 'Synthetic', last_update: '2026-09-14T12:00:00Z',
      data: Array.from({ length: profile.services }, (_, n) => ({ ip_str: ip, port: n + 1, transport: 'tcp',
        product: profile.wide ? 'Synthetic gateway ' + '界'.repeat(1000) : 'Synthetic gateway', version: '1.0',
        cpe: profile.wide ? Array.from({ length: 24 }, (_, c) => `cpe:/a:synthetic:gateway_${c}:${'x'.repeat(500)}`) : ['cpe:/a:synthetic:gateway:1.0'],
        timestamp: '2026-09-14T12:00:00Z', vulns: Object.fromEntries(hostCves.map(cve => [cve, { verified: true }])) })) };
  } else if (u.hostname === 'www.cisa.gov') value = { dateReleased: '2026-09-15T00:00:00Z', vulnerabilities: cves.slice(0, 2).map(cve => ({ cveID: cve, vendorProject: 'Synthetic', product: 'Synthetic gateway', dateAdded: '2026-09-14', requiredAction: 'Synthetic fixture only.' })) };
  else if (u.hostname === 'api.first.org') value = { status: 'OK', data: u.searchParams.get('cve').split(',').map(cve => ({ cve, epss: '0.95', percentile: '0.99', date: '2026-09-15' })) };
  else throw new Error('No real network calls are allowed in this stress test.');
  return new Response(JSON.stringify(value));
};
const metrics = new Metrics();
const http = new HttpClient(metrics, mockFetch, async () => {}, 0);
const cache = new PublicCache(new MemoryCache(), metrics, now);
const input = parseInput({ domains: Array.from({ length: profile.domains }, (_, i) => `d${String(i).padStart(3, '0')}.example.com`) });
const deps = { metrics, now, shodan: new ShodanProvider(http, 'synthetic-stress-secret', metrics, now),
  kev: new KevProvider(http, cache, metrics, now), epss: new EpssProvider(http, cache, metrics, now),
  dns: { resolve: async domain => { metrics.counts.dnsOperations += 2; const n = Number(domain.slice(1, 4)); return {
    ips: Array.from({ length: profile.ips }, (_, i) => profile.shared ? '8.8.8.8' : `8.${n + 1}.0.${i + 1}`), warnings: ['Synthetic stress fixture; no real DNS or provider traffic.'], partial: false }; } } };
let state = null; const rows = []; let maxBytes = 0; let totalBytes = 0; let findingsAssessed = 0; let findingsRetained = 0;
let truncatedRecords = 0; let analysisLimited = 0;
await runPortfolio(input, deps, {
  state: async () => state, saveState: async value => { state = value; }, completed: async () => rows,
  summary: async () => {},
  push: async record => {
    const bytes = recordBytes(record);
    if (bytes !== Buffer.byteLength(JSON.stringify(record)) || bytes > MAX_RECORD_BYTES) throw new Error('Serialized output exceeded its budget or reported size incorrectly.');
    if (record.priorities.some(f => !f.evidence.length || f.applicability === 'CONFIRMED_VULNERABLE')) throw new Error('Evidence/accuracy invariant failed.');
    maxBytes = Math.max(maxBytes, bytes); totalBytes += bytes;
    findingsAssessed += record.output.findingsAssessed; findingsRetained += record.output.findingsRetained;
    if (record.output.truncated) truncatedRecords++;
    if (record.output.analysisLimited) analysisLimited++;
    rows.push({ domain: record.domain, humanSummary: record.humanSummary, summary: record.summary });
  },
}, ['synthetic-stress-secret']);
const diagnostics = metrics.snapshot();
if (rows.length !== profile.domains || Object.keys(diagnostics.errors).length) throw new Error('Portfolio completion or error invariant failed.');
if (profile.shared && diagnostics.shodanRequests !== 1) throw new Error('Shared IP cache invariant failed.');
if (profile.wide && !truncatedRecords) throw new Error('Oversized fixture failed to exercise truncation.');
const report = { profile: name, synthetic: true, networkRequests: 0, wireCalls, rateLimitSleepsSkipped: true,
  limitation: 'Core pipeline with synthetic DNS/HTTP/storage; runtime is not live throughput or an Apify bill.',
  domainsCompleted: rows.length, wallSeconds: +( (performance.now() - started) / 1000).toFixed(3),
  maxRecordBytes: maxBytes, totalRecordBytes: totalBytes, findingsAssessed, findingsRetained, truncatedRecords, analysisLimited, diagnostics };
if (process.env.STRESS_REPORT) await writeFile(process.env.STRESS_REPORT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
