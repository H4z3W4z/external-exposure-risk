import { mkdir, writeFile } from 'node:fs/promises';
import { analyzeDomain } from '../src/analyze.js';
import { parseInput } from '../src/input.js';
import { normalizeHost } from '../src/providers/shodan.js';
import { parseKev } from '../src/providers/cisa-kev.js';
import { parseEpss } from '../src/providers/epss.js';
import { Metrics } from '../src/metrics.js';
import { CVE, NOW, clock, hostRaw, kevRaw, epssRaw } from '../tests/helpers.js';

// Fully synthetic, reserved documentation address; no DNS or HTTP requests.
const ip = '203.0.113.10'; const raw = hostRaw(); raw.ip_str = ip; raw.data[0].ip_str = ip;
const metrics = new Metrics(); metrics.counts.domainsSubmitted = 1; metrics.counts.domainsUnique = 1;
const record = await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), {
  dns: { resolve: async () => ({ ips: [ip], warnings: ['SYNTHETIC DEMO: no network calls were made; this is not an assessment of example.com or a real CVE.'], partial: false }) },
  shodan: { host: async () => normalizeHost(raw, ip, NOW, 200), related: async () => ({ ips: [], warnings: [], truncated: false }) },
  kev: { get: async () => ({ entries: parseKev(kevRaw).entries, source: { url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', fetchedAt: NOW, dataDate: NOW, state: 'fresh', cacheAgeSeconds: 0 }, warnings: [] }) },
  epss: { get: async () => ({ entries: parseEpss(epssRaw, [CVE]), sources: { [CVE]: { url: 'https://api.first.org/data/v1/epss', fetchedAt: NOW, dataDate: '2026-09-15', state: 'fresh', cacheAgeSeconds: 0 } }, warnings: [] }) }, metrics, now: clock,
});
await mkdir('examples', { recursive: true });
await writeFile('examples/synthetic-output.json', JSON.stringify(record, null, 2) + '\n');
await writeFile('examples/synthetic-summary.txt', record.humanSummary + '\n');
console.log(record.humanSummary);
