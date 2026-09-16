import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeDomain } from '../src/analyze.js';
import { parseInput } from '../src/input.js';
import { normalizeHost } from '../src/providers/shodan.js';
import { parseKev } from '../src/providers/cisa-kev.js';
import { parseEpss } from '../src/providers/epss.js';
import { clock, NOW, CVE, hostRaw, kevRaw, epssRaw, resources } from './helpers.js';
// Scenarios exercise uncertainty, not factual intelligence about these fictional products.
const scenarios = [
  { name: 'shared CDN with unrelated hostnames', patch: { hostnames: ['tenant.unrelated.example'] }, data: {}, expected: 'HIGH_PRIORITY', evidenceScope: 'service' },
  { name: 'stale VPN association', patch: {}, data: { timestamp: '2025-01-01T00:00:00Z' }, expected: 'MEDIUM_PRIORITY', evidenceScope: 'service' },
  { name: 'banner could represent a backported patch', patch: {}, data: { product: 'Example enterprise Linux TLS', version: '1.0-vendorpatch' }, expected: 'HIGH_PRIORITY', evidenceScope: 'service' },
  { name: 'product family only creates no CVE', patch: {}, data: { product: 'Example Gateway', version: undefined, vulns: {} }, expected: 'INFORMATIONAL', evidenceScope: 'service' },
  { name: 'invalid calendar timestamp', patch: {}, data: { timestamp: '2026-02-30T12:00:00Z' }, expected: 'MEDIUM_PRIORITY', evidenceScope: 'service' },
  { name: 'unverified provider flag is not a vulnerability confirmation', patch: {}, data: { vulns: { [CVE]: { verified: false } } }, expected: 'HIGH_PRIORITY', evidenceScope: 'service' },
];
for (const scenario of scenarios) test(`uncertainty scenario: ${scenario.name}`, async () => {
  const { metrics } = resources(); const raw = hostRaw({ ...scenario.patch, data: [{ ...hostRaw().data[0], ...scenario.data }] });
  const source = { url: '', fetchedAt: NOW, dataDate: NOW, state: 'fresh' as const, cacheAgeSeconds: 0 };
  const r = await analyzeDomain('example.com', parseInput({ domain: 'example.com' }), { metrics, now: clock,
    dns: { resolve: async () => ({ ips: ['8.8.8.8'], warnings: [], partial: false }) },
    shodan: { host: async () => normalizeHost(raw, '8.8.8.8', NOW, 200), related: async () => ({ ips: [], warnings: [], truncated: false }) },
    kev: { get: async () => ({ entries: parseKev(kevRaw).entries, source, warnings: [] }) },
    epss: { get: async () => ({ entries: parseEpss(epssRaw, [CVE]), sources: { [CVE]: source }, warnings: [] }) },
  });
  const f = r.priorities[0]; assert.equal(f.priority, scenario.expected);
  assert.notEqual(f.priority, 'CRITICAL_PRIORITY'); assert.notEqual(f.applicability, 'CONFIRMED_VULNERABLE');
  assert.equal(f.evidence[0].details.applicabilityVerified, false); assert.equal(f.evidence[0].details.scope, scenario.evidenceScope);
  assert.match(r.warnings.join(' '), /do not prove ownership/);
});
