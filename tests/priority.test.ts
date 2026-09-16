import test from 'node:test';
import assert from 'node:assert/strict';
import { prioritize } from '../src/priority.js';
import { parseInput } from '../src/input.js';
import { parseKev } from '../src/providers/cisa-kev.js';
import { service, intelligence, NOW, CVE, kevRaw } from './helpers.js';
const input = parseInput({ domain: 'example.com' });
test('exact KEV association is high, not a claim of confirmed vulnerability', () => {
  const intel = intelligence(); intel.kev = parseKev(kevRaw).entries;
  const [finding] = prioritize('example.com', service(), intel, input, NOW);
  assert.equal(finding.priority, 'HIGH_PRIORITY'); assert.equal(finding.confidence, 'HIGH');
  assert.equal(finding.applicability, 'ASSOCIATED'); assert.equal(finding.knownRansomwareUse, true);
  assert.equal(finding.evidence[0].details.applicabilityVerified, false);
  assert.equal(finding.evidence[1].details.dateAdded, '2026-09-14');
});
test('unknown ransomware use is null, never false', () => {
  const intel = intelligence(); intel.kev = parseKev(kevRaw).entries; intel.kev[CVE].knownRansomwareCampaignUse = 'Unknown';
  assert.equal(prioritize('example.com', service(), intel, input, NOW)[0].knownRansomwareUse, null);
});
test('stale, missing/future timestamps, conflicting and host-only KEV remain medium/low confidence', () => {
  const intel = intelligence(); intel.kev = parseKev(kevRaw).entries;
  for (const s of [service({ observedAt: '2025-01-01T00:00:00Z' }), service({ observedAt: null }), service({ observedAt: '2027-01-01T00:00:00Z' }), service({ conflictingEvidence: true }), service({ scope: 'host', port: null })]) {
    const [f] = prioritize('example.com', s, intel, input, NOW);
    assert.equal(f.priority, 'MEDIUM_PRIORITY'); assert.equal(f.confidence, 'LOW');
  }
});
test('incomplete version with exact KEV remains high investigation priority', () => {
  const intel = intelligence(); intel.kev = parseKev(kevRaw).entries;
  assert.equal(prioritize('example.com', service({ version: null }), intel, input, NOW)[0].priority, 'HIGH_PRIORITY');
});
test('high EPSS needs fresh score and credible product/version; percentile is not probability', () => {
  const intel = intelligence(); intel.epss[CVE] = { cve: CVE, probability: 0.95, percentile: 0.999, date: '2026-09-15' };
  intel.epssSources[CVE] = { url: '', fetchedAt: NOW, dataDate: '2026-09-15', state: 'fresh', cacheAgeSeconds: 0 };
  assert.equal(prioritize('example.com', service(), intel, input, NOW)[0].priority, 'HIGH_PRIORITY');
  assert.equal(prioritize('example.com', service({ version: null }), intel, input, NOW)[0].priority, 'MEDIUM_PRIORITY');
  assert.equal(prioritize('example.com', service({ product: null }), intel, input, NOW)[0].priority, 'MEDIUM_PRIORITY');
  intel.epssSources[CVE].state = 'stale';
  assert.equal(prioritize('example.com', service(), intel, input, NOW)[0].priority, 'MEDIUM_PRIORITY');
  intel.epssSources[CVE].state = 'fresh'; intel.epss[CVE].probability = 0.001;
  assert.equal(prioritize('example.com', service(), intel, input, NOW)[0].priority, 'MEDIUM_PRIORITY');
});
test('missing intelligence remains null, and a clean fresh catalog means non-KEV', () => {
  const intel = intelligence();
  assert.equal(prioritize('example.com', service(), intel, input, NOW)[0].cisaKev, false);
  intel.kevSource.state = 'unavailable';
  const [f] = prioritize('example.com', service(), intel, input, NOW);
  assert.equal(f.cisaKev, null); assert.equal(f.epss, null);
  intel.kevSource.state = 'stale';
  assert.equal(prioritize('example.com', service(), intel, input, NOW)[0].cisaKev, null);
});
test('product names alone never create CVE matches', () => {
  const intel = intelligence(); intel.kev = parseKev(kevRaw).entries;
  const [f] = prioritize('example.com', service({ associations: [] }), intel, input, NOW);
  assert.equal(f.priority, 'INFORMATIONAL'); assert.equal(f.cve, null); assert.equal(f.cisaKev, null);
  assert.equal(prioritize('example.com', service({ associations: [], product: null }), intel, input, NOW)[0].priority, 'INSUFFICIENT_EVIDENCE');
});
test('fixed input, observations and clock give deterministic findings', () => {
  assert.deepEqual(prioritize('example.com', service(), intelligence(), input, NOW), prioritize('example.com', service(), intelligence(), input, NOW));
});
