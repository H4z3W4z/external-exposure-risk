import type { Intelligence, ServiceObservation } from '../src/models.js';
import { Metrics } from '../src/metrics.js';
import { MemoryCache, PublicCache } from '../src/cache.js';
import type { JsonHttp, ProviderName } from '../src/http.js';
export const NOW = '2026-09-15T12:00:00.000Z';
export const clock = () => new Date(NOW);
export const CVE = 'CVE-2024-0001';
export const kevRaw = { dateReleased: '2026-09-15T00:00:00Z', vulnerabilities: [{ cveID: CVE, vendorProject: 'Example', product: 'Example Gateway', vulnerabilityName: 'Synthetic test vulnerability', dateAdded: '2026-09-14', dueDate: '2026-10-01', knownRansomwareCampaignUse: 'Known', requiredAction: 'Follow vendor guidance.', notes: 'Synthetic fixture; not intelligence about a real CVE.' }] };
export const epssRaw = { status: 'OK', data: [{ cve: CVE, epss: '0.968', percentile: '0.99', date: '2026-09-15' }] };
export function service(overrides: Partial<ServiceObservation> = {}): ServiceObservation {
  return { ip: '8.8.8.8', port: 443, transport: 'tcp', protocol: 'https', hostnames: ['vpn.example.com'], product: 'Example Gateway', version: '1.2.3', cpe: ['cpe:/a:example:gateway:1.2.3'], observedAt: '2026-09-14T12:00:00.000Z', fetchedAt: NOW, associations: [{ cve: CVE, providerVerified: true }], scope: 'service', conflictingEvidence: false, ...overrides };
}
export function hostRaw(overrides: Record<string, unknown> = {}) {
  return { ip_str: '8.8.8.8', hostnames: ['vpn.example.com'], org: 'Synthetic Example', asn: 'AS15169', last_update: '2026-09-14T12:00:00', data: [{ ip_str: '8.8.8.8', port: 443, transport: 'tcp', product: 'Example Gateway', version: '1.2.3', cpe: ['cpe:/a:example:gateway:1.2.3'], timestamp: '2026-09-14T12:00:00', vulns: { [CVE]: { verified: true } } as Record<string, { verified: boolean }> }], ...overrides };
}
export function intelligence(): Intelligence {
  return { kev: {}, epss: {}, kevSource: { url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', fetchedAt: NOW, dataDate: NOW, state: 'fresh', cacheAgeSeconds: 0 }, epssSources: {}, warnings: [] };
}
export class FakeHttp implements JsonHttp {
  calls: { url: string; provider: ProviderName }[] = [];
  constructor(public respond: (url: string, provider: ProviderName) => unknown | Promise<unknown>) {}
  async get(url: string, provider: ProviderName) { this.calls.push({ url, provider }); return this.respond(url, provider); }
}
export function resources() {
  const metrics = new Metrics(); const store = new MemoryCache(); const cache = new PublicCache(store, metrics, clock);
  return { metrics, store, cache };
}
