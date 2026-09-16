import { isIP } from 'node:net';
import type { JsonHttp } from '../http.js';
import { ProviderError } from '../http.js';
import type { Metrics } from '../metrics.js';
import { obj, str, strings, cveId, timestamp } from './parse.js';
import type { Asset, ServiceObservation, VulnerabilityAssociation } from '../models.js';
import { publicIp, canonicalIp } from '../discovery/dns.js';

export interface HostResult { asset: Asset | null; warnings: string[]; truncated: boolean }
export interface RelatedResult { ips: string[]; warnings: string[]; truncated: boolean }
export interface ExposureProvider {
  host(ip: string, maxServices: number): Promise<HostResult>;
  related(domain: string): Promise<RelatedResult>;
}
export function associations(v: unknown): VulnerabilityAssociation[] {
  const values: [string, unknown][] = Array.isArray(v) ? v.map(c => [String(c), null]) : Object.entries(obj(v));
  const found = new Map<string, boolean | null>();
  for (const [key, details] of values) {
    const cve = cveId(key); if (!cve) continue;
    const verified = obj(details).verified;
    found.set(cve, typeof verified === 'boolean' ? verified : null);
  }
  return [...found].sort(([a], [b]) => a.localeCompare(b)).map(([cve, providerVerified]) => ({ cve, providerVerified }));
}
export function normalizeHost(raw: unknown, ip: string, fetchedAt: string, maxServices: number): HostResult {
  const host = obj(raw);
  if (!canonicalIp(ip) || canonicalIp(host.ip_str) !== canonicalIp(ip) || !Array.isArray(host.data)) throw new ProviderError('shodan', 'INVALID_RESPONSE');
  const warnings: string[] = []; const groups = new Map<string, ServiceObservation[]>();
  for (const row of host.data) {
    const r = obj(row);
    if (typeof r.port !== 'number' || !Number.isInteger(r.port) || r.port < 1 || r.port > 65535 || (r.ip_str && canonicalIp(r.ip_str) !== canonicalIp(ip))) {
      warnings.push('A malformed Shodan service was excluded.'); continue;
    }
    const transport = ['tcp','udp'].includes(String(r.transport)) ? String(r.transport) : null;
    const s: ServiceObservation = { ip, port: r.port, transport, protocol: str(obj(r._shodan).module),
      hostnames: strings(r.hostnames), product: str(r.product), version: str(r.version),
      cpe: [...new Set([...strings(r.cpe), ...strings(r.cpe23)])].sort(),
      observedAt: timestamp(r.timestamp), fetchedAt, associations: associations(r.vulns), scope: 'service', conflictingEvidence: false };
    const key = `${s.port}/${s.transport}`;
    groups.set(key, [...(groups.get(key) ?? []), s]);
  }
  const all = [...groups.values()].map(rows => {
    rows.sort((a, b) => (b.observedAt ?? '').localeCompare(a.observedAt ?? '') || JSON.stringify(a).localeCompare(JSON.stringify(b)));
    const newest = rows[0];
    // Do not carry CVEs forward from older banners. Equal-time disagreements are retained as low confidence.
    const peers = rows.filter(r => r.observedAt === newest.observedAt);
    const conflict = peers.some(r => r.product !== newest.product || r.version !== newest.version || JSON.stringify(r.cpe) !== JSON.stringify(newest.cpe) || JSON.stringify(r.associations) !== JSON.stringify(newest.associations));
    if (conflict) warnings.push('Conflicting observations at the same endpoint and timestamp; selected deterministically and reduced confidence.');
    return { ...newest, conflictingEvidence: conflict };
  }).sort((a, b) => a.port! - b.port! || (a.transport ?? '').localeCompare(b.transport ?? ''));
  const truncated = all.length > maxServices;
  if (truncated) warnings.push('Service limit reached; remaining services were not assessed.');
  const services = all.slice(0, maxServices);
  const located = new Set(all.flatMap(s => s.associations.map(a => a.cve)));
  const unlocated = associations(host.vulns).filter(a => !located.has(a.cve));
  const hostAssociations: ServiceObservation | null = unlocated.length ? {
    ip, port: null, transport: null, protocol: null, hostnames: strings(host.hostnames), product: null,
    version: null, cpe: [], observedAt: timestamp(host.last_update), fetchedAt,
    associations: unlocated, scope: 'host', conflictingEvidence: false,
  } : null;
  if (hostAssociations) warnings.push('Host-level CVE associations have no reliable port/product attribution and remain low confidence.');
  if (!services.length && !hostAssociations) return { asset: null, warnings, truncated };
  return { asset: { ip, attribution: [], hostnames: strings(host.hostnames), organization: str(host.org), asn: str(host.asn), isp: str(host.isp),
    location: { country: str(host.country_name), region: str(host.region_code), city: str(host.city) }, services, hostAssociations }, warnings, truncated };
}
export class ShodanProvider implements ExposureProvider {
  // Per-instance run cache only: never share customer observations/credentials between runs.
  private cache = new Map<string, HostResult>();
  private disabled: ProviderError | null = null;
  constructor(private http: JsonHttp, private key: string, private metrics: Metrics, private now: () => Date = () => new Date()) {}
  private async get(path: string, params: Record<string, string> = {}) {
    if (this.disabled) throw this.disabled;
    const url = new URL(path, 'https://api.shodan.io');
    url.search = new URLSearchParams({ ...params, key: this.key }).toString();
    try { return await this.http.get(url.toString(), 'shodan'); }
    catch (e) {
      if (e instanceof ProviderError && [401, 403, 429].includes(e.status ?? 0)) this.disabled = e;
      throw e;
    }
  }
  async host(ip: string, maxServices: number): Promise<HostResult> {
    if (!isIP(ip) || !publicIp(ip)) throw new ProviderError('shodan', 'NON_PUBLIC_IP');
    const key = `${ip}:${maxServices}`;
    if (this.cache.has(key)) { this.metrics.counts.cacheHits++; return structuredClone(this.cache.get(key)!); }
    this.metrics.counts.cacheMisses++;
    try {
      const raw = await this.get(`/shodan/host/${encodeURIComponent(ip)}`, { history: 'false', minify: 'false' });
      const normalized = normalizeHost(raw, ip, this.now().toISOString(), maxServices);
      this.metrics.counts.shodanResultsConsumed += Array.isArray(obj(raw).data) ? (obj(raw).data as unknown[]).length : 0;
      this.cache.set(key, normalized);
      return structuredClone(normalized);
    } catch (e) {
      if (e instanceof ProviderError && e.status === 404) {
        const empty = { asset: null, warnings: ['Shodan has no existing observations for a resolved IP. No-data does not mean safe.'], truncated: false };
        this.cache.set(key, empty); return structuredClone(empty);
      }
      throw e;
    }
  }
  async related(domain: string): Promise<RelatedResult> {
    const raw = obj(await this.get('/shodan/host/search', { query: `hostname:"${domain}"`, page: '1', minify: 'true' }));
    if (!Array.isArray(raw.matches)) throw new ProviderError('shodan', 'INVALID_SEARCH_RESPONSE');
    this.metrics.counts.shodanSearchPages++;
    this.metrics.counts.shodanResultsConsumed += raw.matches.length;
    const ips = raw.matches.filter(row => strings(obj(row).hostnames).some(h => { const n = h.toLowerCase().replace(/\.$/, ''); return n === domain || n.endsWith(`.${domain}`); }))
      .map(row => canonicalIp(obj(row).ip_str)).filter((ip): ip is string => !!ip && publicIp(ip));
    const truncated = typeof raw.total === 'number' && raw.total > raw.matches.length;
    return { ips: [...new Set(ips)].sort(), truncated,
      warnings: ['Related hosts are based on historical Shodan hostnames, not proven ownership.', ...(truncated ? ['Related-host search limited to its first page; discovery is incomplete.'] : [])] };
  }
}
