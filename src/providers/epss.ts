import type { JsonHttp } from '../http.js';
import { ProviderError } from '../http.js';
import type { Metrics } from '../metrics.js';
import { PublicCache, DAY_MS, type CacheEntry } from '../cache.js';
import type { EpssEntry, SourceInfo } from '../models.js';
import { obj, cveId, date } from './parse.js';
export const EPSS_URL = 'https://api.first.org/data/v1/epss';
const valid = (v: unknown): v is EpssEntry => {
  const r = obj(v);
  return !!cveId(r.cve) && typeof r.probability === 'number' && Number.isFinite(r.probability) && r.probability >= 0 && r.probability <= 1 &&
    typeof r.percentile === 'number' && Number.isFinite(r.percentile) && r.percentile >= 0 && r.percentile <= 1 && !!date(r.date);
};
export function parseEpss(raw: unknown, requested: string[]): Record<string, EpssEntry> {
  const r = obj(raw);
  if (!Array.isArray(r.data) || r.status !== 'OK') throw new ProviderError('epss', 'INVALID_RESPONSE');
  const entries: Record<string, EpssEntry> = {};
  for (const row of r.data) {
    const v = obj(row); const cve = cveId(v.cve);
    const entry = { cve, probability: v.epss === '' || v.epss == null ? NaN : Number(v.epss), percentile: v.percentile === '' || v.percentile == null ? NaN : Number(v.percentile), date: v.date };
    if (!valid(entry) || !requested.includes(entry.cve)) throw new ProviderError('epss', 'INVALID_RESPONSE');
    entries[entry.cve] = entry;
  }
  return entries;
}
export class EpssProvider {
  private memory = new Map<string, { entry: CacheEntry<EpssEntry> | null; source: SourceInfo }>();
  constructor(private http: JsonHttp, private cache: PublicCache, private metrics: Metrics, private now: () => Date = () => new Date()) {}
  private isDataRecent(entry: EpssEntry) {
    const age = this.now().getTime() - Date.parse(entry.date);
    return age >= 0 && age < 3 * DAY_MS;
  }
  async get(cves: string[]) {
    const entries: Record<string, EpssEntry> = {}; const sources: Record<string, SourceInfo> = {}; const warnings: string[] = [];
    const unique = [...new Set(cves)].sort();
    const pending: string[] = []; const cached = new Map<string, CacheEntry<EpssEntry> | null>();
    for (const cve of unique) {
      if (this.memory.has(cve)) { this.metrics.counts.cacheHits++; continue; }
      const entry = await this.cache.read(`EPSS-v1-${cve}`, valid);
      if (this.cache.fresh(entry) && entry!.value.cve === cve && this.isDataRecent(entry!.value)) {
        this.metrics.counts.cacheHits++; this.memory.set(cve, { entry, source: this.cache.info(entry, EPSS_URL, entry!.value.date) });
      } else { this.metrics.counts.cacheMisses++; pending.push(cve); cached.set(cve, entry?.value.cve === cve ? entry : null); }
    }
    // 50 CVEs stays below FIRST's 2,000-character query limit even for long IDs.
    for (let i = 0; i < pending.length; i += 50) {
      const batch = pending.slice(i, i + 50);
      try {
        const url = `${EPSS_URL}?${new URLSearchParams({ cve: batch.join(','), limit: '100' })}`;
        const values = parseEpss(await this.http.get(url, 'epss'), batch);
        for (const cve of batch) {
          const value = values[cve];
          const entry = value ? await this.cache.write(`EPSS-v1-${cve}`, value) : null;
          const source = this.cache.info(entry, EPSS_URL, value?.date ?? null, !!value && !this.isDataRecent(value));
          this.memory.set(cve, { entry, source });
        }
      } catch {
        this.metrics.error('epss.UNAVAILABLE');
        for (const cve of batch) {
          let entry = cached.get(cve) ?? null;
          if (entry && (this.now().getTime() - Date.parse(entry.fetchedAt) > 7 * DAY_MS || this.now().getTime() - Date.parse(entry.value.date) > 7 * DAY_MS || Date.parse(entry.value.date) > this.now().getTime())) entry = null;
          if (entry) this.metrics.counts.cacheStaleFallbacks++;
          this.memory.set(cve, { entry, source: this.cache.info(entry, EPSS_URL, entry?.value.date ?? null, true) });
        }
      }
    }
    for (const cve of unique) {
      const result = this.memory.get(cve)!;
      if (result.entry) entries[cve] = result.entry.value;
      sources[cve] = result.source;
    }
    if (Object.values(sources).some(s => s.state === 'unavailable')) warnings.push('EPSS is unavailable or has no score for some CVEs; missing scores are unknown, not zero.');
    if (Object.values(sources).some(s => s.state === 'stale')) warnings.push('Some EPSS scores are stale; they are shown for context and do not raise priority.');
    return { entries, sources, warnings };
  }
}
