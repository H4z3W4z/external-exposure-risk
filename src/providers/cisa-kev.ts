import type { JsonHttp } from '../http.js';
import { ProviderError } from '../http.js';
import type { Metrics } from '../metrics.js';
import { PublicCache, DAY_MS } from '../cache.js';
import type { KevEntry, SourceInfo } from '../models.js';
import { obj, cveId, str, date } from './parse.js';
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
interface Catalog { entries: Record<string, KevEntry>; dateReleased: string }
export function parseKev(raw: unknown): Catalog {
  const r = obj(raw);
  if (!Array.isArray(r.vulnerabilities) || !r.vulnerabilities.length || !str(r.dateReleased) || !Number.isFinite(Date.parse(String(r.dateReleased)))) throw new ProviderError('kev', 'INVALID_CATALOG');
  const entries: Record<string, KevEntry> = {};
  for (const row of r.vulnerabilities) {
    const v = obj(row); const cve = cveId(v.cveID);
    if (!cve || !str(v.vendorProject) || !str(v.product) || !date(v.dateAdded)) throw new ProviderError('kev', 'INVALID_CATALOG');
    entries[cve] = { cve, vendorProject: str(v.vendorProject)!, product: str(v.product)!, vulnerabilityName: str(v.vulnerabilityName) ?? '',
      dateAdded: date(v.dateAdded)!, dueDate: date(v.dueDate) ?? '', knownRansomwareCampaignUse: str(v.knownRansomwareCampaignUse) ?? 'Unknown',
      requiredAction: str(v.requiredAction) ?? '', notes: str(v.notes) ?? '' };
  }
  return { entries, dateReleased: String(r.dateReleased) };
}
const validCatalog = (v: unknown): v is Catalog => {
  const r = obj(v); const entries = obj(r.entries);
  return typeof r.dateReleased === 'string' && Number.isFinite(Date.parse(r.dateReleased)) && Object.keys(entries).length > 0 &&
    Object.entries(entries).every(([key, val]) => cveId(key) === key && obj(val).cve === key && typeof obj(val).product === 'string' && !!date(obj(val).dateAdded));
};
export class KevProvider {
  private result?: { entries: Record<string, KevEntry>; source: SourceInfo; warnings: string[] };
  constructor(private http: JsonHttp, private cache: PublicCache, private metrics: Metrics, private now: () => Date = () => new Date()) {}
  async get() {
    if (this.result) return this.result;
    let entry = await this.cache.read('KEV-v1', validCatalog);
    let stale = false; const warnings: string[] = [];
    if (this.cache.fresh(entry)) this.metrics.counts.cacheHits++;
    else {
      this.metrics.counts.cacheMisses++;
      try { entry = await this.cache.write('KEV-v1', parseKev(await this.http.get(KEV_URL, 'kev'))); }
      catch {
        this.metrics.error('kev.UNAVAILABLE');
        if (entry && this.now().getTime() - Date.parse(entry.fetchedAt) <= 7 * DAY_MS) {
          stale = true; this.metrics.counts.cacheStaleFallbacks++; warnings.push('CISA KEV refresh failed; using a stale cached catalog (at most seven days old). Missing matches are not reliable.');
        } else { entry = null; warnings.push('CISA KEV unavailable; KEV status is unknown, not false.'); }
      }
    }
    const source = this.cache.info(entry, KEV_URL, entry?.value.dateReleased ?? null, stale);
    this.result = { entries: entry?.value.entries ?? {}, source, warnings };
    return this.result;
  }
}
