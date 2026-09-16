export class Metrics {
  private start = performance.now();
  private priorRuntime = 0;
  private priorPeak = 0;
  resumed = false;
  counts = { domainsSubmitted: 0, domainsUnique: 0, domainsAnalyzed: 0, domainsWithObservations: 0,
    shodanRequests: 0, shodanResultsConsumed: 0, shodanSearchPages: 0, dnsOperations: 0,
    kevRefreshes: 0, epssRequests: 0, cveRequests: 0, cacheHits: 0, cacheMisses: 0,
    cacheStaleFallbacks: 0, cacheEvictions: 0, retries: 0, domainsResumed: 0, recordsTruncated: 0 };
  errors: Record<string, number> = {};
  error(code: string) { this.errors[code] = (this.errors[code] ?? 0) + 1; }
  restore(raw: unknown) {
    if (!raw || typeof raw !== 'object') return;
    const r = raw as Record<string, unknown>;
    for (const k of Object.keys(this.counts) as (keyof typeof this.counts)[]) {
      if (typeof r[k] === 'number' && Number.isSafeInteger(r[k]) && r[k] >= 0) this.counts[k] = r[k];
    }
    if (typeof r.runtimeSeconds === 'number' && Number.isFinite(r.runtimeSeconds) && r.runtimeSeconds >= 0) this.priorRuntime = r.runtimeSeconds;
    if (typeof r.peakMemoryBytes === 'number' && Number.isFinite(r.peakMemoryBytes) && r.peakMemoryBytes >= 0) this.priorPeak = r.peakMemoryBytes;
    if (r.errors && typeof r.errors === 'object') for (const [k, v] of Object.entries(r.errors)) {
      if (/^[a-zA-Z0-9_.]+$/.test(k) && typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) this.errors[k] = v;
    }
    this.resumed = true;
  }
  snapshot(platform: { computeUnits: number | null; usageTotalUsd: number | null } | null = null) {
    return { ...this.counts, runtimeSeconds: +(this.priorRuntime + (performance.now() - this.start) / 1000).toFixed(3),
      peakMemoryBytes: Math.max(this.priorPeak, process.resourceUsage().maxRSS * 1024), errors: { ...this.errors },
      resumed: this.resumed, usageMayBeIncomplete: this.resumed,
      apify: platform,
      cost: { actualMarginalCostPerDomainUsd: null,
        observedApifyUsagePerDomainUsd: platform?.usageTotalUsd != null && this.counts.domainsAnalyzed > 0 ? platform.usageTotalUsd / this.counts.domainsAnalyzed : null,
        status: 'incomplete', explanation: 'Final Apify charges and customer Shodan costs are not available in-run. Usage is a snapshot, not final marginal cost. BYO Shodan charges are excluded.' },
      billing: { unit: 'domain_analyzed', eligibleUnits: this.counts.domainsWithObservations, chargedEvents: 0, enabled: false } };
  }
}
