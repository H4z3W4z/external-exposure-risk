export class Metrics {
  private start = performance.now();
  counts = { domainsSubmitted: 0, domainsUnique: 0, domainsAnalyzed: 0, domainsWithObservations: 0,
    shodanRequests: 0, shodanResultsConsumed: 0, shodanSearchPages: 0, dnsOperations: 0,
    kevRefreshes: 0, epssRequests: 0, cveRequests: 0, cacheHits: 0, cacheMisses: 0,
    cacheStaleFallbacks: 0, retries: 0 };
  errors: Record<string, number> = {};
  error(code: string) { this.errors[code] = (this.errors[code] ?? 0) + 1; }
  snapshot(platform: { computeUnits: number | null; usageTotalUsd: number | null } | null = null) {
    return { ...this.counts, runtimeSeconds: +( (performance.now() - this.start) / 1000).toFixed(3),
      peakMemoryBytes: process.resourceUsage().maxRSS * 1024, errors: { ...this.errors },
      apify: platform,
      cost: { actualMarginalCostPerDomainUsd: null,
        observedApifyUsagePerDomainUsd: platform?.usageTotalUsd != null && this.counts.domainsAnalyzed > 0 ? platform.usageTotalUsd / this.counts.domainsAnalyzed : null,
        status: 'incomplete', explanation: 'Final Apify charges and customer Shodan costs are not available in-run. Usage is a snapshot, not final marginal cost. BYO Shodan charges are excluded.' },
      billing: { unit: 'domain_analyzed', eligibleUnits: this.counts.domainsWithObservations, chargedEvents: 0, enabled: false } };
  }
}
