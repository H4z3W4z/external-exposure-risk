import { obj } from './providers/parse.js';

export interface CostPrices {
  label?: string; allocatedMemoryMb?: number; computeUsdPerCu?: number;
  shodanUsdPerRequest?: number; shodanUsdPerSearchPage?: number;
  apifyFinalUsd?: number; shodanFinalUsd?: number; otherRunUsd?: number;
}
export function calculateCost(diagnostics: unknown, rawPrices: unknown) {
  const d = obj(diagnostics); const p = obj(rawPrices);
  const keys = ['label','allocatedMemoryMb','computeUsdPerCu','shodanUsdPerRequest','shodanUsdPerSearchPage','apifyFinalUsd','shodanFinalUsd','otherRunUsd'];
  if (Object.keys(p).some(k => !keys.includes(k)) || (p.label !== undefined && typeof p.label !== 'string')) throw new Error('Invalid cost assumptions.');
  for (const k of keys.filter(k => k !== 'label')) if (p[k] !== undefined && (typeof p[k] !== 'number' || !Number.isFinite(p[k]) || p[k] < 0)) throw new Error('Prices and allocated memory must be finite nonnegative numbers.');
  if (p.allocatedMemoryMb !== undefined && p.allocatedMemoryMb === 0) throw new Error('Allocated memory must be greater than zero.');
  const prices = p as CostPrices;
  const usage = (key: string, integer = true) => {
    const value = d[key];
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || (integer && !Number.isSafeInteger(value))) throw new Error('Diagnostics contain missing or invalid usage counters.');
    return value;
  };
  const domains = usage('domainsAnalyzed'); const observed = usage('domainsWithObservations');
  if (observed > domains) throw new Error('Observed-domain count exceeds analyzed domains.');
  const seconds = usage('runtimeSeconds', false); const requests = usage('shodanRequests'); const pages = usage('shodanSearchPages');
  const missing: string[] = [];
  const requirePrice = (name: keyof CostPrices) => { if (prices[name] === undefined) missing.push(name); };
  let apify: number | null = prices.apifyFinalUsd ?? null;
  if (apify === null) {
    requirePrice('allocatedMemoryMb'); requirePrice('computeUsdPerCu');
    if (prices.allocatedMemoryMb !== undefined && prices.computeUsdPerCu !== undefined) apify = prices.allocatedMemoryMb / 1024 * seconds / 3600 * prices.computeUsdPerCu;
  }
  let shodan: number | null = prices.shodanFinalUsd ?? null;
  if (shodan === null) {
    if (requests) requirePrice('shodanUsdPerRequest');
    if (pages) requirePrice('shodanUsdPerSearchPage');
    if ((!requests || prices.shodanUsdPerRequest !== undefined) && (!pages || prices.shodanUsdPerSearchPage !== undefined)) shodan = requests * (prices.shodanUsdPerRequest ?? 0) + pages * (prices.shodanUsdPerSearchPage ?? 0);
  }
  requirePrice('otherRunUsd');
  const components = { apifyUsd: apify, shodanUsd: shodan, otherRunUsd: prices.otherRunUsd ?? null };
  if (Object.values(components).some(n => n !== null && !Number.isFinite(n))) throw new Error('Cost calculation overflowed.');
  const knownSubtotalUsd = Object.values(components).reduce<number>((sum, n) => sum + (n ?? 0), 0);
  if (!Number.isFinite(knownSubtotalUsd)) throw new Error('Cost calculation overflowed.');
  const finalCosts = prices.apifyFinalUsd !== undefined && prices.shodanFinalUsd !== undefined && prices.otherRunUsd !== undefined;
  if (d.usageMayBeIncomplete === true && !finalCosts) missing.push('completeUsageAfterInterruption');
  const totalUsd = missing.length ? null : knownSubtotalUsd;
  return { schemaVersion: '1.0', basis: finalCosts ? 'user_supplied_final_costs' : 'estimate_from_user_supplied_rates',
    assumptionsLabel: prices.label ?? null, components, knownSubtotalUsd, totalUsd,
    perAnalyzedDomainUsd: totalUsd !== null && domains ? totalUsd / domains : null,
    perObservedDomainUsd: totalUsd !== null && observed ? totalUsd / observed : null,
    domainsAnalyzed: domains, domainsWithObservations: observed, missing,
    limitations: ['No market prices are embedded. Values are as supplied by the caller.',
      'Modeled compute uses allocated GB-hours, not peak RSS. Include storage, transfer, billing minimums and other costs in otherRunUsd.',
      'Request and search-page rates are additive assumptions; explicitly use zero to avoid double-counting a bundled plan.',
      'A running Actor usage snapshot is not a final bill. This report does not calculate revenue or margin.'] };
}
