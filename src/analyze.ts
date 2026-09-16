import type { Input } from './input.js';
import type { DomainResolver } from './discovery/dns.js';
import type { ExposureProvider } from './providers/shodan.js';
import type { KevProvider } from './providers/cisa-kev.js';
import { KEV_URL } from './providers/cisa-kev.js';
import type { EpssProvider } from './providers/epss.js';
import type { Metrics } from './metrics.js';
import type { Asset, DomainRecord, Intelligence } from './models.js';
import { iterateFindings } from './priority.js';
import { ProviderError } from './http.js';
import { FindingSelection, fitRecord, MAX_ASSOCIATIONS, MAX_OBSERVATION_BYTES, MAX_SERVICES } from './output.js';

export interface Dependencies {
  dns: DomainResolver; shodan: ExposureProvider;
  kev: Pick<KevProvider, 'get'>; epss: Pick<EpssProvider, 'get'>;
  metrics: Metrics; now?: () => Date;
}
export async function analyzeDomain(domain: string, input: Input, deps: Dependencies): Promise<DomainRecord> {
  const analyzedAt = (deps.now?.() ?? new Date()).toISOString();
  const warnings = ['DNS and historical hostnames associate infrastructure with a domain; they do not prove ownership. Shared hosting/CDNs may expose unrelated services.'];
  const assets: Asset[] = []; let partial = false; let providerFailed = false;
  let observationBytes = 0; let associationCount = 0; let serviceCount = 0; let analysisLimited = false;
  let dns = { ips: [] as string[], warnings: [] as string[], partial: false };
  try { dns = await deps.dns.resolve(domain); }
  catch { dns.partial = true; dns.warnings.push('DNS lookup failed.'); deps.metrics.error('dns.UNAVAILABLE'); }
  partial ||= dns.partial;
  warnings.push(...dns.warnings);
  let related: string[] = [];
  if (input.discoverRelatedHosts) {
    try { const r = await deps.shodan.related(domain); related = r.ips; warnings.push(...r.warnings); partial ||= r.truncated; }
    catch { partial = true; warnings.push('Related-host search failed; continuing with DNS addresses.'); deps.metrics.error('shodan.SEARCH_FAILED'); }
  }
  // DNS addresses get first use of the cap; historical hostnames cannot displace current DNS.
  const ips = [...new Set([...dns.ips.slice().sort(), ...related.slice().sort()])];
  if (ips.length > input.maxIpsPerDomain) { partial = true; warnings.push('IP limit reached; remaining addresses were not assessed.'); }
  for (const ip of ips.slice(0, input.maxIpsPerDomain)) {
    if (analysisLimited) break;
    if (observationBytes >= MAX_OBSERVATION_BYTES || associationCount >= MAX_ASSOCIATIONS || serviceCount >= MAX_SERVICES) { analysisLimited = true; partial = true; break; }
    try {
      const result = await deps.shodan.host(ip, input.maxServicesPerIp);
      warnings.push(...result.warnings); partial ||= result.truncated;
      if (result.asset) {
        const asset = structuredClone(result.asset);
        asset.attribution = [...(dns.ips.includes(ip) ? ['dns' as const] : []), ...(related.includes(ip) ? ['shodan_hostname' as const] : [])];
        const retained = [];
        const candidates = [...asset.services, ...(asset.hostAssociations ? [asset.hostAssociations] : [])];
        for (const service of candidates) {
          const bytes = Buffer.byteLength(JSON.stringify(service));
          if (observationBytes + bytes > MAX_OBSERVATION_BYTES || associationCount + service.associations.length > MAX_ASSOCIATIONS || serviceCount >= MAX_SERVICES) {
            analysisLimited = true; partial = true; break;
          }
          observationBytes += bytes; associationCount += service.associations.length; serviceCount++;
          retained.push(service);
        }
        asset.services = retained.filter(s => s.scope === 'service');
        asset.hostAssociations = retained.find(s => s.scope === 'host') ?? null;
        if (retained.length) assets.push(asset);
      }
    } catch (e) {
      partial = true; providerFailed = true;
      const code = e instanceof ProviderError ? e.code : 'UNAVAILABLE';
      warnings.push(`Shodan lookup failed (${code}); observations for some IPs are missing.`);
      deps.metrics.error(`analysis.shodan.${code}`);
    }
  }
  if (analysisLimited) warnings.push('Per-domain analysis budget reached (8 MB observations, 20,000 associations, or 5,000 observations); unassessed observations and IPs may contain additional priorities.');
  assets.sort((a, b) => a.ip.localeCompare(b.ip));
  const observations = assets.flatMap(a => [...a.services, ...(a.hostAssociations ? [a.hostAssociations] : [])]);
  const allCves = [...new Set(observations.flatMap(s => s.associations.map(a => a.cve)))].sort();
  const cves = allCves.slice(0, input.maxCvesPerDomain);
  if (allCves.length > cves.length) { partial = true; warnings.push('CVE enrichment limit reached; remaining CVEs retain associations but have incomplete threat intelligence.'); }
  let intel: Intelligence = { kev: {}, epss: {}, kevSource: { url: KEV_URL, state: 'not_requested', fetchedAt: null, dataDate: null, cacheAgeSeconds: null }, epssSources: {}, warnings: [] };
  if (allCves.length) {
    const [kev, epss] = await Promise.all([deps.kev.get(), deps.epss.get(cves)]);
    intel = { kev: kev.entries, epss: epss.entries, kevSource: kev.source, epssSources: epss.sources, warnings: [...kev.warnings, ...epss.warnings] };
    partial ||= kev.source.state !== 'fresh' || Object.values(epss.sources).some(s => s.state !== 'fresh');
    warnings.push(...intel.warnings);
  }
  const selection = new FindingSelection();
  let staleCount = 0; let incompleteVersion = false; let kevMatches = 0; let highEpss = 0; let criticalPriority = 0; let highPriority = 0;
  for (const observation of observations) for (const finding of iterateFindings(domain, observation, intel, input, analyzedAt)) {
    if (finding.stale) staleCount++;
    if (finding.cve && (!finding.product || !finding.version)) incompleteVersion = true;
    if (finding.cisaKev === true) kevMatches++;
    if (finding.epss !== null && finding.epss >= input.highEpssThreshold && finding.cve && intel.epssSources[finding.cve]?.state === 'fresh') highEpss++;
    if (finding.priority === 'CRITICAL_PRIORITY') criticalPriority++;
    if (finding.priority === 'HIGH_PRIORITY') highPriority++;
    selection.add(finding);
  }
  const priorities = selection.finish();
  if (staleCount) warnings.push(`${staleCount} findings have stale, missing, or future-dated observations. Verify current exposure before treating them as current.`);
  if (incompleteVersion) warnings.push('Some CVE associations lack product/version evidence. Affected-version applicability is unverified.');
  if (!assets.length) warnings.push('Insufficient evidence: no usable service observations. No findings does not mean no risk.');
  const summary = { assetsObserved: assets.length, servicesObserved: assets.reduce((n, a) => n + a.services.length, 0),
    cveAssociations: associationCount, uniqueCves: allCves.length, kevMatches, highEpss, criticalPriority, highPriority };
  const status = !assets.length ? providerFailed || dns.partial ? 'failed' : partial ? 'partial' : 'no_data' : partial ? 'partial' : 'ok';
  const record: DomainRecord = { schemaVersion: '1.0', domain, analyzedAt, status, summary, priorities, assets,
    sources: { dns: { resolvedAt: analyzedAt, addresses: dns.ips }, shodan: { fetchedAt: analyzedAt, state: providerFailed ? assets.length ? 'partial' : 'unavailable' : 'available', attribution: 'Observation data: Shodan. Shodan retains ownership and copyright in its materials. Prioritization is independently derived; no endorsement is implied.' }, kev: intel.kevSource, epss: intel.epssSources },
    warnings: [...new Set(warnings)].sort(), humanSummary: '',
    output: { truncated: false, limitBytes: 0, serializedBytes: 0, findingsAssessed: selection.total,
      findingsRetained: priorities.length, findingsOmitted: selection.total - priorities.length, assetsOmitted: 0, summaryScope: 'assessed_observations', analysisLimited } };
  record.humanSummary = humanSummary(record);
  deps.metrics.counts.domainsAnalyzed++;
  if (assets.length) deps.metrics.counts.domainsWithObservations++;
  const fitted = fitRecord(record);
  if (fitted.output!.truncated) deps.metrics.counts.recordsTruncated++;
  return fitted;
}
export function humanSummary(record: DomainRecord): string {
  const s = record.summary;
  const lines = [`${record.domain} — ${record.status}`, `${s.assetsObserved} assets; ${s.servicesObserved} services; ${s.cveAssociations} CVE associations (${s.uniqueCves} unique); ${s.kevMatches} KEV matches; ${s.highEpss} fresh high-EPSS associations.`];
  if (!record.priorities.length) lines.push('Insufficient evidence. No observations does not mean safe.');
  else {
    lines.push('Investigate first:');
    for (const f of record.priorities.slice(0, 5)) lines.push(`- ${f.priority}: ${f.ip}${f.port === null ? ' (host-level)' : `:${f.port}/${f.transport ?? 'unknown'}`} — ${f.cve ?? 'service observation'}; confidence ${f.confidence}. ${f.reason} Last observed: ${f.observedAt ?? 'unknown'}${f.observationAgeDays === null ? '' : ` (${f.observationAgeDays} ${f.observationAgeDays === 1 ? 'day' : 'days'} ago)`}. ${f.recommendedAction}`);
  }
  if (record.warnings.length) lines.push('Caveats:', ...record.warnings.map(w => `- ${w}`));
  lines.push(record.sources.shodan.attribution);
  return lines.join('\n');
}
