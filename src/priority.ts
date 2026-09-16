import { createHash } from 'node:crypto';
import type { Input } from './input.js';
import type { Confidence, Evidence, Intelligence, Priority, PriorityFinding, ServiceObservation } from './models.js';
import { DAY_MS } from './cache.js';

export const priorityOrder: Record<Priority, number> = { CRITICAL_PRIORITY: 0, HIGH_PRIORITY: 1, MEDIUM_PRIORITY: 2, INFORMATIONAL: 3, INSUFFICIENT_EVIDENCE: 4 };
export function prioritize(domain: string, service: ServiceObservation, intel: Intelligence, input: Input, analyzedAt: string): PriorityFinding[] {
  const observed = service.observedAt ? Date.parse(service.observedAt) : NaN;
  const age = (Date.parse(analyzedAt) - observed) / DAY_MS;
  const dated = Number.isFinite(age) && age >= 0;
  const stale = !dated || age > input.staleAfterDays;
  const uncertain = stale || service.conflictingEvidence || service.scope === 'host';
  const host = service.hostnames.filter(h => h === domain || h.endsWith(`.${domain}`)).sort()[0] ?? domain;
  const cvs = service.associations.length ? service.associations : [{ cve: null, providerVerified: null }];
  return cvs.map(association => {
    const cve = association.cve;
    const kev = cve ? intel.kev[cve] : undefined;
    const epss = cve ? intel.epss[cve] : undefined;
    const epssFresh = !!cve && intel.epssSources[cve]?.state === 'fresh';
    const kevStatus = kev ? true : intel.kevSource.state === 'fresh' ? false : null;
    let confidence: Confidence = 'MEDIUM';
    let confidenceRationale = 'Product observed, but version or applicability evidence is incomplete.';
    if (uncertain || (!service.product && !cve)) {
      confidence = 'LOW';
      confidenceRationale = [stale ? 'Observation is stale, missing a valid timestamp, or future-dated.' : '', service.conflictingEvidence ? 'Same-time observations conflict.' : '', service.scope === 'host' ? 'CVE is associated with the host, with no reliable service attribution.' : '', !service.product && !cve ? 'No structured product or CVE evidence.' : ''].filter(Boolean).join(' ');
    } else if (cve || (service.product && service.version && service.cpe.length)) {
      confidence = 'HIGH'; confidenceRationale = 'Recent explicit CVE association or structured product/version/CPE observation. Confidence concerns the observation/association, not confirmed vulnerability.';
    }
    let priority: Priority = 'INFORMATIONAL';
    let reason = 'Externally observed service; no CVE association was supplied. This is not a clean bill of health.';
    if (cve) {
      priority = 'MEDIUM_PRIORITY';
      reason = 'Shodan associates this CVE with the observation; applicability and remediation status remain unverified.';
      if (kev) {
        priority = uncertain ? 'MEDIUM_PRIORITY' : 'HIGH_PRIORITY';
        reason = `Exact CVE match in CISA KEV indicates known exploitation in the wild. ${uncertain ? 'Weak or stale endpoint evidence limits priority.' : 'Investigate applicability promptly.'} This does not confirm exploitation or vulnerability of this endpoint.`;
      } else if (!uncertain && epssFresh && epss && epss.probability >= input.highEpssThreshold && service.product && service.version && service.scope === 'service') {
        priority = 'HIGH_PRIORITY';
        reason = 'Recent product/version observation has an explicit CVE association and high EPSS. Affected-version applicability still needs verification; EPSS is not the probability that this host is vulnerable.';
      }
      if (kev?.knownRansomwareCampaignUse === 'Known') reason += ' CISA reports known ransomware campaign use of this CVE.';
    } else if (uncertain || !service.product) {
      priority = 'INSUFFICIENT_EVIDENCE';
      reason = 'Available observations do not support reliable current vulnerability prioritization.';
    }
    // CRITICAL_PRIORITY is deliberately unreachable without independent affected-version evidence.
    // A provider's `verified` flag or a product/version/CPE triple is not such evidence.
    const evidence: Evidence[] = [{ source: 'Shodan', url: `https://www.shodan.io/host/${encodeURIComponent(service.ip)}`,
      fetchedAt: service.fetchedAt, observedAt: service.observedAt,
      details: { ip: service.ip, port: service.port, transport: service.transport, protocol: service.protocol,
        product: service.product, version: service.version, cpe: service.cpe, cve,
        scope: service.scope, providerVerified: association.providerVerified, applicabilityVerified: false,
        conflictingEvidence: service.conflictingEvidence } }];
    if (kev) evidence.push({ source: 'CISA KEV', url: intel.kevSource.url, fetchedAt: intel.kevSource.fetchedAt, observedAt: intel.kevSource.dataDate,
      details: { ...kev, sourceState: intel.kevSource.state, correlationMethod: 'EXACT_CVE' } });
    if (epss) evidence.push({ source: 'FIRST EPSS', url: `https://api.first.org/data/v1/epss?cve=${cve}`, fetchedAt: intel.epssSources[cve!]?.fetchedAt ?? null,
      observedAt: epss.date, details: { ...epss, sourceState: intel.epssSources[cve!]?.state ?? 'unavailable', correlationMethod: 'EXACT_CVE' } });
    return { id: createHash('sha256').update([domain, service.ip, service.port, service.transport, service.scope, cve].join('|')).digest('hex').slice(0, 20),
      priority, host, ip: service.ip, port: service.port, transport: service.transport, product: service.product, version: service.version,
      cpe: service.cpe, cve, cisaKev: cve ? kevStatus : null, knownRansomwareUse: kev?.knownRansomwareCampaignUse === 'Known' ? true : null,
      epss: epss?.probability ?? null, epssPercentile: epss?.percentile ?? null, epssDate: epss?.date ?? null,
      confidence, confidenceRationale, applicability: cve ? 'ASSOCIATED' : 'OBSERVED', correlationMethod: cve ? 'EXACT_CVE' : 'OBSERVATION_ONLY',
      observationSource: 'Shodan', observedAt: service.observedAt, observationAgeDays: dated ? Math.floor(age) : null,
      stale, reason, recommendedAction: cve ? 'Verify current exposure, asset ownership, installed version, affected-version range, configuration, and remediation status. Follow vendor guidance if affected.' : 'Verify current exposure and business need. Review access restrictions and patch status.', evidence };
  });
}
export function sortFindings(findings: PriorityFinding[]): PriorityFinding[] {
  return findings.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority] ||
    Number(b.cisaKev === true) - Number(a.cisaKev === true) || (b.epss ?? -1) - (a.epss ?? -1) || a.id.localeCompare(b.id));
}
