export type Priority = 'CRITICAL_PRIORITY' | 'HIGH_PRIORITY' | 'MEDIUM_PRIORITY' | 'INFORMATIONAL' | 'INSUFFICIENT_EVIDENCE';
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';
export type SourceState = 'fresh' | 'stale' | 'unavailable' | 'not_requested';
export interface SourceInfo {
  url: string; fetchedAt: string | null; dataDate: string | null;
  state: SourceState; cacheAgeSeconds: number | null;
}
export interface VulnerabilityAssociation { cve: string; providerVerified: boolean | null }
export interface ServiceObservation {
  ip: string; port: number | null; transport: string | null; protocol: string | null;
  hostnames: string[]; product: string | null; version: string | null; cpe: string[];
  observedAt: string | null; fetchedAt: string; associations: VulnerabilityAssociation[];
  scope: 'service' | 'host'; conflictingEvidence: boolean;
}
export interface Asset {
  ip: string; attribution: ('dns' | 'shodan_hostname')[]; hostnames: string[];
  organization: string | null; asn: string | null; isp: string | null;
  location: { country: string | null; region: string | null; city: string | null };
  services: ServiceObservation[];
  hostAssociations: ServiceObservation | null;
}
export interface KevEntry {
  cve: string; vendorProject: string; product: string; vulnerabilityName: string;
  dateAdded: string; dueDate: string; knownRansomwareCampaignUse: string;
  requiredAction: string; notes: string;
}
export interface EpssEntry { cve: string; probability: number; percentile: number; date: string }
export interface Intelligence {
  kev: Record<string, KevEntry>; epss: Record<string, EpssEntry>;
  kevSource: SourceInfo; epssSources: Record<string, SourceInfo>; warnings: string[];
}
export interface Evidence {
  source: 'Shodan' | 'CISA KEV' | 'FIRST EPSS'; url: string;
  fetchedAt: string | null; observedAt: string | null;
  details: Record<string, unknown>;
}
export interface PriorityFinding {
  id: string; priority: Priority; host: string; ip: string; port: number | null;
  transport: string | null; product: string | null; version: string | null; cpe: string[];
  cve: string | null; cisaKev: boolean | null; knownRansomwareUse: true | null;
  epss: number | null; epssPercentile: number | null; epssDate: string | null;
  confidence: Confidence; confidenceRationale: string;
  applicability: 'ASSOCIATED' | 'OBSERVED'; correlationMethod: 'EXACT_CVE' | 'OBSERVATION_ONLY';
  observationSource: 'Shodan'; observedAt: string | null; observationAgeDays: number | null;
  stale: boolean; reason: string; recommendedAction: string; evidence: Evidence[];
}
export interface DomainRecord {
  schemaVersion: '1.0'; domain: string; analyzedAt: string;
  status: 'ok' | 'partial' | 'no_data' | 'failed';
  summary: { assetsObserved: number; servicesObserved: number; cveAssociations: number;
    uniqueCves: number; kevMatches: number; highEpss: number; criticalPriority: number; highPriority: number };
  priorities: PriorityFinding[]; assets: Asset[];
  sources: { dns: { resolvedAt: string; addresses: string[] }; shodan: { fetchedAt: string; state: 'available' | 'partial' | 'unavailable'; attribution: string }; kev: SourceInfo; epss: Record<string, SourceInfo> };
  warnings: string[]; humanSummary: string;
}
