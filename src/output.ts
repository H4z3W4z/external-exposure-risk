import type { DomainRecord, PriorityFinding } from './models.js';
import { sortFindings } from './priority.js';

export const MAX_RECORD_BYTES = 4_000_000; // Headroom below Apify's 9 MB item limit.
export const MAX_RETAINED_FINDINGS = 2000;
export const MAX_OBSERVATION_BYTES = 8_000_000;
export const MAX_ASSOCIATIONS = 20_000;
export const MAX_SERVICES = 5000;

/** Batch-compacted ordered selection: bounded memory, stable tie-breaking. */
export class FindingSelection {
  private selected: PriorityFinding[] = [];
  total = 0;
  add(finding: PriorityFinding) {
    this.total++; this.selected.push(finding);
    if (this.selected.length >= MAX_RETAINED_FINDINGS * 2) this.selected = sortFindings(this.selected).slice(0, MAX_RETAINED_FINDINGS);
  }
  finish() { return sortFindings(this.selected).slice(0, MAX_RETAINED_FINDINGS); }
}

export function recordBytes(record: DomainRecord): number {
  // Avoid allocating a potentially enormous serialized record just to measure it.
  const base = Buffer.byteLength(JSON.stringify({ ...record, priorities: [], assets: [] }), 'utf8');
  return base + [record.priorities, record.assets].reduce((total, items) => total + items.reduce((n, item) => n + Buffer.byteLength(JSON.stringify(item), 'utf8'), 0) + Math.max(0, items.length - 1), 0);
}

/** Summary counts describe all assessed observations. Omitted detail is explicitly counted.
 * Drop duplicated asset detail first, then lower-priority findings. Never strip evidence
 * from a retained finding. Caller owns this record; provider caches are never modified. */
export function fitRecord(record: DomainRecord, limitBytes = MAX_RECORD_BYTES): DomainRecord {
  if (!Number.isInteger(limitBytes) || limitBytes < 32_000) throw new Error('Output budget must be at least 32,000 bytes.');
  const existing = record.output;
  const initialAssets = record.assets.length + (existing?.assetsOmitted ?? 0);
  record.output = { truncated: existing?.truncated ?? false, limitBytes, serializedBytes: 0,
    findingsAssessed: existing?.findingsAssessed ?? record.priorities.length,
    findingsRetained: record.priorities.length, findingsOmitted: existing?.findingsOmitted ?? 0,
    assetsOmitted: existing?.assetsOmitted ?? 0, summaryScope: 'assessed_observations', analysisLimited: existing?.analysisLimited ?? false };
  const update = () => {
    const o = record.output!;
    o.findingsRetained = record.priorities.length; o.findingsOmitted = o.findingsAssessed - o.findingsRetained;
    o.assetsOmitted = initialAssets - record.assets.length;
    o.truncated = o.findingsOmitted > 0 || o.assetsOmitted > 0 || o.analysisLimited;
    if (o.truncated) {
      if (record.status === 'ok') record.status = 'partial';
      record.humanSummary = record.humanSummary.replace(`${record.domain} — ok`, `${record.domain} — ${record.status}`);
      const warning = 'Output or analysis limits reached. Summary counts cover assessed observations; inspect output for omitted detail. Retained findings keep their evidence.';
      if (!record.warnings.includes(warning)) record.warnings.push(warning);
      if (!record.humanSummary.includes(warning)) record.humanSummary += `\n${warning}`;
    }
    // Reach a fixed point as the byte count itself changes the encoded length.
    o.serializedBytes = recordBytes(record); o.serializedBytes = recordBytes(record); o.serializedBytes = recordBytes(record);
  };
  update();
  if (record.output.serializedBytes > limitBytes) { record.assets = []; update(); }
  if (record.output.serializedBytes > limitBytes) {
    // Per-CVE source dates remain in evidence of retained findings.
    record.sources.epss = {};
    while (record.output.serializedBytes > limitBytes && record.priorities.length) {
      record.priorities = record.priorities.slice(0, Math.floor(record.priorities.length * 0.75)); update();
    }
  }
  if (record.output.serializedBytes > limitBytes) throw new Error('Assessment metadata exceeds the output budget.');
  return record;
}
