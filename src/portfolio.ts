import { createHash } from 'node:crypto';
import { analyzeDomain, type Dependencies } from './analyze.js';
import { InputError, type Input } from './input.js';
import type { DomainRecord } from './models.js';
import { fitRecord } from './output.js';
import { redact } from './security.js';

export interface CompletedDomain { domain: string; humanSummary: string; summary: { assetsObserved: number } }
export interface RunState { version: 1; fingerprint: string; diagnostics: unknown }
export interface PortfolioSink {
  state(): Promise<RunState | null>;
  saveState(state: RunState): Promise<void>;
  completed(): Promise<CompletedDomain[]>;
  push(record: DomainRecord): Promise<void>;
  summary(text: string): Promise<void>;
}
export function inputFingerprint(input: Input): string {
  const { shodanApiKey: _secret, ...config } = input;
  return createHash('sha256').update(JSON.stringify({ version: 1, config })).digest('hex');
}
export class InterruptedRun extends Error { constructor() { super('Run interrupted; completed domains are preserved. Resume using the same storage and input.'); } }

/** Resume from committed Dataset rows, not a cursor which could lag a successful write.
 * A failed/ambiguous write stops the process; it is not blindly appended again here.
 * This is single-writer recovery, not a distributed exactly-once transaction. */
export async function runPortfolio(input: Input, deps: Dependencies, sink: PortfolioSink,
  secrets: string[] = [], stopped = () => false, progress: (record: DomainRecord) => void = () => {}) {
  const fingerprint = inputFingerprint(input);
  const state = await sink.state();
  const existing = await sink.completed();
  if ((state && (state.version !== 1 || state.fingerprint !== fingerprint)) || (!state && existing.length)) throw new InputError('Existing storage belongs to different or unrecognized input. Use fresh storage.');
  if (existing.length > input.domains.length || new Set(existing.map(r => r.domain)).size !== existing.length || existing.some(r => !input.domains.includes(r.domain) || typeof r.humanSummary !== 'string' || !Number.isInteger(r.summary?.assetsObserved))) throw new InputError('Stored Dataset contains unexpected or duplicate domains. Review it before resuming.');
  if (state) deps.metrics.restore(state.diagnostics);
  deps.metrics.counts.domainsSubmitted = input.submittedCount;
  deps.metrics.counts.domainsUnique = input.domains.length;
  deps.metrics.counts.domainsAnalyzed = existing.length;
  deps.metrics.counts.domainsWithObservations = existing.filter(r => r.summary.assetsObserved > 0).length;
  deps.metrics.counts.domainsResumed += existing.length;
  const summaries = new Map(existing.map(r => [r.domain, r.humanSummary]));
  const checkpoint = async () => {
    await sink.saveState({ version: 1, fingerprint, diagnostics: redact(deps.metrics.snapshot(), secrets) });
    await sink.summary(input.domains.filter(d => summaries.has(d)).map(d => summaries.get(d)).join('\n\n'));
  };
  // Manifest precedes the first append; no customer credentials or observations are cached here.
  await checkpoint();
  for (const domain of input.domains) {
    if (summaries.has(domain)) continue;
    if (stopped()) { await checkpoint(); throw new InterruptedRun(); }
    const record = fitRecord(redact(await analyzeDomain(domain, input, deps), secrets));
    await sink.push(record);
    summaries.set(domain, record.humanSummary);
    await checkpoint();
    progress(record);
  }
  return { completed: summaries.size, resumed: existing.length };
}
