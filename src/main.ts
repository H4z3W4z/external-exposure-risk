import { Actor, log } from 'apify';
import { parseInput, InputError } from './input.js';
import { Metrics } from './metrics.js';
import { HttpClient } from './http.js';
import { MemoryCache, PublicCache, type CacheStore } from './cache.js';
import { DnsResolver } from './discovery/dns.js';
import { ShodanProvider } from './providers/shodan.js';
import { KevProvider } from './providers/cisa-kev.js';
import { EpssProvider } from './providers/epss.js';
import { redact } from './security.js';
import { runPortfolio, InterruptedRun, type RunState, type CompletedDomain } from './portfolio.js';

await Actor.main(async () => {
  const metrics = new Metrics();
  let secrets: string[] = [process.env.SHODAN_API_KEY ?? '', process.env.APIFY_TOKEN ?? ''];
  try {
    const input = parseInput(await Actor.getInput());
    const key = input.shodanApiKey || process.env.SHODAN_API_KEY?.trim();
    if (!key) throw new InputError('Provide SHODAN_API_KEY as a secret environment variable or the encrypted shodanApiKey input.');
    secrets = [...secrets, key];
    // Do not retain a credential-bearing input in provider-independent configuration.
    delete input.shodanApiKey;
    metrics.counts.domainsSubmitted = input.submittedCount;
    metrics.counts.domainsUnique = input.domains.length;
    let store: CacheStore = new MemoryCache();
    try {
      const kv = await Actor.openKeyValueStore('external-exposure-public-intel-v1');
      store = { get: key => kv.getValue(key), set: async (key, value) => { await kv.setValue(key, value); } };
    } catch { metrics.error('cache.PERSISTENT_STORE_UNAVAILABLE'); }
    const cache = new PublicCache(store, metrics);
    const http = new HttpClient(metrics);
    const deps = { dns: new DnsResolver(metrics), shodan: new ShodanProvider(http, key, metrics),
      kev: new KevProvider(http, cache, metrics), epss: new EpssProvider(http, cache, metrics), metrics };
    const dataset = await Actor.openDataset();
    let stopping = false;
    const stop = () => { stopping = true; };
    process.once('SIGTERM', stop); process.once('SIGINT', stop);
    Actor.on('migrating', stop); Actor.on('aborting', stop);
    try { await runPortfolio(input, deps, {
      state: () => Actor.getValue<RunState>('RUN_STATE'),
      saveState: state => Actor.setValue('RUN_STATE', state),
      completed: async () => {
        const result = await dataset.getData({ limit: 101, fields: ['domain', 'humanSummary', 'summary'] });
        if (result.total > 100) throw new InputError('Existing Dataset exceeds this run\'s domain limit. Use fresh storage.');
        return result.items as unknown as CompletedDomain[];
      },
      push: record => Actor.pushData(record),
      summary: text => Actor.setValue('SUMMARY', text, { contentType: 'text/plain; charset=utf-8' }),
    }, secrets, () => stopping, record => {
      log.info(`Analyzed domain ${metrics.counts.domainsAnalyzed}/${input.domains.length}: ${record.status}; ${record.summary.highPriority} high-priority findings.`);
    }); } finally { process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); }
  } catch (error) {
    metrics.error(error instanceof InputError ? 'run.INVALID_INPUT' : error instanceof InterruptedRun ? 'run.INTERRUPTED' : 'run.FAILED');
    // SDK would otherwise serialize arbitrary exceptions (including HTTP URLs or input).
    throw new Error(error instanceof InputError || error instanceof InterruptedRun ? error.message : 'Actor failed. Inspect DIAGNOSTICS for sanitized error counts.');
  } finally {
    let platform: { computeUnits: number | null; usageTotalUsd: number | null } | null = null;
    if (Actor.isAtHome() && process.env.ACTOR_RUN_ID) {
      try {
        const run = await Actor.apifyClient.run(process.env.ACTOR_RUN_ID).get();
        platform = { computeUnits: run?.stats?.computeUnits ?? null, usageTotalUsd: run?.usageTotalUsd ?? null };
      } catch { metrics.error('apify.USAGE_UNAVAILABLE'); }
    }
    await Actor.setValue('DIAGNOSTICS', redact(metrics.snapshot(platform), secrets));
  }
});
