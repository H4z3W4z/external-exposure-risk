import { Actor, log } from 'apify';
import { parseInput, InputError } from './input.js';
import { Metrics } from './metrics.js';
import { HttpClient } from './http.js';
import { MemoryCache, PublicCache, type CacheStore } from './cache.js';
import { DnsResolver } from './discovery/dns.js';
import { ShodanProvider } from './providers/shodan.js';
import { KevProvider } from './providers/cisa-kev.js';
import { EpssProvider } from './providers/epss.js';
import { analyzeDomain } from './analyze.js';
import { redact } from './security.js';

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
    const summaries: string[] = [];
    for (const domain of input.domains) {
      const record = redact(await analyzeDomain(domain, input, deps), secrets);
      await Actor.pushData(record);
      summaries.push(record.humanSummary);
      log.info(`Analyzed domain ${metrics.counts.domainsAnalyzed}/${input.domains.length}: ${record.status}; ${record.summary.highPriority} high-priority findings.`);
    }
    await Actor.setValue('SUMMARY', summaries.join('\n\n'), { contentType: 'text/plain; charset=utf-8' });
  } catch (error) {
    metrics.error(error instanceof InputError ? 'run.INVALID_INPUT' : 'run.FAILED');
    // SDK would otherwise serialize arbitrary exceptions (including HTTP URLs or input).
    throw new Error(error instanceof InputError ? error.message : 'Actor failed. Inspect DIAGNOSTICS for sanitized error counts.');
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
