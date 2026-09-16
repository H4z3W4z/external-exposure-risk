import { Metrics } from '../src/metrics.js';
import { HttpClient } from '../src/http.js';
import { MemoryCache, PublicCache } from '../src/cache.js';
import { KevProvider } from '../src/providers/cisa-kev.js';
import { EpssProvider } from '../src/providers/epss.js';
import { DnsResolver } from '../src/discovery/dns.js';

// Only public intelligence and DNS, no Shodan key or target contact.
const metrics = new Metrics(); const http = new HttpClient(metrics); const cache = new PublicCache(new MemoryCache(), metrics);
const [dns, kev, epss] = await Promise.all([
  new DnsResolver(metrics).resolve('example.com'), new KevProvider(http, cache, metrics).get(),
  new EpssProvider(http, cache, metrics).get(['CVE-2021-44228']),
]);
console.log(JSON.stringify({ dnsAddresses: dns.ips.length, kevEntries: Object.keys(kev.entries).length, kevSource: kev.source,
  epss: epss.entries['CVE-2021-44228'] ?? null, epssSource: epss.sources['CVE-2021-44228'], diagnostics: metrics.snapshot() }, null, 2));
if (!dns.ips.length || kev.source.state !== 'fresh' || epss.sources['CVE-2021-44228'].state !== 'fresh') process.exitCode = 1;
