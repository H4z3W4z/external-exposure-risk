import { Resolver } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';
import type { Metrics } from '../metrics.js';
export interface DnsResult { ips: string[]; warnings: string[]; partial: boolean }
export interface DomainResolver { resolve(domain: string): Promise<DnsResult> }
export function publicIp(ip: string): boolean {
  try { return ipaddr.process(ip).range() === 'unicast'; } catch { return false; }
}
export class DnsResolver implements DomainResolver {
  constructor(private metrics: Metrics) {}
  async resolve(domain: string): Promise<DnsResult> {
    const resolver = new Resolver({ timeout: 5000, tries: 2 });
    this.metrics.counts.dnsOperations += 2;
    const results = await Promise.allSettled([resolver.resolve4(domain), resolver.resolve6(domain)]);
    const ips: string[] = []; const warnings: string[] = []; let partial = false;
    for (const r of results) {
      if (r.status === 'fulfilled') ips.push(...r.value);
      else if (!['ENODATA','ENOTFOUND'].includes(r.reason?.code)) {
        partial = true; warnings.push('A DNS query failed or timed out; discovery may be incomplete.'); this.metrics.error('dns.LOOKUP_FAILED');
      }
    }
    if (ips.some(ip => !publicIp(ip))) warnings.push('Non-public DNS addresses were excluded from Shodan lookups.');
    const valid = [...new Set(ips.filter(publicIp))].sort();
    if (!valid.length) warnings.push('No public A or AAAA records were resolved. This does not establish absence of external exposure.');
    return { ips: valid, warnings: [...new Set(warnings)], partial };
  }
}
