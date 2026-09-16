// Loaded only by the child-process integration test. Production never imports this file.
import { Resolver } from 'node:dns/promises';
Resolver.prototype.resolve4 = async () => ['8.8.8.8'];
Resolver.prototype.resolve6 = async () => [];
const now = new Date().toISOString();
globalThis.fetch = async (url) => {
  const u = new URL(String(url));
  if (u.hostname === 'api.shodan.io') return new Response(JSON.stringify({ ip_str: '8.8.8.8', data: [
    { port: 443, transport: 'tcp', product: 'Synthetic gateway ' + process.env.SHODAN_API_KEY, version: '1.0', timestamp: now,
      vulns: { 'CVE-2024-0001': { verified: true } } } ] }));
  if (u.hostname === 'www.cisa.gov') return new Response(JSON.stringify({ dateReleased: now, vulnerabilities: [
    { cveID: 'CVE-2024-0001', vendorProject: 'Synthetic', product: 'Gateway', dateAdded: now.slice(0, 10), knownRansomwareCampaignUse: 'Unknown' } ] }));
  if (u.hostname === 'api.first.org') return new Response(JSON.stringify({ status: 'OK', data: [
    { cve: 'CVE-2024-0001', epss: '0.96', percentile: '0.99', date: now.slice(0, 10) } ] }));
  throw new Error('Unexpected network call in offline integration test.');
};
