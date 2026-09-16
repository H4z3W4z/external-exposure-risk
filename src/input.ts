import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';

export interface Input {
  domains: string[]; submittedCount: number; shodanApiKey?: string;
  discoverRelatedHosts: boolean; maxIpsPerDomain: number; maxServicesPerIp: number;
  maxCvesPerDomain: number; staleAfterDays: number; highEpssThreshold: number;
}
export class InputError extends Error {}
export function normalizeDomain(value: unknown): string {
  if (typeof value !== 'string') throw new InputError('Each domain must be a string.');
  const raw = value.trim().toLowerCase().replace(/\.$/, '');
  if (!raw || /[\s/:@?#*\\]/.test(raw)) throw new InputError('Use bare domain names, without URLs, ports or wildcards.');
  const domain = domainToASCII(raw);
  if (!domain || domain.length > 253 || isIP(domain) || !domain.includes('.') ||
      domain.split('.').some(s => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s)) ||
      !/[a-z]/.test(domain.split('.').at(-1)!)) throw new InputError('One or more domain names are malformed.');
  return domain;
}
export function parseInput(raw: unknown): Input {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new InputError('Provide an input object with domains or domain.');
  const r = raw as Record<string, unknown>;
  const allowed = new Set(['domains','domain','shodanApiKey','discoverRelatedHosts','maxIpsPerDomain','maxServicesPerIp','maxCvesPerDomain','staleAfterDays','highEpssThreshold']);
  if (Object.keys(r).some(k => !allowed.has(k))) throw new InputError('Input contains unsupported fields.');
  if (r.domains !== undefined && r.domain !== undefined) throw new InputError('Provide domains or domain, not both.');
  const list = r.domains ?? (r.domain === undefined ? [] : [r.domain]);
  if (!Array.isArray(list) || list.length < 1 || list.length > 100) throw new InputError('Provide 1–100 domains per run.');
  const number = (key: string, fallback: number, min: number, max: number, integer = true) => {
    const n = r[key] ?? fallback;
    if (typeof n !== 'number' || !Number.isFinite(n) || n < min || n > max || (integer && !Number.isInteger(n))) throw new InputError(`Invalid ${key}.`);
    return n;
  };
  if (r.shodanApiKey !== undefined && (typeof r.shodanApiKey !== 'string' || !r.shodanApiKey.trim())) throw new InputError('shodanApiKey must be a nonempty secret string.');
  if (r.discoverRelatedHosts !== undefined && typeof r.discoverRelatedHosts !== 'boolean') throw new InputError('discoverRelatedHosts must be boolean.');
  return {
    domains: [...new Set(list.map(normalizeDomain))].sort(), submittedCount: list.length,
    shodanApiKey: typeof r.shodanApiKey === 'string' ? r.shodanApiKey.trim() : undefined,
    discoverRelatedHosts: r.discoverRelatedHosts === true,
    maxIpsPerDomain: number('maxIpsPerDomain', 20, 1, 100),
    maxServicesPerIp: number('maxServicesPerIp', 200, 1, 1000),
    maxCvesPerDomain: number('maxCvesPerDomain', 2000, 1, 5000),
    staleAfterDays: number('staleAfterDays', 30, 1, 365),
    highEpssThreshold: number('highEpssThreshold', 0.9, 0, 1, false),
  };
}
