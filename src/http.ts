import type { Metrics } from './metrics.js';
export type ProviderName = 'shodan' | 'kev' | 'epss';
export class ProviderError extends Error {
  constructor(public provider: string, public code: string, public status?: number) { super(`${provider}: ${code}`); }
}
export interface JsonHttp { get(url: string, provider: ProviderName): Promise<unknown> }
export class HttpClient implements JsonHttp {
  private nextShodanAt = 0;
  constructor(private metrics: Metrics, private fetcher: typeof fetch = fetch,
    private sleep: (ms: number) => Promise<void> = ms => new Promise(r => setTimeout(r, ms)),
    private shodanIntervalMs = 1100, private timeoutMs = 20_000) {}
  async get(url: string, provider: ProviderName): Promise<unknown> {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (provider === 'shodan') {
        const delay = Math.max(0, this.nextShodanAt - Date.now());
        if (delay) await this.sleep(delay);
        this.nextShodanAt = Date.now() + this.shodanIntervalMs;
      }
      const counter = { shodan: 'shodanRequests', kev: 'kevRefreshes', epss: 'epssRequests' } as const;
      this.metrics.counts[counter[provider]]++;
      let retryMs = 500 * 2 ** attempt;
      try {
        const response = await this.fetcher(url, { signal: AbortSignal.timeout(this.timeoutMs), redirect: 'error', headers: { Accept: 'application/json' } });
        if (!response.ok) {
          const seconds = Number(response.headers.get('retry-after'));
          if (Number.isFinite(seconds) && seconds > 0) retryMs = Math.min(30_000, seconds * 1000);
          await response.body?.cancel();
          throw new ProviderError(provider, response.status === 429 ? 'RATE_LIMITED' : `HTTP_${response.status}`, response.status);
        }
        // Bound payloads, including chunked responses. Never echo a response body or credential-bearing URL.
        const reader = response.body?.getReader();
        if (!reader) throw new ProviderError(provider, 'EMPTY_RESPONSE');
        const chunks: Uint8Array[] = []; let size = 0;
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.byteLength;
          if (size > 20_000_000) { await reader.cancel(); throw new ProviderError(provider, 'RESPONSE_TOO_LARGE'); }
          chunks.push(part.value);
        }
        try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
        catch { throw new ProviderError(provider, 'INVALID_JSON'); }
      } catch (e) {
        const err = e instanceof ProviderError ? e : new ProviderError(provider, 'NETWORK_OR_TIMEOUT');
        this.metrics.error(`${provider}.${err.code}`);
        const retryable = err.code === 'NETWORK_OR_TIMEOUT' || err.status === 429 || (err.status ?? 0) >= 500;
        if (!retryable || attempt === 2) throw err;
        this.metrics.counts.retries++;
        await this.sleep(retryMs);
      }
    }
    throw new ProviderError(provider, 'RETRIES_EXHAUSTED');
  }
}
