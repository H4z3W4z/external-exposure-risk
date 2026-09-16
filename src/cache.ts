import type { Metrics } from './metrics.js';
import type { SourceInfo } from './models.js';
export const DAY_MS = 86_400_000;
export interface CacheEntry<T> { value: T; fetchedAt: string }
export interface CacheStore {
  get(key: string): Promise<unknown>;
  set(key: string, entry: unknown): Promise<void>;
}
export class MemoryCache implements CacheStore {
  entries = new Map<string, unknown>();
  async get(key: string) { return this.entries.get(key) ?? null; }
  async set(key: string, entry: unknown) { this.entries.set(key, entry); }
}
export class PublicCache {
  constructor(private store: CacheStore, private metrics: Metrics, private now: () => Date = () => new Date()) {}
  async read<T>(key: string, valid: (v: unknown) => v is T): Promise<CacheEntry<T> | null> {
    try {
      const raw = await this.store.get(key) as CacheEntry<unknown> | null;
      if (!raw || typeof raw.fetchedAt !== 'string' || !Number.isFinite(Date.parse(raw.fetchedAt)) || Date.parse(raw.fetchedAt) > this.now().getTime() || !valid(raw.value)) return null;
      return raw as CacheEntry<T>;
    } catch { this.metrics.error('cache.READ_FAILED'); return null; }
  }
  async write<T>(key: string, value: T): Promise<CacheEntry<T>> {
    const entry = { value, fetchedAt: this.now().toISOString() };
    try { await this.store.set(key, entry); } catch { this.metrics.error('cache.WRITE_FAILED'); }
    return entry;
  }
  info(entry: CacheEntry<unknown> | null, url: string, dataDate: string | null, stale = false): SourceInfo {
    const age = entry ? Math.max(0, (this.now().getTime() - Date.parse(entry.fetchedAt)) / 1000) : null;
    return { url, fetchedAt: entry?.fetchedAt ?? null, dataDate, cacheAgeSeconds: age,
      state: !entry ? 'unavailable' : stale || age! >= DAY_MS / 1000 ? 'stale' : 'fresh' };
  }
  fresh(entry: CacheEntry<unknown> | null) { return !!entry && this.now().getTime() - Date.parse(entry.fetchedAt) < DAY_MS; }
}
