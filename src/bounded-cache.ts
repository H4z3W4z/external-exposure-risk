/** Least-recently-used cache bounded by both entry count and serialized byte weight.
 * Byte weight is a deterministic budget, not a claim about JavaScript heap usage. */
export class BoundedCache<T> {
  private entries = new Map<string, { value: T; bytes: number }>();
  bytes = 0;
  constructor(readonly maxBytes = 8_000_000, readonly maxEntries = 10_000, private onEvict = () => {}) {}
  get size() { return this.entries.size; }
  has(key: string) { return this.entries.has(key); }
  get(key: string): T | undefined {
    const item = this.entries.get(key);
    if (!item) return undefined;
    this.entries.delete(key); this.entries.set(key, item);
    return item.value;
  }
  set(key: string, value: T): void {
    const bytes = Buffer.byteLength(JSON.stringify(value)) + Buffer.byteLength(key);
    const old = this.entries.get(key);
    if (old) { this.bytes -= old.bytes; this.entries.delete(key); }
    if (bytes > this.maxBytes) { this.onEvict(); return; }
    while (this.entries.size && (this.bytes + bytes > this.maxBytes || this.entries.size >= this.maxEntries)) {
      const first = this.entries.keys().next().value!;
      this.bytes -= this.entries.get(first)!.bytes; this.entries.delete(first); this.onEvict();
    }
    this.entries.set(key, { value, bytes }); this.bytes += bytes;
  }
}
