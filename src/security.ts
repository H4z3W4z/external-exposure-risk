export function redact<T>(value: T, secrets: string[]): T {
  const variants = [...new Set(secrets.filter(Boolean).flatMap(s => [s, encodeURIComponent(s)]))].sort((a, b) => b.length - a.length);
  // Redact string values, not JSON syntax: keys containing quotes/numbers cannot corrupt serialization.
  return JSON.parse(JSON.stringify(value, (_key, item: unknown) => typeof item === 'string'
    ? variants.reduce((s, secret) => s.split(secret).join('[REDACTED]'), item) : item)) as T;
}
