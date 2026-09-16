export function redact<T>(value: T, secrets: string[]): T {
  let encoded = JSON.stringify(value);
  for (const secret of secrets.filter(Boolean)) {
    for (const variant of new Set([secret, encodeURIComponent(secret)])) {
      const escaped = JSON.stringify(variant).slice(1, -1);
      encoded = encoded.split(escaped).join('[REDACTED]');
    }
  }
  return JSON.parse(encoded) as T;
}
