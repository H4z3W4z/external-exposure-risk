export const obj = (v: unknown): Record<string, unknown> => v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};
export const str = (v: unknown): string | null => typeof v === 'string' && v.trim() ? v.trim().slice(0, 2048) : null;
export const strings = (v: unknown): string[] => [...new Set((Array.isArray(v) ? v : []).map(str).filter((s): s is string => !!s))].sort();
export const cveId = (v: unknown): string | null => typeof v === 'string' && /^CVE-\d{4}-\d{4,19}$/i.test(v) ? v.toUpperCase() : null;
export function timestamp(v: unknown): string | null {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$/.test(v)) return null;
  if (!date(v.slice(0, 10))) return null;
  const utc = /(?:Z|[+-]\d{2}:\d{2})$/.test(v) ? v : `${v}Z`;
  const t = Date.parse(utc);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}
export function date(v: unknown): string | null {
  return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString().slice(0, 10) === v ? v : null;
}
