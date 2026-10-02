/**
 * Renders machine tokens (`QUARANTINE_MALWARE`, `audit_access_list`) as
 * readable sentence case for primary UI copy. The raw token stays visible
 * as secondary mono text so operators can still match logs and APIs.
 */
export function humanizeToken(token: string): string {
  const words = token
    .split(/[_\-.]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());
  if (words.length === 0) return token;
  const [first, ...rest] = words;
  return [first.charAt(0).toUpperCase() + first.slice(1), ...rest].join(" ");
}
