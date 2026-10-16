/**
 * Renders machine tokens (`QUARANTINE_MALWARE`, `audit_access_list`) as
 * readable sentence case for primary UI copy. The raw token stays visible
 * as secondary mono text so operators can still match logs and APIs.
 */
const ACRONYMS = new Set([
  "ai",
  "api",
  "bimi",
  "csv",
  "dkim",
  "dmarc",
  "dns",
  "http",
  "https",
  "id",
  "ip",
  "llm",
  "mfa",
  "mta",
  "mx",
  "ruf",
  "smtp",
  "spf",
  "sso",
  "sts",
  "tls",
  "ttl",
  "url",
]);

export function humanizeToken(token: string): string {
  const words = token
    .split(/[_\-.]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());
  if (words.length === 0) return token;
  const [first, ...rest] = words;
  // An acronym keeps its caps wherever it sits, so "deep_ai" reads as "Deep AI"
  // rather than the sentence-cased "Deep ai" that no operator would write.
  const shaped = (word: string, lead: boolean) =>
    ACRONYMS.has(word)
      ? word.toUpperCase()
      : lead
        ? word.charAt(0).toUpperCase() + word.slice(1)
        : word;
  return [shaped(first, true), ...rest.map((word) => shaped(word, false))].join(" ");
}
