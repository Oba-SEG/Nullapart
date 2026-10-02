export type StatusTone = "clean" | "threat" | "review" | "processing" | "delivered" | "muted";

export function severityTone(severity: string): StatusTone {
  if (severity === "critical" || severity === "high") return "threat";
  if (severity === "medium") return "review";
  return "muted";
}
