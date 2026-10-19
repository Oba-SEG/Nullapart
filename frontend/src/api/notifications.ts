/**
 * Customer notification contract.
 *
 * Mirrors `nullapart_mail_core::notification_api` and the acknowledge route in
 * `domain_security`. Wire fields stay snake_case exactly as the API publishes
 * them; the validation helpers below mirror the server's own rules so an
 * operator is not offered a save the API will refuse. The server stays
 * authoritative: nothing here grants or widens a permission.
 *
 * Two facts the console must keep straight, because the API says them plainly:
 *
 * - settings are not a delivery promise. `effective.deliverable` is the
 *   server's answer to "could a notice actually leave";
 * - recipients are constrained to domains this customer has verified. Mailing an
 *   address outside them is refused, not warned about, because otherwise
 *   Nullapart would mail on someone else's behalf.
 */

import type { WriteCapability } from "./capabilities";
import { api } from "./client";

export const SEVERITY_FLOORS = ["info", "warning", "critical"] as const;
export type SeverityFloor = (typeof SEVERITY_FLOORS)[number];

/** Mirrors `MAX_RECIPIENTS` and the database CHECK constraint behind it. */
export const MAX_RECIPIENTS = 10;
export const MAX_DIGEST_WINDOW_MINUTES = 1440;
const MAX_RECIPIENT_LENGTH = 320;

export interface NotificationSettingsView {
  enabled: boolean;
  severity_floor: string;
  recipient_emails: string[];
  digest_window_minutes: number;
  updated_by: string;
  updated_at: string;
}

export interface EffectiveNotificationSettings {
  enabled: boolean;
  severity_floor: string;
  recipient_count: number;
  digest_window_minutes: number;
  deliverable: boolean;
}

/**
 * One row of the delivery ledger: the only answer to "was it sent".
 * `outbound_transaction_id` is the mail server's own queue reference; the key
 * appears only in a platform answer. The ledger publishes no recipient
 * addresses and no message content.
 */
export interface NotificationDelivery {
  notification_id: string;
  status: DeliveryStatus;
  recipient_count: number;
  attempts: number;
  /** Why this notice did not go out, in keys the console puts words to. The
   * platform answer omits it. */
  result?: string;
  /** The delivery worker's own note, which quotes the sending path. The
   * customer answer omits the key. */
  reason?: string;
  outbound_transaction_id?: string;
  created_at: string;
  updated_at: string;
}

export type DeliveryStatus = "queued" | "sent" | "suppressed" | "dead_lettered";

export interface NotificationCapabilities {
  update_settings: WriteCapability;
}

export interface NotificationSettingsResponse {
  /** Which installation answered. The customer answer omits the key. */
  deployment_id?: string;
  generated_at: string;
  /** null until this tenant has saved a row, so the console can show the
   * effective values as platform defaults rather than as somebody's choice. */
  settings: NotificationSettingsView | null;
  effective: EffectiveNotificationSettings;
  verified_domains: string[];
  deliveries: NotificationDelivery[];
  capabilities: NotificationCapabilities;
}

export interface NotificationSettingsInput {
  enabled: boolean;
  severity_floor: SeverityFloor;
  recipient_emails: string[];
  digest_window_minutes: number;
}

export interface NotificationAcknowledgment {
  notification_id: string;
  notification_type: string;
  severity: string;
  title: string;
  status: string;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  /** False when the finding was already acknowledged, so a replay or a second
   * operator can see that this call recorded nothing new. */
  changed: boolean;
}

export function loadNotificationSettings(signal?: AbortSignal) {
  return api.get<NotificationSettingsResponse>("/notifications/settings", signal);
}

/**
 * A full settings write, not a patch: the server fills any omitted field from
 * the stored row, so the console always sends all four values it rendered.
 */
export function saveNotificationSettings(
  body: NotificationSettingsInput,
  idempotencyKey: string,
): Promise<NotificationSettingsView> {
  return api.put<NotificationSettingsView>("/notifications/settings", body, { idempotencyKey });
}

export function acknowledgeNotification(
  notificationId: string,
  idempotencyKey: string,
): Promise<NotificationAcknowledgment> {
  return api.post<NotificationAcknowledgment>(
    `/domain-security/notifications/${encodeURIComponent(notificationId)}/acknowledge`,
    undefined,
    { idempotencyKey },
  );
}

// ---------------------------------------------------------------------------
// Editor state and validation (client-side convenience; the server decides)
// ---------------------------------------------------------------------------

/** Form state for the four values this endpoint writes. */
export interface NotificationDraft {
  enabled: boolean;
  severityFloor: SeverityFloor;
  /** Raw addresses as typed, one per line or comma. */
  recipients: string;
  /** Text so an invalid window can be shown against the field instead of
   * silently coerced to a number the operator never entered. */
  digestWindow: string;
}

const DIGEST_WINDOWS = [0, 15, 60, 360, 1440];

export function draftFromSettings(
  response: NotificationSettingsResponse | undefined,
): NotificationDraft {
  const settings = response?.settings ?? null;
  const effective = response?.effective;
  return {
    enabled: settings?.enabled ?? effective?.enabled ?? true,
    severityFloor: severityFloorOf(settings?.severity_floor ?? effective?.severity_floor),
    recipients: (settings?.recipient_emails ?? []).join("\n"),
    digestWindow: String(settings?.digest_window_minutes ?? effective?.digest_window_minutes ?? 60),
  };
}

export function severityFloorOf(value: string | null | undefined): SeverityFloor {
  return (SEVERITY_FLOORS as readonly string[]).includes(value ?? "")
    ? (value as SeverityFloor)
    : "warning";
}

/** Splits typed addresses the way the server accepts them: spaces and commas
 * are separators, never part of an address. */
export function splitRecipients(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export function recipientAddressError(address: string): string | undefined {
  const value = address.trim();
  if (value.length > MAX_RECIPIENT_LENGTH) return "That address is too long.";
  const parts = value.split("@");
  if (parts.length !== 2 || parts[0].length === 0) {
    return "Enter a complete address like postmaster@example.com.";
  }
  if (/[\r\n<>]/.test(value) || /\s/.test(value)) {
    return "An address cannot contain spaces, angle brackets or line breaks.";
  }
  const domain = parts[1] ?? "";
  if (!domain.includes("."))
    return "Enter an address with a full domain, like postmaster@example.com.";
  return undefined;
}

/**
 * Per-address problems plus the normalized list the server would store.
 * A duplicate is not an error: the ledger records one mail per notice, so the
 * console drops the repeat and says so through `droppedDuplicates`.
 */
export function validateRecipients(
  raw: string[],
  verifiedDomains: string[],
): { emails: string[]; errors: string[]; droppedDuplicates: number } {
  const emails: string[] = [];
  const errors: string[] = [];
  let droppedDuplicates = 0;
  for (const address of raw) {
    const value = address.trim().toLowerCase();
    const shapeError = recipientAddressError(value);
    if (shapeError !== undefined) {
      errors.push(`${address.trim()}: ${shapeError}`);
      continue;
    }
    const domain = value.split("@")[1] ?? "";
    // Subdomains are not covered by a verified parent: the tenant proved the
    // zone it lists, not a host below it.
    if (!verifiedDomains.some((verified) => verified.toLowerCase() === domain)) {
      errors.push(
        `${value} is outside the domains your customer has verified. Verify ${domain} first, or use an address on ${
          verifiedDomains[0] ?? "a verified domain"
        }.`,
      );
      continue;
    }
    if (emails.includes(value)) droppedDuplicates += 1;
    else emails.push(value);
  }
  if (emails.length > MAX_RECIPIENTS) {
    errors.push(`Notification recipients are limited to ${MAX_RECIPIENTS} addresses.`);
  }
  return { emails, errors, droppedDuplicates };
}

export function digestWindowError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0) return "Enter a digest window in minutes.";
  const minutes = Number(trimmed);
  if (!Number.isInteger(minutes)) return "Enter the digest window as whole minutes.";
  if (minutes < 0 || minutes > MAX_DIGEST_WINDOW_MINUTES) {
    return `Digest window must be between 0 and ${MAX_DIGEST_WINDOW_MINUTES} minutes.`;
  }
  return undefined;
}

/** Fastest useful choices, plus whatever the tenant has actually stored. */
export function digestWindowOptions(current: string): { value: string; label: string }[] {
  const values = [...DIGEST_WINDOWS];
  const stored = Number(current.trim());
  if (Number.isInteger(stored) && stored >= 0 && !values.includes(stored)) values.push(stored);
  return values
    .sort((left, right) => left - right)
    .map((minutes) => ({ value: String(minutes), label: digestWindowLabel(minutes) }));
}

export function digestWindowLabel(minutes: number): string {
  if (minutes === 0) return "Immediately, per finding";
  if (minutes < 60) return `Every ${minutes} minutes`;
  if (minutes === 60) return "Every hour";
  if (minutes < 1440) return `Every ${Math.round(minutes / 60)} hours`;
  return "Once a day";
}

export function settingsInputFrom(
  draft: NotificationDraft,
  verifiedDomains: string[],
): {
  input: NotificationSettingsInput | null;
  errors: { recipients?: string; digestWindow?: string };
} {
  const recipients = validateRecipients(splitRecipients(draft.recipients), verifiedDomains);
  const windowError = digestWindowError(draft.digestWindow);
  const errors: { recipients?: string; digestWindow?: string } = {};
  if (recipients.errors.length > 0) errors.recipients = recipients.errors.join(" ");
  if (windowError !== undefined) errors.digestWindow = windowError;
  if (recipients.errors.length > 0 || windowError !== undefined) return { input: null, errors };
  return {
    input: {
      enabled: draft.enabled,
      severity_floor: draft.severityFloor,
      recipient_emails: recipients.emails,
      digest_window_minutes: Number(draft.digestWindow.trim()),
    },
    errors,
  };
}
