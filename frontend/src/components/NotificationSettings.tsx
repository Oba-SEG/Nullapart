import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { capabilityLock } from "../api/capabilities";
import {
  MAX_RECIPIENTS,
  SEVERITY_FLOORS,
  digestWindowOptions,
  draftFromSettings,
  loadNotificationSettings,
  saveNotificationSettings,
  settingsInputFrom,
  severityFloorOf,
  type DeliveryStatus,
  type NotificationDelivery,
  type NotificationDraft,
  type NotificationSettingsInput,
} from "../api/notifications";
import type { ApiError } from "../api/client";
import { hasPermission, loadSession } from "../auth/session";
import { StatusPill } from "./StatusPill";
import { StepUpPrompt } from "./StepUpPrompt";
import { Hint } from "./primitives/Hint";
import { randomUuid } from "../lib/ids";
import type { StatusTone } from "../lib/status";
import "./NotificationSettings.css";

const SEVERITY_FLOOR_LABELS: Record<string, string> = {
  info: "Info and above",
  warning: "Warning and above",
  critical: "Critical only",
};

const DELIVERY_LABELS: Record<DeliveryStatus, string> = {
  queued: "Queued",
  sent: "Delivered",
  suppressed: "Suppressed",
  dead_lettered: "Not delivered",
};

const DELIVERY_TONES: Record<DeliveryStatus, StatusTone> = {
  queued: "processing",
  sent: "delivered",
  suppressed: "review",
  dead_lettered: "threat",
};

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "Notification delivery is temporarily unavailable.";
}

function formatTimestamp(value: string | null): string {
  if (!value) return "not recorded";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(value),
  );
}

function sameDraft(left: NotificationDraft, right: NotificationDraft): boolean {
  return (
    left.enabled === right.enabled &&
    left.severityFloor === right.severityFloor &&
    left.recipients.trim() === right.recipients.trim() &&
    left.digestWindow.trim() === right.digestWindow.trim()
  );
}

function deliveryLabel(status: string): string {
  return DELIVERY_LABELS[status as DeliveryStatus] ?? status;
}

function deliveryTone(status: string): StatusTone {
  return DELIVERY_TONES[status as DeliveryStatus] ?? "muted";
}

interface NotificationSettingsProps {
  /** Titles the page already renders, so a ledger row names the finding it
   * delivered instead of an opaque id. Older notices may be absent, which is
   * why the id is always available as the fallback. */
  titlesById?: Record<string, string>;
}

/**
 * Whether this customer's domain findings get mailed, at what severity, to
 * whom, and how often, plus the delivery ledger that answers "was it sent".
 *
 * The settings are a request, not a promise: `effective.deliverable` is the
 * server's answer to whether a notice can actually leave, and every row below
 * it is what did.
 */
export function NotificationSettings({ titlesById = {} }: NotificationSettingsProps) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<NotificationDraft | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
  });
  const current = session.data ?? null;
  const canView = hasPermission(current, "notifications:view");
  const settings = useQuery({
    queryKey: ["notifications", "settings"],
    queryFn: ({ signal }) => loadNotificationSettings(signal),
    enabled: canView,
    refetchInterval: 60_000,
  });

  const loaded = draftFromSettings(settings.data);
  const form = draft ?? loaded;
  const dirty = draft !== null && !sameDraft(draft, loaded);
  const verifiedDomains = settings.data?.verified_domains ?? [];
  const built = settingsInputFrom(form, verifiedDomains);
  // A published capability is the server's own gate. Until it arrives the
  // console keeps its permission check, expressed in the same shape so a locked
  // control reads the same either way and never offers a refused write.
  const capability =
    settings.data?.capabilities?.update_settings ??
    (hasPermission(current, "notifications:manage")
      ? { allowed: true, blocker: null }
      : { allowed: false, blocker: "permission" });
  const canManage = capability.allowed;
  const manageLock = capabilityLock(
    capability,
    "Saving notification settings",
    "notifications:manage",
  );

  const save = useMutation({
    mutationFn: (input: NotificationSettingsInput) => saveNotificationSettings(input, randomUuid()),
    onSuccess: async (value) => {
      setDraft(null);
      setSaved(
        `${value.recipient_emails.length} recipient(s), ${severityFloorLabel(
          value.severity_floor,
        ).toLowerCase()}, ${formatTimestamp(value.updated_at)}`,
      );
      await queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });

  if (!canView) {
    return (
      <section className="card notification-settings" aria-labelledby="notifications-heading">
        <h2 id="notifications-heading">Alert mail</h2>
        <p className="notification-locked">
          Mail delivery for your domain findings needs the capability to view delivery alerts, which
          your roles do not grant. Ask your provider to add it to a role on this account.
        </p>
      </section>
    );
  }

  if (settings.isPending) {
    return (
      <section className="card notification-settings" aria-labelledby="notifications-heading">
        <h2 id="notifications-heading">Alert mail</h2>
        <p className="notification-state" role="status">
          Loading notification settings…
        </p>
      </section>
    );
  }

  if (settings.isError) {
    return (
      <section className="card notification-settings" aria-labelledby="notifications-heading">
        <h2 id="notifications-heading">Alert mail</h2>
        <p className="notification-state error" role="alert">
          {errorMessage(settings.error)}
        </p>
      </section>
    );
  }

  const data = settings.data;
  const effective = data.effective;
  const saveError = save.isError ? errorMessage(save.error) : null;

  return (
    <section className="card notification-settings" aria-labelledby="notifications-heading">
      <div className="notification-settings-head">
        <div>
          <h2 id="notifications-heading">Alert mail</h2>
          <p>
            {data.settings
              ? `Last saved by ${data.settings.updated_by} on ${formatTimestamp(
                  data.settings.updated_at,
                )}.`
              : "Nobody has saved settings for this customer yet, so the values below are the defaults."}
          </p>
        </div>
        <StatusPill
          tone={!effective.enabled ? "muted" : effective.deliverable ? "clean" : "review"}
          label={
            !effective.enabled
              ? "Alert mail off"
              : effective.deliverable
                ? "Alert mail live"
                : "No recipient yet"
          }
        />
      </div>

      <p className="notification-effective">
        Currently: {severityFloorLabel(effective.severity_floor)} findings,{" "}
        {effective.recipient_count === 0
          ? "no recipient addresses"
          : `${effective.recipient_count} recipient${effective.recipient_count === 1 ? "" : "s"}`}
        , {digestWindowSentence(effective.digest_window_minutes)}.{" "}
        {!effective.deliverable && effective.enabled
          ? "Nothing leaves until at least one verified recipient is saved."
          : null}
      </p>

      <div className="notification-settings-form">
        <label className="notification-switch">
          <input
            type="checkbox"
            checked={form.enabled}
            disabled={!canManage}
            onChange={(event) => setDraft({ ...form, enabled: event.target.checked })}
          />
          <span>Send alert mail for domain findings</span>
        </label>

        <div className="notification-field">
          <label htmlFor="notification-severity-floor">Severity floor</label>
          <select
            id="notification-severity-floor"
            value={form.severityFloor}
            disabled={!canManage}
            onChange={(event) =>
              setDraft({ ...form, severityFloor: severityFloorOf(event.target.value) })
            }
          >
            {SEVERITY_FLOORS.map((floor) => (
              <option value={floor} key={floor}>
                {SEVERITY_FLOOR_LABELS[floor]}
              </option>
            ))}
          </select>
          <small>
            A finding at or above this severity is eligible. The security floor still applies.
          </small>
        </div>

        <div className="notification-field">
          <label htmlFor="notification-digest">Digest window</label>
          <select
            id="notification-digest"
            value={form.digestWindow}
            disabled={!canManage}
            onChange={(event) => setDraft({ ...form, digestWindow: event.target.value })}
          >
            {digestWindowOptions(form.digestWindow).map((option) => (
              <option value={option.value} key={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <small>
            Repeats within this window for the same domain and finding type are sent once.
          </small>
          {built.errors.digestWindow ? (
            <p className="notification-field-error" role="alert">
              {built.errors.digestWindow}
            </p>
          ) : null}
        </div>

        <div className="notification-field notification-field-wide">
          <label htmlFor="notification-recipients">Recipients</label>
          <textarea
            id="notification-recipients"
            rows={3}
            value={form.recipients}
            disabled={!canManage}
            onChange={(event) => setDraft({ ...form, recipients: event.target.value })}
          />
          <small>
            One address per line or separated by commas, up to {MAX_RECIPIENTS}. Every address must
            sit inside a domain this customer has verified; a subdomain is not covered by its
            parent. Verified domains available now:{" "}
            {verifiedDomains.length === 0 ? "none yet" : verifiedDomains.join(", ")}.
          </small>
          {built.errors.recipients ? (
            <p className="notification-field-error" role="alert">
              {built.errors.recipients}
            </p>
          ) : null}
        </div>
      </div>

      {manageLock ? (
        <p className="notification-locked" role="status">
          {manageLock}
        </p>
      ) : (
        <div className="notification-save">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!dirty || !built.input || save.isPending}
            onClick={() => {
              if (built.input) save.mutate(built.input);
            }}
          >
            {save.isPending ? "Saving…" : "Save settings"}
          </button>
          {dirty ? (
            <button
              type="button"
              className="btn btn-ghost"
              disabled={save.isPending}
              onClick={() => setDraft(null)}
            >
              Discard changes
            </button>
          ) : null}
          <Hint label="Changing who receives alerts signs you in again first, and the change is recorded in your audit log.">
            <span className="notification-save-note">Needs a fresh sign-in, and is audited</span>
          </Hint>
        </div>
      )}

      {saved && !save.isPending ? (
        <p className="notification-saved" role="status">
          Saved: {saved}.
        </p>
      ) : null}
      {saveError ? (
        <p className="notification-error" role="alert">
          {saveError}
        </p>
      ) : null}
      <StepUpPrompt error={save.error} />

      <section aria-label="Delivery history" className="notification-deliveries">
        <h3>Delivery history</h3>
        {data.deliveries.length === 0 ? (
          <p className="notification-state">
            No notice has been queued for this customer yet. The ledger is the only record of what
            was sent.
          </p>
        ) : (
          <div className="notification-delivery-list">
            {data.deliveries.map((delivery) => (
              <DeliveryRow
                delivery={delivery}
                title={titlesById[delivery.notification_id]}
                key={delivery.notification_id}
              />
            ))}
          </div>
        )}
      </section>
    </section>
  );
}

function DeliveryRow({ delivery, title }: { delivery: NotificationDelivery; title?: string }) {
  return (
    <div className="notification-delivery">
      <StatusPill tone={deliveryTone(delivery.status)} label={deliveryLabel(delivery.status)} />
      <div className="notification-delivery-copy">
        <strong>{title ?? `Notice ${delivery.notification_id}`}</strong>
        <span>
          {delivery.recipient_count} recipient{delivery.recipient_count === 1 ? "" : "s"} ·{" "}
          {delivery.attempts} attempt{delivery.attempts === 1 ? "" : "s"} ·{" "}
          {formatTimestamp(delivery.updated_at)}
        </span>
        {delivery.reason ? <small>{delivery.reason}</small> : null}
        {delivery.outbound_transaction_id ? (
          <small className="notification-delivery-ref">
            Mail queue reference {delivery.outbound_transaction_id}
          </small>
        ) : null}
      </div>
    </div>
  );
}

function severityFloorLabel(value: string): string {
  return SEVERITY_FLOOR_LABELS[value] ?? `Findings at ${value} and above`;
}

function digestWindowSentence(minutes: number): string {
  if (minutes === 0) return "mailed as each finding opens";
  if (minutes < 60) return `coalesced over ${minutes} minutes`;
  if (minutes === 60) return "coalesced over an hour";
  if (minutes < 1440) return `coalesced over ${Math.round(minutes / 60)} hours`;
  return "coalesced over a day";
}
