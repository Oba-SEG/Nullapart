import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, ExternalLink, RefreshCw, ShieldCheck } from "lucide-react";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import { acknowledgeNotification } from "../api/notifications";
import { hasPermission, loadSession } from "../auth/session";
import { StatusPill } from "../components/StatusPill";
import { ControlRail } from "../components/ControlRail";
import { NotificationSettings } from "../components/NotificationSettings";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { Hint } from "../components/primitives/Hint";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { randomUuid } from "../lib/ids";
import {
  checkVerdictLabel,
  dmarcPolicyLabel,
  domainTypeLabel,
  sourceClassificationLabel,
  tokenLabel,
  verificationStatusLabel,
} from "../lib/labels";
import type { StatusTone } from "../lib/status";
import { severityLabel } from "../lib/status";
import "./DomainSecurity.css";

interface DomainSecuritySummary {
  domains_total: number;
  verified_domains: number;
  messages_30d: number;
  dmarc_aligned_messages_30d: number;
  unknown_sources: number;
  report_authorization_broken: number;
  bimi_not_ready: number;
  open_notifications: number;
}

interface DmarcMetrics {
  latest_policy: string | null;
  reports_30d: number;
  messages_30d: number;
  dkim_aligned_messages_30d: number;
  spf_aligned_messages_30d: number;
  dmarc_aligned_messages_30d: number;
  rejected_or_quarantined_messages_30d: number;
}

interface ReportAuthorizationStatus {
  report_host: string;
  owner_name: string;
  expected_value: string;
  actual_value: string | null;
  status: "valid" | "missing" | "invalid" | "unknown";
  checked_at: string | null;
  detail: string;
}

interface BimiStatus {
  selector: string;
  status: "ready" | "not_ready" | "invalid" | "unknown";
  validation_scope: "dns_metadata_only";
  logo_url: string | null;
  svg_status: "valid" | "invalid" | "not_checked" | "unknown";
  dmarc_enforcement_status: "enforced" | "not_enforced" | "unknown";
  certificate_status: "valid" | "missing" | "invalid" | "not_required" | "unknown";
  errors: string[];
  checked_at: string | null;
}

interface DomainObservation {
  check_type: string;
  status: "pass" | "warning" | "fail" | "unknown";
  observed_value: string | null;
  detail: string;
  observed_at: string;
}

interface DomainSourceSummary {
  source_key: string;
  source_ip: string;
  source_domain: string | null;
  messages_30d: number;
  dkim_aligned_messages_30d: number;
  spf_aligned_messages_30d: number;
  dmarc_aligned_messages_30d: number;
  classification:
    "authorized" | "expected_incomplete" | "unknown" | "suspicious" | "malicious" | "third_party";
  suggested_action: string;
}

type SourceClassification = DomainSourceSummary["classification"];

interface DomainSecurityDomain {
  id: string;
  domain: string;
  verification_status: string;
  domain_type: string;
  dmarc: DmarcMetrics;
  report_authorization: ReportAuthorizationStatus | null;
  bimi: BimiStatus | null;
  observations: DomainObservation[];
  sources: DomainSourceSummary[];
  next_actions: string[];
}

interface DomainSecurityNotification {
  id: string;
  domain_id: string | null;
  notification_type: string;
  severity: "info" | "warning" | "critical";
  title: string;
  detail: string;
  status: string;
  created_at: string;
}

interface AcknowledgedNotification {
  id: string;
  domain_id: string | null;
  notification_type: string;
  severity: "info" | "warning" | "critical";
  title: string;
  detail: string;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
}

interface DomainSecurityResponse {
  /** Which installation answered. The customer answer omits the key. */
  deployment_id?: string;
  generated_at: string;
  summary: DomainSecuritySummary;
  domains: DomainSecurityDomain[];
  notifications: DomainSecurityNotification[];
  recent_acknowledgments: AcknowledgedNotification[];
}

interface SourceClassificationRequest {
  domain_id: string;
  source_key: string;
  source_ip: string;
  source_domain: string | null;
  classification: SourceClassification;
  notes: string;
}

interface SourceClassificationResult {
  domain_id: string;
  domain: string;
  source_key: string;
  classification: SourceClassification;
  notes: string | null;
  changed: boolean;
  updated_at: string;
}

const CLASSIFICATION_OPTIONS: { value: SourceClassification; label: string }[] = [
  { value: "authorized", label: "Authorized" },
  { value: "expected_incomplete", label: "Expected but incomplete" },
  { value: "third_party", label: "Third-party service" },
  { value: "suspicious", label: "Suspicious" },
  { value: "malicious", label: "Malicious" },
  { value: "unknown", label: "Unknown" },
];

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "Domain security is temporarily unavailable.";
}

function percent(part: number, total: number): string {
  // A withheld or malformed count must not become "NaN%" on a customer's page.
  if (!Number.isFinite(part) || !Number.isFinite(total) || total <= 0) return "—";
  return `${Math.round((part / total) * 100)}%`;
}

function toneForStatus(status: string): StatusTone {
  if (["valid", "ready", "pass", "verified", "enforced"].includes(status)) return "clean";
  if (["warning", "missing", "not_ready", "not_checked", "unknown"].includes(status)) {
    return "review";
  }
  return "threat";
}

function formatDate(value: string | null): string {
  if (!value) return "not checked";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function policyTone(policy: string | null): StatusTone {
  if (policy === "reject" || policy === "quarantine") return "clean";
  if (policy === "none") return "review";
  return "threat";
}

function bimiStatusLabel(bimi: BimiStatus): string {
  const verdict = checkVerdictLabel(bimi.status);
  return bimi.validation_scope === "dns_metadata_only" ? `${verdict} (DNS records only)` : verdict;
}

function SummaryCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="domain-security-summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

export function DomainSecurity() {
  const queryClient = useQueryClient();
  const [classificationDrafts, setClassificationDrafts] = useState<
    Record<string, SourceClassification>
  >({});
  const [notice, setNotice] = useState<string | null>(null);
  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
  });
  const security = useQuery({
    queryKey: ["domain-security"],
    queryFn: ({ signal }) => api.get<DomainSecurityResponse>("/domain-security", signal),
    refetchInterval: 60_000,
  });
  const canManage = hasPermission(session.data ?? null, "domain-security:manage");
  const classifySource = useMutation({
    mutationFn: (request: SourceClassificationRequest) =>
      api.post<SourceClassificationResult>("/domain-security/source-classifications", request, {
        idempotencyKey: randomUuid(),
      }),
    onSuccess: async (result) => {
      setNotice(
        `${result.domain} sending source is now ${sourceClassificationLabel(result.classification).toLowerCase()}.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["domain-security"] });
    },
  });

  const acknowledge = useMutation({
    mutationFn: (notificationId: string) => acknowledgeNotification(notificationId, randomUuid()),
    onSuccess: async (result) => {
      setNotice(
        result.changed
          ? `“${result.title}” acknowledged${
              result.acknowledged_by ? ` by ${result.acknowledged_by}` : ""
            }.`
          : `“${result.title}” was already acknowledged. Nothing new was recorded.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["domain-security"] });
    },
  });
  const acknowledgeError = acknowledge.isError ? errorMessage(acknowledge.error) : null;

  if (security.isPending) {
    return (
      <div className="domain-security-state" role="status">
        Loading domain security…
      </div>
    );
  }

  if (security.isError) {
    return (
      <div className="domain-security-state error" role="alert">
        {errorMessage(security.error)}
      </div>
    );
  }

  const data = security.data;
  const aligned = percent(data.summary.dmarc_aligned_messages_30d, data.summary.messages_30d);
  const classifyError = classifySource.isError ? errorMessage(classifySource.error) : null;
  // The delivery ledger names notices by id only, so the findings this page
  // already renders supply the words beside it.
  const notificationTitles: Record<string, string> = Object.fromEntries(
    [...data.notifications, ...data.recent_acknowledgments].map((item) => [item.id, item.title]),
  );

  function sourceDraftKey(domainId: string, sourceKey: string): string {
    return `${domainId}:${sourceKey}`;
  }

  function selectedClassification(
    domainId: string,
    source: DomainSourceSummary,
  ): SourceClassification {
    return (
      classificationDrafts[sourceDraftKey(domainId, source.source_key)] ?? source.classification
    );
  }

  function setSelectedClassification(
    domainId: string,
    sourceKey: string,
    classification: SourceClassification,
  ) {
    setClassificationDrafts((current) => ({
      ...current,
      [sourceDraftKey(domainId, sourceKey)]: classification,
    }));
  }

  return (
    <div className="domain-security-page">
      <WorkspaceHeader
        eyebrow="Trust & identity"
        title="Domain security"
        description="DMARC reporting, sending sources, external report receiving and BIMI logo readiness for the domains in this scope."
        scope="Domain configuration"
        actions={
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => void security.refetch()}
            aria-label="Refresh domain security"
          >
            <RefreshCw size={14} aria-hidden="true" />
            Refresh
          </button>
        }
      />

      <ControlRail
        title="Domain trust priorities"
        summary="Start with broken report receiving and unknown sources before you treat a domain as ready to send from."
        signals={[
          {
            label: "Verified domains",
            value: `${data.summary.verified_domains}/${data.summary.domains_total}`,
            detail: "Domains that pass verification now.",
            tone:
              data.summary.verified_domains === data.summary.domains_total
                ? "healthy"
                : "attention",
          },
          {
            label: "Unknown sources",
            value: data.summary.unknown_sources,
            detail: "Sending sources that still need a classification.",
            tone: data.summary.unknown_sources > 0 ? "attention" : "healthy",
          },
          {
            label: "Open notices",
            value: data.summary.open_notifications,
            detail: "Domain checks that need your review.",
            tone: data.summary.open_notifications > 0 ? "attention" : "healthy",
          },
        ]}
      />

      <WorkflowGuide
        title="Establish a defensible sending identity"
        description="Work from what you observe, then correct the domain configuration where your role allows."
        steps={[
          {
            label: "Observe",
            detail: "Review SPF, DKIM and DMARC verification status and evidence.",
          },
          {
            label: "Correct",
            detail: "Make the domain change your role allows, with a reason.",
          },
          {
            label: "Verify",
            detail: "Refresh and confirm before treating the domain as ready.",
          },
        ]}
      />

      {notice ? (
        <div className="domain-security-notice" role="status">
          {notice}
        </div>
      ) : null}
      {classifyError ? (
        <div className="domain-security-notice error" role="alert">
          {classifyError}
        </div>
      ) : null}

      <section className="card domain-security-summary" aria-label="Domain security summary">
        <SummaryCard
          label="Verified domains"
          value={`${data.summary.verified_domains}/${data.summary.domains_total}`}
          detail="eligible for reporting"
        />
        <SummaryCard
          label="DMARC alignment"
          value={aligned}
          detail={`${data.summary.messages_30d} messages in the last 30 days`}
        />
        <SummaryCard
          label="Unknown sources"
          value={data.summary.unknown_sources}
          detail="need classification"
        />
        <SummaryCard
          label="Report receiving"
          value={data.summary.report_authorization_broken}
          detail="external receiving needs attention"
        />
        <SummaryCard
          label="BIMI logo not ready"
          value={data.summary.bimi_not_ready}
          detail="logo checks that need attention"
        />
        <SummaryCard
          label="Open alerts"
          value={data.summary.open_notifications}
          detail="domain checks that need your review"
        />
      </section>

      {data.notifications.length > 0 || data.recent_acknowledgments.length > 0 ? (
        <section className="card domain-security-alerts" aria-labelledby="domain-alerts-heading">
          <h2 id="domain-alerts-heading">Findings</h2>
          {data.notifications.length === 0 ? (
            <p className="domain-security-good">
              <CheckCircle2 size={15} aria-hidden="true" />
              No open findings.
            </p>
          ) : (
            <div className="domain-security-alert-list">
              {data.notifications.map((notification) => (
                <article
                  className={`domain-security-alert ${notification.severity}`}
                  key={notification.id}
                >
                  <AlertTriangle size={16} aria-hidden="true" />
                  <div className="domain-security-alert-body">
                    <strong>{notification.title}</strong>
                    <p>{notification.detail}</p>
                    <small>
                      {severityLabel(notification.severity)} · opened{" "}
                      {formatDate(notification.created_at)}
                    </small>
                  </div>
                  {canManage ? (
                    <div className="domain-security-alert-action">
                      <button
                        type="button"
                        className="btn btn-ghost"
                        disabled={acknowledge.isPending}
                        onClick={() => acknowledge.mutate(notification.id)}
                      >
                        Acknowledge
                      </button>
                      <Hint label="Acknowledging records who closed the finding and when. It does not change the domain or the mail flow.">
                        <span className="domain-security-alert-note">Audited</span>
                      </Hint>
                    </div>
                  ) : null}
                </article>
              ))}
            </div>
          )}
          {acknowledgeError ? (
            <p className="domain-security-alert-error" role="alert">
              {acknowledgeError}
            </p>
          ) : null}
          <StepUpPrompt error={acknowledge.error} />
          {data.recent_acknowledgments.length > 0 ? (
            <section aria-label="Recently acknowledged findings">
              <h3>Recently acknowledged</h3>
              <ul className="domain-security-acknowledged">
                {data.recent_acknowledgments.map((item) => (
                  <li key={item.id}>
                    <strong>{item.title}</strong>
                    <span>
                      {item.acknowledged_by ?? "a previous operator"} ·{" "}
                      {formatDate(item.acknowledged_at)}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </section>
      ) : null}

      <NotificationSettings titlesById={notificationTitles} />

      {data.domains.length === 0 ? (
        <section className="card domain-security-empty">
          <ShieldCheck size={28} aria-hidden="true" />
          <div>
            <h2>No domains yet</h2>
            <p>Add and verify customer domains to see their sending and logo checks here.</p>
          </div>
        </section>
      ) : (
        <div className="domain-security-domain-list">
          {data.domains.map((domain) => (
            <article className="card domain-security-domain" key={domain.id}>
              <div className="domain-security-domain-head">
                <div>
                  <h2>{domain.domain}</h2>
                  <p>
                    {domainTypeLabel(domain.domain_type)} ·{" "}
                    {verificationStatusLabel(domain.verification_status)}
                  </p>
                </div>
                <StatusPill
                  tone={policyTone(domain.dmarc.latest_policy)}
                  label={`DMARC ${dmarcPolicyLabel(domain.dmarc.latest_policy ?? "missing")}`}
                />
              </div>

              <div className="domain-security-grid">
                <section aria-label={`${domain.domain} DMARC metrics`}>
                  <h3>DMARC report volume</h3>
                  <dl className="domain-security-metrics">
                    <div>
                      <dt>Reports</dt>
                      <dd>{domain.dmarc.reports_30d}</dd>
                    </div>
                    <div>
                      <dt>Messages</dt>
                      <dd>{domain.dmarc.messages_30d}</dd>
                    </div>
                    <div>
                      <dt>Aligned</dt>
                      <dd>
                        {percent(
                          domain.dmarc.dmarc_aligned_messages_30d,
                          domain.dmarc.messages_30d,
                        )}
                      </dd>
                    </div>
                    <div>
                      <dt>Quarantine/reject</dt>
                      <dd>{domain.dmarc.rejected_or_quarantined_messages_30d}</dd>
                    </div>
                  </dl>
                </section>

                <section aria-label={`${domain.domain} report receiving`}>
                  <h3>
                    <Hint label="Where domain reports are sent">
                      <span className="hint-term">External report receiving</span>
                    </Hint>
                  </h3>
                  {domain.report_authorization ? (
                    <div className="domain-security-record">
                      <StatusPill
                        tone={toneForStatus(domain.report_authorization.status)}
                        label={checkVerdictLabel(domain.report_authorization.status)}
                      />
                      <code>{domain.report_authorization.owner_name}</code>
                      <span>TXT {domain.report_authorization.expected_value}</span>
                      <small>{domain.report_authorization.detail}</small>
                    </div>
                  ) : (
                    <p className="domain-security-muted">No report receiving check recorded yet.</p>
                  )}
                </section>

                <section aria-label={`${domain.domain} BIMI readiness`}>
                  <h3>
                    <Hint label="These checks read DNS records only; logo files are not downloaded.">
                      <span className="hint-term">BIMI readiness</span>
                    </Hint>
                  </h3>
                  {domain.bimi ? (
                    <div className="domain-security-record">
                      <StatusPill
                        tone={toneForStatus(domain.bimi.status)}
                        label={bimiStatusLabel(domain.bimi)}
                      />
                      <span>Selector {domain.bimi.selector}</span>
                      <span>Logo file {checkVerdictLabel(domain.bimi.svg_status)}</span>
                      <span>Certificate {checkVerdictLabel(domain.bimi.certificate_status)}</span>
                      <span>DMARC {checkVerdictLabel(domain.bimi.dmarc_enforcement_status)}</span>
                      {domain.bimi.logo_url ? (
                        <span className="domain-security-logo-url">
                          <ExternalLink size={13} aria-hidden="true" />
                          {domain.bimi.logo_url}
                        </span>
                      ) : null}
                      <small>These checks read DNS records only.</small>
                    </div>
                  ) : (
                    <p className="domain-security-muted">No BIMI check recorded yet.</p>
                  )}
                </section>
              </div>

              <section
                className="domain-security-actions"
                aria-label={`${domain.domain} next actions`}
              >
                <h3>Next actions</h3>
                {domain.next_actions.length === 0 ? (
                  <p className="domain-security-good">
                    <CheckCircle2 size={15} aria-hidden="true" />
                    No action needed from the checks recorded so far.
                  </p>
                ) : (
                  <ul>
                    {domain.next_actions.map((action) => (
                      <li key={action}>{action}</li>
                    ))}
                  </ul>
                )}
              </section>

              <section aria-label={`${domain.domain} source inventory`}>
                <h3>Top sources</h3>
                {domain.sources.length === 0 ? (
                  <p className="domain-security-muted">No report sources in the last 30 days.</p>
                ) : (
                  <div className="domain-security-table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Source</th>
                          <th>Classification</th>
                          <th>Volume</th>
                          <th>Aligned</th>
                          <th>Action</th>
                          {canManage ? <th>Classify</th> : null}
                        </tr>
                      </thead>
                      <tbody>
                        {domain.sources.map((source) => (
                          <tr key={`${domain.id}-${source.source_key}`}>
                            <td>
                              <strong>{source.source_ip}</strong>
                              {source.source_domain ? <span>{source.source_domain}</span> : null}
                            </td>
                            <td>
                              <Hint label="How the mail system judges this sending source. Authorized matches your published policy; partially set up sources have a record that does not line up yet.">
                                <span className="hint-term">
                                  {sourceClassificationLabel(source.classification)}
                                </span>
                              </Hint>
                            </td>
                            <td>{source.messages_30d}</td>
                            <td>
                              {percent(source.dmarc_aligned_messages_30d, source.messages_30d)}
                            </td>
                            <td>{source.suggested_action}</td>
                            {canManage ? (
                              <td>
                                <div className="domain-security-classifier">
                                  <select
                                    value={selectedClassification(domain.id, source)}
                                    aria-label={`Classify ${source.source_ip}`}
                                    onChange={(event) =>
                                      setSelectedClassification(
                                        domain.id,
                                        source.source_key,
                                        event.target.value as SourceClassification,
                                      )
                                    }
                                  >
                                    {CLASSIFICATION_OPTIONS.map((option) => (
                                      <option value={option.value} key={option.value}>
                                        {option.label}
                                      </option>
                                    ))}
                                  </select>
                                  <button
                                    type="button"
                                    className="btn btn-ghost"
                                    disabled={classifySource.isPending}
                                    onClick={() =>
                                      classifySource.mutate({
                                        domain_id: domain.id,
                                        source_key: source.source_key,
                                        source_ip: source.source_ip,
                                        source_domain: source.source_domain,
                                        classification: selectedClassification(domain.id, source),
                                        notes: "Classified from the domain security dashboard",
                                      })
                                    }
                                  >
                                    Save
                                  </button>
                                </div>
                              </td>
                            ) : null}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              {domain.observations.length > 0 ? (
                <section aria-label={`${domain.domain} domain checks`}>
                  <h3>Domain checks</h3>
                  <div className="domain-security-observations">
                    {domain.observations.map((observation) => (
                      <div key={`${domain.id}-${observation.check_type}`}>
                        <StatusPill
                          tone={toneForStatus(observation.status)}
                          label={tokenLabel(observation.check_type)}
                        />
                        <span>{observation.detail}</span>
                      </div>
                    ))}
                  </div>
                </section>
              ) : null}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
