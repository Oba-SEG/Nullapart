import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useId, useState } from "react";

import { api, type ApiError } from "../api/client";
import { capabilityLock, type CustomerCapabilities } from "../api/capabilities";
import { hasPermission, isTenantTier, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { ControlRail } from "../components/ControlRail";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
import {
  HINTS,
  LIFECYCLE_LABELS,
  VERIFICATION_STATUS_LABELS,
  verificationMethodLabel,
} from "../lib/labels";
import "./CustomerDetail.css";

import { notify } from "../lib/notify";
type CustomerLifecycle = "active" | "grace" | "suspended" | "terminated";
type DomainType = "internal" | "send_only";

interface Domain {
  id: string;
  domain: string;
  domain_type: DomainType;
  verification_status: "pending" | "verified" | "failed";
  verification_method: string;
  verification_attempts: number;
  verification_expires_at: string | null;
  verified_at: string | null;
  created_at: string;
}

interface SourceIpGroup {
  id: string;
  name: string;
  cidrs: string[];
  created_at: string;
}

interface CustomerSummary {
  id: string;
  display_name: string;
  /** Operational placement. A customer answer omits these keys; an older
   * answer may still carry them as null, so the render checks for a number. */
  internal_key?: number | null;
  region_code?: string | null;
  sequence_no?: number | null;
  lifecycle: CustomerLifecycle;
  created_at: string;
  updated_at: string;
  domain_count: number;
}

interface CustomerDetail extends CustomerSummary {
  domains: Domain[];
  source_ip_groups: SourceIpGroup[];
  capabilities: CustomerCapabilities;
}

interface SourceIpGroupList {
  groups: SourceIpGroup[];
}

const MIN_REASON_LENGTH = 10;

// Exact server-allowed transitions per current lifecycle.
const LIFECYCLE_TRANSITIONS: Record<CustomerLifecycle, CustomerLifecycle[]> = {
  active: ["grace", "suspended", "terminated"],
  grace: ["active", "suspended", "terminated"],
  suspended: ["active", "terminated"],
  terminated: ["active"],
};

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    const message = String((error as ApiError).message);
    if (errorCode(error) === "RATE_LIMITED") {
      return `${message} Please wait a moment before retrying.`;
    }
    return message;
  }
  return "Customer data is temporarily unavailable.";
}

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : "";
}

function verifyErrorMessage(error: unknown): string {
  const code = errorCode(error);
  if (code === "CONFLICT" || code === "HTTP_409") {
    return "Domain verification failed or the verification attempt expired. Request a new verification and try again.";
  }
  if (code === "UNAVAILABLE" || code === "HTTP_503") {
    return "Domain verification is temporarily unavailable. Please try again shortly.";
  }
  return errorMessage(error);
}

function isLifecycle(value: string): value is CustomerLifecycle {
  return value === "active" || value === "grace" || value === "suspended" || value === "terminated";
}

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((char) => {
    const code = char.charCodeAt(0);
    return code < 0x20 || code === 0x7f;
  });
}

function domainError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 253) {
    return "Enter a domain name.";
  }
  if (hasControlCharacters(trimmed) || /[\s/\\]/.test(trimmed)) {
    return "Enter a domain name without spaces or control characters.";
  }
  return undefined;
}

function groupNameError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 128 || hasControlCharacters(trimmed)) {
    return "Enter a group name between 1 and 128 characters.";
  }
  return undefined;
}

// Client-side convenience parsing only; the server validates every CIDR.
function parseCidrs(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * The customer record: lifecycle, domains, verification and source IP groups.
 *
 * `ownRecord` renders it as the operator's own organisation rather than a
 * record pulled out of the directory: no back link to a directory a customer
 * session cannot use, and copy addressed to the owner. The data and every
 * gate are identical, because both views read the same server-published
 * capabilities.
 */
export function CustomerRecord({
  customerId,
  ownRecord = false,
}: {
  customerId: string;
  ownRecord?: boolean;
}) {
  const queryClient = useQueryClient();
  const cidrInputId = useId();

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const detail = useQuery({
    queryKey: ["customer", customerId],
    queryFn: ({ signal }) =>
      api.get<CustomerDetail>(`/admin/customers/${encodeURIComponent(customerId)}`, signal),
    enabled: customerId.length > 0,
  });
  const groups = useQuery({
    queryKey: ["customer-source-ip-groups", customerId],
    queryFn: ({ signal }) =>
      api.get<SourceIpGroupList>(
        `/admin/customers/${encodeURIComponent(customerId)}/source-ip-groups`,
        signal,
      ),
    enabled: customerId.length > 0,
  });

  const current = session.data ?? null;
  // Reading these from the customer record rather than from role names keeps
  // the console and the API in agreement: a custom role that holds
  // `admin:customers:manage` is not silently assumed to be able to switch a
  // customer off, and a session that can is never offered a refused form.
  const capabilities = detail.data?.capabilities;
  const mayChangeLifecycle = capabilities?.change_lifecycle.allowed ?? false;
  const lifecycleLock = capabilityLock(
    capabilities?.change_lifecycle,
    ownRecord ? "Changing your customer's lifecycle" : "Changing this lifecycle",
    "admin:customers:manage",
  );
  const mayOfferSendOnly = capabilities?.add_send_only_domain.allowed ?? false;
  const sendOnlyLock = capabilityLock(
    capabilities?.add_send_only_domain,
    "Adding a send-only domain",
    "admin:domains:manage",
  );
  const canManageCustomers = hasPermission(current, "admin:customers:manage");
  const canManageDomains = hasPermission(current, "admin:domains:manage");
  // The source IP group routes publish no capability, so the console's own
  // permission check decides, stated in the same sentence a blocker produces.
  const groupsLock = capabilityLock(
    canManageCustomers
      ? { allowed: true, blocker: null }
      : ({ allowed: false, blocker: "permission" } as const),
    ownRecord ? "Changing your source IP groups" : "Changing source IP groups",
    "admin:customers:manage",
  );

  const customer = detail.data ?? null;

  const [targetLifecycle, setTargetLifecycle] = useState<CustomerLifecycle | "">("");
  const [reason, setReason] = useState("");
  const [lifecycleNotice, setLifecycleNotice] = useState<string | null>(null);
  const [domain, setDomain] = useState("");
  const [domainType, setDomainType] = useState<DomainType>("internal");
  const [domainNotice, setDomainNotice] = useState<string | null>(null);
  const [verifyNotice, setVerifyNotice] = useState<{
    domain: string;
    status: Domain["verification_status"];
  } | null>(null);
  const [groupName, setGroupName] = useState("");
  const [cidrText, setCidrText] = useState("");
  const [groupNotice, setGroupNotice] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<SourceIpGroup | null>(null);

  const changeLifecycle = useMutation({
    mutationFn: ({
      lifecycle,
      lifecycleReason,
    }: {
      lifecycle: CustomerLifecycle;
      lifecycleReason: string;
    }) =>
      api.patch<CustomerSummary>(
        `/admin/customers/${encodeURIComponent(customerId)}`,
        { lifecycle, reason: lifecycleReason },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async (updated) => {
      setTargetLifecycle("");
      setReason("");
      setLifecycleNotice(`Lifecycle changed to ${LIFECYCLE_LABELS[updated.lifecycle]}.`);
      await queryClient.invalidateQueries({ queryKey: ["customer", customerId] });
      await queryClient.invalidateQueries({ queryKey: ["customers"] });
    },
  });

  const addDomain = useMutation({
    mutationFn: ({ name, type }: { name: string; type: DomainType }) =>
      api.post<Domain>(
        `/admin/customers/${encodeURIComponent(customerId)}/domains`,
        { domain: name, domain_type: type },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async (created) => {
      setDomain("");
      setDomainType("internal");
      setDomainNotice(
        `${created.domain} was added. It is ${VERIFICATION_STATUS_LABELS[created.verification_status].toLowerCase()}.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["customer", customerId] });
    },
  });

  const verifyDomain = useMutation({
    mutationFn: (target: Domain) =>
      api.post<Domain>(
        `/admin/customers/${encodeURIComponent(customerId)}/domains/${encodeURIComponent(target.id)}/verify`,
        undefined,
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: (verified) => {
      setVerifyNotice({
        domain: verified.domain,
        status: verified.verification_status,
      });
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["customer", customerId] }),
  });

  const addGroup = useMutation({
    mutationFn: ({ name, cidrs }: { name: string; cidrs: string[] }) =>
      api.post<SourceIpGroup>(
        `/admin/customers/${encodeURIComponent(customerId)}/source-ip-groups`,
        { name, cidrs },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async (created) => {
      setGroupName("");
      setCidrText("");
      setGroupNotice(`${created.name} was added.`);
      await queryClient.invalidateQueries({ queryKey: ["customer-source-ip-groups", customerId] });
    },
  });

  const deleteGroup = useMutation({
    mutationFn: (target: SourceIpGroup) =>
      api.delete<{ id: string; deleted: boolean }>(
        `/admin/customers/${encodeURIComponent(customerId)}/source-ip-groups/${encodeURIComponent(target.id)}`,
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async () => {
      setPendingDelete(null);
      notify("Source IP group removed.");
      await queryClient.invalidateQueries({ queryKey: ["customer-source-ip-groups", customerId] });
    },
  });

  const reasonTooShort = reason.trim().length < MIN_REASON_LENGTH;
  const lifecycleValid = targetLifecycle !== "" && !reasonTooShort;
  const domainValueError = domainError(domain);
  const groupNameValueError = groupNameError(groupName);
  const cidrList = parseCidrs(cidrText);
  const groupValid = groupNameValueError === undefined && cidrList.length > 0;

  const domainTypeOptions = [
    { value: "internal", label: "Internal" },
    ...(mayOfferSendOnly ? [{ value: "send_only", label: "Send only" }] : []),
  ];

  return (
    <div className="customer-detail-page">
      {ownRecord ? null : (
        <Link to="/customers" className="customer-detail-back">
          <ArrowLeft size={16} aria-hidden="true" />
          Customers
        </Link>
      )}

      <header className="customer-detail-header">
        {detail.isPending ? (
          <p className="customer-detail-hint" role="status">
            Loading customer…
          </p>
        ) : null}
        {detail.isError ? (
          <>
            <p className="customer-detail-error" role="alert">
              {errorMessage(detail.error)}
            </p>
            <StepUpPrompt error={detail.error} />
          </>
        ) : null}
        {customer ? (
          <>
            <div className="customer-detail-heading">
              {/* The organisation surface already carries a page-level h1, so the
                  customer name is the section heading there. */}
              {ownRecord ? (
                <h2 className="customer-detail-title">{customer.display_name}</h2>
              ) : (
                <h1 className="customer-detail-title">{customer.display_name}</h1>
              )}
              <Hint label={HINTS.lifecycle}>
                <span
                  className={`customer-detail-lifecycle customer-detail-lifecycle-${customer.lifecycle} hint-term`}
                >
                  {LIFECYCLE_LABELS[customer.lifecycle]}
                </span>
              </Hint>
            </div>
            <dl className="customer-detail-facts">
              <div>
                <dt>Customer ID</dt>
                <dd className="truncate customer-detail-id">{customer.id}</dd>
              </div>
              {/* The server publishes operational placement to platform seats
                  only, and a customer answer omits the keys rather than sending
                  null. A number in the surrogate slot is therefore the marker
                  that the whole set was handed over; a legacy row that is
                  genuinely unplaced still says so. */}
              {typeof customer.internal_key === "number" ? (
                <>
                  <div>
                    <dt>Internal key</dt>
                    <dd>{customer.internal_key}</dd>
                  </div>
                  <div>
                    <dt>
                      <Hint
                        label={`The sending region assigned to ${
                          ownRecord ? "your customer" : "this customer"
                        }. ${ownRecord ? "Your provider" : "The platform"} sets it.`}
                      >
                        <span className="hint-term">Region</span>
                      </Hint>
                    </dt>
                    <dd>{customer.region_code ?? "Not placed"}</dd>
                  </div>
                  <div>
                    <dt>
                      <Hint
                        label={`The position assigned to ${
                          ownRecord ? "your customer" : "this customer"
                        } within its region. ${
                          ownRecord ? "Your provider" : "The platform"
                        } assigns it.`}
                      >
                        <span className="hint-term">Sequence</span>
                      </Hint>
                    </dt>
                    <dd>{customer.sequence_no ?? "Not assigned"}</dd>
                  </div>
                </>
              ) : null}
              <div>
                <dt>Created</dt>
                <dd>{new Date(customer.created_at).toLocaleString()}</dd>
              </div>
              <div>
                <dt>Domains</dt>
                <dd>{customer.domain_count}</dd>
              </div>
            </dl>
          </>
        ) : null}
      </header>

      {customer ? (
        <ControlRail
          title={ownRecord ? "Your organisation" : "Customer status"}
          summary={
            ownRecord
              ? "Your own customer record. Controls your provider keeps say why they are withheld."
              : "The current record decides which lifecycle and configuration actions are still relevant."
          }
          signals={[
            {
              label: "Lifecycle",
              value: LIFECYCLE_LABELS[customer.lifecycle],
              detail: ownRecord
                ? "The state your provider set for your customer."
                : "The lifecycle set for this customer.",
              tone: customer.lifecycle === "active" ? "healthy" : "attention",
            },
            {
              label: "Domains",
              value: customer.domain_count,
              detail: ownRecord
                ? "Domains registered for your customer."
                : "Domains set up for this customer.",
            },
            ownRecord
              ? {
                  label: "Verified",
                  value: customer.domains.filter(
                    (entry) => entry.verification_status === "verified",
                  ).length,
                  detail: "Domains your customer has proved it controls.",
                }
              : {
                  label: "Transitions",
                  value: LIFECYCLE_TRANSITIONS[customer.lifecycle].length,
                  detail: "Lifecycle states you can move to next.",
                },
          ]}
        />
      ) : null}

      {customer ? (
        <WorkflowGuide
          title={ownRecord ? "Set your customer up" : "Manage the customer"}
          description={
            ownRecord
              ? "Verify the domains your customer sends from and list the addresses allowed to send as them. Anything your provider has to change says so here."
              : "Set the lifecycle and sending configuration here before you rely on customer-specific policies or connectors."
          }
          steps={
            ownRecord
              ? [
                  {
                    label: "Verify each domain",
                    detail: "A domain reports only after its DNS check passes.",
                  },
                  {
                    label: "List the senders",
                    detail: "Source IP groups decide which addresses count as your customer.",
                  },
                  {
                    label: "Add alert recipients",
                    detail: "Domain security lists the verified domains you may mail findings to.",
                  },
                ]
              : [
                  {
                    label: "Confirm identity",
                    detail: "Check the customer record and its current lifecycle.",
                  },
                  {
                    label: "Configure sending",
                    detail: "Manage domains and source IP groups through the forms below.",
                  },
                  {
                    label: "Record change",
                    detail: "Enter a reason with each change so you can review it later.",
                  },
                ]
          }
        />
      ) : null}

      {mayChangeLifecycle && customer ? (
        <section className="card customer-detail-panel" aria-labelledby="lifecycle-heading">
          <h2 id="lifecycle-heading">Lifecycle</h2>
          <p className="customer-detail-hint">
            The current lifecycle is <strong>{LIFECYCLE_LABELS[customer.lifecycle]}</strong>. You
            can move only to an allowed next state. Each change needs a reason of at least{" "}
            {MIN_REASON_LENGTH} characters.
          </p>
          <div className="customer-detail-form">
            <Select
              label="New lifecycle"
              value={targetLifecycle}
              placeholder="Select a lifecycle"
              onChange={(event) => {
                const value = event.target.value;
                setTargetLifecycle(isLifecycle(value) ? value : "");
              }}
              options={LIFECYCLE_TRANSITIONS[customer.lifecycle].map((value) => ({
                value,
                label: LIFECYCLE_LABELS[value],
              }))}
            />
            <Input
              label="Reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Reason for this lifecycle change"
              minLength={MIN_REASON_LENGTH}
              maxLength={500}
              error={
                reason.length > 0 && reasonTooShort
                  ? `Enter at least ${MIN_REASON_LENGTH} characters.`
                  : undefined
              }
            />
            {changeLifecycle.isError ? (
              <>
                <p className="customer-detail-error" role="alert">
                  {errorMessage(changeLifecycle.error)}
                </p>
                <StepUpPrompt error={changeLifecycle.error} />
              </>
            ) : null}
            {lifecycleNotice ? (
              <p className="customer-detail-notice" role="status">
                {lifecycleNotice}
              </p>
            ) : null}
            <div className="customer-detail-form-actions">
              <Button
                type="button"
                variant="primary"
                loading={changeLifecycle.isPending}
                disabled={changeLifecycle.isPending || !lifecycleValid}
                onClick={() => {
                  setLifecycleNotice(null);
                  if (targetLifecycle === "") return;
                  changeLifecycle.mutate({
                    lifecycle: targetLifecycle,
                    lifecycleReason: reason.trim(),
                  });
                }}
              >
                Apply lifecycle change
              </Button>
            </div>
          </div>
        </section>
      ) : null}

      {customer && !mayChangeLifecycle && lifecycleLock !== "" ? (
        <p className="customer-detail-lock" role="status">
          {lifecycleLock}
        </p>
      ) : null}

      {customer ? (
        <section className="card customer-detail-panel" aria-labelledby="domains-heading">
          <h2 id="domains-heading">Domains</h2>
          {customer.domains.length === 0 ? (
            <p className="customer-detail-hint">
              {ownRecord
                ? "No domains are registered yet. Add the domain your customer sends from, then verify it."
                : "No domains are registered for this customer."}
            </p>
          ) : (
            <div className="customer-detail-table-wrap">
              <table className="customer-detail-table">
                <caption className="sr-only">Domains registered for this customer</caption>
                <thead>
                  <tr>
                    <th scope="col">Domain</th>
                    <th scope="col">Type</th>
                    <th scope="col">Verification</th>
                    <th scope="col">Attempts</th>
                    <th scope="col">Expires</th>
                    <th scope="col">Verified</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {customer.domains.map((entry) => (
                    <tr key={entry.id}>
                      <td>
                        {entry.domain}
                        <span className="customer-detail-meta">
                          {verificationMethodLabel(entry.verification_method)}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`customer-detail-badge customer-detail-type-${entry.domain_type}`}
                        >
                          {entry.domain_type === "send_only" ? "Send only" : "Internal"}
                        </span>
                      </td>
                      <td>
                        <Hint label="Verified means the customer proved it controls this domain. Pending waits on a DNS check. Failed needs a new verification request.">
                          <span
                            className={`customer-detail-badge customer-detail-verify-${entry.verification_status} hint-term`}
                          >
                            {VERIFICATION_STATUS_LABELS[entry.verification_status]}
                          </span>
                        </Hint>
                      </td>
                      <td>{entry.verification_attempts}</td>
                      <td>
                        {entry.verification_expires_at
                          ? new Date(entry.verification_expires_at).toLocaleString()
                          : "—"}
                      </td>
                      <td>
                        {entry.verified_at ? new Date(entry.verified_at).toLocaleString() : "—"}
                      </td>
                      <td>
                        {entry.verification_status !== "verified" ? (
                          <Button
                            type="button"
                            size="sm"
                            loading={
                              verifyDomain.isPending && verifyDomain.variables?.id === entry.id
                            }
                            onClick={() => {
                              setVerifyNotice(null);
                              verifyDomain.mutate(entry);
                            }}
                          >
                            Verify
                          </Button>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {verifyNotice ? (
            <p className="customer-detail-notice" role="status">
              Verification for {verifyNotice.domain}:{" "}
              {VERIFICATION_STATUS_LABELS[verifyNotice.status]}.
            </p>
          ) : null}
          {verifyDomain.isError ? (
            <>
              <p className="customer-detail-error" role="alert">
                {verifyErrorMessage(verifyDomain.error)}
              </p>
              <StepUpPrompt error={verifyDomain.error} />
            </>
          ) : null}

          {canManageDomains ? (
            <form
              className="customer-detail-form"
              onSubmit={(event) => {
                event.preventDefault();
                if (domainValueError) return;
                setDomainNotice(null);
                addDomain.mutate({ name: domain.trim(), type: domainType });
              }}
            >
              <h3>Add domain</h3>
              <Input
                label="Domain"
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                placeholder="mail.example.test"
                maxLength={253}
                error={domain.length > 0 ? domainValueError : undefined}
              />
              <Select
                label="Domain type"
                value={domainType}
                onChange={(event) => {
                  const value = event.target.value;
                  if (value === "internal" || value === "send_only") setDomainType(value);
                }}
                options={domainTypeOptions}
                hint={HINTS.domainType}
              />
              {!mayOfferSendOnly && sendOnlyLock !== "" ? (
                <p className="customer-detail-hint" role="status">
                  {sendOnlyLock} Only internal domains can be added in this session.
                </p>
              ) : null}
              {addDomain.isError ? (
                <>
                  <p className="customer-detail-error" role="alert">
                    {errorMessage(addDomain.error)}
                  </p>
                  <StepUpPrompt error={addDomain.error} />
                </>
              ) : null}
              {domainNotice ? (
                <p className="customer-detail-notice" role="status">
                  {domainNotice}
                </p>
              ) : null}
              <div className="customer-detail-form-actions">
                <Button
                  type="submit"
                  variant="primary"
                  loading={addDomain.isPending}
                  disabled={addDomain.isPending || domainValueError !== undefined}
                >
                  Add domain
                </Button>
              </div>
            </form>
          ) : null}
        </section>
      ) : null}

      {customer ? (
        <section className="card customer-detail-panel" aria-labelledby="source-ip-heading">
          <h2 id="source-ip-heading">Source IP groups</h2>

          {groups.isPending ? (
            <p className="customer-detail-hint" role="status">
              Loading source IP groups…
            </p>
          ) : null}
          {groups.isError ? (
            <>
              <p className="customer-detail-error" role="alert">
                {errorMessage(groups.error)}
              </p>
              <StepUpPrompt error={groups.error} />
            </>
          ) : null}
          {groups.isSuccess && groups.data.groups.length === 0 ? (
            <p className="customer-detail-hint">
              {ownRecord
                ? "No source IP groups yet. A group is the set of addresses Nullapart trusts as your customer."
                : "No source IP groups are configured."}
            </p>
          ) : null}
          {groups.isSuccess && groups.data.groups.length > 0 ? (
            <ul className="customer-detail-groups">
              {groups.data.groups.map((group) => (
                <li key={group.id} className="customer-detail-group">
                  <div className="customer-detail-group-head">
                    <strong>{group.name}</strong>
                    <span className="customer-detail-meta">
                      Added {new Date(group.created_at).toLocaleString()}
                    </span>
                  </div>
                  <span className="customer-detail-cidrs">{group.cidrs.join(", ")}</span>
                  {canManageCustomers ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="danger"
                      onClick={() => setPendingDelete(group)}
                    >
                      Remove
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : null}

          {groupsLock !== "" ? (
            <p className="customer-detail-lock" role="status">
              {groupsLock}
            </p>
          ) : null}

          {canManageCustomers ? (
            <form
              className="customer-detail-form"
              onSubmit={(event) => {
                event.preventDefault();
                if (!groupValid) return;
                setGroupNotice(null);
                addGroup.mutate({ name: groupName.trim(), cidrs: cidrList });
              }}
            >
              <h3>Add source IP group</h3>
              <Input
                label="Group name"
                value={groupName}
                onChange={(event) => setGroupName(event.target.value)}
                placeholder="Office network"
                maxLength={128}
                error={groupName.length > 0 ? groupNameValueError : undefined}
              />
              <div className="customer-detail-field">
                <label htmlFor={cidrInputId} className="customer-detail-field-label">
                  CIDRs
                </label>
                <textarea
                  id={cidrInputId}
                  className="customer-detail-textarea"
                  value={cidrText}
                  onChange={(event) => setCidrText(event.target.value)}
                  rows={3}
                  placeholder="203.0.113.0/24, 198.51.100.7/32"
                />
                <p className="customer-detail-hint">
                  Addresses that are allowed to send as{" "}
                  {ownRecord ? "your customer" : "this customer"}. Separate each range with a comma
                  or a new line.
                  {cidrList.length > 0 ? ` You entered ${cidrList.length}.` : ""}
                </p>
              </div>
              {addGroup.isError ? (
                <>
                  <p className="customer-detail-error" role="alert">
                    {errorMessage(addGroup.error)}
                  </p>
                  <StepUpPrompt error={addGroup.error} />
                </>
              ) : null}
              {groupNotice ? (
                <p className="customer-detail-notice" role="status">
                  {groupNotice}
                </p>
              ) : null}
              <div className="customer-detail-form-actions">
                <Button
                  type="submit"
                  variant="primary"
                  loading={addGroup.isPending}
                  disabled={addGroup.isPending || !groupValid}
                >
                  Add group
                </Button>
              </div>
            </form>
          ) : null}
        </section>
      ) : null}

      <Dialog
        open={pendingDelete !== null}
        onClose={() => {
          setPendingDelete(null);
          deleteGroup.reset();
        }}
        title={`Remove ${pendingDelete?.name ?? ""}`}
      >
        {pendingDelete ? (
          <div className="customer-detail-form">
            <p>
              Removing this source IP group stops those addresses being trusted as this customer
              right away. This cannot be undone from this page.
            </p>
            <p className="customer-detail-cidrs">{pendingDelete.cidrs.join(", ")}</p>
            {deleteGroup.isError ? (
              <>
                <p className="customer-detail-error" role="alert">
                  {errorMessage(deleteGroup.error)}
                </p>
                <StepUpPrompt error={deleteGroup.error} />
              </>
            ) : null}
            <div className="customer-detail-form-actions">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setPendingDelete(null);
                  deleteGroup.reset();
                }}
                disabled={deleteGroup.isPending}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="danger"
                loading={deleteGroup.isPending}
                onClick={() => deleteGroup.mutate(pendingDelete)}
              >
                Remove group
              </Button>
            </div>
          </div>
        ) : null}
      </Dialog>
    </div>
  );
}

/**
 * The route form of the record: a customer opened out of the directory, with
 * the back link and the platform's own framing. A customer session that names
 * its own organisation here is reading its own record, not a directory row, so
 * it gets the owner framing the `/customers` route uses. The server still
 * decides whether the read is allowed.
 */
export function CustomerDetail() {
  const { customerId = "" } = useParams({ from: "/customers/$customerId" });
  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const current = session.data ?? null;
  const ownRecord = isTenantTier(current) && current?.customerId === customerId;
  return <CustomerRecord customerId={customerId} ownRecord={ownRecord} />;
}
