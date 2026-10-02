import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useId, useState } from "react";

import { api, type ApiError } from "../api/client";
import { hasPermission, hasRole, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
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
  internal_key: number;
  lifecycle: CustomerLifecycle;
  created_at: string;
  updated_at: string;
  domain_count: number;
}

interface CustomerDetail extends CustomerSummary {
  domains: Domain[];
  source_ip_groups: SourceIpGroup[];
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

export function CustomerDetail() {
  const { customerId = "" } = useParams({ from: "/customers/$customerId" });
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
  const canManageCustomers = hasPermission(current, "admin:customers:manage");
  const canManageDomains = hasPermission(current, "admin:domains:manage");
  const mayChangeLifecycle =
    canManageCustomers && (hasRole(current, "system_admin") || hasRole(current, "support"));
  const mayOfferSendOnly = hasRole(current, "system_admin") || hasRole(current, "support");

  const customer = detail.data ?? null;

  const [targetLifecycle, setTargetLifecycle] = useState<CustomerLifecycle | "">("");
  const [reason, setReason] = useState("");
  const [lifecycleNotice, setLifecycleNotice] = useState<string | null>(null);
  const [domain, setDomain] = useState("");
  const [domainType, setDomainType] = useState<DomainType>("internal");
  const [domainNotice, setDomainNotice] = useState<string | null>(null);
  const [verifyNotice, setVerifyNotice] = useState<{ domain: string; status: string } | null>(null);
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
      setLifecycleNotice(`Lifecycle changed to ${updated.lifecycle}.`);
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
        `${created.domain} was added. Verification status: ${created.verification_status}.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["customer", customerId] });
    },
  });

  const verifyDomain = useMutation({
    mutationFn: (target: Domain) =>
      api.post<Domain>(
        `/admin/customers/${encodeURIComponent(customerId)}/domains/${encodeURIComponent(target.id)}/verify`,
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
      <Link to="/customers" className="customer-detail-back">
        <ArrowLeft size={16} aria-hidden="true" />
        Customers
      </Link>

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
              <h1 className="customer-detail-title">{customer.display_name}</h1>
              <span
                className={`customer-detail-lifecycle customer-detail-lifecycle-${customer.lifecycle}`}
              >
                {customer.lifecycle}
              </span>
            </div>
            <dl className="customer-detail-facts">
              <div>
                <dt>Customer ID</dt>
                <dd className="truncate customer-detail-id">{customer.id}</dd>
              </div>
              <div>
                <dt>Internal key</dt>
                <dd>{customer.internal_key}</dd>
              </div>
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

      {mayChangeLifecycle && customer ? (
        <section className="card customer-detail-panel" aria-labelledby="lifecycle-heading">
          <h2 id="lifecycle-heading">Lifecycle</h2>
          <p className="customer-detail-hint">
            Current lifecycle is <strong>{customer.lifecycle}</strong>. Only allowed transitions are
            offered; every change requires a reason of at least {MIN_REASON_LENGTH} characters and
            is audited.
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
                label: value,
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

      {customer ? (
        <section className="card customer-detail-panel" aria-labelledby="domains-heading">
          <h2 id="domains-heading">Domains</h2>
          {customer.domains.length === 0 ? (
            <p className="customer-detail-hint">No domains are registered for this customer.</p>
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
                        <span className="customer-detail-meta">{entry.verification_method}</span>
                      </td>
                      <td>
                        <span
                          className={`customer-detail-badge customer-detail-type-${entry.domain_type}`}
                        >
                          {entry.domain_type === "send_only" ? "Send only" : "Internal"}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`customer-detail-badge customer-detail-verify-${entry.verification_status}`}
                        >
                          {entry.verification_status}
                        </span>
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
              Verification result for {verifyNotice.domain}: {verifyNotice.status}.
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
              />
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

      {canManageCustomers ? (
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
            <p className="customer-detail-hint">No source IP groups are configured.</p>
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
                  <Button
                    type="button"
                    size="sm"
                    variant="danger"
                    onClick={() => setPendingDelete(group)}
                  >
                    Remove
                  </Button>
                </li>
              ))}
            </ul>
          ) : null}

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
                Separate CIDRs with commas or newlines
                {cidrList.length > 0
                  ? ` — ${cidrList.length} entr${cidrList.length === 1 ? "y" : "ies"} parsed`
                  : ""}
                . The server validates every entry.
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
              Removing this source IP group takes effect immediately and is audited. This action
              cannot be undone from this page.
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
