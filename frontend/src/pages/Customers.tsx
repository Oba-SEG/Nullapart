import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import { canImpersonate, hasPermission, loadSession, startImpersonation } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { ControlRail } from "../components/ControlRail";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Input } from "../components/primitives/Input";
import { randomUuid } from "../lib/ids";
import "./Customers.css";

import { notify } from "../lib/notify";
type CustomerLifecycle = "active" | "grace" | "suspended" | "terminated";

interface CustomerSummary {
  id: string;
  display_name: string;
  internal_key: number;
  lifecycle: CustomerLifecycle;
  created_at: string;
  updated_at: string;
  domain_count: number;
}

interface CustomerList {
  customers: CustomerSummary[];
}

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

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((char) => {
    const code = char.charCodeAt(0);
    return code < 0x20 || code === 0x7f;
  });
}

const MIN_REASON_LENGTH = 10;

// Mirrors the server-side display-name rule; the server stays authoritative.
function displayNameError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    return "Enter a display name between 1 and 128 characters.";
  }
  if (hasControlCharacters(trimmed)) {
    return "Control characters are not allowed.";
  }
  return undefined;
}

export function Customers() {
  const queryClient = useQueryClient();
  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const customers = useQuery({
    queryKey: ["customers"],
    queryFn: ({ signal }) => api.get<CustomerList>("/admin/customers", signal),
  });

  const [open, setOpen] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const [entryTarget, setEntryTarget] = useState<CustomerSummary | null>(null);
  const [reason, setReason] = useState("");
  const [entryError, setEntryError] = useState<unknown>(null);
  const [entryBusy, setEntryBusy] = useState(false);

  const current = session.data ?? null;
  const canManage = hasPermission(current, "admin:customers:manage");
  const mayEnter = canImpersonate(current) && !current?.impersonation;
  const nameError = displayNameError(displayName);
  const reasonTooShort = reason.trim().length < MIN_REASON_LENGTH;
  const rows = customers.data?.customers ?? [];
  const customersAvailable = customers.isSuccess;
  const customersState = customers.isError ? "Unavailable" : "Loading";

  function closeDialog() {
    setOpen(false);
    setDisplayName("");
    setError(null);
  }

  function closeEntryDialog() {
    setEntryTarget(null);
    setReason("");
    setEntryError(null);
  }

  async function handleEnter() {
    if (!entryTarget || reasonTooShort) return;
    setEntryBusy(true);
    setEntryError(null);
    try {
      const customerName = entryTarget.display_name;
      await startImpersonation(entryTarget.id, reason.trim());
      await queryClient.invalidateQueries({ queryKey: ["session"] });
      closeEntryDialog();
      notify(`Entered customer "${customerName}". Your roles and permissions are unchanged.`);
    } catch (err) {
      setEntryError(err);
    } finally {
      setEntryBusy(false);
    }
  }

  async function handleCreate() {
    if (nameError) return;
    setBusy(true);
    setError(null);
    try {
      await api.post<CustomerSummary>(
        "/admin/customers",
        { display_name: displayName.trim() },
        { idempotencyKey: randomUuid() },
      );
      const createdName = displayName.trim();
      await queryClient.invalidateQueries({ queryKey: ["customers"] });
      closeDialog();
      notify(`Customer "${createdName}" created.`);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="customers-page">
      <WorkspaceHeader
        eyebrow="Tenant administration"
        title="Customers"
        description="Create and enter customer workspaces, then manage lifecycle, domains and source IP groups from the customer record. Every state-changing action is audited."
        scope="Customer lifecycle controls"
        actions={
          canManage ? (
            <Button type="button" variant="primary" onClick={() => setOpen(true)}>
              New customer
            </Button>
          ) : null
        }
      />

      <ControlRail
        title="Customer estate"
        summary="Choose a customer record to enter its lifecycle and trust configuration workspace."
        signals={[
          {
            label: "Customers",
            value: customersAvailable ? rows.length : customersState,
            detail: customersAvailable
              ? "Records visible in your current deployment scope."
              : "Customer scope has not produced an authoritative result yet.",
          },
          {
            label: "Active",
            value: customersAvailable
              ? rows.filter((row) => row.lifecycle === "active").length
              : customersState,
            detail: customersAvailable
              ? "Currently active customer records."
              : "Lifecycle state is unavailable until the customer query succeeds.",
            tone: customersAvailable ? "healthy" : "neutral",
          },
          {
            label: "Needs review",
            value: customersAvailable
              ? rows.filter((row) => row.lifecycle !== "active").length
              : customersState,
            detail: customersAvailable
              ? "Grace, suspended or terminated records require deliberate handling."
              : "No review queue is inferred while the customer query is unavailable.",
            tone: customersAvailable ? "attention" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Establish a tenant safely"
        description="Customer records are the boundary for all downstream configuration and investigation work."
        steps={[
          { label: "Create", detail: "Create the customer record with a controlled display name." },
          {
            label: "Configure",
            detail: "Open the record to manage lifecycle, domains and source IP groups.",
          },
          {
            label: "Enter",
            detail: "Use a recorded reason before entering a customer-scoped workspace.",
          },
        ]}
      />

      {customers.isPending ? (
        <div className="customers-state" role="status">
          Loading customers…
        </div>
      ) : null}
      {customers.isError ? (
        <div className="customers-state error" role="alert">
          {errorMessage(customers.error)}
          <StepUpPrompt error={customers.error} />
        </div>
      ) : null}
      {customers.isSuccess && rows.length === 0 ? (
        <div className="customers-state">No customers exist yet.</div>
      ) : null}

      {rows.length > 0 ? (
        <div className="card customers-table-wrap">
          <table className="customers-table">
            <caption className="sr-only">Customers in this deployment</caption>
            <thead>
              <tr>
                <th scope="col">Display name</th>
                <th scope="col">Customer ID</th>
                <th scope="col">Lifecycle</th>
                <th scope="col">Domains</th>
                <th scope="col">Created</th>
                {mayEnter ? <th scope="col">Actions</th> : null}
              </tr>
            </thead>
            <tbody>
              {rows.map((customer) => (
                <tr key={customer.id}>
                  <td>
                    <Link to="/customers/$customerId" params={{ customerId: customer.id }}>
                      {customer.display_name}
                    </Link>
                  </td>
                  <td>
                    <span className="truncate customers-id">{customer.id}</span>
                  </td>
                  <td>
                    <span
                      className={`customers-lifecycle customers-lifecycle-${customer.lifecycle}`}
                    >
                      {customer.lifecycle}
                    </span>
                  </td>
                  <td>{customer.domain_count}</td>
                  <td>{new Date(customer.created_at).toLocaleString()}</td>
                  {mayEnter ? (
                    <td>
                      {customer.lifecycle === "active" ? (
                        <Button
                          type="button"
                          size="sm"
                          onClick={() => {
                            setEntryError(null);
                            setReason("");
                            setEntryTarget(customer);
                          }}
                        >
                          Enter
                        </Button>
                      ) : null}
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <Dialog open={open} onClose={closeDialog} title="New customer">
        <form
          className="customers-form"
          onSubmit={(event) => {
            event.preventDefault();
            void handleCreate();
          }}
        >
          <p className="customers-hint">
            The display name identifies the customer across the control plane. Every creation is
            audited.
          </p>
          <Input
            label="Display name"
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
            placeholder="Acme Corporation"
            maxLength={128}
            error={displayName.length > 0 ? nameError : undefined}
          />
          {nameError !== undefined && displayName.length === 0 ? (
            <p className="dialog-hint" id="customer-name-hint">
              {nameError}
            </p>
          ) : null}
          {error !== null ? (
            <p className="customers-error" role="alert">
              {errorMessage(error)}
            </p>
          ) : null}
          <StepUpPrompt error={error} />
          <div className="customers-form-actions">
            <Button type="button" variant="ghost" onClick={closeDialog} disabled={busy}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              loading={busy}
              disabled={busy || nameError !== undefined}
              aria-describedby={
                nameError !== undefined && displayName.length === 0
                  ? "customer-name-hint"
                  : undefined
              }
            >
              Create customer
            </Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={entryTarget !== null}
        onClose={closeEntryDialog}
        title={`Enter ${entryTarget?.display_name ?? ""}`}
      >
        <div className="customers-form">
          <p className="customers-hint">
            Your roles and permissions stay exactly as they are; only the customer scope of this
            session switches. Every action is audited under your identity. A reason is required (at
            least {MIN_REASON_LENGTH} characters).
          </p>
          <Input
            label="Reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Investigating a customer report"
            minLength={MIN_REASON_LENGTH}
            maxLength={500}
            error={
              reason.length > 0 && reasonTooShort ? "Enter at least 10 characters." : undefined
            }
          />
          {reasonTooShort ? (
            <p className="dialog-hint" id="customer-entry-reason-hint">
              Enter at least {MIN_REASON_LENGTH} characters to continue.
            </p>
          ) : null}
          {entryError !== null ? (
            <p className="customers-error" role="alert">
              {errorMessage(entryError)}
            </p>
          ) : null}
          <StepUpPrompt error={entryError} />
          <div className="customers-form-actions">
            <Button type="button" variant="ghost" onClick={closeEntryDialog} disabled={entryBusy}>
              Cancel
            </Button>
            <Button
              type="button"
              variant="primary"
              onClick={() => void handleEnter()}
              disabled={entryBusy || reasonTooShort}
              aria-describedby={reasonTooShort ? "customer-entry-reason-hint" : undefined}
            >
              Enter customer
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
