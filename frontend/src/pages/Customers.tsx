import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import { capabilityLock, type CustomerCapabilities } from "../api/capabilities";
import {
  canImpersonate,
  hasPermission,
  isTenantTier,
  loadSession,
  startImpersonation,
} from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { Hint } from "../components/primitives/Hint";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { ControlRail } from "../components/ControlRail";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Input } from "../components/primitives/Input";
import { CustomerRecord } from "./CustomerDetail";
import { randomUuid } from "../lib/ids";
import { HINTS, LIFECYCLE_LABELS } from "../lib/labels";
import "./Customers.css";

import { notify } from "../lib/notify";
type CustomerLifecycle = "active" | "grace" | "suspended" | "terminated";

interface CustomerSummary {
  id: string;
  display_name: string;
  internal_key: number;
  region_code: string | null;
  sequence_no: number | null;
  lifecycle: CustomerLifecycle;
  created_at: string;
  updated_at: string;
  domain_count: number;
}

interface CustomerList {
  customers: CustomerSummary[];
  capabilities: CustomerCapabilities;
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
  const current = session.data ?? null;
  // A customer session administers one organisation, so the directory read
  // never happens: the record below is the same customer the list would
  // return, fetched by the id the session already carries.
  const ownCustomerId = isTenantTier(current) ? (current?.customerId ?? "") : "";
  const customers = useQuery({
    queryKey: ["customers"],
    queryFn: ({ signal }) => api.get<CustomerList>("/admin/customers", signal),
    enabled: !session.isPending && ownCustomerId.length === 0,
  });

  const [open, setOpen] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const [entryTarget, setEntryTarget] = useState<CustomerSummary | null>(null);
  const [reason, setReason] = useState("");
  const [entryError, setEntryError] = useState<unknown>(null);
  const [entryBusy, setEntryBusy] = useState(false);

  // The list carries the server's own verdict on creating a customer, computed
  // by the same predicate the POST runs. A role that holds
  // `admin:customers:manage` without a platform role therefore reads a stated
  // lock here instead of a button that can only be refused.
  const createCapability = customers.data?.capabilities?.create_customer;
  const canCreate = createCapability
    ? createCapability.allowed
    : hasPermission(current, "admin:customers:manage");
  const createLock = capabilityLock(createCapability, "Creating a customer");
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

  // Which surface this route is depends on the session's own tier, and nothing
  // about the directory should paint for a customer session that will never see
  // another customer's name.
  if (session.isPending) {
    return (
      <div className="customers-page">
        <p className="customers-state" role="status">
          Checking whether this session administers one customer or the whole platform…
        </p>
      </div>
    );
  }

  if (ownCustomerId.length > 0) {
    return (
      <div className="customers-page">
        <WorkspaceHeader
          eyebrow="Your customer"
          title="Your organisation"
          description="The domains your customer sends from, the addresses allowed to send as them, and the checks that decide whether either counts. Controls your provider keeps state what they need."
          scope="Your customer"
        />
        <CustomerRecord customerId={ownCustomerId} ownRecord />
      </div>
    );
  }

  return (
    <div className="customers-page">
      <WorkspaceHeader
        eyebrow="Customer administration"
        title="Customers"
        description="Create a customer, enter its workspace, then manage its lifecycle, domains and source IP groups from the customer record. Changes to a customer affect how its mail is treated."
        scope="Customer lifecycle controls"
        actions={
          canCreate ? (
            <Button type="button" variant="primary" onClick={() => setOpen(true)}>
              New customer
            </Button>
          ) : null
        }
      />

      {createLock !== "" ? (
        <p className="customers-lock" role="status">
          {createLock}
        </p>
      ) : null}

      <ControlRail
        title="Customers"
        summary="Choose a customer to open its lifecycle and sending configuration."
        signals={[
          {
            label: "Customers",
            value: customersAvailable ? rows.length : customersState,
            detail: customersAvailable
              ? "Customers you can see in this installation."
              : "The customer list is still loading.",
          },
          {
            label: "Active",
            value: customersAvailable
              ? rows.filter((row) => row.lifecycle === "active").length
              : customersState,
            detail: customersAvailable
              ? "Customers that can send and receive normally."
              : "The lifecycle count is unavailable until the customers load.",
            tone: customersAvailable ? "healthy" : "neutral",
          },
          {
            label: "Needs review",
            value: customersAvailable
              ? rows.filter((row) => row.lifecycle !== "active").length
              : customersState,
            detail: customersAvailable
              ? "Customers in Grace, Suspended or Terminated need a decision."
              : "No review queue shows while the customer list is unavailable.",
            tone: customersAvailable ? "attention" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Add a customer safely"
        description="A customer record is the boundary for all its later configuration and investigation."
        steps={[
          { label: "Create", detail: "Create the customer with a clear display name." },
          {
            label: "Configure",
            detail: "Open the record to manage lifecycle, domains and source IP groups.",
          },
          {
            label: "Enter",
            detail: "Give a reason before entering a customer workspace.",
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
                <th scope="col">Region</th>
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
                    <span className="customers-region">{customer.region_code ?? "Not placed"}</span>
                  </td>
                  <td>
                    <Hint label={HINTS.lifecycle}>
                      <span
                        className={`customers-lifecycle customers-lifecycle-${customer.lifecycle} hint-term`}
                      >
                        {LIFECYCLE_LABELS[customer.lifecycle]}
                      </span>
                    </Hint>
                  </td>
                  <td>{customer.domain_count}</td>
                  <td>{new Date(customer.created_at).toLocaleString()}</td>
                  {mayEnter ? (
                    <td>
                      {customer.lifecycle === "active" ? (
                        <Hint label="Entering a customer lets you work inside that customer's data. Your own roles and permissions do not change.">
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
                        </Hint>
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
            The display name is how this customer appears throughout the console.
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
            Your roles and permissions stay the same. Only the customer you are working on changes.
            Actions you take here are recorded under your own identity. Enter a reason of at least{" "}
            {MIN_REASON_LENGTH} characters.
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
