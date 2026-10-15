import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Search } from "lucide-react";
import { useState, type FormEvent } from "react";

import type { ApiError } from "../api/client";
import { traceSearch, type TraceSearchResult } from "../api/trace";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import "./Messages.css";

const MIN_QUERY_LENGTH = 3;
const SEARCH_LIMIT = 25;

function errorMessage(error: unknown, fallback: string): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return fallback;
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

function directionClass(direction: string): string {
  const value = direction.toLowerCase();
  if (value === "inbound") return "badge inbound";
  if (value === "outbound") return "badge outbound";
  return "badge";
}

function dispositionClass(disposition: string): string {
  const value = disposition.toLowerCase();
  if (["allow", "allowed", "delivered", "accepted"].includes(value)) return "badge success";
  if (
    ["quarantine", "quarantined", "reject", "rejected", "hold", "defer", "deferred"].includes(value)
  ) {
    return "badge warning";
  }
  return "badge";
}

export function Messages() {
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  const search = useQuery({
    queryKey: ["mail-trace-search", submitted],
    queryFn: ({ signal }) => traceSearch({ q: submitted ?? "", limit: SEARCH_LIMIT }, signal),
    enabled: submitted !== null,
  });

  const hasSearched = submitted !== null;
  const results: TraceSearchResult[] = search.data?.results ?? [];
  const showResults = hasSearched && search.isSuccess && !search.isFetching && results.length > 0;

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = query.trim();
    if (trimmed.length < MIN_QUERY_LENGTH) {
      setValidationError(`Enter at least ${MIN_QUERY_LENGTH} characters to search.`);
      return;
    }
    setValidationError(null);
    setSubmitted(trimmed);
  }

  return (
    <div className="messages-page">
      <WorkspaceHeader
        eyebrow="Trace investigation"
        title="Messages"
        description="Search the mail trace index by transaction ID, sender, recipient or message ID. Results are authorized server-side for your current scope."
        scope="Metadata-only search"
      />

      <ControlRail
        title="Trace search state"
        summary="Search is intentionally metadata-first. Results become actionable only after the server authorizes the current query and scope."
        signals={[
          {
            label: "Query",
            value: !submitted
              ? "not run"
              : search.isError
                ? "failed"
                : search.isFetching
                  ? "searching"
                  : "complete",
            detail: !submitted
              ? "Enter an identifier before a trace result set exists."
              : search.isError
                ? "The current search did not produce an authorized trace result."
                : "A server-authorized trace lookup is in progress or complete.",
          },
          {
            label: "Results",
            value: search.isSuccess ? results.length : search.isError ? "Unavailable" : "—",
            detail: search.isSuccess
              ? "Trace records returned within the current authorized scope."
              : "Result count is not inferred before a successful server response.",
          },
          {
            label: "Content",
            value: "isolated",
            detail: "Any permitted message content remains in the sandboxed record view.",
            tone: "healthy",
          },
        ]}
      />

      <WorkflowGuide
        title="Trace mail without rendering untrusted content"
        description="Search transaction metadata first, then open a single trace only when its delivery and scanner context is relevant to the investigation."
        steps={[
          {
            label: "Search",
            detail: "Use identifiers and metadata to narrow the transaction set.",
          },
          {
            label: "Trace",
            detail: "Open one result to inspect authentication, delivery and scanner outcomes.",
          },
          {
            label: "Escalate",
            detail:
              "Follow linked quarantine or policy workflows when the trace indicates a required action.",
          },
        ]}
      />

      <form className="messages-search" onSubmit={handleSubmit} noValidate>
        <label className="search-box messages-search-field">
          <span className="sr-only">Search messages</span>
          <Search size={18} className="search-icon" aria-hidden="true" />
          <input
            className="search-input"
            type="search"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              if (validationError) setValidationError(null);
            }}
            placeholder="Transaction ID, sender, recipient or message ID"
            aria-describedby={validationError ? "messages-search-error" : undefined}
          />
        </label>
        <button type="submit" className="btn btn-primary">
          Search
        </button>
      </form>

      {validationError && (
        <p className="messages-state error" role="alert" id="messages-search-error">
          {validationError}
        </p>
      )}

      {!hasSearched && !validationError && (
        <div className="messages-state" role="status">
          No search has been run yet. Enter a query to list matching messages.
        </div>
      )}

      {hasSearched && search.isError && (
        <div className="messages-state error" role="alert">
          {errorMessage(search.error, "Mail trace search is temporarily unavailable.")}
        </div>
      )}

      {hasSearched && search.isFetching && (
        <div className="messages-state" role="status">
          Searching messages…
        </div>
      )}

      {hasSearched && search.isSuccess && !search.isFetching && results.length === 0 && (
        <div className="messages-state">No messages match this search.</div>
      )}

      {showResults && (
        <div className="card messages-table-wrap">
          <table className="messages-table">
            <caption className="sr-only">Mail trace search results</caption>
            <thead>
              <tr>
                <th>Transaction</th>
                <th>Received</th>
                <th>Direction</th>
                <th>Sender</th>
                <th>Message ID</th>
                <th>Recipients</th>
                <th>Dispositions</th>
              </tr>
            </thead>
            <tbody>
              {results.map((result) => (
                <tr key={result.transaction_id}>
                  <td>
                    <Link
                      to="/messages/$messageId"
                      params={{ messageId: result.transaction_id }}
                      className="message-link"
                    >
                      {result.transaction_id}
                    </Link>
                  </td>
                  <td>{formatTimestamp(result.received_at)}</td>
                  <td>
                    <span className={directionClass(result.direction)}>{result.direction}</span>
                  </td>
                  <td>{result.envelope_sender ?? "—"}</td>
                  <td className="message-id-cell">{result.message_id ?? "—"}</td>
                  <td>{result.recipients.length}</td>
                  <td className="message-dispositions">
                    {result.instances.length === 0
                      ? "—"
                      : result.instances.map((instance) => (
                          <span
                            key={instance.tenant_message_id}
                            className={dispositionClass(instance.disposition)}
                          >
                            {instance.disposition}
                          </span>
                        ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showResults && search.data && search.data.has_more && (
        <p className="messages-more">
          Showing {results.length} of {search.data.total_count} matches — refine the search to
          narrow the results.
        </p>
      )}
    </div>
  );
}
