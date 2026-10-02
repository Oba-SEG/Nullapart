import { useQuery } from "@tanstack/react-query";

import { api, type ApiError } from "../api/client";
import "./ScannerOperations.css";

interface NodeStatus {
  node_id: string;
  status: "healthy" | "degraded";
  configured_capabilities: number;
  required_unhealthy: number;
}

interface CapabilityStatus {
  capability: string;
  requirement: "required" | "optional";
  status: "healthy" | "unavailable";
  checked_at: string;
  queue_depth?: number | null;
}

interface RecentScannerTotals {
  total: number;
  clean: number;
  non_clean: number;
  inconclusive: number;
  average_duration_ms: number;
  release_reinjection_failures: number;
}

interface ScannerOperationsResponse {
  node: NodeStatus;
  capabilities: CapabilityStatus[];
  last_24_hours: RecentScannerTotals;
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "Scanner operations are temporarily unavailable.";
}

export function ScannerOperations() {
  const operations = useQuery({
    queryKey: ["scanner-operations"],
    queryFn: ({ signal }) => api.get<ScannerOperationsResponse>("/scanner-operations", signal),
    refetchInterval: 30_000,
  });

  if (operations.isPending) {
    return (
      <div className="scanner-state" role="status">
        Loading scanner operations…
      </div>
    );
  }
  if (operations.isError) {
    return (
      <div className="scanner-state error" role="alert">
        {errorMessage(operations.error)}
      </div>
    );
  }

  const { node, capabilities, last_24_hours: totals } = operations.data;
  return (
    <div className="scanner-page">
      <header className="page-header">
        <div>
          <h1 className="page-title">Scanner operations</h1>
          <p className="scanner-subtitle">
            Product capability health and tenant-scoped results. Engine details and message content
            remain private.
          </p>
        </div>
        <span className={`scanner-node-status ${node.status}`}>{node.status}</span>
      </header>

      <section className="card scanner-stats" aria-label="Scanner totals for the last 24 hours">
        <div className="stat-row">
          <span>Results (24h)</span>
          <strong>{totals.total}</strong>
        </div>
        <div className="stat-row">
          <span>Clean</span>
          <strong>{totals.clean}</strong>
        </div>
        <div className={`stat-row${totals.non_clean > 0 ? " attention" : ""}`}>
          <span>Threat or suspicious</span>
          <strong>{totals.non_clean}</strong>
        </div>
        <div className="stat-row">
          <span>Inconclusive</span>
          <strong>{totals.inconclusive}</strong>
        </div>
        <div className={`stat-row${totals.release_reinjection_failures > 0 ? " attention" : ""}`}>
          <span>Release delivery failures</span>
          <strong>{totals.release_reinjection_failures}</strong>
        </div>
      </section>

      <section className="card scanner-node" aria-labelledby="scanner-node-heading">
        <div>
          <h2 id="scanner-node-heading">Mail security node</h2>
          <code>{node.node_id}</code>
        </div>
        <dl>
          <div>
            <dt>Capabilities</dt>
            <dd>{node.configured_capabilities}</dd>
          </div>
          <div>
            <dt>Required unavailable</dt>
            <dd>{node.required_unhealthy}</dd>
          </div>
          <div>
            <dt>Average duration</dt>
            <dd>{Math.round(totals.average_duration_ms)} ms</dd>
          </div>
        </dl>
      </section>

      <section className="card scanner-table-wrap" aria-labelledby="scanner-capabilities-heading">
        <h2 id="scanner-capabilities-heading">Configured capabilities</h2>
        <table className="scanner-table">
          <thead>
            <tr>
              <th>Capability</th>
              <th>Requirement</th>
              <th>Status</th>
              <th>Queue</th>
              <th>Checked</th>
            </tr>
          </thead>
          <tbody>
            {capabilities.map((capability) => (
              <tr key={capability.capability}>
                <td>{capability.capability}</td>
                <td>{capability.requirement}</td>
                <td>
                  <span className={`scanner-capability-status ${capability.status}`}>
                    {capability.status}
                  </span>
                </td>
                <td>{capability.queue_depth ?? "—"}</td>
                <td>{new Date(capability.checked_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
