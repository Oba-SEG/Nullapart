import { useQuery } from "@tanstack/react-query";

import { api, type ApiError } from "../api/client";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Hint } from "../components/primitives/Hint";
import { nodeStatusLabel, requirementLabel, scannerStatusLabel } from "../lib/status";
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
      <WorkspaceHeader
        eyebrow="Mail security"
        title="Scanner operations"
        description="Inspect check health and per-customer results. Engine detail and message content stay private by design."
        scope="Health only"
        actions={
          <span className={`scanner-node-status ${node.status}`}>
            {nodeStatusLabel(node.status)}
          </span>
        }
      />

      <ControlRail
        title="Scanner capacity state"
        summary="Health is shown by check name so you do not need to know the engine behind it."
        signals={[
          {
            label: "Required checks down",
            value: node.required_unhealthy,
            detail: "Required checks that are not healthy right now.",
            tone: node.required_unhealthy > 0 ? "attention" : "healthy",
          },
          {
            label: "Healthy checks",
            value: `${capabilities.filter((item) => item.status === "healthy").length}/${capabilities.length}`,
            detail: "Check health on this node.",
            tone: capabilities.every((item) => item.status === "healthy") ? "healthy" : "attention",
          },
          {
            label: "Release delivery failures",
            value: totals.release_reinjection_failures,
            detail: "Released messages that failed to re-enter delivery in the last 24 hours.",
            tone: totals.release_reinjection_failures > 0 ? "attention" : "healthy",
          },
        ]}
      />

      <WorkflowGuide
        title="Check scanner health before you rely on it"
        description="This page reports health only. It does not expose scanner engines or management controls."
        steps={[
          {
            label: "Read health",
            detail: "Confirm active, draining and unavailable capacity.",
          },
          {
            label: "Inspect operation",
            detail: "Compare the check names and their health.",
          },
          {
            label: "Escalate safely",
            detail: "Use runtime operations to refresh when the health signals need it.",
          },
        ]}
      />

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
          <span>
            <Hint label="A released message that failed to re-enter delivery after being held.">
              <span className="hint-term">Release delivery failures</span>
            </Hint>
          </span>
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
            <dt>Checks</dt>
            <dd>{node.configured_capabilities}</dd>
          </div>
          <div>
            <dt>Required down</dt>
            <dd>{node.required_unhealthy}</dd>
          </div>
          <div>
            <dt>Average duration</dt>
            <dd>{Math.round(totals.average_duration_ms)} ms</dd>
          </div>
        </dl>
      </section>

      <section className="card scanner-table-wrap" aria-labelledby="scanner-capabilities-heading">
        <h2 id="scanner-capabilities-heading">Configured checks</h2>
        <table className="scanner-table">
          <thead>
            <tr>
              <th>Check</th>
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
                <td>{requirementLabel(capability.requirement)}</td>
                <td>
                  <span className={`scanner-capability-status ${capability.status}`}>
                    {scannerStatusLabel(capability.status)}
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
