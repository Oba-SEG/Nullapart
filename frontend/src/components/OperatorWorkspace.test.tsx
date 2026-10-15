import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ControlRail } from "./ControlRail";
import { WorkflowGuide } from "./WorkflowGuide";
import { WorkspaceHeader } from "./WorkspaceHeader";

describe("operator workspace components", () => {
  it("exposes a route title, authority boundary and only the supplied action", () => {
    render(
      <WorkspaceHeader
        eyebrow="Runtime control"
        title="Runtime operations"
        description="Server-reported deployment state."
        scope="Deployment operator"
        actions={<button type="button">Refresh</button>}
      />,
    );

    expect(screen.getByRole("heading", { level: 1, name: "Runtime operations" })).toBeTruthy();
    expect(screen.getByText("Deployment operator")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeTruthy();
  });

  it("uses ordered workflow steps and labelled server-reported control state", () => {
    render(
      <>
        <WorkflowGuide
          title="Safe release"
          description="Evidence before change."
          steps={[
            { label: "Inspect", detail: "Read current evidence." },
            { label: "Release", detail: "Use the authorized action." },
          ]}
        />
        <ControlRail
          title="Release state"
          summary="Values originate from the current server response."
          signals={[
            { label: "Eligible", value: "1", detail: "Case can enter step-up." },
            { label: "Blocked", value: "0", detail: "No blocked cases.", tone: "healthy" },
          ]}
        />
      </>,
    );

    expect(screen.getByRole("heading", { level: 2, name: "Safe release" })).toBeTruthy();
    expect(screen.getByRole("list").querySelectorAll("li")).toHaveLength(2);
    expect(screen.getByRole("region", { name: "Release state" })).toBeTruthy();
    expect(screen.getByText("Eligible")).toBeTruthy();
    expect(screen.getByText("Values originate from the current server response.")).toBeTruthy();
  });
});
