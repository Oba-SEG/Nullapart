import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { Hint } from "./Hint";

describe("Hint", () => {
  it("keeps the explanation reachable to assistive tech without a hover", () => {
    render(
      <Hint label="Security floors cannot be turned off.">
        <button type="button">Save override</button>
      </Hint>,
    );
    const trigger = screen.getByRole("button", { name: "Save override" });
    expect(trigger.getAttribute("aria-describedby")).toBeTruthy();
    expect(screen.getByText("Security floors cannot be turned off.")).toBeTruthy();
  });

  it("reveals the bubble on keyboard focus and hides it on Escape", async () => {
    const user = userEvent.setup();
    render(
      <Hint label="Re-authenticate to continue.">
        <button type="button">Activate</button>
      </Hint>,
    );
    expect(screen.queryByRole("tooltip")).toBeNull();
    await user.tab();
    expect(screen.getByRole("tooltip")).toHaveTextContent("Re-authenticate to continue.");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("takes a tab stop itself when the content is not focusable", async () => {
    const user = userEvent.setup();
    render(
      <Hint label="Set by the system scope.">
        <span className="hint-term">Currently active</span>
      </Hint>,
    );
    await user.tab();
    expect(screen.getByRole("tooltip")).toHaveTextContent("Set by the system scope.");
  });

  it("does not add a second tab stop around a focusable child", async () => {
    const user = userEvent.setup();
    render(
      <Hint label="Removes the override.">
        <button type="button">Clear override</button>
      </Hint>,
    );
    await user.tab();
    expect(screen.getByRole("button", { name: "Clear override" })).toHaveFocus();
    await user.tab();
    expect(document.body).toHaveFocus();
  });
});
