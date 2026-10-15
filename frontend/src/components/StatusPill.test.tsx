import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { StatusTone } from "../lib/status";
import { StatusPill } from "./StatusPill";

const tones: StatusTone[] = ["clean", "threat", "review", "processing", "delivered", "muted"];

describe("StatusPill", () => {
  it.each(tones)("renders the %s semantic label", (tone) => {
    render(<StatusPill tone={tone} label={`${tone} message`} />);
    expect(screen.getByText(`${tone} message`)).toHaveClass(`status-${tone}`);
  });

  it("uses local image assets for the production status artwork", () => {
    const { container } = render(<StatusPill tone="clean" label="Clean" />);
    expect(container.querySelector('img[src="/brand/status/status-clean-256.png"]')).toBeTruthy();
  });
});
