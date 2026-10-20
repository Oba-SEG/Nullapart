import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CorporateWebsite } from "./CorporateWebsite";

describe("CorporateWebsite", () => {
  it("keeps the corporate landing public and directs administrators to sign in", () => {
    render(<CorporateWebsite />);

    expect(screen.getByRole("heading", { name: /protect the mail boundary/i })).toBeTruthy();
    expect(screen.getAllByRole("link", { name: /sign in/i })[0]).toHaveAttribute("href", "/login");
    expect(screen.getAllByRole("img", { name: "Nullapart" })).toHaveLength(2);
  });
});
