import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { MessageContentData } from "../api/trace";
import { MessageContent } from "./MessageContent";
import componentSource from "./MessageContent.tsx?raw";

const maliciousHtml = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  '<a href="javascript:alert(1)">dangerous link</a>',
  "<svg onload=alert(1)></svg>",
  '<iframe src="https://evil.test/frame"></iframe>',
  '<img src="https://evil.test/p.gif" alt="tracking pixel">',
  "<style>@import 'https://evil.test';</style>",
  "<p>Rendered paragraph</p>",
].join("\n");

const baseContent: MessageContentData = {
  transaction_id: "tx-3003",
  subject: "Status update",
  from: "sender@example.test",
  to: ["alice@example.test", "bob@example.test"],
  date: "2026-09-30T09:30:00Z",
  headers: [
    { name: "Subject", value: "Status update" },
    { name: "X-Nullapart-Trace", value: "trace-abc123" },
  ],
  plain_text: "Hello team,\n<script>alert(1)</script>\nRegards",
  html: maliciousHtml,
  truncated: false,
  attachments: [
    { filename: "invoice.pdf", content_type: "application/pdf", size_bytes: 1024 },
    { filename: null, content_type: null, size_bytes: null },
  ],
};

describe("MessageContent", () => {
  it("renders the sanitized HTML preview in a fully sandboxed iframe", async () => {
    const user = userEvent.setup();
    render(<MessageContent data={baseContent} />);

    expect(screen.queryByTitle("Sanitized message preview")).toBeNull();

    await user.click(screen.getByRole("tab", { name: "HTML" }));

    const frame = screen.getByTitle("Sanitized message preview");
    expect(frame.getAttribute("sandbox")).toBe("");
    const sandbox = frame.getAttribute("sandbox") ?? "";
    expect(sandbox).not.toContain("allow-scripts");
    expect(sandbox).not.toContain("allow-same-origin");
    expect(sandbox).not.toContain("allow-popups");
    expect(sandbox).not.toContain("allow-forms");
    expect(sandbox).not.toContain("allow-top-navigation");

    const srcDoc = frame.getAttribute("srcdoc") ?? "";
    expect(srcDoc).toContain("Content-Security-Policy");
    expect(srcDoc).toContain("default-src 'none'");
    expect(srcDoc).toContain("Rendered paragraph");
    expect(srcDoc).not.toContain("script>alert");
    expect(srcDoc).not.toContain("onerror");
    expect(srcDoc).not.toContain("javascript:");
    expect(srcDoc).not.toContain("evil.test");

    expect(
      screen.getByText(
        "Active content is blocked; images and links inside the preview are disabled.",
      ),
    ).toBeTruthy();
  });

  it("renders the plain text part as a literal React text node", () => {
    render(
      <MessageContent
        data={{ ...baseContent, plain_text: "<script>alert(1)</script>", html: null }}
      />,
    );

    expect(screen.getByText("<script>alert(1)</script>")).toBeTruthy();
    const pre = document.querySelector("pre");
    expect(pre?.innerHTML ?? "").toContain("&lt;script&gt;");
    expect(screen.queryByTitle("Sanitized message preview")).toBeNull();
  });

  it("renders headers, attachment metadata and the honest download limitation", async () => {
    const user = userEvent.setup();
    render(<MessageContent data={baseContent} />);

    expect(screen.getByText("invoice.pdf")).toBeTruthy();
    expect(screen.getByText(/application\/pdf · 1024 bytes/)).toBeTruthy();
    expect(screen.getByText("Unnamed attachment")).toBeTruthy();
    expect(screen.getByText(/unknown content type/)).toBeTruthy();
    expect(
      screen.getByText("Attachment download is not available in this environment."),
    ).toBeTruthy();

    await user.click(screen.getByRole("tab", { name: "Headers" }));

    expect(screen.getByText("X-Nullapart-Trace")).toBeTruthy();
    expect(screen.getByText("trace-abc123")).toBeTruthy();
    expect(screen.getByText("Subject")).toBeTruthy();
  });

  it("shows the truncation notice and missing-part fallbacks", async () => {
    const user = userEvent.setup();
    render(
      <MessageContent
        data={{
          ...baseContent,
          plain_text: null,
          html: null,
          headers: [],
          truncated: true,
        }}
      />,
    );

    expect(screen.getByText("This message was truncated for display.")).toBeTruthy();

    expect(screen.getByText("No plain text part.")).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "HTML" }));
    expect(screen.getByText("No HTML part.")).toBeTruthy();
    expect(screen.queryByTitle("Sanitized message preview")).toBeNull();
    await user.click(screen.getByRole("tab", { name: "Headers" }));
    expect(screen.getByText("No headers are available for this message.")).toBeTruthy();
  });

  it("never injects markup with dangerouslySetInnerHTML", () => {
    expect(componentSource).not.toContain("dangerouslySetInnerHTML");
    expect(componentSource).toContain('sandbox=""');
  });
});
