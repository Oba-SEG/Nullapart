import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ScannerOperations } from "./ScannerOperations";

describe("ScannerOperations", () => {
  it("renders capability labels and normalized totals without engine details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            node: {
              node_id: "mailcore-local-01",
              status: "healthy",
              configured_capabilities: 2,
              required_unhealthy: 0,
            },
            capabilities: [
              {
                capability: "Malware analysis",
                requirement: "required",
                status: "healthy",
                checked_at: "2026-01-01T00:00:00Z",
                queue_depth: 0,
              },
              {
                capability: "Document safety",
                requirement: "optional",
                status: "healthy",
                checked_at: "2026-01-01T00:00:00Z",
              },
            ],
            last_24_hours: {
              total: 14,
              clean: 10,
              non_clean: 3,
              inconclusive: 1,
              average_duration_ms: 42.4,
              release_reinjection_failures: 0,
            },
          },
        }),
      }),
    );
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    render(
      <QueryClientProvider client={queryClient}>
        <ScannerOperations />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("Malware analysis")).toBeTruthy();
    expect(screen.getByText("Document safety")).toBeTruthy();
    expect(screen.getByText("14")).toBeTruthy();
    expect(screen.queryByText(/clamav|tesseract|engine version/i)).toBeNull();
    expect(screen.getByText(/content stay private/i)).toBeTruthy();
  });
});
