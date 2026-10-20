import { afterEach, describe, expect, it } from "vitest";
import {
  captureException,
  initTelemetry,
  isTelemetryConfigured,
  scrubbedOrNone,
} from "./telemetry";

describe("scrubbedOrNone", () => {
  it("keeps static console error text", () => {
    expect(scrubbedOrNone("render failed: unexpected state")).toBe(
      "render failed: unexpected state",
    );
  });

  it("drops secret-shaped text", () => {
    expect(scrubbedOrNone("-----BEGIN PRIVATE KEY-----MIIEv")).toBe(null);
    expect(scrubbedOrNone("AKIAexpiration")).toBe(null);
    expect(scrubbedOrNone("ghp_16CharactersXXXXXXXX")).toBe(null);
  });

  it("drops header-style fragments", () => {
    expect(scrubbedOrNone("Set-Cookie: session=abc")).toBe(null);
    expect(scrubbedOrNone("Subject: you have won")).toBe(null);
  });

  it("drops empty and over-long content", () => {
    expect(scrubbedOrNone("   ")).toBe(null);
    const long = "a".repeat(600);
    expect(scrubbedOrNone(long)!.length).toBe(512);
  });

  it("strips control characters", () => {
    expect(scrubbedOrNone("line\u{0001}break")).toBe("line\u{FFFD}break");
  });
});

describe("isTelemetryConfigured", () => {
  it("requires an http dsn", () => {
    expect(isTelemetryConfigured(undefined)).toBe(false);
    expect(isTelemetryConfigured("")).toBe(false);
    expect(isTelemetryConfigured("tcp://key@host/seg")).toBe(false);
    expect(isTelemetryConfigured("http://key@127.0.0.1:9050/seg")).toBe(true);
  });
});

describe("captureException", () => {
  afterEach(() => {
    // Reset the module-level state so tests stay order-independent.
    initTelemetry({ dsn: "" });
  });

  it("stays inert when never configured", () => {
    expect(captureException(new Error("boom"))).toBe("");
  });

  it("stays inert when configured with an unusable dsn", () => {
    initTelemetry({ dsn: "not-a-dsn", environment: "test" });
    expect(captureException(new Error("boom"))).toBe("");
  });
});
