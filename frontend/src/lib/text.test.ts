import { describe, expect, it } from "vitest";

import { humanizeToken } from "./text";

describe("humanizeToken", () => {
  it("writes sentence case for ordinary machine tokens", () => {
    expect(humanizeToken("quarantine_release")).toBe("Quarantine release");
    expect(humanizeToken("QUARANTINE_MALWARE")).toBe("Quarantine malware");
    expect(humanizeToken("audit.access.list")).toBe("Audit access list");
  });

  it("keeps the caps on an acronym wherever it sits", () => {
    expect(humanizeToken("deep_ai_analysis_result_recorded")).toBe(
      "Deep AI analysis result recorded",
    );
    expect(humanizeToken("external_account_id")).toBe("External account ID");
    expect(humanizeToken("dmarc_ruf_record")).toBe("DMARC RUF record");
  });

  it("leaves a single word, or nothing, as it stands", () => {
    expect(humanizeToken("checkpoint")).toBe("Checkpoint");
    expect(humanizeToken("")).toBe("");
  });
});
