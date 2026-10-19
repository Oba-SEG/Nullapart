import { describe, expect, it } from "vitest";

import {
  auditDetailFieldLabel,
  auditDetailValueLabel,
  familyDisplayName,
  policyFamilyLabel,
  tenantResourceReference,
} from "./labels";

describe("policy family naming", () => {
  it("renames a catalog name that describes the engine", () => {
    expect(policyFamilyLabel("ml_threat_classification")).toBe("Automatic threat review");
    expect(policyFamilyLabel("bulk_sending")).toBe("Bulk sending limits");
  });

  it("keeps the catalog name for a platform seat and the outcome word for a tenant", () => {
    expect(familyDisplayName("ml_threat_classification", "ML threat classification", true)).toBe(
      "Automatic threat review",
    );
    expect(familyDisplayName("ml_threat_classification", "ML threat classification", false)).toBe(
      "ML threat classification",
    );
  });

  it("names an unmapped family rather than printing its key", () => {
    expect(policyFamilyLabel("future_family")).toBe("Future family");
  });
});

describe("tenantResourceReference", () => {
  it("names the family a policy row changed", () => {
    expect(tenantResourceReference("policy_family", "bulk_sending")).toBe("Bulk sending limits");
    expect(tenantResourceReference("policy_family", "families")).toBe("All your mail policies");
  });

  it("reduces a composite sender key to the sender", () => {
    expect(
      tenantResourceReference("approved_bulk_sender", "news@example.test:smtp_mta:office-vpn"),
    ).toBe("news@example.test");
  });

  it("withholds a reference that names platform machinery", () => {
    expect(tenantResourceReference("audit", "checkpoint-status")).toBeNull();
  });

  it("withholds a database row key, whichever table it came from", () => {
    // `resource_id` holds the primary key of the row a write touched. A login
    // row, an audit row and an artifact row are all the platform's own records,
    // and the key says nothing the customer can act on.
    expect(tenantResourceReference("session", "86538d62-3b7d-4003-a7e6-740341e252f1")).toBeNull();
    expect(tenantResourceReference("audit", "17b90409-291d-4333-962f-4b199e3a437f")).toBeNull();
    expect(tenantResourceReference("artifact", "b061642519d7468e989fdb08751473d8")).toBeNull();
    expect(
      tenantResourceReference(
        "connector_remediation_action",
        "5c8a1e2f-9b3d-4a16-8e77-0d2f4c6a9b11",
      ),
    ).toBeNull();
  });

  it("withholds a composite keyed by a database row", () => {
    // A domain-source row is keyed `domain-id:source`; neither half matches the
    // shape alone, so the segment check is what keeps the id off the screen.
    expect(
      tenantResourceReference(
        "domain_source",
        "6f1c2d33-4b55-4a6f-9c8a-1d2e3f4a5b6c:dmarc_aggregate",
      ),
    ).toBeNull();
  });

  it("keeps a reference that names the customer's own mail", () => {
    // A quarantine case is routed by its message id and a transaction id is that
    // same message on the trace page. UUID shape notwithstanding, they are the
    // customer's identifiers to quote.
    expect(tenantResourceReference("quarantine_case", "7d2c4e6a-1111-2222-3333-444455556666")).toBe(
      "7d2c4e6a-1111-2222-3333-444455556666",
    );
    expect(tenantResourceReference("transaction", "2a7b1c9d-0e12-4a3b-9f88-77c6b5a49321")).toBe(
      "2a7b1c9d-0e12-4a3b-9f88-77c6b5a49321",
    );
  });

  it("passes a reference the customer quotes back untouched", () => {
    expect(tenantResourceReference("customer", "CZA-1")).toBe("CZA-1");
    expect(tenantResourceReference("message", "msg-2026-01-06-001")).toBe("msg-2026-01-06-001");
    expect(tenantResourceReference("session", null)).toBeNull();
  });
});

describe("audit detail naming", () => {
  it("labels a stored column instead of printing it", () => {
    expect(auditDetailFieldLabel("family_key")).toBe("Mail policy");
    expect(auditDetailFieldLabel("scope_level")).toBe("Applies to");
    expect(auditDetailFieldLabel("source_key")).toBe("Sending range");
  });

  it("humanizes a column the map has never seen", () => {
    expect(auditDetailFieldLabel("future_field")).toBe("Future field");
  });

  it("says which policy, role or scope a field records", () => {
    expect(auditDetailValueLabel("family_key", "ml_threat_classification")).toBe(
      "Automatic threat review",
    );
    expect(auditDetailValueLabel("role_key", "customer_admin")).toBe("Customer admin");
    expect(auditDetailValueLabel("scope_level", "tenant")).toBe("Your organisation");
    expect(auditDetailValueLabel("scope_level", "system")).toBe("Provider");
    expect(auditDetailValueLabel("reason_code", "QUARANTINE_MALWARE")).toBe("Held: malware");
    expect(auditDetailValueLabel("classification", "third_party")).toBe(
      "Another party sends for you",
    );
  });

  it("answers a boolean flag in words and leaves a plain value alone", () => {
    expect(auditDetailValueLabel("changed", "true")).toBe("Yes");
    expect(auditDetailValueLabel("truncated", "false")).toBe("No");
    expect(auditDetailValueLabel("row_count", "50")).toBe("50");
    expect(auditDetailValueLabel("release_reason", "Validated false positive")).toBe(
      "Validated false positive",
    );
  });
});
