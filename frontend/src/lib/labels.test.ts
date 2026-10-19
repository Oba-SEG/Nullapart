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

  it("passes a reference the customer quotes back untouched", () => {
    expect(tenantResourceReference("customer", "CZA-1")).toBe("CZA-1");
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
