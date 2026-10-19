import { describe, expect, it } from "vitest";

import { familyDisplayName, policyFamilyLabel, tenantResourceReference } from "./labels";

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
