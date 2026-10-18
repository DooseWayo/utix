import { describe, expect, it, beforeEach } from "vitest";
import {
  exportRecords,
  createExportIdempotencyStore,
  createExportQuotaStore,
  EXPORT_CURRENT_SCHEMA_VERSION,
  type ExportRecordSource
} from "../exporter";
import { createMemoryQuotaStorage, createQuotaStore } from "@/core/quota/quota";
import { createIdempotencyStore } from "@/core/idempotency/idempotency";

describe("Privacy-Safe Export with Field-Level Authorization (#272)", () => {
  beforeEach(() => {
    createExportIdempotencyStore(createIdempotencyStore());
    createExportQuotaStore(createQuotaStore({ storage: createMemoryQuotaStorage() }));
  });

  const sampleSource: ExportRecordSource = {
    recordType: "transaction_audit",
    schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
    scope: "own",
    collect: () => [
      {
        id: "tx-001",
        amount: "150.00",
        currency: "USDC",
        status: "settled",
        ipAddress: "203.0.113.195",
        userAgent: "Mozilla/5.0 Chrome/120.0",
        internalLatencyMs: 45,
        adminNotes: "Compliance review completed",
        riskScore: 0.12
      },
      {
        id: "tx-002",
        amount: "5000.00",
        currency: "XLM",
        status: "pending",
        ipAddress: "198.51.100.42",
        userAgent: "Utix-Mobile/1.2",
        internalLatencyMs: 120,
        adminNotes: "High-value transaction alert",
        riskScore: 0.78
      }
    ]
  };

  it("filters sensitive fields for standard user actor by default", () => {
    const res = exportRecords(
      {
        schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
        scope: "own",
        actor: { kind: "user" }
      },
      [sampleSource]
    );

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.recordCount).toBe(2);
    expect(res.value.fieldsFiltered).toBeGreaterThan(0);

    const first = res.value.records[0];
    // Public/safe fields are present
    expect(first.id).toBe("tx-001");
    expect(first.amount).toBe("150.00");
    expect(first.currency).toBe("USDC");
    expect(first.status).toBe("settled");

    // Internal fields omitted
    expect(first.internalLatencyMs).toBeUndefined();
    expect(first.userAgent).toBeUndefined();
    expect(first.riskScore).toBeUndefined();

    // Masked sensitive fields
    expect(first.ipAddress).toBe("[FILTERED: UNAUTHORIZED]");
    expect(first.adminNotes).toBe("[FILTERED: UNAUTHORIZED]");
  });

  it("permits maintainer to view all fields without field-level masking", () => {
    const res = exportRecords(
      {
        schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
        scope: "maintainer",
        actor: { kind: "maintainer" }
      },
      [sampleSource]
    );

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const first = res.value.records[0];
    expect(first.id).toBe("tx-001");
    expect(first.internalLatencyMs).toBe(45);
    expect(first.userAgent).toBe("Mozilla/5.0 Chrome/120.0");
    expect(first.ipAddress).toBe("203.0.113.195");
    expect(first.adminNotes).toBe("Compliance review completed");
    expect(first.riskScore).toBe(0.12);
  });

  it("supports explicit projection of authorized fields", () => {
    const res = exportRecords(
      {
        schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
        scope: "own",
        actor: { kind: "user" },
        fields: ["id", "amount", "currency"]
      },
      [sampleSource]
    );

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const first = res.value.records[0];
    expect(first.id).toBe("tx-001");
    expect(first.amount).toBe("150.00");
    expect(first.currency).toBe("USDC");
    // Unrequested fields are not projected
    expect(first.status).toBeUndefined();
    expect(first.ipAddress).toBeUndefined();
  });

  it("strictly refuses export when user explicitly requests unauthorized fields with strictFields: true", () => {
    const res = exportRecords(
      {
        schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
        scope: "own",
        actor: { kind: "user" },
        fields: ["id", "adminNotes"],
        strictFields: true
      },
      [sampleSource]
    );

    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe("field_authorization_denied");
  });

  it("respects requiredPermissions for custom field rules", () => {
    const customSource: ExportRecordSource = {
      recordType: "special_data",
      schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
      scope: "own",
      fieldRules: [
        {
          field: "billingSecretCode",
          requiredPermissions: ["export:billing"],
          onDenied: "omit"
        }
      ],
      collect: () => [
        {
          id: "rec-1",
          name: "Item Alpha",
          billingSecretCode: "SECRET-BILL-99"
        }
      ]
    };

    // User without required permission
    const denied = exportRecords(
      {
        schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
        scope: "own",
        actor: { kind: "user", permissions: ["export:standard"] }
      },
      [customSource]
    );
    expect(denied.ok).toBe(true);
    if (denied.ok) {
      expect(denied.value.records[0].billingSecretCode).toBeUndefined();
    }

    // User with required permission
    const granted = exportRecords(
      {
        schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
        scope: "own",
        actor: { kind: "user", permissions: ["export:billing"] }
      },
      [customSource]
    );
    expect(granted.ok).toBe(true);
    if (granted.ok) {
      expect(granted.value.records[0].billingSecretCode).toBe("SECRET-BILL-99");
    }
  });
});
