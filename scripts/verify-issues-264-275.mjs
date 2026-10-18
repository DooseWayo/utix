#!/usr/bin/env node
/**
 * Automated Verification Test Suite for Issues #264, #272, #273, #275
 *
 * Verifies all 4 hard contributor assignments:
 * - Issue #264: Safe ownership transfer with pending acceptance and expiry
 * - Issue #272: Privacy-safe export with field-level authorization
 * - Issue #273: Feature rollout guardrails with emergency disablement
 * - Issue #275: Contributor diagnostics for environment and dependency validation
 *
 * Usage:
 *   node scripts/verify-issues-264-275.mjs
 */

import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

console.log("============================================================");
console.log("   AUTOMATED VERIFICATION: ISSUES #264, #272, #273, #275    ");
console.log("============================================================\n");

// -------------------------------------------------------------
// TEST 1: ISSUE #264 - Safe Ownership Transfer
// -------------------------------------------------------------
console.log("--> Testing Issue #264: Safe Ownership Transfer...");
const { createOwnershipStore } = await import("../core/ownership/ownership.ts");
const { recordMachine, stateView } = await import("../core/lifecycle/records.ts");

const ownershipStore = createOwnershipStore();
const ALICE = "GBBD6W3NZUBY7J572J45A75Z7P4C0B634S8X2A7X6M27B2B642C3N444";
const BOB = "GA7YOFXNY2WAGM56WJ2W6LKK3F3HMRQ74NFD5Z5P4C0B634S8X2A7X6M";
const EVE = "GC5W5O5IUBY7J572J45A75Z7P4C0B634S8X2A7X6M27B2B642C3N4555";

// 1. Propose transfer
const proposeRes = ownershipStore.initiate({
  resourceId: "ticket-101",
  resourceType: "ticket",
  currentOwner: ALICE,
  proposedOwner: BOB,
  expiresInMs: 3600_000,
  priceStroops: 5_000_000,
  actor: { kind: "user", id: ALICE }
});
assert.equal(proposeRes.ok, true, "Propose transfer must succeed");
assert.equal(proposeRes.value.status, "pending", "Initial state must be pending");
assert.equal(proposeRes.value.currentOwner, ALICE);
assert.equal(proposeRes.value.proposedOwner, BOB);

// 2. Reject self-transfer
const selfRes = ownershipStore.initiate({
  resourceId: "ticket-102",
  currentOwner: ALICE,
  proposedOwner: ALICE,
  actor: { kind: "user", id: ALICE }
});
assert.equal(selfRes.ok, false, "Self-transfer must be rejected");
assert.equal(selfRes.code, "cannot_transfer_to_self");

// 3. Reject unauthorized initiator
const unauthPropose = ownershipStore.initiate({
  resourceId: "ticket-103",
  currentOwner: ALICE,
  proposedOwner: BOB,
  actor: { kind: "user", id: EVE }
});
assert.equal(unauthPropose.ok, false, "Unauthorized initiator must be rejected");
assert.equal(unauthPropose.code, "unauthorized_not_owner");

// 4. Unauthorized acceptance
const unauthAccept = ownershipStore.accept({
  transferId: proposeRes.value.id,
  actor: { kind: "user", id: EVE }
});
assert.equal(unauthAccept.ok, false, "Unauthorized recipient must be rejected");
assert.equal(unauthAccept.code, "unauthorized_not_recipient");

// 5. Authorized acceptance
const authAccept = ownershipStore.accept({
  transferId: proposeRes.value.id,
  actor: { kind: "user", id: BOB }
});
assert.equal(authAccept.ok, true, "Authorized recipient acceptance must succeed");
assert.equal(authAccept.value.status, "accepted");
assert.ok(authAccept.value.settledAt, "Settled timestamp must be present");

// 6. Expiry enforcement
const baseNow = Date.now();
const expiredProp = ownershipStore.initiate({
  resourceId: "ticket-201",
  currentOwner: ALICE,
  proposedOwner: BOB,
  expiresInMs: 60_000,
  now: baseNow,
  actor: { kind: "user", id: ALICE }
});
assert.equal(expiredProp.ok, true);
const acceptExpired = ownershipStore.accept({
  transferId: expiredProp.value.id,
  actor: { kind: "user", id: BOB },
  now: baseNow + 70_000
});
assert.equal(acceptExpired.ok, false, "Expired proposal cannot be accepted");
assert.equal(acceptExpired.code, "transfer_expired");

// 7. Lifecycle machine check
const machineRes = recordMachine("ownership_transfer");
assert.equal(machineRes.ok, true, "ownership_transfer must be registered in core/lifecycle");
const view = stateView("ownership_transfer", "pending");
assert.equal(view.label, "Pending Acceptance");
console.log("    [PASS] Safe Ownership Transfer verified (propose, accept, reject, expiry, lifecycle)\n");

// -------------------------------------------------------------
// TEST 2: ISSUE #272 - Privacy-Safe Export with Field-Level Auth
// -------------------------------------------------------------
console.log("--> Testing Issue #272: Privacy-Safe Export with Field-Level Authorization...");
const { exportRecords, EXPORT_CURRENT_SCHEMA_VERSION } = await import("../core/export/exporter.ts");

const exportSource = {
  recordType: "audit_events",
  schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
  scope: "own",
  collect: () => [
    {
      id: "ev-01",
      action: "payment",
      amount: "100.00",
      ipAddress: "192.0.2.1",
      userAgent: "curl/7.88",
      internalLatencyMs: 35,
      adminNotes: "Risk verified",
      riskScore: 0.05
    }
  ]
};

// Standard user export: sensitive fields filtered
const userExport = exportRecords(
  {
    schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
    scope: "own",
    actor: { kind: "user" }
  },
  [exportSource]
);
assert.equal(userExport.ok, true, "User export must succeed");
assert.equal(userExport.value.recordCount, 1);
const userRec = userExport.value.records[0];
assert.equal(userRec.id, "ev-01");
assert.equal(userRec.amount, "100.00");
assert.equal(userRec.internalLatencyMs, undefined, "internalLatencyMs must be omitted for user");
assert.equal(userRec.userAgent, undefined, "userAgent must be omitted for user");
assert.equal(userRec.ipAddress, "[FILTERED: UNAUTHORIZED]", "ipAddress must be masked for user");
assert.equal(userRec.adminNotes, "[FILTERED: UNAUTHORIZED]", "adminNotes must be masked for user");
assert.ok((userExport.value.fieldsFiltered ?? 0) > 0, "Fields filtered count must be > 0");

// Maintainer export: all fields accessible
const maintainerExport = exportRecords(
  {
    schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
    scope: "maintainer",
    actor: { kind: "maintainer" }
  },
  [exportSource]
);
assert.equal(maintainerExport.ok, true, "Maintainer export must succeed");
const maintRec = maintainerExport.value.records[0];
assert.equal(maintRec.internalLatencyMs, 35, "Maintainer must see internalLatencyMs");
assert.equal(maintRec.ipAddress, "192.0.2.1", "Maintainer must see raw ipAddress");
assert.equal(maintRec.adminNotes, "Risk verified", "Maintainer must see adminNotes");

// Strict field refusal
const strictDenied = exportRecords(
  {
    schemaVersion: EXPORT_CURRENT_SCHEMA_VERSION,
    scope: "own",
    actor: { kind: "user" },
    fields: ["id", "adminNotes"],
    strictFields: true
  },
  [exportSource]
);
assert.equal(strictDenied.ok, false, "Strict request of unauthorized fields must be refused");
assert.equal(strictDenied.code, "field_authorization_denied");
console.log("    [PASS] Privacy-Safe Export with Field-Level Authorization verified\n");

// -------------------------------------------------------------
// TEST 3: ISSUE #273 - Feature Rollout Guardrails & Kill Switch
// -------------------------------------------------------------
console.log("--> Testing Issue #273: Feature Rollout Guardrails with Emergency Disablement...");
const {
  isFeatureEnabled,
  triggerEmergencyDisable,
  clearEmergencyDisable,
  triggerGlobalEmergencyKillSwitch,
  clearGlobalEmergencyKillSwitch,
  configureRollout,
  recordFeatureSuccess,
  recordFeatureFailure,
  resetCircuitBreaker,
  resetRolloutEngine,
  computeRolloutBucket
} = await import("../core/feature-flags/flags.ts");

resetRolloutEngine();

// Normal default
assert.equal(isFeatureEnabled("detailedFriendbotClassification"), true, "Friendbot flag default is true");

// Emergency kill switch
triggerEmergencyDisable("detailedFriendbotClassification", {
  reason: "Exploit mitigation",
  actor: "security"
});
assert.equal(isFeatureEnabled("detailedFriendbotClassification"), false, "Kill switch forces flag to false");
clearEmergencyDisable("detailedFriendbotClassification");
assert.equal(isFeatureEnabled("detailedFriendbotClassification"), true, "Clearing restores flag");

// Global kill switch
triggerGlobalEmergencyKillSwitch({ reason: "Site incident" });
assert.equal(isFeatureEnabled("detailedFriendbotClassification"), false, "Global kill switch disables all");
clearGlobalEmergencyKillSwitch();
assert.equal(isFeatureEnabled("detailedFriendbotClassification"), true);

// Circuit breaker
configureRollout("detailedFriendbotClassification", {
  errorThresholdPercent: 25,
  minErrorSamples: 4
});
recordFeatureSuccess("detailedFriendbotClassification");
recordFeatureFailure("detailedFriendbotClassification");
recordFeatureFailure("detailedFriendbotClassification");
recordFeatureFailure("detailedFriendbotClassification"); // 3/4 = 75% > 25%
assert.equal(isFeatureEnabled("detailedFriendbotClassification"), false, "Circuit breaker trips on errors");
resetCircuitBreaker("detailedFriendbotClassification");
assert.equal(isFeatureEnabled("detailedFriendbotClassification"), true);

// Network constraint
configureRollout("testnetOnly", {
  percentage: 100,
  allowedNetworks: ["testnet"]
});
assert.equal(isFeatureEnabled("testnetOnly", { network: "testnet" }), true);
assert.equal(isFeatureEnabled("testnetOnly", { network: "mainnet" }), false);

// Deterministic hashing
const b1 = computeRolloutBucket("feat", "acc-G123");
const b2 = computeRolloutBucket("feat", "acc-G123");
assert.equal(b1, b2, "Canary hashing must be deterministic");
console.log("    [PASS] Feature Rollout Guardrails & Emergency Disablement verified\n");

// -------------------------------------------------------------
// TEST 4: ISSUE #275 - Contributor Diagnostics
// -------------------------------------------------------------
console.log("--> Testing Issue #275: Contributor Diagnostics...");
const { runContributorDiagnostics, formatDiagnosticsReport } = await import("../core/diagnostics/runner.ts");

const diagReport = await runContributorDiagnostics({ projectRoot: root });
assert.ok(diagReport.evaluatedAt);
assert.equal(diagReport.summary.total, 5, "Must run all 5 diagnostic checks");
assert.ok(["healthy", "degraded", "failing"].includes(diagReport.overallStatus));

const formatted = formatDiagnosticsReport(diagReport);
assert.ok(formatted.includes("UTIX CONTRIBUTOR DIAGNOSTICS REPORT"));
assert.ok(formatted.includes("[PASS]") || formatted.includes("[WARN]") || formatted.includes("[FAIL]"));
console.log("    [PASS] Contributor Diagnostics verified (all 5 checks run successfully)\n");

console.log("============================================================");
console.log("   ALL 4 ISSUES (#264, #272, #273, #275) VERIFIED [PASS]    ");
console.log("============================================================");
