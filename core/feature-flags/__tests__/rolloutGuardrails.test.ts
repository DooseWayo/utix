import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearEmergencyDisable,
  clearGlobalEmergencyKillSwitch,
  computeRolloutBucket,
  configureRollout,
  getRolloutStatus,
  isEmergencyDisabled,
  isFeatureEnabled,
  recordFeatureFailure,
  recordFeatureSuccess,
  resetCircuitBreaker,
  resetRolloutEngine,
  triggerEmergencyDisable,
  triggerGlobalEmergencyKillSwitch
} from "../flags";

describe("Feature Rollout Guardrails with Emergency Disablement (#273)", () => {
  beforeEach(() => {
    resetRolloutEngine();
    delete process.env.UTIX_KILL_SWITCH;
    delete process.env.UTIX_EMERGENCY_DISABLE_detailedFriendbotClassification;
  });

  afterEach(() => {
    resetRolloutEngine();
    delete process.env.UTIX_KILL_SWITCH;
    delete process.env.UTIX_EMERGENCY_DISABLE_detailedFriendbotClassification;
  });

  describe("emergency kill switches", () => {
    it("immediately disables a feature when emergency disable is triggered", () => {
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(true);

      triggerEmergencyDisable("detailedFriendbotClassification", {
        reason: "Zero-day vulnerability reported in faucet classifier",
        actor: "security-team"
      });

      expect(isEmergencyDisabled("detailedFriendbotClassification")).toBe(true);
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(false);

      // Status diagnostics reflect kill-switch state
      const status = getRolloutStatus("detailedFriendbotClassification");
      expect(status.emergencyDisabled).toBe(true);
      expect(status.enabled).toBe(false);

      // Clearing restores normal operation
      clearEmergencyDisable("detailedFriendbotClassification");
      expect(isEmergencyDisabled("detailedFriendbotClassification")).toBe(false);
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(true);
    });

    it("triggers global kill switch disabling all feature rollouts", () => {
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(true);
      expect(isFeatureEnabled("safeOwnershipTransfer")).toBe(true);

      triggerGlobalEmergencyKillSwitch({ reason: "System-wide incident declaration" });

      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(false);
      expect(isFeatureEnabled("safeOwnershipTransfer")).toBe(false);

      clearGlobalEmergencyKillSwitch();
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(true);
      expect(isFeatureEnabled("safeOwnershipTransfer")).toBe(true);
    });

    it("honors environment emergency disablement variables", () => {
      process.env.UTIX_EMERGENCY_DISABLE_detailedFriendbotClassification = "true";
      expect(isEmergencyDisabled("detailedFriendbotClassification")).toBe(true);
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(false);

      delete process.env.UTIX_EMERGENCY_DISABLE_detailedFriendbotClassification;

      process.env.UTIX_KILL_SWITCH = "all";
      expect(isEmergencyDisabled("detailedFriendbotClassification")).toBe(true);
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(false);
    });
  });

  describe("circuit breaker error budget guardrail", () => {
    it("trips circuit breaker automatically when error rate breaches threshold", () => {
      configureRollout("detailedFriendbotClassification", {
        errorThresholdPercent: 30,
        minErrorSamples: 4
      });

      // 1 success, 3 failures -> 3/4 = 75% error rate (> 30%)
      recordFeatureSuccess("detailedFriendbotClassification");
      recordFeatureFailure("detailedFriendbotClassification");
      recordFeatureFailure("detailedFriendbotClassification");
      recordFeatureFailure("detailedFriendbotClassification");

      const status = getRolloutStatus("detailedFriendbotClassification");
      expect(status.circuitBreakerTripped).toBe(true);
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(false);

      // Resetting circuit breaker restores normal evaluation
      resetCircuitBreaker("detailedFriendbotClassification");
      expect(isFeatureEnabled("detailedFriendbotClassification")).toBe(true);
    });
  });

  describe("canary percentage rollouts", () => {
    it("deterministically assigns consistent buckets to subjects", () => {
      const bucket1 = computeRolloutBucket("newTool", "account:GAAA");
      const bucket2 = computeRolloutBucket("newTool", "account:GAAA");
      expect(bucket1).toBe(bucket2);
      expect(bucket1).toBeGreaterThanOrEqual(0);
      expect(bucket1).toBeLessThan(100);
    });

    it("respects percentage thresholds", () => {
      configureRollout("canaryTest", {
        percentage: 0
      });
      expect(isFeatureEnabled("canaryTest", { subjectId: "user-123" })).toBe(false);

      configureRollout("canaryTest", {
        percentage: 100
      });
      expect(isFeatureEnabled("canaryTest", { subjectId: "user-123" })).toBe(true);
    });
  });

  describe("targeting guardrails (allowlist, blocklist, network)", () => {
    it("respects allowlist and blocklist regardless of percentage", () => {
      configureRollout("guardedTool", {
        percentage: 0,
        allowlist: ["VIP_TESTER_1"],
        blocklist: ["BLOCKED_ACTOR_2"]
      });

      // Allowlisted is enabled even at 0%
      expect(isFeatureEnabled("guardedTool", { subjectId: "VIP_TESTER_1" })).toBe(true);

      configureRollout("guardedTool", {
        percentage: 100,
        allowlist: ["VIP_TESTER_1"],
        blocklist: ["BLOCKED_ACTOR_2"]
      });

      // Blocklisted is disabled even at 100%
      expect(isFeatureEnabled("guardedTool", { subjectId: "BLOCKED_ACTOR_2" })).toBe(false);
    });

    it("enforces network restriction guardrail", () => {
      configureRollout("testnetOnlyFeature", {
        percentage: 100,
        allowedNetworks: ["testnet"]
      });

      expect(isFeatureEnabled("testnetOnlyFeature", { network: "testnet" })).toBe(true);
      expect(isFeatureEnabled("testnetOnlyFeature", { network: "mainnet" })).toBe(false);
    });
  });
});
