/**
 * Feature Flags & Rollout Guardrails with Emergency Disablement (#273)
 *
 * Implements deterministic canary rollouts, network-targeted guardrails,
 * circuit breakers, and global/per-flag emergency kill switches to safeguard
 * production against faulty deployments or unexpected protocol behavior.
 */

export type FeatureFlag =
  | "detailedFriendbotClassification"
  | "safeOwnershipTransfer"
  | "fieldLevelExportAuth"
  | "contributorDiagnostics"
  | "policySimulationPreview"
  | (string & {});

export interface RolloutContext {
  readonly subjectId?: string; // e.g. "G...", account ID, IP, or session token
  readonly network?: "testnet" | "mainnet";
  readonly actor?: { kind: string; id: string };
  readonly metadata?: Record<string, unknown>;
}

export interface RolloutConfig {
  percentage?: number; // 0 to 100
  allowedNetworks?: readonly ("testnet" | "mainnet")[];
  allowlist?: readonly string[]; // Subjects always granted access
  blocklist?: readonly string[]; // Subjects always blocked
  errorThresholdPercent?: number; // e.g. 20 (20%)
  minErrorSamples?: number; // e.g. 5
}

export interface EmergencyDisableRecord {
  active: boolean;
  reason?: string;
  triggeredBy?: string;
  triggeredAt?: string;
}

export interface CircuitBreakerState {
  successes: number;
  failures: number;
  tripped: boolean;
  trippedAt?: string;
}

const defaults: Record<string, boolean> = {
  detailedFriendbotClassification: true,
  safeOwnershipTransfer: true,
  fieldLevelExportAuth: true,
  contributorDiagnostics: true,
  policySimulationPreview: true
};

// In-memory runtime state for emergency disablement and guardrails
const emergencyDisables = new Map<string, EmergencyDisableRecord>();
let globalEmergencyKillSwitch: EmergencyDisableRecord | null = null;

const rolloutConfigs = new Map<string, RolloutConfig>();
const circuitBreakers = new Map<string, CircuitBreakerState>();

/** Computes a uniform, deterministic 0-99 bucket for canary rollouts. */
export function computeRolloutBucket(flag: string, subjectId: string): number {
  let hash = 2166136261;
  const input = `${flag}:${subjectId}`;
  for (let i = 0; i < input.length; i++) {
    hash = Math.imul(hash ^ input.charCodeAt(i), 16777619);
  }
  return Math.abs((hash >>> 0) % 100);
}

/** Configures rollout parameters for a feature flag. */
export function configureRollout(flag: FeatureFlag, config: RolloutConfig): void {
  rolloutConfigs.set(flag, { ...config });
}

/** Triggers emergency disablement (kill switch) for a specific flag. */
export function triggerEmergencyDisable(
  flag: FeatureFlag,
  options?: { reason?: string; actor?: string; now?: number | Date }
): void {
  const at = options?.now instanceof Date
    ? options.now.toISOString()
    : typeof options?.now === "number"
      ? new Date(options.now).toISOString()
      : new Date().toISOString();

  emergencyDisables.set(flag, {
    active: true,
    reason: options?.reason ?? "Manual emergency kill-switch invoked",
    triggeredBy: options?.actor ?? "system",
    triggeredAt: at
  });
}

/** Clears emergency disablement for a specific flag. */
export function clearEmergencyDisable(flag: FeatureFlag): void {
  emergencyDisables.delete(flag);
}

/** Triggers the global kill switch disabling ALL dynamic feature rollouts. */
export function triggerGlobalEmergencyKillSwitch(options?: { reason?: string; actor?: string }): void {
  globalEmergencyKillSwitch = {
    active: true,
    reason: options?.reason ?? "Global emergency kill-switch invoked",
    triggeredBy: options?.actor ?? "maintainer",
    triggeredAt: new Date().toISOString()
  };
}

/** Clears the global emergency kill switch. */
export function clearGlobalEmergencyKillSwitch(): void {
  globalEmergencyKillSwitch = null;
}

/** Records an operational success for a feature flag (circuit breaker tracking). */
export function recordFeatureSuccess(flag: FeatureFlag): void {
  let state = circuitBreakers.get(flag);
  if (!state) {
    state = { successes: 0, failures: 0, tripped: false };
    circuitBreakers.set(flag, state);
  }
  state.successes += 1;
}

/** Records an operational failure for a feature flag, tripping circuit breaker if threshold is breached. */
export function recordFeatureFailure(flag: FeatureFlag): void {
  let state = circuitBreakers.get(flag);
  if (!state) {
    state = { successes: 0, failures: 0, tripped: false };
    circuitBreakers.set(flag, state);
  }
  state.failures += 1;

  const config = rolloutConfigs.get(flag);
  const minSamples = config?.minErrorSamples ?? 5;
  const threshold = config?.errorThresholdPercent ?? 25; // 25% default threshold

  const total = state.successes + state.failures;
  if (total >= minSamples) {
    const errorRate = (state.failures / total) * 100;
    if (errorRate >= threshold) {
      state.tripped = true;
      state.trippedAt = new Date().toISOString();
    }
  }
}

/** Resets the circuit breaker state for a feature flag. */
export function resetCircuitBreaker(flag: FeatureFlag): void {
  circuitBreakers.delete(flag);
}

/** Checks whether a flag is currently disabled by an active emergency kill switch. */
export function isEmergencyDisabled(flag: FeatureFlag): boolean {
  if (globalEmergencyKillSwitch?.active) return true;
  if (process.env.UTIX_KILL_SWITCH === "all" || process.env.UTIX_KILL_SWITCH === "true") return true;

  const envFlagKill = process.env[`UTIX_KILL_SWITCH_${flag}`] ?? process.env[`UTIX_EMERGENCY_DISABLE_${flag}`];
  if (envFlagKill === "1" || envFlagKill?.toLowerCase() === "true") return true;

  return emergencyDisables.get(flag)?.active ?? false;
}

function configuredValue(flag: FeatureFlag): boolean | undefined {
  const raw = process.env[`UTIX_FLAG_${flag}`];
  if (raw === undefined) return undefined;
  return raw === "1" || raw.toLowerCase() === "true";
}

/**
 * Main evaluation entry point. Evaluates flag status against emergency kill switches,
 * circuit breakers, blocklists/allowlists, environment overrides, network restrictions,
 * and deterministic percentage canary bucketing.
 */
export function isFeatureEnabled(flag: FeatureFlag, context?: RolloutContext): boolean {
  // 1. Emergency Kill Switch Guardrail
  if (isEmergencyDisabled(flag)) {
    return false;
  }

  // 2. Circuit Breaker Guardrail
  const cb = circuitBreakers.get(flag);
  if (cb?.tripped) {
    return false;
  }

  const config = rolloutConfigs.get(flag);

  // 3. Subject Allowlist / Blocklist Guardrails
  if (context?.subjectId && config) {
    const subject = context.subjectId.trim();
    if (config.blocklist && config.blocklist.includes(subject)) {
      return false;
    }
    if (config.allowlist && config.allowlist.includes(subject)) {
      return true;
    }
  }

  // 4. Explicit Environment Override
  const envVal = configuredValue(flag);
  if (envVal !== undefined) {
    return envVal;
  }

  // 5. Network Targeting Guardrail
  if (context?.network && config?.allowedNetworks && config.allowedNetworks.length > 0) {
    if (!config.allowedNetworks.includes(context.network)) {
      return false;
    }
  }

  // 6. Percentage Canary Rollout Guardrail
  if (config && typeof config.percentage === "number") {
    if (config.percentage <= 0) return false;
    if (config.percentage >= 100) return true;

    if (context?.subjectId) {
      const bucket = computeRolloutBucket(flag, context.subjectId);
      return bucket < config.percentage;
    }
  }

  // 7. Base Default Fallback
  return defaults[flag] ?? false;
}

export function featureFlagDefaults(): Readonly<Record<string, boolean>> {
  return defaults;
}

/** Provides diagnostic status for operational monitoring. */
export function getRolloutStatus(flag: FeatureFlag): {
  flag: FeatureFlag;
  enabled: boolean;
  emergencyDisabled: boolean;
  circuitBreakerTripped: boolean;
  config: RolloutConfig | null;
  metrics: { successes: number; failures: number; total: number } | null;
} {
  const cb = circuitBreakers.get(flag);
  return {
    flag,
    enabled: isFeatureEnabled(flag),
    emergencyDisabled: isEmergencyDisabled(flag),
    circuitBreakerTripped: cb?.tripped ?? false,
    config: rolloutConfigs.get(flag) ?? null,
    metrics: cb ? { successes: cb.successes, failures: cb.failures, total: cb.successes + cb.failures } : null
  };
}

/** Test seam: clears all in-memory rollout configurations and kill-switches. */
export function resetRolloutEngine(): void {
  emergencyDisables.clear();
  globalEmergencyKillSwitch = null;
  rolloutConfigs.clear();
  circuitBreakers.clear();
}