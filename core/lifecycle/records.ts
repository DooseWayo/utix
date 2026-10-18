/**
 * The core record kinds and their lifecycle tables.
 *
 * This is the only file that says what "queued", "unread" or "generated" mean.
 * The worker framework, the notification store and any future record type
 * import their machine from here, so a UI badge, an API response and a test
 * all read the same state model instead of re-deriving it.
 */

import {
  applyTransition,
  createLifecycle,
  type LifecycleErrorCode,
  type LifecycleMachine,
  type TransitionContext
} from "@/core/lifecycle/lifecycle";
import { err, ok, type Result } from "@/core/result/result";

/**
 * Delayed background work. `queued` is initial; `succeeded` and `dead_lettered`
 * are terminal because a settled job must never run again — retries come from
 * `retrying`, not from a finished record.
 */
export const workerJobMachine = createLifecycle({
  name: "worker_job",
  initial: "queued",
  states: ["queued", "running", "retrying", "succeeded", "dead_lettered"],
  terminal: ["succeeded", "dead_lettered"],
  transitions: [
    { from: "queued", event: "start", to: "running" },
    { from: "queued", event: "fail", to: "retrying" },
    { from: "queued", event: "dead_letter", to: "dead_lettered" },
    { from: "running", event: "succeed", to: "succeeded" },
    { from: "running", event: "fail", to: "retrying" },
    { from: "running", event: "exhaust", to: "dead_lettered" },
    { from: "running", event: "dead_letter", to: "dead_lettered" },
    { from: "retrying", event: "start", to: "running" },
    { from: "retrying", event: "fail", to: "retrying" },
    { from: "retrying", event: "exhaust", to: "dead_lettered" },
    { from: "retrying", event: "retry", to: "queued" },
    { from: "retrying", event: "dead_letter", to: "dead_lettered" }
  ]
});

/**
 * A stored notification. Purging is terminal and unrecoverable by design, and
 * it is legal from any live state because "clear all" is a user action that
 * must never be blocked by a status the user cannot see.
 */
export const notificationMachine = createLifecycle({
  name: "notification",
  initial: "unread",
  states: ["unread", "read", "archived", "purged"],
  terminal: ["purged"],
  transitions: [
    { from: "unread", event: "read", to: "read" },
    { from: "unread", event: "archive", to: "archived" },
    { from: "unread", event: "purge", to: "purged" },
    { from: "read", event: "archive", to: "archived" },
    { from: "read", event: "purge", to: "purged" },
    { from: "archived", event: "purge", to: "purged" }
  ]
});

/** A generated export artifact. Expiry and purge are the only legal moves. */
export const exportEnvelopeMachine = createLifecycle({
  name: "export_envelope",
  initial: "generated",
  states: ["generated", "expired", "purged"],
  terminal: ["purged"],
  transitions: [
    { from: "generated", event: "expire", to: "expired" },
    { from: "generated", event: "purge", to: "purged" },
    { from: "expired", event: "purge", to: "purged" }
  ]
});

/**
 * One measured operation (a Horizon request, an export, a job). `succeeded` and
 * `failed` are terminal for a single attempt; a retry starts a *new* record
 * rather than reopening a settled one.
 */
export const operationMachine = createLifecycle({
  name: "operation",
  initial: "started",
  states: ["started", "succeeded", "failed"],
  terminal: ["succeeded", "failed"],
  transitions: [
    { from: "started", event: "succeed", to: "succeeded" },
    { from: "started", event: "fail", to: "failed" }
  ]
});

/** Safe ownership transfer. `pending` is initial; `accepted`, `cancelled`, `rejected`, `expired` are terminal. */
export const ownershipTransferMachine = createLifecycle({
  name: "ownership_transfer",
  initial: "pending",
  states: ["pending", "accepted", "cancelled", "rejected", "expired"],
  terminal: ["accepted", "cancelled", "rejected", "expired"],
  transitions: [
    { from: "pending", event: "accept", to: "accepted" },
    { from: "pending", event: "cancel", to: "cancelled" },
    { from: "pending", event: "reject", to: "rejected" },
    { from: "pending", event: "expire", to: "expired" }
  ]
});

/** Human labels for badges and API `label` fields. */
export const LIFECYCLE_LABELS: Record<string, Record<string, string>> = {
  worker_job: {
    queued: "Queued",
    running: "Running",
    retrying: "Retrying",
    succeeded: "Succeeded",
    dead_lettered: "Dead-lettered"
  },
  notification: {
    unread: "Unread",
    read: "Read",
    archived: "Archived",
    purged: "Purged"
  },
  export_envelope: {
    generated: "Generated",
    expired: "Expired",
    purged: "Purged"
  },
  operation: {
    started: "Started",
    succeeded: "Succeeded",
    failed: "Failed"
  },
  ownership_transfer: {
    pending: "Pending Acceptance",
    accepted: "Accepted",
    cancelled: "Cancelled",
    rejected: "Rejected",
    expired: "Expired"
  }
};

export type CoreRecordKind = "worker_job" | "notification" | "export_envelope" | "operation" | "ownership_transfer";

/** Every core record machine, keyed by record kind. */
export const RECORD_MACHINES: Record<CoreRecordKind, LifecycleMachine> = {
  worker_job: workerJobMachine,
  notification: notificationMachine,
  export_envelope: exportEnvelopeMachine,
  operation: operationMachine,
  ownership_transfer: ownershipTransferMachine
};

export function recordMachine(kind: string): Result<LifecycleMachine, LifecycleErrorCode> {
  const machine = RECORD_MACHINES[kind as CoreRecordKind];
  return machine ? ok(machine) : err("unknown_record_kind");
}

export function labelsFor(kind: string): Record<string, string> {
  return LIFECYCLE_LABELS[kind] ?? {};
}

export interface StateView {
  readonly kind: string;
  readonly state: string;
  readonly label: string;
  readonly tone: "success" | "info" | "warning" | "danger" | "muted";
  readonly terminal: boolean;
  readonly allowedEvents: readonly string[];
}

/**
 * The one function a UI component and an API response both call. Neither is
 * allowed to map a state to a colour or a label on its own.
 */
export function stateView(kind: string, state: string): StateView {
  const machine = RECORD_MACHINES[kind as CoreRecordKind];
  if (!machine) {
    return {
      kind,
      state: "unknown",
      label: "Unknown",
      tone: "muted",
      terminal: false,
      allowedEvents: []
    };
  }
  return machine.view(state, labelsFor(kind));
}

/** Applies a transition through the machine registered for `kind`. */
export function transitionRecord(
  kind: string,
  id: string,
  state: string,
  event: string,
  context: TransitionContext = {}
): Result<{ state: string; at: string }, LifecycleErrorCode> {
  const resolved = recordMachine(kind);
  if (!resolved.ok) return resolved;
  const outcome = applyTransition(
    resolved.value,
    { id, state },
    event,
    context
  );
  return outcome.ok ? ok({ state: outcome.value.to, at: outcome.value.transition.at }) : outcome;
}
