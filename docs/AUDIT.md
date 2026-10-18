# Audit trail

## What this covers

Some actions in Utix matter more than others. Dead-lettering a job, retrying
one by hand, generating a repository-wide export, clearing someone's
notifications, releasing an in-flight idempotency claim, publishing a
reconciliation report: these are the actions someone will ask about later. The
question is always the same — **who did this, on what, and why?**

`core/audit/` is the trail that answers it. Telemetry does not: telemetry is
best-effort, sampled, and dropped under load, and it is shaped for dashboards
rather than for review.

## The rules

- **One structured event per sensitive action**, written at the domain
  boundary — not by the UI. A button that forgets to call the audit helper
  cannot produce a silent action, because the action itself audits.
- **Attribution is always present**: `action`, `actor` (kind and id), `scope`,
  `target`, `reason` when one applies, `at`, `correlationId`, and an `outcome`
  of `allowed` or `denied`.
- **Before/after are small and scalar.** Values must be primitives, keys are
  capped at 12, strings are truncated to 160 characters, and everything passes
  through `redact()` plus an embedded Stellar-secret scrub on the way in. A
  nested object is dropped rather than serialised. This is the rule that keeps
  a private payload out of a durable record: an audit event cannot hold one.
- **The trail is append-only.** There is no update and no per-event delete, only
  retention pruning of the oldest entries.
- **Reading it is authorized.** A `user` actor sees only its own `own`-scope
  events; a `maintainer` sees everything. Anything else is `audit_denied`.
- **Refusals are recorded too.** A denied maintainer-scope export or a refused
  transition is exactly the event a reviewer looks for.

## Sensitive actions

Declared once in `SENSITIVE_ACTIONS`, so the docs, the emitters and the tests
cannot disagree about coverage:

| Action                      | Emitted by                                   |
| --------------------------- | -------------------------------------------- |
| `record.state_changed`      | `core/lifecycle/lifecycle.ts` (`applyTransition`) |
| `record.transition_denied`  | `core/lifecycle/lifecycle.ts` (`applyTransition`) |
| `export.generated`          | `core/export/exporter.ts`                     |
| `notification.published`    | `core/notifications/store.ts` (`publish`)     |
| `notification.cleared`      | `core/notifications/store.ts` (`clear`)       |
| `reconciliation.reported`   | `core/reconciliation/job.ts`                  |
| `idempotency.claim_released`| `core/idempotency/idempotency.ts` (`abandon`) |
| `quota.override_granted`    | `core/quota/quota.ts` (`grantOverride`)       |
| `quota.override_revoked`    | `core/quota/quota.ts` (`revokeOverride`)      |
| `projection.replayed`       | `core/replay/replay.ts` (`replayProjection`)  |
| `projection.activated`      | `core/replay/replay.ts` (`promoteProjection`, `rollbackProjection`) |

### Which lifecycle moves are audited

Not every transition belongs in an audit trail — a job starting and succeeding
is routine operation, and it is already in telemetry as `worker.run`. The rule
in `core/audit/audit.ts` is:

- **Terminal or irreversible moves always audit**, whatever the actor:
  `dead_letter`, `exhaust`, `purge`, `archive`, `expire`. A job that
  dead-letters or exhausts its budget is what a maintainer reviews.
- **Reversible moves audit only when a human asked**: `retry` and `fail`. The
  worker's own backoff and a handler that threw stay in telemetry.
- **Refusals always audit**, with the error code.
- `retryJob` and `deadLetter` pass `audited: true` in the transition context,
  because those two are operator decisions even though the worker performs them.

## Reading the trail

```ts
import { getAuditTrail } from "@/core/audit";

const trail = getAuditTrail();

// A maintainer sees everything and can filter.
const page = trail.query({ kind: "maintainer", id: "ada" }, {
  action: "record.state_changed",
  targetKind: "worker_job",
  from: "2026-09-01T00:00:00.000Z",
  limit: 50
});
if (page.ok) {
  for (const event of page.value.events) {
    console.log(event.at, event.actorId, event.target.id, event.reason);
  }
}

// A user sees only its own own-scope events. Asking for anything wider is denied.
trail.query({ kind: "user", id: "account:G…" });
// → { ok: false, code: "audit_denied" }
```

Filters: `action`, `actorId`, `targetKind`, `targetId`, `outcome`, `from`
(inclusive), `to` (exclusive), `limit`. The page reports `total` and
`hasMore` so a UI can tell "that was everything" from "there is more".

## Export for a review

`trail.export(actor, { format, ...filter })` supports `ndjson` (default, one
event per line — pipe it into `jq`), `json` (with a `schemaVersion`) and `csv`
(one row per event, with the before/after objects serialised into their cells).
Export goes through the same authorization as `query`: a user can only export
what it could read.

## Recording an event

Domain code uses `recordAudit`, which never throws — a malformed context is
rejected rather than allowed to break a domain path:

```ts
import { recordAudit } from "@/core/audit";

recordAudit({
  action: "export.generated",
  actor: { kind: "user", id: "account:G…" },
  scope: "own",
  target: { kind: "export_envelope", id: envelope.id },
  after: { recordCount: 12, schemaVersion: "1.0" }
});
```

Rules an input must satisfy, or it is rejected as `invalid_audit_field`:

- `action` must be in `SENSITIVE_ACTIONS`.
- `target.kind` and `target.id` must be non-empty and short.
- `reason` must be a stable token (`^[a-z0-9_.:-]{1,64}$`) — a reason is a code
  an operator can group by, not a sentence a payload can hide in.
- `before`/`after` are normalised by `auditContext`.

## Storage and retention

`createAuditTrail({ storage, limit, now, newId })` takes all four. The clock and
id factory are injected so a test can assert an exact trail; the default storage
is `window.localStorage` when available, otherwise in-memory; `limit` defaults
to `AUDIT_DEFAULT_LIMIT` (500) and `prune()` drops the oldest events beyond it.
The trail is a review aid, not a data lake — if you need long retention, the
events are already structured for an export into a real store.

## Verification

`npm run verify:audit` (wired into `npm run check`) fails when:

- an action in `SENSITIVE_ACTIONS` has no emitter at a domain boundary, or a
  boundary records an action the list does not declare;
- an emitter forgets to import the audit module;
- the trail gains an update, patch or delete method;
- redaction is removed, or an embedded Stellar secret could survive;
- a nested value would be stored as an audit context, or the retention limit
  stops being injectable.

## Tamper evidence

The app-wide trail (`getAuditTrail()`) commits every recorded event to the
hash-chained ledger in `core/ledger/`: the ledger entry carries the event id
and a SHA-256 digest of the event as stored. `verifyAuditTrail(trail, ledger)`
reports events edited (`tampered`) or removed outside retention (`missing`)
after they were recorded. The `AuditEvent` shape and export formats are
unchanged. See [LEDGER.md](./LEDGER.md) for verification, export, failure
modes and recovery.

## What this is not

- It is not telemetry. No sampling, no dashboards, no alert thresholds.
- It is not a write-ahead log of every request. Only the seven actions above.
- It does not replace access control: `query` and `export` are authorized, but
  the trail is stored client-side, so a real deployment should export it
  server-side rather than trust the browser copy.
