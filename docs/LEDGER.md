# Tamper-evident ledger

## What this covers

The [audit trail](./AUDIT.md) records *who did what, on what, and why* for
privileged actions. It is append-only by API, but its storage is a JSON array:
an edited, removed or reordered event looks exactly like a real one.

`core/ledger/` is the evidence layer underneath it. Every privileged event (each
audit event) and every financial event is written to a **hash-chained,
chronological ledger**. Any change to a recorded entry — an edit, an insertion,
a removal, a reorder, a backdated timestamp — breaks the chain at that entry,
and `verify()` names the sequence number where it broke.

| Kind         | Actions                                   | Emitted by                                           |
| ------------ | ----------------------------------------- | ---------------------------------------------------- |
| `privileged` | every action in `SENSITIVE_ACTIONS`        | `core/audit/audit.ts` (`record`, app-wide trail only) |
| `financial`  | `faucet.funded`                            | `features/testnet-faucet/lib/friendbot.ts`            |
| `privileged` | `ledger.resealed` (the ledger itself)      | `core/ledger/ledger.ts` (`reseal`)                    |

## How an entry is chained

```text
entry[n].prevHash = entry[n-1].hash            (entry[1].prevHash = 64 × "0")
entry[n].hash     = sha256(canonicalJson(entry[n] without "hash"))
```

- `canonicalJson` sorts keys at every depth and drops `undefined`, so the hash
  does not depend on key order or on how the entry was serialised.
- `seq` is contiguous (1, 2, 3, …) and continues across prunes.
- `at` never decreases. The ledger stamps its own append instant; if the clock
  steps backwards it is clamped to the head's instant. A caller-supplied `at`
  earlier than the head is refused with `ledger_out_of_order`.
- `data` goes through the same normalisation as an audit context
  (`auditContext`): scalars only, ≤12 keys, ≤160 chars, secrets scrubbed.
- A privileged entry does not copy the audit event. It carries `ref` (the audit
  event id), `refDigest` (sha256 of the event *as stored*), and
  `data.eventAt` (the audit event's own instant, which may be in the past).

SHA-256 is computed by `core/ledger/sha256.ts`, a synchronous, dependency-free
implementation checked against the FIPS 180-4 vectors and `node:crypto`. It is
synchronous because an audit write is synchronous, and `crypto.subtle` is not.

## Using it

```ts
import { getLedger, recordFinancialEvent, verifyAuditTrail, verifyLedgerExport } from "@/core/ledger";
import { getAuditTrail } from "@/core/audit";

// Financial emitters — never throws, returns undefined if refused.
recordFinancialEvent({
  action: "faucet.funded",
  actorId: "friendbot",
  subject: { kind: "stellar_account", id: accountId },
  data: { network: "testnet", transactionHash }
});

// Full verification, from the anchor to the head.
const result = getLedger().verify();
// → { ok: true, count, anchor, head } | { ok: false, code, seq, verified, lastGood }

// Take a checkpoint and keep it OUTSIDE the browser (ticket, chat, repo).
const checkpoint = getLedger().head(); // { seq, hash, at }
// Later: detects truncation or a full rewrite since the checkpoint.
getLedger().verify({ expectedHead: checkpoint });

// Cross-check the audit trail against what the ledger committed.
verifyAuditTrail(getAuditTrail(), getLedger());
// → { anchored, tampered: [ids], unanchored: [ids], missing: [ids] }
```

## Export and offline verification

`ledger.export(actor, { format: "ndjson" | "json", fromSeq? })` is
**maintainer-only** (a user gets `ledger_denied`): the ledger spans every
principal. The export carries a header with the `anchor` it starts from, the
`head` it ends at and the entry `count`:

```text
{"type":"ledger.header","schemaVersion":"1.0","exportedAt":"…","anchor":{"seq":0,"hash":"000…"},"head":{"seq":2,"hash":"9f…"},"count":2}
{"type":"ledger.entry","v":1,"seq":1,"at":"…","kind":"financial","action":"faucet.funded",…,"prevHash":"000…","hash":"5c…"}
{"type":"ledger.entry","v":1,"seq":2,…,"prevHash":"5c…","hash":"9f…"}
```

`fromSeq` exports a suffix whose anchor is the entry before it, so a partial
export still verifies on its own.

Verify an export in TypeScript with `verifyLedgerExport(text, { expectedHead })`,
or from a shell with nothing but Node — the script re-implements the check with
`node:crypto`, independently of the code that wrote the export:

```sh
npm run verify:ledger -- ./ledger-2026-10-18.ndjson
npm run verify:ledger -- ./ledger-2026-10-18.ndjson --expect-head 42:9f…
```

Without arguments, `npm run verify:ledger` (wired into `npm run check`) runs the
static contract checks: every financial action has an emitter, the app-wide audit
trail still commits to the ledger, there is no update/patch/delete, a broken
chain fails closed, entries stay hash-linked with SHA-256.

## Failure modes

| `verify()` code          | What it means                                                         | Likely cause                                   |
| ------------------------ | --------------------------------------------------------------------- | ---------------------------------------------- |
| `ledger_corrupt`         | The stored bytes are not a ledger.                                    | Hand edit, partial write, another app's key    |
| `ledger_malformed_entry` | An entry is missing a field or has a kind that does not fit its action. | Hand edit, schema drift                        |
| `ledger_sequence_gap`    | `seq` skips, repeats, or doesn't continue from the anchor.            | Entry removed or reordered                     |
| `ledger_link_broken`     | `prevHash` ≠ previous hash.                                           | Entry removed/inserted with renumbering, edited entry with recomputed hash, forged anchor |
| `ledger_hash_mismatch`   | The entry no longer hashes to its `hash`.                             | Entry edited in place                          |
| `ledger_out_of_order`    | `at` goes backwards.                                                  | Backdated entry                                |
| `ledger_head_mismatch`   | The chain does not reach a checkpoint taken earlier (or an export does not reach its own header). | Tail truncated, whole chain rewritten, export trimmed |

`append()` errors: `invalid_ledger_field` (unknown action, kind/action mismatch,
empty actor or subject, bad digest), `ledger_out_of_order`, and `ledger_broken`.

## Operational edge cases

- **Fail closed.** If the stored blob does not parse, or the head entry no
  longer matches its own hash, `append()` returns `ledger_broken` and writes
  nothing. Unlike the audit trail, an unreadable ledger is never treated as
  empty — silently restarting from genesis would hide the tampering.
- **The audit write never fails because of the ledger.** If the ledger refuses
  or throws (broken chain, storage quota), the audit event is still recorded;
  `verifyAuditTrail` then reports it as `unanchored`.
- **Head check vs full check.** `append()` only re-hashes the head (O(1)); an
  edit deeper in the chain is found by `verify()`, which re-hashes everything
  (O(n), ≤ `LEDGER_DEFAULT_LIMIT` = 2000 entries by default). Run `verify()`
  before an export, during an incident, and on a schedule if you persist the
  ledger server-side.
- **Retention.** `prune()` drops the oldest entries beyond the limit and moves
  the `anchor` to the last dropped entry. The retained suffix still verifies,
  and a checkpoint taken before the prune still verifies if it is at or after
  the new anchor. Audit-trail retention (500 events) is independent and
  shorter, so after an audit prune `verifyAuditTrail` lists the dropped ids in
  `missing` — expected, and distinguishable from tampering by comparing with
  the audit prune count.
- **Clock skew.** A clock that steps backwards is clamped (two entries share an
  instant); order is by `seq`, not by `at`.
- **Multiple tabs.** Two tabs appending at the same instant can each read the
  same head and write, the later write winning. The surviving chain still
  verifies; the losing tab's entry is gone and shows up in `verifyAuditTrail`
  as `unanchored`. If that matters, persist server-side behind a single writer.
- **What a hash chain alone cannot prove.** Anyone who can write to storage can
  rebuild the *entire* chain consistently, or cut its tail. Both are detected
  only against a checkpoint (`head()`) or an earlier export held somewhere the
  attacker cannot write. Take one per release, per incident, and per export.

## Recovery and rollback

### A chain fails `verify()`

1. **Do not reset.** Export what you can (`export` fails closed on a broken
   chain, so copy the raw `utix:ledger:v1:chain` value from storage instead)
   and note the `code`, `seq` and `lastGood` from `verify()`.
2. Compare `lastGood` with your most recent external checkpoint. If the
   checkpoint is *after* `lastGood`, entries between them were lost; recover
   them from the last export that verifies against that checkpoint.
3. Run `getLedger().reseal({ kind: "maintainer", id }, "incident:<id>")`. It:
   - stores the raw bytes unchanged under `utix:ledger:v1:quarantine:<instant>`;
   - keeps the prefix that still verifies;
   - appends a `ledger.resealed` entry linked to `lastGood`, recording the
     code, the broken sequence, how many entries were set aside and why.
   The chain verifies again, and the incident is part of it.
4. Take a new checkpoint and record it with the incident.

`reseal` is refused on an intact chain (`ledger_intact`) and for anyone but a
maintainer (`ledger_denied`); the reason must be a stable token.

### The audit trail disagrees with the ledger

`verifyAuditTrail` returning `tampered` ids means those audit events changed
after they were recorded. The ledger entry (actor, subject, outcome, reason,
`eventAt`) is the trustworthy version; treat the audit event as the suspect
one. `unanchored` ids were recorded while the ledger was refusing writes, or
before this feature shipped.

### Rolling the feature back

The ledger is additive: no existing schema, storage key or public API changed.

- `AuditEvent` and every audit export format are unchanged. `AuditOptions` gains
  an optional `ledger`; existing `createAuditTrail` / `createIsolatedAuditTrail`
  callers are unaffected.
- `fundTestnetAccount` returns the same `FaucetResult`.
- Rolling back means reverting the commit. The `utix:ledger:v1:*` keys left in
  storage are inert; delete them or leave them. Rolling forward again resumes
  from that chain if it still verifies, otherwise `append()` reports
  `ledger_broken` and the recovery steps above apply.

### Migrating the schema

Entries carry `v: 1` and the storage key is versioned (`utix:ledger:v1:`). A
future `v2` must not rewrite v1 entries: write a new key whose first entry's
`prevHash` is the final v1 head, so the two chains verify end to end, and keep
the v1 key read-only until it ages out.
