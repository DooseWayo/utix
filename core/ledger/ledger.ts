/**
 * Tamper-evident, chronological ledger for privileged and financial events.
 *
 * The audit trail (`core/audit/`) answers *who did this, on what, and why?*
 * It is append-only by API, but its storage is a plain JSON array: an edited,
 * reordered or deleted event looks exactly like a real one. This ledger is the
 * evidence layer underneath it. Its rules:
 *
 * - **every entry is hash-chained**. `hash = sha256(canonical(entry \ hash))`
 *   and each entry carries the previous entry's hash as `prevHash`, starting
 *   from `LEDGER_GENESIS_HASH`. Editing, inserting, removing or reordering an
 *   entry breaks the chain at that point, and `verify()` names the sequence;
 * - **entries are chronological**. `seq` is contiguous from the anchor and
 *   `at` never decreases. A clock that steps backwards is clamped to the head's
 *   instant; an explicit `at` earlier than the head is refused;
 * - **an audit event is committed, not copied**. A privileged entry carries the
 *   audit event's id and a digest of its stored form, so `verifyAuditTrail()`
 *   detects an audit event edited after the fact without duplicating it;
 * - **appending fails closed**. If the stored chain does not parse, or its
 *   head no longer matches its own hash, nothing is appended on top of it:
 *   the operator runs `reseal()`, which quarantines the raw bytes and records
 *   the incident in the chain itself;
 * - **retention keeps the chain verifiable**. `prune()` drops the oldest
 *   entries and moves the `anchor` (seq and hash of the last dropped entry)
 *   forward, so the retained suffix still verifies from a known point;
 * - **exports are self-verifying**. An export carries its anchor and head and
 *   `verifyLedgerExport()` re-checks it offline, optionally against a
 *   checkpoint (`head()`) taken earlier and kept somewhere else.
 *
 * What a hash chain cannot do alone: someone with write access to storage can
 * rewrite the whole chain consistently, or cut its tail. Both are caught only
 * by comparing against a checkpoint held outside the browser — see
 * `docs/LEDGER.md`.
 *
 * The clock and the storage are injected, so a test can assert an exact chain.
 *
 * Module note: this file and `core/audit/audit.ts` import each other. Nothing
 * from the audit module is read at this module's top level, only inside
 * functions, so either can be loaded first.
 */

import { err, ok, type Result } from "@/core/result/result";
import {
  auditContext,
  SENSITIVE_ACTIONS,
  type AuditAction,
  type AuditActor,
  type AuditContext,
  type AuditEvent,
  type AuditOutcome,
  type AuditStorage,
  type AuditTrail
} from "@/core/audit/audit";
import { redact } from "@/core/telemetry/telemetry";
import { sha256Hex } from "@/core/ledger/sha256";

export const LEDGER_SCHEMA_VERSION = 1;

/** `prevHash` of the first entry ever written. */
export const LEDGER_GENESIS_HASH = "0".repeat(64);

export const LEDGER_STORAGE_KEY = "utix:ledger:v1:chain";
export const LEDGER_QUARANTINE_PREFIX = "utix:ledger:v1:quarantine:";

/** How many entries `prune()` keeps. Larger than the audit trail on purpose. */
export const LEDGER_DEFAULT_LIMIT = 2000;

/**
 * Financial events: value moved, or was asked to move, on a network. Declared
 * once so docs, emitters and `verify:ledger` cannot disagree.
 */
export const FINANCIAL_ACTIONS = [
  /** Friendbot funded a testnet account. */
  "faucet.funded"
] as const;

/** Events the ledger writes about itself. */
export const LEDGER_SYSTEM_ACTIONS = [
  /** A broken chain was quarantined and a new segment linked to its last good entry. */
  "ledger.resealed"
] as const;

export type FinancialAction = (typeof FINANCIAL_ACTIONS)[number];
export type LedgerSystemAction = (typeof LEDGER_SYSTEM_ACTIONS)[number];
export type LedgerAction = AuditAction | FinancialAction | LedgerSystemAction;

export type LedgerKind = "privileged" | "financial";

export type LedgerErrorCode =
  | "ledger_denied"
  | "invalid_ledger_field"
  | "ledger_out_of_order"
  | "ledger_broken"
  | "ledger_intact";

/** Why `verify()` failed. Each maps to a recovery step in `docs/LEDGER.md`. */
export type LedgerIntegrityCode =
  /** The stored bytes are not a ledger at all. */
  | "ledger_corrupt"
  /** An entry is missing a field or has the wrong shape. */
  | "ledger_malformed_entry"
  /** `seq` skips, repeats, or does not continue from the anchor. */
  | "ledger_sequence_gap"
  /** `prevHash` does not equal the previous entry's hash: a removal, insertion or reorder. */
  | "ledger_link_broken"
  /** The entry's content no longer hashes to its `hash`: an edit. */
  | "ledger_hash_mismatch"
  /** `at` goes backwards. */
  | "ledger_out_of_order"
  /** The chain does not reach a checkpoint taken earlier: truncation or rewrite. */
  | "ledger_head_mismatch";

export interface LedgerSubject {
  readonly kind: string;
  readonly id: string;
}

export interface LedgerEntry {
  readonly v: typeof LEDGER_SCHEMA_VERSION;
  /** 1-based, contiguous across prunes. */
  readonly seq: number;
  /** ISO-8601 instant, never earlier than the previous entry's. */
  readonly at: string;
  readonly kind: LedgerKind;
  readonly action: LedgerAction;
  readonly actorId: string;
  readonly subject: LedgerSubject;
  readonly outcome: AuditOutcome;
  /** Small scalar context, normalised and redacted like an audit context. */
  readonly data?: AuditContext;
  /** Id of the audit event this entry commits to, for privileged entries. */
  readonly ref?: string;
  /** `auditEventDigest()` of that audit event as stored. */
  readonly refDigest?: string;
  readonly prevHash: string;
  readonly hash: string;
}

/** A point in the chain. Keep one outside the browser to detect truncation. */
export interface LedgerCheckpoint {
  readonly seq: number;
  readonly hash: string;
  readonly at?: string;
}

export interface LedgerInput {
  kind: LedgerKind;
  action: LedgerAction;
  actorId: string;
  subject: LedgerSubject;
  outcome?: AuditOutcome;
  data?: Record<string, unknown>;
  ref?: string;
  refDigest?: string;
  at?: string;
}

export type LedgerVerification =
  | { readonly ok: true; readonly count: number; readonly anchor: LedgerCheckpoint; readonly head: LedgerCheckpoint }
  | {
      readonly ok: false;
      readonly code: LedgerIntegrityCode;
      /** First sequence number that failed, or `null` when the whole blob failed. */
      readonly seq: number | null;
      /** Entries before `seq` that still verify. */
      readonly verified: number;
      /** Last checkpoint that verified, for recovery. */
      readonly lastGood: LedgerCheckpoint;
    };

export interface LedgerExportOptions {
  format?: "ndjson" | "json";
  /** First sequence number to include. The export's anchor becomes `fromSeq - 1`. */
  fromSeq?: number;
}

export interface ResealReport {
  readonly code: LedgerIntegrityCode;
  readonly quarantineKey: string;
  readonly resumedFrom: LedgerCheckpoint;
  readonly droppedEntries: number;
  readonly entry: LedgerEntry;
}

export interface Ledger {
  /** Appends one entry. The only write besides `prune` and `reseal`. */
  append(input: LedgerInput): Result<LedgerEntry, LedgerErrorCode>;
  /** Recomputes every hash and link from the anchor to the head. */
  verify(options?: { expectedHead?: LedgerCheckpoint }): LedgerVerification;
  /** The current head, to keep as an external checkpoint. */
  head(): LedgerCheckpoint;
  /** Every retained entry, oldest first. */
  entries(): readonly LedgerEntry[];
  /** Maintainer-only export that `verifyLedgerExport` can check offline. */
  export(actor: AuditActor, options?: LedgerExportOptions): Result<string, LedgerErrorCode>;
  /** Drops the oldest entries beyond the limit and moves the anchor forward. */
  prune(): number;
  /**
   * Recovery for a chain that fails `verify()`: quarantines the raw bytes,
   * keeps the prefix that still verifies, and appends a `ledger.resealed`
   * entry that links to it. Maintainer-only; refused on an intact chain.
   */
  reseal(actor: AuditActor, reason: string): Result<ResealReport, LedgerErrorCode>;
  reset(): void;
}

export interface LedgerOptions {
  storage?: AuditStorage;
  limit?: number;
  now?: () => number;
}

interface StoredLedger {
  v: typeof LEDGER_SCHEMA_VERSION;
  anchor: LedgerCheckpoint;
  entries: LedgerEntry[];
}

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const REASON_PATTERN = /^[a-z0-9_.:-]{1,64}$/;
const GENESIS: LedgerCheckpoint = { seq: 0, hash: LEDGER_GENESIS_HASH };

/**
 * JSON with keys sorted at every depth and `undefined` dropped, so the same
 * value always hashes the same way whatever order its keys were written in.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) {
    return `[${value.map((entry) => (entry === undefined ? "null" : canonicalJson(entry))).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const parts = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${parts.join(",")}}`;
}

/** The hash an entry must carry: everything but `hash` itself. */
export function hashLedgerEntry(entry: Omit<LedgerEntry, "hash"> | LedgerEntry): string {
  const { hash: _ignored, ...body } = entry as LedgerEntry;
  void _ignored;
  return sha256Hex(canonicalJson(body));
}

/** Digest of an audit event in the form the trail stores it. */
export function auditEventDigest(event: AuditEvent): string {
  return sha256Hex(canonicalJson(redact(event)));
}

function allActions(): readonly string[] {
  return [...SENSITIVE_ACTIONS, ...FINANCIAL_ACTIONS, ...LEDGER_SYSTEM_ACTIONS];
}

function kindOf(action: string): LedgerKind {
  return (FINANCIAL_ACTIONS as readonly string[]).includes(action) ? "financial" : "privileged";
}

function isLabel(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= 128;
}

function isCheckpoint(value: unknown): value is LedgerCheckpoint {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<LedgerCheckpoint>;
  return Number.isInteger(item.seq) && (item.seq as number) >= 0 && typeof item.hash === "string" && HASH_PATTERN.test(item.hash);
}

function isEntryShape(value: unknown): value is LedgerEntry {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<LedgerEntry>;
  return (
    item.v === LEDGER_SCHEMA_VERSION &&
    Number.isInteger(item.seq) &&
    typeof item.at === "string" &&
    !Number.isNaN(Date.parse(item.at)) &&
    (item.kind === "privileged" || item.kind === "financial") &&
    typeof item.action === "string" &&
    allActions().includes(item.action) &&
    item.kind === kindOf(item.action) &&
    typeof item.actorId === "string" &&
    isLabel(item.subject?.kind) &&
    isLabel(item.subject?.id) &&
    (item.outcome === "allowed" || item.outcome === "denied") &&
    typeof item.prevHash === "string" &&
    HASH_PATTERN.test(item.prevHash) &&
    typeof item.hash === "string" &&
    HASH_PATTERN.test(item.hash)
  );
}

/**
 * Verifies a chain segment from `anchor`. Pure: used by the live ledger, by
 * `verifyLedgerExport`, and by tests.
 */
export function verifyLedgerChain(
  entries: readonly unknown[],
  anchor: LedgerCheckpoint = GENESIS,
  options: { expectedHead?: LedgerCheckpoint } = {}
): LedgerVerification {
  let previous: LedgerCheckpoint = { seq: anchor.seq, hash: anchor.hash, at: anchor.at };
  let verified = 0;

  const fail = (code: LedgerIntegrityCode, seq: number | null): LedgerVerification => ({
    ok: false,
    code,
    seq,
    verified,
    lastGood: previous
  });

  for (let index = 0; index < entries.length; index += 1) {
    const raw = entries[index];
    const expectedSeq = previous.seq + 1;
    if (!isEntryShape(raw)) return fail("ledger_malformed_entry", expectedSeq);
    if (raw.seq !== expectedSeq) return fail("ledger_sequence_gap", expectedSeq);
    if (raw.prevHash !== previous.hash) return fail("ledger_link_broken", raw.seq);
    if (hashLedgerEntry(raw) !== raw.hash) return fail("ledger_hash_mismatch", raw.seq);
    if (previous.at && raw.at < previous.at) return fail("ledger_out_of_order", raw.seq);
    previous = { seq: raw.seq, hash: raw.hash, at: raw.at };
    verified += 1;
  }

  const expected = options.expectedHead;
  if (expected) {
    // The checkpoint must be on this chain: either the head itself, or an
    // entry inside the retained segment with the same hash.
    const atHead = expected.seq === previous.seq && expected.hash === previous.hash;
    const inside = (entries as LedgerEntry[]).some(
      (entry) => entry.seq === expected.seq && entry.hash === expected.hash
    );
    const isAnchor = expected.seq === anchor.seq && expected.hash === anchor.hash;
    if (!atHead && !inside && !isAnchor) {
      return { ok: false, code: "ledger_head_mismatch", seq: expected.seq, verified, lastGood: previous };
    }
  }

  return { ok: true, count: verified, anchor, head: previous };
}

export interface LedgerExportHeader {
  readonly type: "ledger.header";
  readonly schemaVersion: "1.0";
  readonly exportedAt: string;
  readonly anchor: LedgerCheckpoint;
  readonly head: LedgerCheckpoint;
  readonly count: number;
}

/**
 * Re-verifies an export produced by `Ledger.export` — offline, with no access
 * to the ledger that produced it. Also checks that the header's head is the
 * last entry, so a trimmed export is not mistaken for a complete one.
 */
export function verifyLedgerExport(
  text: string,
  options: { expectedHead?: LedgerCheckpoint } = {}
): LedgerVerification {
  const corrupt: LedgerVerification = { ok: false, code: "ledger_corrupt", seq: null, verified: 0, lastGood: GENESIS };
  let header: LedgerExportHeader;
  let entries: unknown[];
  try {
    const trimmed = text.trim();
    // `json` is one document with an `entries` array; `ndjson` is a header
    // line followed by one entry per line.
    let whole: (LedgerExportHeader & { entries?: unknown[] }) | undefined;
    try {
      whole = JSON.parse(trimmed) as LedgerExportHeader & { entries?: unknown[] };
    } catch {
      whole = undefined;
    }
    if (whole && Array.isArray(whole.entries)) {
      const { entries: list, ...rest } = whole;
      header = rest;
      entries = list;
    } else {
      const lines = trimmed.split("\n").filter((line) => line.trim().length > 0);
      header = JSON.parse(lines[0]) as LedgerExportHeader;
      entries = lines.slice(1).map((line) => {
        const { type: _type, ...entry } = JSON.parse(line) as LedgerEntry & { type?: string };
        void _type;
        return entry;
      });
    }
  } catch {
    return corrupt;
  }
  if (header?.type !== "ledger.header" || !isCheckpoint(header.anchor) || !isCheckpoint(header.head) || !Array.isArray(entries)) {
    return corrupt;
  }

  const result = verifyLedgerChain(entries, header.anchor, options);
  if (!result.ok) return result;
  if (result.head.seq !== header.head.seq || result.head.hash !== header.head.hash || result.count !== header.count) {
    return { ok: false, code: "ledger_head_mismatch", seq: header.head.seq, verified: result.count, lastGood: result.head };
  }
  return result;
}

function memoryStorage(): AuditStorage {
  const values = new Map<string, string>();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => void values.set(key, value),
    removeItem: (key) => void values.delete(key)
  };
}

function browserStorage(): AuditStorage {
  try {
    if (typeof window !== "undefined" && window.localStorage) return window.localStorage;
  } catch {
    return memoryStorage();
  }
  return memoryStorage();
}

type ReadState = { ok: true; state: StoredLedger } | { ok: false };

export function createLedger(options: LedgerOptions = {}): Ledger {
  const limit = Math.max(1, Math.floor(options.limit ?? LEDGER_DEFAULT_LIMIT));
  const now = options.now ?? (() => Date.now());
  const storage = options.storage ?? browserStorage();

  /**
   * Unlike the audit trail, an unparseable blob is *not* read as empty: a
   * ledger that silently restarts from genesis would hide the tampering it
   * exists to detect.
   */
  function read(): ReadState {
    const raw = storage.getItem(LEDGER_STORAGE_KEY);
    if (raw === null) return { ok: true, state: { v: LEDGER_SCHEMA_VERSION, anchor: GENESIS, entries: [] } };
    try {
      const parsed = JSON.parse(raw) as Partial<StoredLedger>;
      if (parsed?.v !== LEDGER_SCHEMA_VERSION || !isCheckpoint(parsed.anchor) || !Array.isArray(parsed.entries)) {
        return { ok: false };
      }
      return { ok: true, state: parsed as StoredLedger };
    } catch {
      return { ok: false };
    }
  }

  function write(state: StoredLedger): void {
    storage.setItem(LEDGER_STORAGE_KEY, JSON.stringify(state));
  }

  function headOf(state: StoredLedger): LedgerCheckpoint {
    const last = state.entries[state.entries.length - 1];
    return last ? { seq: last.seq, hash: last.hash, at: last.at } : state.anchor;
  }

  function build(previous: LedgerCheckpoint, input: LedgerInput, at: string): LedgerEntry {
    const body: Omit<LedgerEntry, "hash"> = {
      v: LEDGER_SCHEMA_VERSION,
      seq: previous.seq + 1,
      at,
      kind: input.kind,
      action: input.action,
      actorId: input.actorId,
      subject: { kind: input.subject.kind, id: input.subject.id },
      outcome: input.outcome ?? "allowed",
      data: auditContext(input.data),
      ref: input.ref,
      refDigest: input.refDigest,
      prevHash: previous.hash
    };
    // Store exactly what was hashed: a JSON round trip drops `undefined` keys,
    // and canonicalJson drops them too, so the stored entry re-hashes equal.
    const stored = JSON.parse(JSON.stringify(redact(body))) as Omit<LedgerEntry, "hash">;
    return { ...stored, hash: hashLedgerEntry(stored) };
  }

  return {
    append(input: LedgerInput): Result<LedgerEntry, LedgerErrorCode> {
      if (typeof input.action !== "string" || !allActions().includes(input.action)) return err("invalid_ledger_field");
      if (input.kind !== kindOf(input.action)) return err("invalid_ledger_field");
      if (!isLabel(input.actorId) || !input.subject || !isLabel(input.subject.kind) || !isLabel(input.subject.id)) {
        return err("invalid_ledger_field");
      }
      if (input.refDigest !== undefined && !HASH_PATTERN.test(input.refDigest)) return err("invalid_ledger_field");
      if (input.at !== undefined && Number.isNaN(Date.parse(input.at))) return err("invalid_ledger_field");

      const current = read();
      if (!current.ok) return err("ledger_broken");
      const { state } = current;

      // Cheap head check on every append: refuse to extend a chain whose last
      // entry was edited. A full `verify()` is the operator's call.
      const last = state.entries[state.entries.length - 1];
      if (last && (!isEntryShape(last) || hashLedgerEntry(last) !== last.hash)) return err("ledger_broken");

      const previous = headOf(state);
      let at = input.at ?? new Date(now()).toISOString();
      if (previous.at && at < previous.at) {
        // A caller-supplied instant before the head is a misordered write; a
        // clock that stepped backwards is clamped so order still holds.
        if (input.at !== undefined) return err("ledger_out_of_order");
        at = previous.at;
      }

      const entry = build(previous, input, at);
      write({ ...state, entries: [...state.entries, entry] });
      return ok(entry);
    },

    verify(verifyOptions = {}): LedgerVerification {
      const current = read();
      if (!current.ok) return { ok: false, code: "ledger_corrupt", seq: null, verified: 0, lastGood: GENESIS };
      return verifyLedgerChain(current.state.entries, current.state.anchor, verifyOptions);
    },

    head(): LedgerCheckpoint {
      const current = read();
      return current.ok ? headOf(current.state) : GENESIS;
    },

    entries(): readonly LedgerEntry[] {
      const current = read();
      return current.ok ? current.state.entries : [];
    },

    export(actor: AuditActor, exportOptions: LedgerExportOptions = {}): Result<string, LedgerErrorCode> {
      // The ledger spans every principal and every maintainer action.
      if (actor.kind !== "maintainer" || !actor.id) return err("ledger_denied");
      const current = read();
      if (!current.ok) return err("ledger_broken");
      const { state } = current;
      const fromSeq = exportOptions.fromSeq;
      if (fromSeq !== undefined && (!Number.isInteger(fromSeq) || fromSeq < 1)) return err("invalid_ledger_field");

      let anchor = state.anchor;
      let entries = state.entries;
      if (fromSeq !== undefined && fromSeq > state.anchor.seq + 1) {
        const index = entries.findIndex((entry) => entry.seq === fromSeq);
        if (index < 0) return err("invalid_ledger_field");
        const before = entries[index - 1];
        anchor = { seq: before.seq, hash: before.hash, at: before.at };
        entries = entries.slice(index);
      }

      const last = entries[entries.length - 1];
      const header: LedgerExportHeader = {
        type: "ledger.header",
        schemaVersion: "1.0",
        exportedAt: new Date(now()).toISOString(),
        anchor,
        head: last ? { seq: last.seq, hash: last.hash, at: last.at } : anchor,
        count: entries.length
      };

      if (exportOptions.format === "json") return ok(JSON.stringify({ ...header, entries }, null, 2));
      return ok(
        [JSON.stringify(header), ...entries.map((entry) => JSON.stringify({ type: "ledger.entry", ...entry }))].join("\n")
      );
    },

    prune(): number {
      const current = read();
      if (!current.ok) return 0;
      const { state } = current;
      if (state.entries.length <= limit) return 0;
      const dropped = state.entries.length - limit;
      const lastDropped = state.entries[dropped - 1];
      write({
        v: LEDGER_SCHEMA_VERSION,
        anchor: { seq: lastDropped.seq, hash: lastDropped.hash, at: lastDropped.at },
        entries: state.entries.slice(dropped)
      });
      return dropped;
    },

    reseal(actor: AuditActor, reason: string): Result<ResealReport, LedgerErrorCode> {
      if (actor.kind !== "maintainer" || !actor.id) return err("ledger_denied");
      if (!REASON_PATTERN.test(reason)) return err("invalid_ledger_field");

      const verification = this.verify();
      if (verification.ok) return err("ledger_intact");

      const raw = storage.getItem(LEDGER_STORAGE_KEY) ?? "";
      const at = new Date(now()).toISOString();
      const quarantineKey = `${LEDGER_QUARANTINE_PREFIX}${at}`;
      // Keep the evidence. Nothing about the broken chain is discarded, only
      // moved aside where `verify()` no longer reads it.
      storage.setItem(quarantineKey, raw);

      const current = read();
      const anchor = current.ok ? current.state.anchor : GENESIS;
      const kept = current.ok ? (current.state.entries.slice(0, verification.verified) as LedgerEntry[]) : [];
      const total = current.ok ? current.state.entries.length : 0;
      const resumedFrom = verification.lastGood;

      const entry = build(
        resumedFrom,
        {
          kind: "privileged",
          action: "ledger.resealed",
          actorId: actor.id,
          subject: { kind: "ledger", id: quarantineKey },
          data: {
            code: verification.code,
            brokenAtSeq: verification.seq,
            droppedEntries: total - kept.length,
            reason
          }
        },
        resumedFrom.at && resumedFrom.at > at ? resumedFrom.at : at
      );

      write({ v: LEDGER_SCHEMA_VERSION, anchor, entries: [...kept, entry] });
      return ok({
        code: verification.code,
        quarantineKey,
        resumedFrom,
        droppedEntries: total - kept.length,
        entry
      });
    },

    reset(): void {
      storage.removeItem(LEDGER_STORAGE_KEY);
    }
  };
}

let singleton: Ledger | undefined;

/** The app-wide ledger, shared by the audit trail and financial emitters. */
export function getLedger(): Ledger {
  if (!singleton) singleton = createLedger();
  return singleton;
}

/** Test seam: a fresh, isolated ledger. */
export function createIsolatedLedger(options: LedgerOptions = {}): Ledger {
  return createLedger({ storage: memoryStorage(), ...options });
}

/**
 * Records a financial event on the app-wide ledger, or returns `undefined`
 * when it was rejected. Like `recordAudit`, it never throws through the
 * domain path that called it.
 */
export function recordFinancialEvent(
  input: Omit<LedgerInput, "kind"> & { action: FinancialAction }
): LedgerEntry | undefined {
  try {
    const appended = getLedger().append({ ...input, kind: "financial" });
    return appended.ok ? appended.value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The ledger entry for an audit event that was just stored. The ledger keeps
 * its own append instant: an audit caller may pass an `at` from the past (a
 * transition's own time), and the chain must not refuse it for that. The
 * event's instant is kept as `eventAt` and committed through the digest.
 */
export function ledgerInputForAudit(event: AuditEvent): LedgerInput {
  return {
    kind: "privileged",
    action: event.action,
    actorId: event.actorId,
    subject: { kind: event.target.kind, id: event.target.id },
    outcome: event.outcome,
    data: { eventAt: event.at, reason: event.reason ?? null },
    ref: event.id,
    refDigest: auditEventDigest(event)
  };
}

export interface AuditCrossCheck {
  /** Audit events whose stored form matches the digest the ledger committed. */
  readonly anchored: number;
  /** Audit events edited after they were committed. */
  readonly tampered: readonly string[];
  /** Audit events with no ledger entry: written before the ledger, or resealed away. */
  readonly unanchored: readonly string[];
  /** Ledger entries whose audit event is gone — expected after audit retention. */
  readonly missing: readonly string[];
}

/**
 * Compares the audit trail with the digests the ledger committed. A tampered
 * audit event is one whose stored form no longer matches; an event removed
 * from the trail by anything other than retention shows up in `missing`.
 */
export function verifyAuditTrail(trail: AuditTrail, ledger: Ledger): AuditCrossCheck {
  const committed = new Map<string, string>();
  for (const entry of ledger.entries()) {
    if (entry.ref && entry.refDigest) committed.set(entry.ref, entry.refDigest);
  }
  const tampered: string[] = [];
  const unanchored: string[] = [];
  const seen = new Set<string>();
  let anchored = 0;
  for (const event of trail.all()) {
    seen.add(event.id);
    const digest = committed.get(event.id);
    if (!digest) unanchored.push(event.id);
    else if (digest !== auditEventDigest(event)) tampered.push(event.id);
    else anchored += 1;
  }
  const missing = [...committed.keys()].filter((id) => !seen.has(id));
  return { anchored, tampered, unanchored, missing };
}
