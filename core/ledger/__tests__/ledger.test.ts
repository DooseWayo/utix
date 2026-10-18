import { beforeEach, describe, expect, it } from "vitest";
import { createIsolatedAuditTrail, getAuditTrail, recordAudit, type AuditInput } from "@/core/audit/audit";
import {
  canonicalJson,
  createIsolatedLedger,
  createLedger,
  getLedger,
  hashLedgerEntry,
  LEDGER_GENESIS_HASH,
  LEDGER_QUARANTINE_PREFIX,
  LEDGER_STORAGE_KEY,
  recordFinancialEvent,
  verifyAuditTrail,
  verifyLedgerChain,
  verifyLedgerExport,
  type Ledger,
  type LedgerEntry,
  type LedgerInput
} from "@/core/ledger/ledger";
import type { AuditStorage } from "@/core/audit/audit";

const MAINTAINER = { kind: "maintainer", id: "ada" } as const;
const USER = { kind: "user", id: "account:GABC" } as const;
const START = Date.parse("2026-10-01T00:00:00.000Z");

function memory(): AuditStorage & { raw: Map<string, string> } {
  const raw = new Map<string, string>();
  return {
    raw,
    getItem: (key) => raw.get(key) ?? null,
    setItem: (key, value) => void raw.set(key, value),
    removeItem: (key) => void raw.delete(key)
  };
}

/** A ledger with a clock that ticks one second per call. */
function ledgerWith(storage = memory(), limit?: number) {
  let tick = 0;
  const ledger = createLedger({ storage, limit, now: () => START + 1000 * tick++ });
  return { ledger, storage };
}

function privileged(overrides: Partial<LedgerInput> = {}): LedgerInput {
  return {
    kind: "privileged",
    action: "quota.override_granted",
    actorId: "ada",
    subject: { kind: "quota", id: "global" },
    data: { limit: 10 },
    ...overrides
  };
}

function financial(overrides: Partial<LedgerInput> = {}): LedgerInput {
  return {
    kind: "financial",
    action: "faucet.funded",
    actorId: "friendbot",
    subject: { kind: "stellar_account", id: "GDESTINATION" },
    data: { network: "testnet" },
    ...overrides
  };
}

function seed(ledger: Ledger, count: number): LedgerEntry[] {
  const out: LedgerEntry[] = [];
  for (let i = 0; i < count; i += 1) {
    const appended = ledger.append(i % 2 === 0 ? privileged({ subject: { kind: "quota", id: `q-${i}` } }) : financial());
    if (!appended.ok) throw new Error(appended.code);
    out.push(appended.value);
  }
  return out;
}

/** Rewrites the stored chain the way an attacker with storage access would. */
function tamper(storage: ReturnType<typeof memory>, mutate: (state: { anchor: unknown; entries: Record<string, unknown>[] }) => void) {
  const state = JSON.parse(storage.raw.get(LEDGER_STORAGE_KEY)!);
  mutate(state);
  storage.raw.set(LEDGER_STORAGE_KEY, JSON.stringify(state));
}

describe("ledger chain", () => {
  it("links every entry to the previous hash, starting from genesis", () => {
    const { ledger } = ledgerWith();
    const [first, second, third] = seed(ledger, 3);
    expect(first.seq).toBe(1);
    expect(first.prevHash).toBe(LEDGER_GENESIS_HASH);
    expect(second.prevHash).toBe(first.hash);
    expect(third.prevHash).toBe(second.hash);
    expect(hashLedgerEntry(third)).toBe(third.hash);
    expect(ledger.head()).toEqual({ seq: 3, hash: third.hash, at: third.at });
    expect(ledger.verify()).toMatchObject({ ok: true, count: 3 });
  });

  it("classifies financial and privileged entries and rejects a mismatch", () => {
    const { ledger } = ledgerWith();
    expect(ledger.append(financial()).ok).toBe(true);
    expect(ledger.append(financial({ kind: "privileged" }))).toEqual({ ok: false, code: "invalid_ledger_field" });
    expect(ledger.append(privileged({ kind: "financial" }))).toEqual({ ok: false, code: "invalid_ledger_field" });
    expect(ledger.append(privileged({ action: "nope" as LedgerInput["action"] }))).toEqual({
      ok: false,
      code: "invalid_ledger_field"
    });
    expect(ledger.append(privileged({ subject: { kind: "", id: "x" } }))).toEqual({ ok: false, code: "invalid_ledger_field" });
  });

  it("is chronological: a backwards clock is clamped, an explicit earlier instant is refused", () => {
    const storage = memory();
    const times = [START + 5000, START + 1000];
    const ledger = createLedger({ storage, now: () => times.shift() ?? START });
    const first = ledger.append(privileged());
    const second = ledger.append(privileged());
    expect(first.ok && second.ok).toBe(true);
    if (first.ok && second.ok) expect(second.value.at).toBe(first.value.at);
    expect(ledger.append(privileged({ at: "2020-01-01T00:00:00.000Z" }))).toEqual({
      ok: false,
      code: "ledger_out_of_order"
    });
    expect(ledger.verify().ok).toBe(true);
  });

  it("keeps scalar data only, redacted, so a payload or a secret cannot enter the chain", () => {
    const { ledger } = ledgerWith();
    const secret = `S${"A".repeat(55)}`;
    const appended = ledger.append(
      privileged({ data: { note: `seed ${secret}`, nested: { a: 1 }, apiKey: "x", amount: 5 } })
    );
    expect(appended.ok).toBe(true);
    if (!appended.ok) return;
    expect(appended.value.data).toEqual({ note: "seed [REDACTED]", apiKey: "[REDACTED]", amount: 5 });
    expect(JSON.stringify(ledger.entries())).not.toContain(secret);
  });

  it("hashes canonically, whatever the key order", () => {
    expect(canonicalJson({ b: 1, a: { d: [1, undefined], c: null }, e: undefined })).toBe(
      '{"a":{"c":null,"d":[1,null]},"b":1}'
    );
  });
});

describe("tamper detection", () => {
  let storage: ReturnType<typeof memory>;
  let ledger: Ledger;
  let entries: LedgerEntry[];

  beforeEach(() => {
    ({ ledger, storage } = ledgerWith());
    entries = seed(ledger, 5);
  });

  it("detects an edited field", () => {
    tamper(storage, (state) => {
      state.entries[2].actorId = "mallory";
    });
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_hash_mismatch", seq: 3, verified: 2 });
  });

  it("detects edited data even when the attacker recomputes that entry's hash", () => {
    tamper(storage, (state) => {
      const entry = state.entries[1] as unknown as LedgerEntry & { data: Record<string, unknown> };
      entry.data = { network: "public" };
      (entry as { hash: string }).hash = hashLedgerEntry(entry);
    });
    // The next entry still points at the old hash.
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_link_broken", seq: 3 });
  });

  it("detects a deleted entry", () => {
    tamper(storage, (state) => {
      state.entries.splice(1, 1);
    });
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_sequence_gap", seq: 2 });
  });

  it("detects a deleted entry with renumbered sequence", () => {
    tamper(storage, (state) => {
      state.entries.splice(1, 1);
      state.entries.forEach((entry, index) => (entry.seq = index + 1));
    });
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_link_broken" });
  });

  it("detects reordered entries", () => {
    tamper(storage, (state) => {
      [state.entries[1], state.entries[2]] = [state.entries[2], state.entries[1]];
    });
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_sequence_gap", seq: 2 });
  });

  it("detects an inserted, forged entry", () => {
    tamper(storage, (state) => {
      const forged = { ...entries[1], actorId: "mallory", seq: 3, prevHash: entries[1].hash } as Partial<LedgerEntry>;
      delete forged.hash;
      state.entries.splice(2, 0, { ...forged, hash: hashLedgerEntry(forged as LedgerEntry) });
    });
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_sequence_gap", seq: 4 });
  });

  it("detects a backdated entry even with consistent hashes", () => {
    const { ledger: fresh, storage: freshStorage } = ledgerWith();
    seed(fresh, 3);
    tamper(freshStorage, (state) => {
      let prevHash = LEDGER_GENESIS_HASH;
      state.entries.forEach((raw, index) => {
        const entry = raw as unknown as Record<string, unknown>;
        if (index === 2) entry.at = "2020-01-01T00:00:00.000Z";
        entry.prevHash = prevHash;
        delete entry.hash;
        entry.hash = hashLedgerEntry(entry as unknown as LedgerEntry);
        prevHash = entry.hash as string;
      });
    });
    expect(fresh.verify()).toMatchObject({ ok: false, code: "ledger_out_of_order", seq: 3 });
  });

  it("detects a malformed entry and an unparseable blob", () => {
    tamper(storage, (state) => {
      state.entries[0].kind = "financial";
    });
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_malformed_entry", seq: 1 });

    storage.raw.set(LEDGER_STORAGE_KEY, "{not json");
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_corrupt", seq: null });
  });

  it("detects truncation and a full rewrite only against an external checkpoint", () => {
    const checkpoint = ledger.head();
    tamper(storage, (state) => {
      state.entries.splice(3);
    });
    // The remaining prefix is internally consistent...
    expect(ledger.verify().ok).toBe(true);
    // ...but it no longer reaches the checkpoint taken before.
    expect(ledger.verify({ expectedHead: checkpoint })).toMatchObject({ ok: false, code: "ledger_head_mismatch" });
  });

  it("accepts an older checkpoint that is still on the chain", () => {
    const older = { seq: entries[1].seq, hash: entries[1].hash };
    expect(ledger.verify({ expectedHead: older }).ok).toBe(true);
    expect(ledger.verify({ expectedHead: { seq: 2, hash: "f".repeat(64) } })).toMatchObject({
      ok: false,
      code: "ledger_head_mismatch"
    });
  });

  it("fails closed: nothing is appended on top of a corrupt blob or an edited head", () => {
    tamper(storage, (state) => {
      state.entries[4].actorId = "mallory";
    });
    expect(ledger.append(privileged())).toEqual({ ok: false, code: "ledger_broken" });

    storage.raw.set(LEDGER_STORAGE_KEY, "[]");
    expect(ledger.append(privileged())).toEqual({ ok: false, code: "ledger_broken" });
    expect(ledger.export(MAINTAINER)).toEqual({ ok: false, code: "ledger_broken" });
  });
});

describe("export", () => {
  it("is maintainer-only", () => {
    const { ledger } = ledgerWith();
    seed(ledger, 2);
    expect(ledger.export(USER)).toEqual({ ok: false, code: "ledger_denied" });
    expect(ledger.export({ kind: "system" })).toEqual({ ok: false, code: "ledger_denied" });
  });

  it.each(["ndjson", "json"] as const)("round-trips through offline verification as %s", (format) => {
    const { ledger } = ledgerWith();
    seed(ledger, 4);
    const exported = ledger.export(MAINTAINER, { format });
    expect(exported.ok).toBe(true);
    if (!exported.ok) return;
    expect(verifyLedgerExport(exported.value)).toMatchObject({ ok: true, count: 4, head: { seq: 4 } });
    expect(verifyLedgerExport(exported.value, { expectedHead: ledger.head() }).ok).toBe(true);
  });

  it("exports an empty ledger that still verifies", () => {
    const { ledger } = ledgerWith();
    const exported = ledger.export(MAINTAINER);
    expect(exported.ok && verifyLedgerExport(exported.value).ok).toBe(true);
  });

  it("exports a suffix anchored to the entry before it", () => {
    const { ledger } = ledgerWith();
    const entries = seed(ledger, 5);
    const exported = ledger.export(MAINTAINER, { fromSeq: 3 });
    expect(exported.ok).toBe(true);
    if (!exported.ok) return;
    const header = JSON.parse(exported.value.split("\n")[0]);
    expect(header.anchor).toMatchObject({ seq: 2, hash: entries[1].hash });
    expect(verifyLedgerExport(exported.value)).toMatchObject({ ok: true, count: 3 });
    expect(ledger.export(MAINTAINER, { fromSeq: 0 })).toEqual({ ok: false, code: "invalid_ledger_field" });
    expect(ledger.export(MAINTAINER, { fromSeq: 99 })).toEqual({ ok: false, code: "invalid_ledger_field" });
  });

  it("detects an edited, trimmed or garbled export", () => {
    const { ledger } = ledgerWith();
    seed(ledger, 4);
    const exported = ledger.export(MAINTAINER);
    if (!exported.ok) throw new Error(exported.code);
    const lines = exported.value.split("\n");

    const edited = [...lines];
    edited[2] = edited[2].replace('"actorId":"friendbot"', '"actorId":"mallory"');
    expect(edited[2]).toContain("mallory");
    expect(verifyLedgerExport(edited.join("\n"))).toMatchObject({ ok: false, code: "ledger_hash_mismatch", seq: 2 });

    // Dropping the tail leaves a consistent prefix the header disowns.
    expect(verifyLedgerExport(lines.slice(0, -1).join("\n"))).toMatchObject({ ok: false, code: "ledger_head_mismatch" });

    expect(verifyLedgerExport("not a ledger")).toMatchObject({ ok: false, code: "ledger_corrupt" });
    expect(verifyLedgerExport('{"type":"something.else"}')).toMatchObject({ ok: false, code: "ledger_corrupt" });
  });
});

describe("retention", () => {
  it("prunes the oldest entries and keeps the suffix verifiable from a moved anchor", () => {
    const { ledger } = ledgerWith(memory(), 3);
    const entries = seed(ledger, 5);
    const checkpoint = ledger.head();
    expect(ledger.prune()).toBe(2);
    expect(ledger.entries().map((entry) => entry.seq)).toEqual([3, 4, 5]);
    expect(ledger.verify({ expectedHead: checkpoint })).toMatchObject({
      ok: true,
      count: 3,
      anchor: { seq: 2, hash: entries[1].hash }
    });
    // New entries continue the numbering.
    const next = ledger.append(privileged());
    expect(next.ok && next.value.seq).toBe(6);
    expect(ledger.prune()).toBe(1);
    expect(ledger.verify().ok).toBe(true);
  });

  it("detects a forged anchor after a prune", () => {
    const storage = memory();
    const { ledger } = ledgerWith(storage, 2);
    seed(ledger, 4);
    ledger.prune();
    tamper(storage, (state) => {
      state.anchor = { seq: 2, hash: "a".repeat(64) };
    });
    expect(ledger.verify()).toMatchObject({ ok: false, code: "ledger_link_broken", seq: 3 });
  });
});

describe("recovery", () => {
  it("refuses to reseal an intact chain or for a non-maintainer", () => {
    const { ledger } = ledgerWith();
    seed(ledger, 2);
    expect(ledger.reseal(MAINTAINER, "operator_check")).toEqual({ ok: false, code: "ledger_intact" });
    expect(ledger.reseal(USER, "operator_check")).toEqual({ ok: false, code: "ledger_denied" });
    expect(ledger.reseal(MAINTAINER, "Free text reason")).toEqual({ ok: false, code: "invalid_ledger_field" });
  });

  it("quarantines a broken chain, keeps the verified prefix and records the incident", () => {
    const { ledger, storage } = ledgerWith();
    const entries = seed(ledger, 5);
    tamper(storage, (state) => {
      state.entries[3].actorId = "mallory";
    });
    const brokenRaw = storage.raw.get(LEDGER_STORAGE_KEY);

    const resealed = ledger.reseal(MAINTAINER, "incident:42");
    expect(resealed.ok).toBe(true);
    if (!resealed.ok) return;
    expect(resealed.value).toMatchObject({
      code: "ledger_hash_mismatch",
      droppedEntries: 2,
      resumedFrom: { seq: 3, hash: entries[2].hash }
    });
    expect(resealed.value.quarantineKey.startsWith(LEDGER_QUARANTINE_PREFIX)).toBe(true);
    expect(storage.raw.get(resealed.value.quarantineKey)).toBe(brokenRaw);

    expect(resealed.value.entry).toMatchObject({
      seq: 4,
      action: "ledger.resealed",
      actorId: "ada",
      prevHash: entries[2].hash,
      data: { code: "ledger_hash_mismatch", brokenAtSeq: 4, droppedEntries: 2, reason: "incident:42" }
    });
    expect(ledger.verify()).toMatchObject({ ok: true, count: 4 });
    expect(ledger.append(financial()).ok).toBe(true);
  });

  it("recovers from an unparseable blob by starting a new segment", () => {
    const { ledger, storage } = ledgerWith();
    seed(ledger, 2);
    storage.raw.set(LEDGER_STORAGE_KEY, "garbage");
    const resealed = ledger.reseal(MAINTAINER, "storage_corrupted");
    expect(resealed.ok && resealed.value.code).toBe("ledger_corrupt");
    if (!resealed.ok) return;
    expect(storage.raw.get(resealed.value.quarantineKey)).toBe("garbage");
    expect(resealed.value.entry.prevHash).toBe(LEDGER_GENESIS_HASH);
    expect(ledger.verify()).toMatchObject({ ok: true, count: 1 });
  });
});

describe("audit trail anchoring", () => {
  const input: AuditInput = {
    action: "record.state_changed",
    actor: MAINTAINER,
    scope: "maintainer",
    target: { kind: "worker_job", id: "job-1" },
    reason: "manual_dead_letter",
    before: { state: "retrying" },
    after: { state: "dead_lettered" },
    at: "2026-09-26T00:00:00.000Z"
  };

  it("commits each audit event to the ledger, even with an instant from the past", () => {
    const ledger = createIsolatedLedger();
    const trail = createIsolatedAuditTrail({ ledger });
    trail.record(input);
    trail.record({ ...input, at: "2020-01-01T00:00:00.000Z" });
    const entries = ledger.entries();
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({
      kind: "privileged",
      action: "record.state_changed",
      actorId: "ada",
      subject: { kind: "worker_job", id: "job-1" },
      ref: trail.all()[0].id,
      data: { eventAt: input.at, reason: "manual_dead_letter" }
    });
    expect(verifyAuditTrail(trail, ledger)).toEqual({ anchored: 2, tampered: [], unanchored: [], missing: [] });
    expect(ledger.verify().ok).toBe(true);
  });

  it("detects an audit event edited after it was recorded", () => {
    const storage = memory();
    const ledger = createIsolatedLedger();
    const trail = createIsolatedAuditTrail({ ledger, storage });
    trail.record(input);
    const key = [...storage.raw.keys()][0];
    const events = JSON.parse(storage.raw.get(key)!);
    events[0].reason = "routine";
    storage.raw.set(key, JSON.stringify(events));
    expect(verifyAuditTrail(trail, ledger).tampered).toEqual([events[0].id]);
  });

  it("detects an audit event removed outside retention", () => {
    const storage = memory();
    const ledger = createIsolatedLedger();
    const trail = createIsolatedAuditTrail({ ledger, storage });
    trail.record(input);
    trail.record({ ...input, target: { kind: "worker_job", id: "job-2" } });
    const key = [...storage.raw.keys()][0];
    const events = JSON.parse(storage.raw.get(key)!);
    storage.raw.set(key, JSON.stringify(events.slice(1)));
    expect(verifyAuditTrail(trail, ledger)).toMatchObject({ anchored: 1, missing: [events[0].id] });
  });

  it("never fails the audit write when the ledger refuses", () => {
    const trail = createIsolatedAuditTrail({
      ledger: {
        append: () => {
          throw new Error("storage full");
        }
      }
    });
    expect(trail.record(input).ok).toBe(true);
  });

  it("anchors the app-wide trail to the app-wide ledger", () => {
    getAuditTrail().reset();
    getLedger().reset();
    recordAudit(input);
    expect(getLedger().entries()).toHaveLength(1);
    expect(verifyAuditTrail(getAuditTrail(), getLedger()).anchored).toBe(1);
  });

  it("records financial events on the app-wide ledger without throwing", () => {
    getLedger().reset();
    expect(recordFinancialEvent({ action: "faucet.funded", actorId: "friendbot", subject: { kind: "stellar_account", id: "GX" } })).toMatchObject({
      kind: "financial",
      seq: 1
    });
    expect(
      recordFinancialEvent({ action: "faucet.funded", actorId: "", subject: { kind: "stellar_account", id: "GX" } })
    ).toBeUndefined();
  });
});

describe("verifyLedgerChain", () => {
  it("verifies an empty segment from any anchor", () => {
    expect(verifyLedgerChain([])).toMatchObject({ ok: true, count: 0, head: { seq: 0 } });
  });
});
