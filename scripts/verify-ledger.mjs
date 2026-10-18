#!/usr/bin/env node
/**
 * Verifies the tamper-evident ledger contract, and optionally an export.
 *
 *   npm run verify:ledger                         # static contract checks (CI)
 *   npm run verify:ledger -- ledger.ndjson        # also verify an export offline
 *   npm run verify:ledger -- ledger.ndjson --expect-head 42:<sha256-hex>
 *
 * Static checks fail when:
 *
 * 1. every action in `FINANCIAL_ACTIONS` is not recorded by some emitter, or an
 *    emitter records a financial action the list does not declare;
 * 2. the audit trail stops committing events to the ledger;
 * 3. the ledger gains an update, patch or per-entry delete;
 * 4. an unparseable blob would be read as an empty ledger (fail-open);
 * 5. entries stop being hash-linked, or the hash stops being SHA-256.
 *
 * Export verification re-implements the chain check in plain Node (with
 * `node:crypto`), independent of the TypeScript that wrote it, so a reviewer
 * can check an export with nothing but this file.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (file) => readFile(path.join(root, file), "utf8");

const failures = [];

const ledger = await read("core/ledger/ledger.ts");
const audit = await read("core/audit/audit.ts");

const emitters = [{ file: "features/testnet-faucet/lib/friendbot.ts", action: "faucet.funded" }];

const declared = (() => {
  const match = ledger.match(/FINANCIAL_ACTIONS\s*=\s*\[([\s\S]*?)\]\s*as const/);
  return match ? [...match[1].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]) : null;
})();

if (!declared || declared.length === 0) {
  failures.push("core/ledger/ledger.ts: FINANCIAL_ACTIONS is missing or empty");
} else {
  const emitted = new Set();
  for (const { file, action } of emitters) {
    const source = await read(file);
    if (!new RegExp(`recordFinancialEvent\\(\\{[\\s\\S]*?action:\\s*"${action.replace(".", "\\.")}"`).test(source)) {
      failures.push(`no financial emitter for ${action}: ${file}`);
    }
    emitted.add(action);
  }
  for (const action of declared) {
    if (!emitted.has(action)) failures.push(`financial action declared but never recorded: ${action}`);
  }
  for (const action of emitted) {
    if (!declared.includes(action)) failures.push(`emitter records an undeclared financial action: ${action}`);
  }
}

if (!/commitToLedger\(event\)/.test(audit) || !/createAuditTrail\(\{\s*ledger:\s*getLedger\(\)\s*\}\)/.test(audit)) {
  failures.push("core/audit/audit.ts: the app-wide audit trail no longer commits events to the ledger");
}

if (/\b(update|patch|mutate|destroy|remove)\s*\(/.test(ledger.replace(/storage\.removeItem\(/g, ""))) {
  failures.push("core/ledger/ledger.ts: the ledger must not offer an update, patch or per-entry delete");
}

if (!/return \{ ok: false \};/.test(ledger) || !/err\("ledger_broken"\)/.test(ledger)) {
  failures.push("core/ledger/ledger.ts: an unparseable or broken chain must fail closed, not read as empty");
}

if (!/prevHash:\s*previous\.hash/.test(ledger) || !/raw\.prevHash !== previous\.hash/.test(ledger)) {
  failures.push("core/ledger/ledger.ts: entries are no longer hash-linked to their predecessor");
}

if (!/sha256Hex\(canonicalJson\(/.test(ledger)) {
  failures.push("core/ledger/ledger.ts: entries must be hashed with sha256Hex over canonical JSON");
}

// ── Optional: verify an export file ──────────────────────────────────────────

const args = process.argv.slice(2);
const exportFile = args.find((arg) => !arg.startsWith("--") && args[args.indexOf(arg) - 1] !== "--expect-head");
const expectArg = args.includes("--expect-head") ? args[args.indexOf("--expect-head") + 1] : undefined;

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map((entry) => (entry === undefined ? "null" : canonical(entry))).join(",")}]`;
  return `{${Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

function verifyExport(text, expectedHead) {
  let header;
  let entries;
  const trimmed = text.trim();
  try {
    let whole;
    try {
      whole = JSON.parse(trimmed);
    } catch {
      whole = undefined;
    }
    if (whole && Array.isArray(whole.entries)) {
      ({ entries, ...header } = whole);
    } else {
      const lines = trimmed.split("\n").filter((line) => line.trim());
      header = JSON.parse(lines[0]);
      entries = lines.slice(1).map((line) => {
        const entry = JSON.parse(line);
        delete entry.type;
        return entry;
      });
    }
  } catch {
    return "ledger_corrupt: not a ledger export";
  }
  if (header?.type !== "ledger.header" || !header.anchor || !header.head) return "ledger_corrupt: missing header";

  let previous = header.anchor;
  for (const entry of entries) {
    if (entry.seq !== previous.seq + 1) return `ledger_sequence_gap at seq ${previous.seq + 1}`;
    if (entry.prevHash !== previous.hash) return `ledger_link_broken at seq ${entry.seq}`;
    const { hash, ...body } = entry;
    if (createHash("sha256").update(canonical(body), "utf8").digest("hex") !== hash) {
      return `ledger_hash_mismatch at seq ${entry.seq}`;
    }
    if (previous.at && entry.at < previous.at) return `ledger_out_of_order at seq ${entry.seq}`;
    previous = entry;
  }
  if (previous.seq !== header.head.seq || previous.hash !== header.head.hash || entries.length !== header.count) {
    return "ledger_head_mismatch: the export does not reach its own header's head";
  }
  if (expectedHead) {
    const onChain =
      (header.anchor.seq === expectedHead.seq && header.anchor.hash === expectedHead.hash) ||
      entries.some((entry) => entry.seq === expectedHead.seq && entry.hash === expectedHead.hash);
    if (!onChain) return `ledger_head_mismatch: checkpoint ${expectedHead.seq}:${expectedHead.hash} is not on this chain`;
  }
  return { count: entries.length, head: previous };
}

let exportSummary = "";
if (exportFile) {
  let expectedHead;
  if (expectArg) {
    const [seq, hash] = expectArg.split(":");
    expectedHead = { seq: Number(seq), hash };
  }
  const outcome = verifyExport(await readFile(path.resolve(exportFile), "utf8"), expectedHead);
  if (typeof outcome === "string") failures.push(`${exportFile}: ${outcome}`);
  else exportSummary = `; export ${path.basename(exportFile)} verifies: ${outcome.count} entries, head ${outcome.head.seq}:${outcome.head.hash}`;
}

if (failures.length > 0) {
  console.error("verify:ledger failed\n");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(
  `verify:ledger ok — ${declared.length} financial action(s), audit trail anchored, hash-linked and fail-closed${exportSummary}`
);
