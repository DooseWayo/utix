import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createIsolatedLedger } from "@/core/ledger/ledger";

/**
 * `scripts/verify-ledger.mjs` re-implements the chain check with node:crypto.
 * Running it against exports written by the TypeScript ledger keeps the two
 * implementations from drifting apart.
 */
const script = path.resolve(__dirname, "../../../scripts/verify-ledger.mjs");
const dir = mkdtempSync(path.join(tmpdir(), "utix-ledger-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function run(...args: string[]): { status: number; output: string } {
  try {
    return { status: 0, output: execFileSync(process.execPath, [script, ...args], { encoding: "utf8", stdio: "pipe" }) };
  } catch (error) {
    const failed = error as { status: number; stdout: string; stderr: string };
    return { status: failed.status, output: `${failed.stdout}${failed.stderr}` };
  }
}

function exported(format: "ndjson" | "json") {
  let tick = 0;
  const ledger = createIsolatedLedger({ now: () => Date.parse("2026-10-01T00:00:00.000Z") + 1000 * tick++ });
  ledger.append({ kind: "financial", action: "faucet.funded", actorId: "friendbot", subject: { kind: "stellar_account", id: "GA" }, data: { note: "ünïcode ✓" } });
  ledger.append({ kind: "privileged", action: "quota.override_granted", actorId: "ada", subject: { kind: "quota", id: "global" } });
  const text = ledger.export({ kind: "maintainer", id: "ada" }, { format });
  if (!text.ok) throw new Error(text.code);
  return { text: text.value, head: ledger.head() };
}

describe("scripts/verify-ledger.mjs", () => {
  it.each(["ndjson", "json"] as const)("accepts an intact %s export and its checkpoint", (format) => {
    const { text, head } = exported(format);
    const file = path.join(dir, `ok.${format}`);
    writeFileSync(file, text);
    const result = run(file, "--expect-head", `${head.seq}:${head.hash}`);
    expect(result.output).toContain(`head ${head.seq}:${head.hash}`);
    expect(result.status).toBe(0);
  });

  it("rejects a tampered export and a foreign checkpoint", () => {
    const { text } = exported("ndjson");
    const file = path.join(dir, "tampered.ndjson");
    writeFileSync(file, text.replace('"actorId":"ada"', '"actorId":"mallory"'));
    const tampered = run(file);
    expect(tampered.status).toBe(1);
    expect(tampered.output).toContain("ledger_hash_mismatch at seq 2");

    const intact = path.join(dir, "intact.ndjson");
    writeFileSync(intact, text);
    const foreign = run(intact, "--expect-head", `2:${"f".repeat(64)}`);
    expect(foreign.status).toBe(1);
    expect(foreign.output).toContain("ledger_head_mismatch");
  });
});
