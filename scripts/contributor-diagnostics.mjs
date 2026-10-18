#!/usr/bin/env node
/**
 * Contributor Diagnostics CLI Tool (#275)
 *
 * Validates the contributor development environment:
 * - Node.js version >= v20
 * - Package and dependency integrity
 * - Sanitized environment variables and zero secret keys
 * - Feature registry synchronization
 * - Feature boundary isolation
 *
 * Usage:
 *   node scripts/contributor-diagnostics.mjs
 *   node scripts/contributor-diagnostics.mjs --json
 *   node scripts/contributor-diagnostics.mjs --strict
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { runContributorDiagnostics, formatDiagnosticsReport } from "../core/diagnostics/runner.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function main() {
  const isJson = process.argv.includes("--json");
  const isStrict = process.argv.includes("--strict");

  try {
    const report = await runContributorDiagnostics({
      projectRoot: root,
      strict: isStrict
    });

    if (isJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatDiagnosticsReport(report));
    }

    if (report.overallStatus === "failing") {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (err) {
    console.error("[contributor-diagnostics] Unexpected fatal error:");
    console.error(err);
    process.exit(2);
  }
}

main();
