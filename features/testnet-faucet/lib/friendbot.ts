import { err, ok, type Result } from "@/core/result/result";
import { FRIENDBOT_URL } from "@/core/network/config";
import { isFeatureEnabled } from "@/core/feature-flags/flags";
import { runHorizonRequest } from "@/core/horizon/request";
import { recordFinancialEvent } from "@/core/ledger";
import { toFaucetErrorCode } from "@/features/testnet-faucet/lib/friendbot.errors";
import type {
  FaucetErrorCode,
  FaucetErrorDetail,
  FaucetInput,
  FaucetSuccess
} from "@/features/testnet-faucet/types";

/**
 * Friendbot waits up to 30 seconds for its own transaction submission before
 * answering, so the client budget sits just above that rather than at the
 * 10-second Horizon read default.
 */
export const FRIENDBOT_TIMEOUT_MS = 35_000;

/** Statuses a gateway uses when the upstream did not answer in time. */
const TIMEOUT_STATUSES = new Set([408, 504, 524]);

export type FaucetResult = Result<FaucetSuccess, FaucetErrorCode, FaucetErrorDetail>;

export interface FundOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Clock used to resolve an HTTP-date `Retry-After`; injectable for tests. */
  now?: () => number;
}

export function friendbotUrl(accountId: string): string {
  const url = new URL(FRIENDBOT_URL);
  url.searchParams.set("addr", accountId);
  return url.toString();
}

/**
 * Makes one funding attempt. Retrying is the caller's decision — see
 * `fundWithBackoff` — because only a rate limit is worth retrying.
 *
 * Friendbot only exists on testnet — there is deliberately no mainnet path
 * here, and the manifest declares `networks: ["testnet"]` for the same reason.
 */
export async function fundTestnetAccount(
  { accountId }: FaucetInput,
  { signal, timeoutMs = FRIENDBOT_TIMEOUT_MS, now = Date.now }: FundOptions = {}
): Promise<FaucetResult> {
  let response: Response;

  try {
    response = await runHorizonRequest(fetch(friendbotUrl(accountId), { signal }), {
      signal,
      timeoutMs
    });
  } catch (error) {
    return err(toFaucetErrorCode(error));
  }

  if (!response.ok) {
    const code = await classifyFriendbotResponse(response);
    const retryAfterMs =
      code === "rate_limited"
        ? parseRetryAfter(response.headers.get("retry-after"), now())
        : undefined;
    return retryAfterMs === undefined ? err(code) : err(code, { retryAfterMs });
  }

  let success: FaucetSuccess;
  try {
    const body = (await response.json()) as { hash?: string; ledger?: number };
    success = { accountId, transactionHash: body.hash, ledger: body.ledger };
  } catch {
    // Friendbot succeeded but returned something we cannot parse. The account
    // is funded either way, so this is still a success.
    success = { accountId };
  }

  // Value moved: record it on the tamper-evident ledger. Never throws.
  recordFinancialEvent({
    action: "faucet.funded",
    actorId: "friendbot",
    subject: { kind: "stellar_account", id: accountId },
    data: {
      network: "testnet",
      transactionHash: success.transactionHash ?? null,
      networkLedger: success.ledger ?? null
    }
  });
  return ok(success);
}

interface FriendbotProblem {
  detail?: unknown;
  extras?: { invalid_field?: unknown };
}

/**
 * Friendbot answers every refusal with a 400 problem document, so the body
 * decides the category:
 *
 * - `detail: "account already funded to starting balance"` — the account holds
 *   at least the starting balance already;
 * - `detail: "createAccountAlreadyExist (…)"` — it was created between
 *   Friendbot's balance check and its submission;
 * - `extras.invalid_field: "addr"` — Friendbot rejected the address itself.
 *
 * 429 comes from the rate limiter in front of Friendbot, not from Friendbot.
 */
export async function classifyFriendbotResponse(response: Response): Promise<FaucetErrorCode> {
  if (response.status === 429) return "rate_limited";
  if (TIMEOUT_STATUSES.has(response.status)) return "timeout";
  if (response.status >= 500) return "friendbot_unavailable";
  if (response.status !== 400) return "request_failed";

  if (!isFeatureEnabled("detailedFriendbotClassification")) return "request_failed";

  let problem: FriendbotProblem;
  try {
    problem = (await response.json()) as FriendbotProblem;
  } catch {
    return "request_failed";
  }

  if (problem?.extras?.invalid_field === "addr") return "invalid_address";

  const detail = typeof problem?.detail === "string" ? problem.detail.toLowerCase() : "";
  if (detail.includes("already funded") || detail.includes("createaccountalreadyexist")) {
    return "already_funded";
  }

  return "request_failed";
}

/**
 * Reads `Retry-After` (RFC 9110 §10.2.3): either a non-negative number of
 * seconds or an HTTP-date, which senders must write in GMT. Anything else is
 * ignored rather than guessed at — `Date.parse` alone accepts far too much.
 */
export function parseRetryAfter(value: string | null, nowMs: number): number | undefined {
  if (value === null) return undefined;
  const trimmed = value.trim();

  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1_000;

  const date = trimmed.endsWith("GMT") ? Date.parse(trimmed) : Number.NaN;
  return Number.isNaN(date) ? undefined : Math.max(0, date - nowMs);
}
