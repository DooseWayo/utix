import { describe, expect, it } from "vitest";
import { getLedger } from "@/core/ledger";
import { withMswHandlers } from "@/core/testing/msw";
import {
  classifyFriendbotResponse,
  friendbotUrl,
  fundTestnetAccount,
  parseRetryAfter
} from "@/features/testnet-faucet/lib/friendbot";
import {
  handlers,
  hangingHandler,
  retryAfterHandler,
  unavailableHandler,
  unparseableSuccessHandler
} from "@/features/testnet-faucet/msw/handlers";
import {
  PROBLEM_JSON,
  accountRacedBody,
  alreadyFundedBody,
  fundedAccountId,
  invalidAddressBody,
  newAccountId,
  racedAccountId,
  rateLimitedAccountId,
  rejectedAddressAccountId,
  timedOutAccountId,
  upstreamErrorAccountId
} from "@/features/testnet-faucet/fixtures/testnetFaucet.fixture";

const server = withMswHandlers(...handlers);

const problem = (body: string) => new Response(body, { status: 400, headers: PROBLEM_JSON });

describe("friendbotUrl", () => {
  it("encodes the address as the addr parameter", () => {
    expect(friendbotUrl(newAccountId)).toBe(
      `https://friendbot.stellar.org/?addr=${newAccountId}`
    );
  });
});

describe("classifyFriendbotResponse", () => {
  it("reads 429 as rate limiting", async () => {
    expect(await classifyFriendbotResponse(new Response("", { status: 429 }))).toBe(
      "rate_limited"
    );
  });

  it.each([408, 504, 524])("reads %i as a timeout, not an outage", async (status) => {
    expect(await classifyFriendbotResponse(new Response("", { status }))).toBe("timeout");
  });

  it.each([500, 502, 503])("reads %i as the faucet being unavailable", async (status) => {
    expect(await classifyFriendbotResponse(new Response("", { status }))).toBe(
      "friendbot_unavailable"
    );
  });

  it("recognises both of Friendbot's 'account exists' problems", async () => {
    expect(await classifyFriendbotResponse(problem(alreadyFundedBody))).toBe("already_funded");
    expect(await classifyFriendbotResponse(problem(accountRacedBody))).toBe("already_funded");
  });

  it("recognises Friendbot rejecting the address field", async () => {
    expect(await classifyFriendbotResponse(problem(invalidAddressBody))).toBe(
      "invalid_address"
    );
  });

  it("falls back to a plain failure for any other 400", async () => {
    expect(await classifyFriendbotResponse(problem("not json"))).toBe("request_failed");
    expect(await classifyFriendbotResponse(problem('{"detail":"something else"}'))).toBe(
      "request_failed"
    );
  });
});

describe("parseRetryAfter", () => {
  const now = Date.parse("Fri, 25 Sep 2026 10:00:00 GMT");

  it("reads delay-seconds", () => {
    expect(parseRetryAfter("120", now)).toBe(120_000);
  });

  it("reads an HTTP-date relative to now, never negative", () => {
    expect(parseRetryAfter("Fri, 25 Sep 2026 10:00:30 GMT", now)).toBe(30_000);
    expect(parseRetryAfter("Fri, 25 Sep 2026 09:59:00 GMT", now)).toBe(0);
  });

  it("ignores a missing or malformed value instead of guessing", () => {
    expect(parseRetryAfter(null, now)).toBeUndefined();
    expect(parseRetryAfter("1.5", now)).toBeUndefined();
    expect(parseRetryAfter("soon", now)).toBeUndefined();
  });
});

describe("fundTestnetAccount", () => {
  it("funds a new account and reports the transaction", async () => {
    const result = await fundTestnetAccount({ accountId: newAccountId });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.transactionHash).toHaveLength(64);
    expect(result.value.ledger).toBe(1017700);
  });

  it("records a successful funding on the tamper-evident ledger, and nothing on a refusal", async () => {
    getLedger().reset();
    const result = await fundTestnetAccount({ accountId: newAccountId });
    await fundTestnetAccount({ accountId: fundedAccountId });

    const entries = getLedger().entries();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      kind: "financial",
      action: "faucet.funded",
      subject: { kind: "stellar_account", id: newAccountId },
      data: { network: "testnet", transactionHash: result.ok ? result.value.transactionHash : null }
    });
    expect(getLedger().verify().ok).toBe(true);
  });

  it.each([
    [fundedAccountId, "already_funded"],
    [racedAccountId, "already_funded"],
    [rejectedAddressAccountId, "invalid_address"],
    [rateLimitedAccountId, "rate_limited"],
    [timedOutAccountId, "timeout"],
    [upstreamErrorAccountId, "friendbot_unavailable"]
  ])("classifies the mocked failure for %s as %s", async (accountId, code) => {
    expect(await fundTestnetAccount({ accountId })).toEqual({ ok: false, code });
  });

  it("reports the faucet being down", async () => {
    server.use(unavailableHandler);
    const result = await fundTestnetAccount({ accountId: newAccountId });
    expect(result).toEqual({ ok: false, code: "friendbot_unavailable" });
  });

  it("carries the Retry-After wait on a rate limit", async () => {
    server.use(retryAfterHandler(90));
    const result = await fundTestnetAccount({ accountId: newAccountId });
    expect(result).toEqual({ ok: false, code: "rate_limited", detail: { retryAfterMs: 90_000 } });
  });

  it("gives up with a timeout when Friendbot never answers", async () => {
    server.use(hangingHandler);
    const result = await fundTestnetAccount({ accountId: newAccountId }, { timeoutMs: 5 });
    expect(result).toEqual({ ok: false, code: "timeout" });
  });

  it("still succeeds when the success body cannot be parsed", async () => {
    server.use(unparseableSuccessHandler);
    const result = await fundTestnetAccount({ accountId: newAccountId });

    expect(result.ok).toBe(true);
    expect(result.ok && result.value.transactionHash).toBeUndefined();
  });
});
