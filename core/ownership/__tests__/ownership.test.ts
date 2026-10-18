import { describe, expect, it, beforeEach } from "vitest";
import {
  createOwnershipStore,
  normalizePrincipal,
  isValidPrincipal,
  OwnershipTransferStore,
  DEFAULT_EXPIRY_MS
} from "../ownership";
import { recordMachine, stateView } from "@/core/lifecycle/records";
import type { DomainState, Ticket } from "@/core/invariants/types";
import { initiateSafeTicketTransfer, acceptSafeTicketTransfer } from "@/core/invariants/mutations";

describe("Safe Ownership Transfer (#264)", () => {
  let store: OwnershipTransferStore;
  const OWNER_A = "GBBD6W3NZUBY7J572J45A75Z7P4C0B634S8X2A7X6M27B2B642C3N444";
  const RECIPIENT_B = "GA7YOFXNY2WAGM56WJ2W6LKK3F3HMRQ74NFD5Z5P4C0B634S8X2A7X6M";
  const ATTACKER_C = "GC5W5O5IUBY7J572J45A75Z7P4C0B634S8X2A7X6M27B2B642C3N4555";

  beforeEach(() => {
    store = createOwnershipStore();
  });

  describe("propose / initiate transfer", () => {
    it("successfully creates a pending ownership transfer proposal", () => {
      const res = store.initiate({
        resourceId: "ticket-101",
        resourceType: "ticket",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        expiresInMs: 3600_000,
        priceStroops: 10_000_000,
        actor: { kind: "user", id: OWNER_A }
      });

      expect(res.ok).toBe(true);
      if (!res.ok) return;

      expect(res.value.status).toBe("pending");
      expect(res.value.currentOwner).toBe(OWNER_A);
      expect(res.value.proposedOwner).toBe(RECIPIENT_B);
      expect(res.value.resourceId).toBe("ticket-101");
      expect(res.value.priceStroops).toBe(10_000_000);
      expect(new Date(res.value.expiresAt).getTime()).toBeGreaterThan(Date.now());
    });

    it("rejects transfer to oneself", () => {
      const res = store.initiate({
        resourceId: "ticket-101",
        currentOwner: OWNER_A,
        proposedOwner: OWNER_A,
        actor: { kind: "user", id: OWNER_A }
      });

      expect(res.ok).toBe(false);
      if (res.ok) return;
      expect(res.code).toBe("cannot_transfer_to_self");
    });

    it("rejects initiation from an unauthorized actor", () => {
      const res = store.initiate({
        resourceId: "ticket-101",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        actor: { kind: "user", id: ATTACKER_C }
      });

      expect(res.ok).toBe(false);
      if (res.ok) return;
      expect(res.code).toBe("unauthorized_not_owner");
    });

    it("allows maintainer to initiate on behalf of owner", () => {
      const res = store.initiate({
        resourceId: "ticket-101",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        actor: { kind: "maintainer", id: "maintainer-admin" }
      });

      expect(res.ok).toBe(true);
    });

    it("rejects invalid expiry windows (< 1 min or > 30 days)", () => {
      const tooShort = store.initiate({
        resourceId: "ticket-101",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        expiresInMs: 30_000, // 30 sec
        actor: { kind: "user", id: OWNER_A }
      });
      expect(tooShort.ok).toBe(false);
      if (tooShort.ok) return;
      expect(tooShort.code).toBe("invalid_expiry_window");

      const tooLong = store.initiate({
        resourceId: "ticket-101",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        expiresInMs: 35 * 86400_000, // 35 days
        actor: { kind: "user", id: OWNER_A }
      });
      expect(tooLong.ok).toBe(false);
      if (tooLong.ok) return;
      expect(tooLong.code).toBe("invalid_expiry_window");
    });

    it("prevents multiple conflicting active proposals on the same resource", () => {
      const first = store.initiate({
        resourceId: "ticket-202",
        resourceType: "ticket",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        actor: { kind: "user", id: OWNER_A }
      });
      expect(first.ok).toBe(true);

      const conflict = store.initiate({
        resourceId: "ticket-202",
        resourceType: "ticket",
        currentOwner: OWNER_A,
        proposedOwner: ATTACKER_C,
        actor: { kind: "user", id: OWNER_A }
      });
      expect(conflict.ok).toBe(false);
      if (conflict.ok) return;
      expect(conflict.code).toBe("transfer_active_conflict");
    });

    it("replays idempotent proposal with identical response", () => {
      const first = store.initiate({
        resourceId: "ticket-303",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        idempotencyKey: "idem-transfer-1",
        actor: { kind: "user", id: OWNER_A }
      });
      expect(first.ok).toBe(true);

      const replay = store.initiate({
        resourceId: "ticket-303",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        idempotencyKey: "idem-transfer-1",
        actor: { kind: "user", id: OWNER_A }
      });
      expect(replay.ok).toBe(true);
      if (!first.ok || !replay.ok) return;
      expect(replay.value.id).toBe(first.value.id);
    });
  });

  describe("accept transfer", () => {
    it("successfully accepts pending transfer by the designated recipient", () => {
      const prop = store.initiate({
        resourceId: "ticket-404",
        resourceType: "ticket",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        actor: { kind: "user", id: OWNER_A }
      });
      expect(prop.ok).toBe(true);
      if (!prop.ok) return;

      const accepted = store.accept({
        transferId: prop.value.id,
        actor: { kind: "user", id: RECIPIENT_B }
      });

      expect(accepted.ok).toBe(true);
      if (!accepted.ok) return;
      expect(accepted.value.status).toBe("accepted");
      expect(accepted.value.settledAt).toBeDefined();

      // Active resource pointer is cleared
      const active = store.getActiveTransferForResource("ticket", "ticket-404");
      expect(active).toBeNull();
    });

    it("rejects acceptance by unauthorized caller", () => {
      const prop = store.initiate({
        resourceId: "ticket-505",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        actor: { kind: "user", id: OWNER_A }
      });
      if (!prop.ok) return;

      const res = store.accept({
        transferId: prop.value.id,
        actor: { kind: "user", id: ATTACKER_C }
      });

      expect(res.ok).toBe(false);
      if (res.ok) return;
      expect(res.code).toBe("unauthorized_not_recipient");
    });

    it("rejects acceptance if transfer has expired", () => {
      const baseNow = Date.now();
      const prop = store.initiate({
        resourceId: "ticket-606",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        expiresInMs: 60_000,
        now: baseNow,
        actor: { kind: "user", id: OWNER_A }
      });
      if (!prop.ok) return;

      // Try accepting after 65 seconds
      const res = store.accept({
        transferId: prop.value.id,
        actor: { kind: "user", id: RECIPIENT_B },
        now: baseNow + 65_000
      });

      expect(res.ok).toBe(false);
      if (res.ok) return;
      expect(res.code).toBe("transfer_expired");

      // Verify status in store transitioned to expired
      const fetched = store.getTransfer(prop.value.id, baseNow + 65_000);
      expect(fetched?.status).toBe("expired");
    });

    it("rejects duplicate acceptance on already settled transfer", () => {
      const prop = store.initiate({
        resourceId: "ticket-707",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        actor: { kind: "user", id: OWNER_A }
      });
      if (!prop.ok) return;

      store.accept({
        transferId: prop.value.id,
        actor: { kind: "user", id: RECIPIENT_B }
      });

      const second = store.accept({
        transferId: prop.value.id,
        actor: { kind: "user", id: RECIPIENT_B }
      });

      expect(second.ok).toBe(false);
      if (second.ok) return;
      expect(second.code).toBe("transfer_already_settled");
    });
  });

  describe("cancel and reject", () => {
    it("owner can cancel a pending transfer", () => {
      const prop = store.initiate({
        resourceId: "ticket-808",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        actor: { kind: "user", id: OWNER_A }
      });
      if (!prop.ok) return;

      const cancelled = store.cancel({
        transferId: prop.value.id,
        reason: "Seller changed mind",
        actor: { kind: "user", id: OWNER_A }
      });

      expect(cancelled.ok).toBe(true);
      if (!cancelled.ok) return;
      expect(cancelled.value.status).toBe("cancelled");

      // Recipient cannot accept after cancellation
      const accept = store.accept({
        transferId: prop.value.id,
        actor: { kind: "user", id: RECIPIENT_B }
      });
      expect(accept.ok).toBe(false);
    });

    it("proposed recipient can reject a pending transfer", () => {
      const prop = store.initiate({
        resourceId: "ticket-909",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        actor: { kind: "user", id: OWNER_A }
      });
      if (!prop.ok) return;

      const rejected = store.reject({
        transferId: prop.value.id,
        reason: "Not interested",
        actor: { kind: "user", id: RECIPIENT_B }
      });

      expect(rejected.ok).toBe(true);
      if (!rejected.ok) return;
      expect(rejected.value.status).toBe("rejected");
    });
  });

  describe("queries and expiration sweeping", () => {
    it("sweeps expired proposals and queries by filter", () => {
      const baseNow = Date.now();
      store.initiate({
        resourceId: "item-1",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        expiresInMs: 60_000,
        now: baseNow,
        actor: { kind: "user", id: OWNER_A }
      });
      store.initiate({
        resourceId: "item-2",
        currentOwner: OWNER_A,
        proposedOwner: RECIPIENT_B,
        expiresInMs: 3600_000,
        now: baseNow,
        actor: { kind: "user", id: OWNER_A }
      });

      const swept = store.sweepExpired(baseNow + 70_000);
      expect(swept).toBe(1);

      const active = store.queryTransfers({ activeOnly: true }, baseNow + 70_000);
      expect(active.length).toBe(1);
      expect(active[0].resourceId).toBe("item-2");
    });
  });

  describe("core lifecycle integration", () => {
    it("resolves ownership_transfer machine and labels from core/lifecycle", () => {
      const machineRes = recordMachine("ownership_transfer");
      expect(machineRes.ok).toBe(true);
      if (!machineRes.ok) return;

      expect(machineRes.value.name).toBe("ownership_transfer");
      expect(machineRes.value.initial()).toBe("pending");

      const view = stateView("ownership_transfer", "pending");
      expect(view.label).toBe("Pending Acceptance");
      expect(view.allowedEvents).toContain("accept");
      expect(view.allowedEvents).toContain("cancel");
    });
  });

  describe("domain invariants ticket mutation integration", () => {
    it("initiates and accepts a safe ticket transfer atomically updating DomainState", () => {
      const initialTicket: Ticket = {
        id: "tkt-alpha",
        eventId: "event-1",
        tierId: "tier-ga",
        ownerAddress: OWNER_A,
        priceStroops: 50_000_000,
        status: "issued",
        issuedAt: Date.now(),
        validFrom: 100,
        validUntil: 200,
        fraudFlag: false,
        nonce: 0,
        metadataHash: ""
      };

      const domainState: DomainState = {
        events: new Map([["event-1", { id: "event-1", organizerAddress: "GORG", totalCapacity: 100, issuedCount: 1, status: "active", feeBasisPoints: 200 }]]),
        tickets: new Map([[initialTicket.id, initialTicket]]),
        transfers: [],
        processedNonces: new Set(),
        blacklistedAddresses: new Set()
      };

      // 1. Initiate safe transfer
      const initRes = initiateSafeTicketTransfer(domainState, {
        ticketId: "tkt-alpha",
        fromAddress: OWNER_A,
        toAddress: RECIPIENT_B,
        actor: { kind: "user", id: OWNER_A }
      }, store);

      expect(initRes.ok).toBe(true);
      if (!initRes.ok) return;
      const transferId = initRes.value.id;

      // 2. Accept safe transfer
      const acceptRes = acceptSafeTicketTransfer(domainState, {
        transferId,
        transferRecordId: "tx-record-01",
        nonce: "nonce-101",
        actor: { kind: "user", id: RECIPIENT_B }
      }, store);

      expect(acceptRes.ok).toBe(true);
      if (!acceptRes.ok) return;

      const nextState = acceptRes.value.state;
      const updatedTicket = nextState.tickets.get("tkt-alpha");
      expect(updatedTicket?.ownerAddress).toBe(RECIPIENT_B);
      expect(updatedTicket?.status).toBe("transferred");
      expect(updatedTicket?.nonce).toBe(1);
      expect(nextState.transfers.length).toBe(1);
      expect(nextState.transfers[0].toAddress).toBe(RECIPIENT_B);
      expect(nextState.processedNonces.has("nonce-101")).toBe(true);
    });
  });
});
