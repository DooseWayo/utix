import { describe, expect, it } from 'vitest';
import { DomainInvariantChecker } from '../checker';
import { issueTicket, redeemTicket, transferTicket } from '../mutations';
import type { DomainState, Event, Ticket } from '../types';

describe('Domain Model Invariant Test Suite (#78)', () => {
  const createInitialState = (): DomainState => {
    const events = new Map<string, Event>([
      [
        'event_festival_2026',
        {
          id: 'event_festival_2026',
          organizerAddress: 'G_ORGANIZER_ALICE',
          totalCapacity: 100,
          issuedCount: 1,
          status: 'active',
          feeBasisPoints: 500
        }
      ]
    ]);

    const tickets = new Map<string, Ticket>([
      [
        'ticket_001',
        {
          id: 'ticket_001',
          eventId: 'event_festival_2026',
          tierId: 'tier_vip',
          ownerAddress: 'G_USER_BOB',
          priceStroops: 100_000_000,
          status: 'issued',
          issuedAt: 1700000000000,
          validFrom: 1700000000000,
          validUntil: 1700090000000,
          fraudFlag: false,
          nonce: 0,
          metadataHash: 'QmTestHash123'
        }
      ]
    ]);

    return {
      events,
      tickets,
      transfers: [],
      processedNonces: new Set<string>(),
      blacklistedAddresses: new Set<string>(['G_FRAUDSTER_EVE'])
    };
  };

  describe('INV-01 & INV-10: Non-Negative & Capacity-Bounded Event Solvency', () => {
    it('passes when event ticket issuance is strictly within total venue capacity', () => {
      const state = createInitialState();
      const violations = DomainInvariantChecker.verifyAll(state);
      expect(violations).toHaveLength(0);
    });

    it('detects actual ticket records exceeding event capacity', () => {
      const state = createInitialState();
      const event = state.events.get('event_festival_2026')!;
      const modifiedTickets = new Map(state.tickets);
      modifiedTickets.set('ticket_002', {
        ...modifiedTickets.get('ticket_001')!,
        id: 'ticket_002',
        eventId: event.id,
      });

      const invalidState: DomainState = {
        ...state,
        tickets: modifiedTickets,
      };
      const violations = DomainInvariantChecker.verifyAll(invalidState);

      expect(violations.some((v) => v.invariantId === 'INV-10')).toBe(true);
    });
    it('fails when event issuedCount exceeds total venue capacity', () => {
      const state = createInitialState();
      const event = state.events.get('event_festival_2026')!;
      const modifiedEvents = new Map(state.events);
      modifiedEvents.set(event.id, { ...event, totalCapacity: 10, issuedCount: 15 });

      const invalidState: DomainState = { ...state, events: modifiedEvents };
      const violations = DomainInvariantChecker.verifyAll(invalidState);

      expect(violations.some((v) => v.invariantId === 'INV-10')).toBe(true);
    });

    it('prevents issueTicket mutation when event is sold out', () => {
      const state = createInitialState();
      const event = state.events.get('event_festival_2026')!;
      const modifiedEvents = new Map(state.events);
      modifiedEvents.set(event.id, { ...event, totalCapacity: 1, issuedCount: 1 });

      const soldOutState: DomainState = { ...state, events: modifiedEvents };
      const result = issueTicket(soldOutState, {
        id: 'ticket_002',
        eventId: 'event_festival_2026',
        tierId: 'tier_general',
        ownerAddress: 'G_USER_CHARLIE',
        priceStroops: 50_000_000,
        validFrom: 1700000000000,
        validUntil: 1700090000000
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code.invariantId).toBe('INV-10');
      }
    });
  });

  describe('INV-02: Single Active Ownership', () => {
    it('rejects transfer when initiator is not the current ticket owner', () => {
      const state = createInitialState();
      const result = transferTicket(state, {
        id: 'tx_001',
        ticketId: 'ticket_001',
        fromAddress: 'G_IMPOSTOR', // Not Bob
        toAddress: 'G_USER_CHARLIE',
        priceStroops: 100_000_000,
        organizerFeeStroops: 5_000_000,
        protocolFeeStroops: 2_500_000,
        sellerProceedsStroops: 92_500_000,
        nonce: 'nonce_001'
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code.invariantId).toBe('INV-02');
      }
    });

    it('updates owner atomically upon successful transfer', () => {
      const state = createInitialState();
      const result = transferTicket(state, {
        id: 'tx_001',
        ticketId: 'ticket_001',
        fromAddress: 'G_USER_BOB',
        toAddress: 'G_USER_CHARLIE',
        priceStroops: 100_000_000,
        organizerFeeStroops: 5_000_000,
        protocolFeeStroops: 2_500_000,
        sellerProceedsStroops: 92_500_000,
        nonce: 'nonce_001'
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        const transferredTicket = result.value.tickets.get('ticket_001')!;
        expect(transferredTicket.ownerAddress).toBe('G_USER_CHARLIE');
        expect(transferredTicket.status).toBe('transferred');
        expect(result.value.transfers).toHaveLength(1);
      }
    });
  });

  describe('INV-03 & INV-04: Terminal State Immutability & Lifecycle Progression', () => {
    it('blocks transfer of already redeemed tickets', () => {
      const state = createInitialState();
      const ticket = state.tickets.get('ticket_001')!;
      const modifiedTickets = new Map(state.tickets);
      modifiedTickets.set(ticket.id, { ...ticket, status: 'redeemed' });

      const redeemedState: DomainState = { ...state, tickets: modifiedTickets };
      const result = transferTicket(redeemedState, {
        id: 'tx_002',
        ticketId: 'ticket_001',
        fromAddress: 'G_USER_BOB',
        toAddress: 'G_USER_CHARLIE',
        priceStroops: 100_000_000,
        organizerFeeStroops: 5_000_000,
        protocolFeeStroops: 2_500_000,
        sellerProceedsStroops: 92_500_000,
        nonce: 'nonce_002'
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code.invariantId).toBe('INV-03');
      }
    });

    it('blocks second redemption of an already redeemed ticket', () => {
      const state = createInitialState();
      const redeem1 = redeemTicket(state, {
        ticketId: 'ticket_001',
        claimerAddress: 'G_USER_BOB',
        timestamp: 1700050000000
      });
      expect(redeem1.ok).toBe(true);

      if (redeem1.ok) {
        const redeem2 = redeemTicket(redeem1.value, {
          ticketId: 'ticket_001',
          claimerAddress: 'G_USER_BOB',
          timestamp: 1700050000000
        });
        expect(redeem2.ok).toBe(false);
        if (!redeem2.ok) {
          expect(redeem2.code.invariantId).toBe('INV-03');
        }
      }
    });
  });

  describe('INV-05: Escrow / Fraud Lock Transfer Bar', () => {
    it('fails when a fraud-flagged ticket is not locked or burned', () => {
      const state = createInitialState();
      const ticket = state.tickets.get('ticket_001')!;
      const modifiedTickets = new Map(state.tickets);
      modifiedTickets.set(ticket.id, { ...ticket, fraudFlag: true, status: 'issued' });

      const flaggedState: DomainState = { ...state, tickets: modifiedTickets };
      const violations = DomainInvariantChecker.verifyAll(flaggedState);

      expect(violations.some((v) => v.invariantId === 'INV-05')).toBe(true);
    });

    it('prevents transfer of locked or fraud-flagged ticket', () => {
      const state = createInitialState();
      const ticket = state.tickets.get('ticket_001')!;
      const modifiedTickets = new Map(state.tickets);
      modifiedTickets.set(ticket.id, { ...ticket, status: 'locked', fraudFlag: true });

      const lockedState: DomainState = { ...state, tickets: modifiedTickets };
      const result = transferTicket(lockedState, {
        id: 'tx_003',
        ticketId: 'ticket_001',
        fromAddress: 'G_USER_BOB',
        toAddress: 'G_USER_CHARLIE',
        priceStroops: 100_000_000,
        organizerFeeStroops: 5_000_000,
        protocolFeeStroops: 2_500_000,
        sellerProceedsStroops: 92_500_000,
        nonce: 'nonce_003'
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code.invariantId).toBe('INV-05');
      }
    });
  });

  describe('INV-06: Value Conservation & Zero-Sum Fee Split', () => {
    it('fails when fee split sum does not match total payment price', () => {
      const state = createInitialState();
      const result = transferTicket(state, {
        id: 'tx_004',
        ticketId: 'ticket_001',
        fromAddress: 'G_USER_BOB',
        toAddress: 'G_USER_CHARLIE',
        priceStroops: 100_000_000,
        organizerFeeStroops: 5_000_000,
        protocolFeeStroops: 2_500_000,
        sellerProceedsStroops: 90_000_000, // Sum = 97.5M != 100M
        nonce: 'nonce_004'
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code.invariantId).toBe('INV-06');
      }
    });
  });

  describe('INV-07: Stroop Precision & Positive Bounds', () => {
    it('rejects issuance with negative or fractional Stroop prices', () => {
      const state = createInitialState();
      const resultNegative = issueTicket(state, {
        id: 'ticket_neg',
        eventId: 'event_festival_2026',
        tierId: 'tier_general',
        ownerAddress: 'G_USER_CHARLIE',
        priceStroops: -100,
        validFrom: 1700000000000,
        validUntil: 1700090000000
      });
      expect(resultNegative.ok).toBe(false);
      if (!resultNegative.ok) expect(resultNegative.code.invariantId).toBe('INV-07');

      const resultFractional = issueTicket(state, {
        id: 'ticket_frac',
        eventId: 'event_festival_2026',
        tierId: 'tier_general',
        ownerAddress: 'G_USER_CHARLIE',
        priceStroops: 10.5,
        validFrom: 1700000000000,
        validUntil: 1700090000000
      });
      expect(resultFractional.ok).toBe(false);
      if (!resultFractional.ok) expect(resultFractional.code.invariantId).toBe('INV-07');
    });
  });

  describe('INV-08: Timebound Redemption Validity Window', () => {
    it('rejects ticket creation with inverted timebounds (validFrom > validUntil)', () => {
      const state = createInitialState();
      const result = issueTicket(state, {
        id: 'ticket_inverted',
        eventId: 'event_festival_2026',
        tierId: 'tier_general',
        ownerAddress: 'G_USER_CHARLIE',
        priceStroops: 50_000_000,
        validFrom: 1700090000000,
        validUntil: 1700000000000 // Inverted
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code.invariantId).toBe('INV-08');
    });

    it('rejects redemption outside valid timebound window', () => {
      const state = createInitialState();

      // Early redemption attempt
      const earlyRedeem = redeemTicket(state, {
        ticketId: 'ticket_001',
        claimerAddress: 'G_USER_BOB',
        timestamp: 1699999999000 // Before validFrom
      });
      expect(earlyRedeem.ok).toBe(false);
      if (!earlyRedeem.ok) expect(earlyRedeem.code.invariantId).toBe('INV-08');

      // Late redemption attempt
      const lateRedeem = redeemTicket(state, {
        ticketId: 'ticket_001',
        claimerAddress: 'G_USER_BOB',
        timestamp: 1700090001000 // After validUntil
      });
      expect(lateRedeem.ok).toBe(false);
      if (!lateRedeem.ok) expect(lateRedeem.code.invariantId).toBe('INV-08');
    });
  });

  describe('INV-09: Nonce & Idempotency Replay Protection', () => {
    it('rejects transfer with replayed nonce', () => {
      const state = createInitialState();
      const firstTransfer = transferTicket(state, {
        id: 'tx_first',
        ticketId: 'ticket_001',
        fromAddress: 'G_USER_BOB',
        toAddress: 'G_USER_CHARLIE',
        priceStroops: 100_000_000,
        organizerFeeStroops: 5_000_000,
        protocolFeeStroops: 2_500_000,
        sellerProceedsStroops: 92_500_000,
        nonce: 'replayed_nonce_xyz'
      });
      expect(firstTransfer.ok).toBe(true);

      if (firstTransfer.ok) {
        // Attempt another transfer reusing same nonce
        const secondTransfer = transferTicket(firstTransfer.value, {
          id: 'tx_second',
          ticketId: 'ticket_001',
          fromAddress: 'G_USER_CHARLIE',
          toAddress: 'G_USER_DAVID',
          priceStroops: 100_000_000,
          organizerFeeStroops: 5_000_000,
          protocolFeeStroops: 2_500_000,
          sellerProceedsStroops: 92_500_000,
          nonce: 'replayed_nonce_xyz' // Same nonce!
        });
        expect(secondTransfer.ok).toBe(false);
        if (!secondTransfer.ok) {
          expect(secondTransfer.code.invariantId).toBe('INV-09');
        }
      }
    });
  });

  describe('INV-11: Blacklisted Principal Action Quarantine', () => {
    it('rejects issuance to a blacklisted address', () => {
      const state = createInitialState();
      const result = issueTicket(state, {
        id: 'ticket_fraudster',
        eventId: 'event_festival_2026',
        tierId: 'tier_general',
        ownerAddress: 'G_FRAUDSTER_EVE', // Blacklisted
        priceStroops: 50_000_000,
        validFrom: 1700000000000,
        validUntil: 1700090000000
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code.invariantId).toBe('INV-11');
    });

    it('rejects transfer involving a blacklisted address', () => {
      const state = createInitialState();
      const result = transferTicket(state, {
        id: 'tx_fraud',
        ticketId: 'ticket_001',
        fromAddress: 'G_USER_BOB',
        toAddress: 'G_FRAUDSTER_EVE', // Blacklisted
        priceStroops: 100_000_000,
        organizerFeeStroops: 5_000_000,
        protocolFeeStroops: 2_500_000,
        sellerProceedsStroops: 92_500_000,
        nonce: 'nonce_fraud_01'
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code.invariantId).toBe('INV-11');
    });
  });
});
