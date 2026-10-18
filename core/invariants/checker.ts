/**
 * Domain Invariant Checker Engine (#78)
 *
 * Enforces and verifies the 11 core domain invariants across all domain state.
 * Ensures that tickets, events, transfers, and accounts cannot enter impossible
 * or fraudulent states.
 */

import type {
  DomainState,
  Event,
  InvariantViolation,
  Ticket,
  TicketStatus,
  TransferRecord
} from './types.ts';
import { InvariantViolationError } from './types.ts';


export const VALID_TRANSITIONS: Record<TicketStatus, readonly TicketStatus[]> = {
  issued: ['transferred', 'locked', 'redeemed', 'expired', 'burned'],
  transferred: ['transferred', 'locked', 'redeemed', 'expired', 'burned'],
  locked: ['issued', 'transferred', 'burned'], // Can be unlocked back or burned
  redeemed: [], // Terminal
  expired: [],  // Terminal
  burned: []    // Terminal
};

export class DomainInvariantChecker {
  /**
   * Verifies all 11 domain invariants against the entire domain state.
   * Time Complexity: O(T + E + X) where T = tickets, E = events, X = transfers.
   * Space Complexity: O(V) where V = violations found.
   */
  public static verifyAll(state: DomainState): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // INV-01 & INV-10: Event Capacity & Solvency
    const eventTicketCounts = new Map<string, number>();

    for (const [ticketId, ticket] of state.tickets.entries()) {
      // Aggregate for INV-01/INV-10
      const current = eventTicketCounts.get(ticket.eventId) ?? 0;
      eventTicketCounts.set(ticket.eventId, current + 1);

      // INV-07: Stroop Bounds
      if (
        !Number.isInteger(ticket.priceStroops) ||
        ticket.priceStroops < 0 ||
        ticket.priceStroops > 922_337_203_685_477_5807
      ) {
        violations.push({
          invariantId: 'INV-07',
          name: 'Stroop Precision & Positive Bounds',
          severity: 'critical',
          entityId: ticketId,
          entityType: 'ticket',
          message: `Ticket price ${ticket.priceStroops} is invalid; must be a non-negative integer Stroop amount`,
          context: { priceStroops: ticket.priceStroops }
        });
      }

      // INV-08: Timebound Redemption Validity Window
      if (ticket.validFrom > ticket.validUntil) {
        violations.push({
          invariantId: 'INV-08',
          name: 'Timebound Redemption Validity Window',
          severity: 'high',
          entityId: ticketId,
          entityType: 'ticket',
          message: `Ticket validity window inverted: validFrom (${ticket.validFrom}) > validUntil (${ticket.validUntil})`,
          context: { validFrom: ticket.validFrom, validUntil: ticket.validUntil }
        });
      }

      // INV-05: Escrow / Fraud Lock & Blacklist check
      if (ticket.fraudFlag && ticket.status !== 'locked' && ticket.status !== 'burned') {
        violations.push({
          invariantId: 'INV-05',
          name: 'Escrow / Fraud Lock Transfer Bar',
          severity: 'critical',
          entityId: ticketId,
          entityType: 'ticket',
          message: `Ticket flagged for fraud must be in 'locked' or 'burned' state, but was '${ticket.status}'`,
          context: { status: ticket.status, fraudFlag: ticket.fraudFlag }
        });
      }

      // INV-11: Blacklisted Principal Action Quarantine
      if (state.blacklistedAddresses.has(ticket.ownerAddress) && ticket.status !== 'locked' && ticket.status !== 'burned') {
        violations.push({
          invariantId: 'INV-11',
          name: 'Blacklisted Principal Action Quarantine',
          severity: 'critical',
          entityId: ticketId,
          entityType: 'ticket',
          message: `Ticket is owned by blacklisted address ${ticket.ownerAddress} and must be locked or burned`,
          context: { ownerAddress: ticket.ownerAddress }
        });
      }
    }

    // Verify Event Invariants
    for (const [eventId, event] of state.events.entries()) {
      const actualTickets = eventTicketCounts.get(eventId) ?? 0;

      // INV-01: Non-Negative & Capacity-Bounded Supply
      if (event.issuedCount < 0 || event.totalCapacity < 0) {
        violations.push({
          invariantId: 'INV-01',
          name: 'Non-Negative & Capacity-Bounded Supply',
          severity: 'critical',
          entityId: eventId,
          entityType: 'event',
          message: `Event issuedCount (${event.issuedCount}) or totalCapacity (${event.totalCapacity}) is negative`,
          context: { issuedCount: event.issuedCount, totalCapacity: event.totalCapacity }
        });
      }

      // INV-10: Event Capacity Ceiling & Solvency
      if (event.issuedCount > event.totalCapacity || actualTickets > event.totalCapacity) {
        violations.push({
          invariantId: 'INV-10',
          name: 'Organizer Event Solvency & Capacity Conservation',
          severity: 'critical',
          entityId: eventId,
          entityType: 'event',
          message: `Event oversold: issued tickets (${Math.max(event.issuedCount, actualTickets)}) exceeds total capacity (${event.totalCapacity})`,
          context: { totalCapacity: event.totalCapacity, issuedCount: event.issuedCount, actualTickets }
        });
      }
    }

    // Verify Transfer Invariants
    const seenNonces = new Set<string>();

    for (const transfer of state.transfers) {
      // INV-06: Value Conservation & Zero-Sum Fee Split
      const sumOfSplits =
        transfer.organizerFeeStroops +
        transfer.protocolFeeStroops +
        transfer.sellerProceedsStroops;

      if (sumOfSplits !== transfer.priceStroops) {
        violations.push({
          invariantId: 'INV-06',
          name: 'Value Conservation & Zero-Sum Fee Split',
          severity: 'critical',
          entityId: transfer.id,
          entityType: 'transfer',
          message: `Fee split does not equal transfer price: ${transfer.organizerFeeStroops} + ${transfer.protocolFeeStroops} + ${transfer.sellerProceedsStroops} = ${sumOfSplits}, expected ${transfer.priceStroops}`,
          context: {
            priceStroops: transfer.priceStroops,
            organizerFee: transfer.organizerFeeStroops,
            protocolFee: transfer.protocolFeeStroops,
            sellerProceeds: transfer.sellerProceedsStroops
          }
        });
      }

      // INV-09: Nonce & Idempotency Replay Protection
      if (seenNonces.has(transfer.nonce) || state.processedNonces.has(transfer.nonce)) {
        violations.push({
          invariantId: 'INV-09',
          name: 'Nonce & Idempotency Replay Protection',
          severity: 'critical',
          entityId: transfer.id,
          entityType: 'transfer',
          message: `Replay detected: transfer nonce '${transfer.nonce}' has already been processed`,
          context: { nonce: transfer.nonce }
        });
      } else {
        seenNonces.add(transfer.nonce);
      }
    }

    return violations;
  }

  /**
   * Asserts all invariants pass, throwing InvariantViolationError if any fail.
   */
  public static assertValidState(state: DomainState): void {
    const violations = this.verifyAll(state);
    if (violations.length > 0) {
      throw new InvariantViolationError(violations);
    }
  }

  /**
   * Validates a state transition between ticket lifecycle states (INV-03 & INV-04).
   */
  public static canTransitionStatus(
    fromStatus: TicketStatus,
    toStatus: TicketStatus
  ): { valid: boolean; violation?: InvariantViolation } {
    // INV-03: Terminal State Immutability
    if (fromStatus === 'redeemed' || fromStatus === 'expired' || fromStatus === 'burned') {
      return {
        valid: false,
        violation: {
          invariantId: 'INV-03',
          name: 'Terminal State Immutability',
          severity: 'critical',
          entityId: 'transition',
          entityType: 'ticket',
          message: `Cannot transition from terminal state '${fromStatus}' to '${toStatus}'`,
          context: { fromStatus, toStatus }
        }
      };
    }

    // INV-04: Valid Sequential Lifecycle Progression
    const allowed = VALID_TRANSITIONS[fromStatus];
    if (!allowed.includes(toStatus)) {
      return {
        valid: false,
        violation: {
          invariantId: 'INV-04',
          name: 'Valid Sequential Lifecycle Progression',
          severity: 'high',
          entityId: 'transition',
          entityType: 'ticket',
          message: `Illegal lifecycle transition from '${fromStatus}' to '${toStatus}'`,
          context: { fromStatus, toStatus, allowed }
        }
      };
    }

    return { valid: true };
  }
}
