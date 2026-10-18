/**
 * Safe Ownership Transfer with Pending Acceptance and Expiry (#264)
 *
 * Implements two-step ownership handover (propose -> accept) to eliminate the risk
 * of irreversible ownership loss caused by typos, inactive keys, or incompatible
 * receiver accounts in Stellar/Soroban protocols.
 */

import type { Result } from "@/core/result/result";

export type OwnershipTransferStatus =
  | "pending"
  | "accepted"
  | "cancelled"
  | "rejected"
  | "expired";

export type OwnershipErrorCode =
  | "unauthorized_not_owner"
  | "unauthorized_not_recipient"
  | "cannot_transfer_to_self"
  | "invalid_recipient"
  | "invalid_owner"
  | "invalid_expiry_window"
  | "transfer_not_found"
  | "transfer_expired"
  | "transfer_already_settled"
  | "transfer_active_conflict"
  | "resource_locked"
  | "resource_not_found"
  | "idempotency_conflict";

export interface OwnershipActor {
  readonly kind: "user" | "maintainer" | "service" | "contract";
  readonly id: string; // e.g. "account:G...", "G..."
}

export interface OwnershipTransferProposal {
  readonly id: string;
  readonly resourceId: string;
  readonly resourceType: string; // e.g. "ticket", "event", "role", "account"
  readonly currentOwner: string;
  readonly proposedOwner: string;
  readonly status: OwnershipTransferStatus;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly settledAt?: string;
  readonly priceStroops?: number;
  readonly memo?: string;
  readonly idempotencyKey?: string;
  readonly correlationId?: string;
  readonly metadata?: Record<string, unknown>;
}

export interface InitiateOwnershipTransferParams {
  readonly resourceId: string;
  readonly resourceType?: string;
  readonly currentOwner: string;
  readonly proposedOwner: string;
  readonly expiresInMs?: number;
  readonly priceStroops?: number;
  readonly memo?: string;
  readonly idempotencyKey?: string;
  readonly correlationId?: string;
  readonly actor: OwnershipActor;
  readonly metadata?: Record<string, unknown>;
  readonly now?: number | Date;
}

export interface AcceptOwnershipTransferParams {
  readonly transferId: string;
  readonly actor: OwnershipActor;
  readonly correlationId?: string;
  readonly idempotencyKey?: string;
  readonly now?: number | Date;
}

export interface CancelOwnershipTransferParams {
  readonly transferId: string;
  readonly actor: OwnershipActor;
  readonly reason?: string;
  readonly correlationId?: string;
  readonly idempotencyKey?: string;
  readonly now?: number | Date;
}

export interface RejectOwnershipTransferParams {
  readonly transferId: string;
  readonly actor: OwnershipActor;
  readonly reason?: string;
  readonly correlationId?: string;
  readonly idempotencyKey?: string;
  readonly now?: number | Date;
}

export interface QueryOwnershipTransfersFilter {
  readonly resourceId?: string;
  readonly resourceType?: string;
  readonly currentOwner?: string;
  readonly proposedOwner?: string;
  readonly status?: OwnershipTransferStatus;
  readonly activeOnly?: boolean;
}

export type OwnershipResult<T> = Result<T, OwnershipErrorCode>;
