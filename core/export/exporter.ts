/**
 * Privacy-safe data export workflow.
 *
 * Exports are scoped, schema-versioned and time-limited. A consumer requests a
 * schema version and an authorization scope; the exporter only ever yields
 * records the caller is allowed to see, tags the envelope with generation
 * metadata, redacts secret-shaped values, and stamps an expiry so generated
 * artifacts do not live forever.
 *
 * This module is pure and synchronous: collectable sources are passed in, so
 * the workflow is unit-testable without a store.
 */

import { recordAudit } from "@/core/audit/audit";
import {
  createIdempotencyStore,
  type IdempotencyErrorCode,
  type IdempotencyStore
} from "@/core/idempotency/idempotency";
import {
  createMemoryQuotaStorage,
  createQuotaStore,
  type QuotaErrorCode,
  type QuotaStore
} from "@/core/quota/quota";
import { err, ok, type Result } from "@/core/result/result";
import { paginateByCursor } from "@/core/pagination/cursor";
import {
  emitTelemetry,
  measureSync,
  newCorrelationId,
  redact
} from "@/core/telemetry/telemetry";

export type ExportErrorCode =
  | "export_denied"
  | "field_authorization_denied"
  | "schema_unsupported"
  | "empty_source"
  | "unsupported_scope"
  | IdempotencyErrorCode
  | QuotaErrorCode;

/** Increment on any breaking change to record shapes or the envelope. */
export const EXPORT_CURRENT_SCHEMA_VERSION = "1.0";

export const EXPORT_GENERATOR = "utix-export@1";

/** Default retention for a generated export artifact. */
export const EXPORT_DEFAULT_TTL_MS = 24 * 60 * 60 * 1_000;

export type ExportScope = "own" | "maintainer";

/** Who is asking. Only maintainers may request the `maintainer` scope. */
export type ExportActor =
  | { kind: "user"; id?: string; permissions?: readonly string[] }
  | { kind: "maintainer"; token?: string; id?: string; permissions?: readonly string[] }
  | { kind: "service"; id?: string; permissions?: readonly string[] };

/** Rule defining authorization requirements for individual record fields. */
export interface FieldAuthorizationRule {
  readonly field: string;
  readonly minScope?: ExportScope;
  readonly requiredPermissions?: readonly string[];
  readonly onDenied?: "omit" | "mask" | "error";
}

export const DEFAULT_SENSITIVE_FIELD_RULES: readonly FieldAuthorizationRule[] = [
  { field: "internalLatencyMs", minScope: "maintainer", onDenied: "omit" },
  { field: "ipAddress", minScope: "maintainer", onDenied: "mask" },
  { field: "userAgent", minScope: "maintainer", onDenied: "omit" },
  { field: "sessionToken", minScope: "maintainer", onDenied: "omit" },
  { field: "nodeId", minScope: "maintainer", onDenied: "omit" },
  { field: "adminNotes", minScope: "maintainer", onDenied: "mask" },
  { field: "riskScore", minScope: "maintainer", onDenied: "omit" },
  { field: "debugTrace", minScope: "maintainer", onDenied: "omit" },
  { field: "traceId", minScope: "maintainer", onDenied: "omit" },
  { field: "rawPayload", minScope: "maintainer", onDenied: "omit" },
  { field: "systemSignature", minScope: "maintainer", onDenied: "omit" }
];

export interface ExportRecordSource {
  /** Stable identifier, e.g. `operation_log`. */
  recordType: string;
  /** The schema version this source produces. */
  schemaVersion: string;
  /** Which scope the source's records belong to. */
  scope: ExportScope;
  /** Optional field-level authorization rules for records in this source. */
  fieldRules?: readonly FieldAuthorizationRule[];
  /** Collects the records synchronously. May include sensitive-looking fields. */
  collect: () => ExportRecord[];
}

export type ExportRecord = Record<string, unknown>;

export interface ExportRequest {
  schemaVersion: string;
  scope: ExportScope;
  actor: ExportActor;
  /** Optional generation correlation id to thread through. */
  correlationId?: string;
  /** Retention override in ms; defaults to `EXPORT_DEFAULT_TTL_MS`. */
  ttlMs?: number;
  /** Optional pagination: how many records per page. */
  pageSize?: number;
  page?: number;
  /** Opaque cursor returned by a previous page. */
  cursor?: string;
  /** Optional field selection projection. */
  fields?: readonly string[];
  /** Optional field-level authorization rules to apply. */
  fieldRules?: readonly FieldAuthorizationRule[];
  /** When true, requesting unauthorized fields returns field_authorization_denied. */
  strictFields?: boolean;
  /**
   * When set, generating this export is a high-risk write guarded by an
   * idempotency key: a retried request replays the same envelope instead of
   * producing a second artifact (and a second notification).
   */
  idempotencyKey?: string;
  /**
   * Who the `export.generate` quota is charged to, e.g. `account:G…`. Without
   * one, every anonymous caller of a scope shares a single allowance.
   */
  principal?: string;
}

export interface ExportEnvelope {
  schemaVersion: string;
  scope: ExportScope;
  generatedAt: string;
  expiresAt: string;
  generator: string;
  correlationId: string;
  recordCount: number;
  page: number;
  totalRecords: number;
  nextCursor: string | null;
  hasMore: boolean;
  fieldsFiltered?: number;
  records: ExportRecord[];
}

export type ExportResult = Result<ExportEnvelope, ExportErrorCode>;

function nowIso(): string {
  return new Date().toISOString();
}

function authScope(actor: ExportActor): ExportScope {
  return actor.kind === "maintainer" ? "maintainer" : "own";
}

/** Authorization gate: a request must not out-scope its actor. */
export function authorizeExport(
  actor: ExportActor,
  requestedScope: ExportScope
): Result<ExportScope, "export_denied"> {
  if (requestedScope === "maintainer" && authScope(actor) !== "maintainer") {
    return err("export_denied");
  }
  return ok(authScope(actor));
}

/**
 * Evaluates whether an actor has permission to export specific fields under given rules.
 */
export function evaluateFieldAuthorization(
  actor: ExportActor,
  requestedFields: readonly string[] | undefined,
  rules: readonly FieldAuthorizationRule[]
): { authorized: boolean; deniedFields: string[] } {
  if (actor.kind === "maintainer") {
    return { authorized: true, deniedFields: [] };
  }

  const isRulePermitted = (rule: FieldAuthorizationRule): boolean => {
    if (rule.minScope === "maintainer" && actor.kind !== "maintainer") {
      return false;
    }
    if (rule.requiredPermissions && rule.requiredPermissions.length > 0) {
      const actorPerms = actor.permissions ?? [];
      const hasAll = rule.requiredPermissions.every((p) => actorPerms.includes(p));
      if (!hasAll) return false;
    }
    return true;
  };

  const deniedFields: string[] = [];
  if (requestedFields) {
    for (const field of requestedFields) {
      const rule = rules.find((r) => r.field === field);
      if (rule && !isRulePermitted(rule)) {
        deniedFields.push(field);
      }
    }
  }

  return { authorized: deniedFields.length === 0, deniedFields };
}

/**
 * Filters a record's fields based on field-level authorization rules and optional projection.
 */
export function applyFieldLevelAuthorization(
  record: ExportRecord,
  actor: ExportActor,
  options: {
    requestedFields?: readonly string[];
    rules: readonly FieldAuthorizationRule[];
  }
): { record: ExportRecord; filteredCount: number } {
  const isMaintainer = actor.kind === "maintainer";
  const userPerms = actor.permissions ?? [];
  const allowedProjection = options.requestedFields ? new Set(options.requestedFields) : null;

  const sanitized: ExportRecord = {};
  let filteredCount = 0;

  for (const [key, value] of Object.entries(record)) {
    // If a projection was requested and this field is not in it, omit it
    if (allowedProjection && !allowedProjection.has(key)) {
      continue;
    }

    const rule = options.rules.find((r) => r.field === key);
    let isAuthorized = true;

    if (rule && !isMaintainer) {
      if (rule.minScope === "maintainer") {
        isAuthorized = false;
      }
      if (rule.requiredPermissions && rule.requiredPermissions.length > 0) {
        if (!rule.requiredPermissions.every((p) => userPerms.includes(p))) {
          isAuthorized = false;
        }
      }
    }

    if (isAuthorized) {
      sanitized[key] = value;
    } else {
      filteredCount += 1;
      const onDenied = rule?.onDenied ?? "omit";
      if (onDenied === "mask") {
        sanitized[key] = "[FILTERED: UNAUTHORIZED]";
      }
      // If "omit", field is not added to sanitized
    }
  }

  return { record: sanitized, filteredCount };
}

interface CollectedExportRecord {
  key: string;
  record: ExportRecord;
}

function cursorRecordKey(record: ExportRecord, index: number): string {
  const candidate = record.id ?? record.pagingToken ?? record.paging_token ?? record.index;
  let value: string;
  if (typeof candidate === "string" || typeof candidate === "number") {
    value = String(candidate);
  } else {
    try {
      value = JSON.stringify(record);
    } catch {
      value = String(index);
    }
  }
  let hash = 2166136261;
  for (let position = 0; position < value.length; position += 1) {
    hash = Math.imul(hash ^ value.charCodeAt(position), 16777619);
  }
  return `record-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function collectWithCursorKeys(records: ExportRecord[]): CollectedExportRecord[] {
  const occurrences = new Map<string, number>();
  return records.map((record, index) => {
    const base = cursorRecordKey(record, index);
    const occurrence = occurrences.get(base) ?? 0;
    occurrences.set(base, occurrence + 1);
    return { key: `${base}-${occurrence}`, record };
  });
}

/**
 * Persisted generation outcomes, one store per session. Held behind a ref so a
 * test can install an isolated store; the default is in-memory.
 */
const exportIdempotencyRef: { current: IdempotencyStore } = { current: createIdempotencyStore() };

/** Test seam: installs an isolated store and returns it. */
export function createExportIdempotencyStore(
  store: IdempotencyStore = createIdempotencyStore()
): IdempotencyStore {
  exportIdempotencyRef.current = store;
  return store;
}

/**
 * The `export.generate` quota. Held behind a ref for the same reason as the
 * idempotency store: a test installs an isolated one.
 */
const exportQuotaRef: { current: QuotaStore } = {
  current: createQuotaStore({ storage: createMemoryQuotaStorage() })
};

/** Test seam: installs an isolated quota store and returns it. */
export function createExportQuotaStore(
  store: QuotaStore = createQuotaStore({ storage: createMemoryQuotaStorage() })
): QuotaStore {
  exportQuotaRef.current = store;
  return store;
}

/**
 * Every export attempt is audited, including the ones that were refused: a
 * denied maintainer-scope request is exactly the event a reviewer looks for.
 * Only counts and version metadata are recorded, never the records themselves.
 */
function auditExport(
  request: ExportRequest,
  outcome: "allowed" | "denied",
  after: Record<string, string | number | boolean | null>,
  errorCode?: string
): void {
  recordAudit({
    action: "export.generated",
    actor:
      request.actor.kind === "maintainer"
        ? { kind: "maintainer", id: "maintainer" }
        : { kind: "user", id: `account:${request.scope}` },
    scope: request.scope === "maintainer" ? "maintainer" : "own",
    target: { kind: "export_envelope", id: request.idempotencyKey ?? request.correlationId ?? "ad-hoc" },
    outcome,
    after,
    correlationId: request.correlationId,
    errorCode
  });
}

/**
 * Generates a scoped, versioned export from the given sources.
 *
 * Records are filtered to the requested scope, sensitive-shaped fields are
 * redacted, and the envelope carries generation metadata plus an expiry.
 */
export function exportRecords(
  request: ExportRequest,
  sources: ExportRecordSource[]
): ExportResult {
  return measureSync(
    "export.generate",
    { actorType: "user", correlationId: request.correlationId },
    () => {
      // Replay before doing any work: a duplicate submission must not collect
      // records or mint a second artifact.
      const protectedRequest = request.idempotencyKey;
      if (protectedRequest) {
        const begun = exportIdempotencyRef.current.begin<ExportEnvelope>({
          key: request.idempotencyKey,
          operation: "export.generate",
          request: {
            schemaVersion: request.schemaVersion,
            scope: request.scope,
            actor: request.actor.kind,
            pageSize: request.pageSize ?? null,
            page: request.page ?? null,
            cursor: request.cursor ?? null
          },
          correlationId: request.correlationId
        });
        if (!begun.ok) return begun;
        if (begun.value.replay && begun.value.record.response) {
          return ok(begun.value.record.response);
        }
      }

      const authorization = authorizeExport(request.actor, request.scope);
      if (!authorization.ok) {
        auditExport(request, "denied", { requestedScope: request.scope }, "export_denied");
        if (protectedRequest) exportIdempotencyRef.current.fail(protectedRequest, "export_denied");
        emitTelemetry({
          op: "export.authorize",
          actorType: "user",
          result: "failure",
          correlationId: request.correlationId ?? newCorrelationId(),
          errorCode: "export_denied"
        });
        return authorization;
      }

      if (request.schemaVersion !== EXPORT_CURRENT_SCHEMA_VERSION) {
        auditExport(request, "denied", { requestedSchema: request.schemaVersion }, "schema_unsupported");
        if (protectedRequest) exportIdempotencyRef.current.fail(protectedRequest, "schema_unsupported");
        return err("schema_unsupported");
      }

      const combinedRules: FieldAuthorizationRule[] = [
        ...DEFAULT_SENSITIVE_FIELD_RULES,
        ...(request.fieldRules ?? []),
        ...sources.flatMap((s) => s.fieldRules ?? [])
      ];

      // Strict field authorization gate: if strictFields is requested with specific fields, verify permissions
      if (request.fields && request.strictFields) {
        const fieldAuth = evaluateFieldAuthorization(request.actor, request.fields, combinedRules);
        if (!fieldAuth.authorized) {
          auditExport(
            request,
            "denied",
            { requestedFields: request.fields.join(","), deniedFields: fieldAuth.deniedFields.join(",") },
            "field_authorization_denied"
          );
          if (protectedRequest) exportIdempotencyRef.current.fail(protectedRequest, "field_authorization_denied");
          emitTelemetry({
            op: "export.authorize",
            actorType: "user",
            result: "failure",
            correlationId: request.correlationId ?? newCorrelationId(),
            errorCode: "field_authorization_denied"
          });
          return err("field_authorization_denied");
        }
      }

      // Charged after the cheap refusals and after a replay, so neither an
      // invalid request nor a retried one spends the caller's allowance.
      const charged = exportQuotaRef.current.consume({
        operation: "export.generate",
        principal: request.principal ?? (request.actor.kind === "maintainer" ? "maintainer" : `account:${request.scope}`),
        correlationId: request.correlationId
      });
      if (!charged.ok) {
        auditExport(request, "denied", { quota: "export.generate" }, charged.code);
        // Released, not failed: a failed record would replay the refusal
        // forever, but the same key should succeed once the window resets.
        if (protectedRequest) exportIdempotencyRef.current.abandon(protectedRequest);
        return charged;
      }

      const allowed = sources.filter(
        (source) =>
          source.schemaVersion === request.schemaVersion &&
          (request.scope === "maintainer" || source.scope === "own")
      );

      const collected = allowed.flatMap((source) =>
        source
          .collect()
          .map((record) => ({
            ...record,
            recordType: source.recordType,
            scope: source.scope
          }))
      );
      const keyed = collectWithCursorKeys(collected);
      const ttlMs = request.ttlMs ?? EXPORT_DEFAULT_TTL_MS;
      const pageSize = Math.max(1, request.pageSize ?? (keyed.length > 0 ? keyed.length : 1));
      const page = Math.max(1, request.page ?? 1);
      const cursorPage = paginateByCursor(keyed, {
        pageSize,
        cursor: request.cursor,
        startIndex: (page - 1) * pageSize,
        getKey: (entry) => entry.key
      });
      const paged = cursorPage.items.map((entry) => entry.record);
      const totalRecords = keyed.length;

      let totalFieldsFiltered = 0;
      const sanitizedPaged = paged.map((record) => {
        const result = applyFieldLevelAuthorization(record, request.actor, {
          requestedFields: request.fields,
          rules: combinedRules
        });
        totalFieldsFiltered += result.filteredCount;
        return redact(result.record) as ExportRecord;
      });

      const envelope: ExportEnvelope = {
        schemaVersion: request.schemaVersion,
        scope: request.scope,
        generatedAt: nowIso(),
        expiresAt: new Date(Date.now() + ttlMs).toISOString(),
        generator: EXPORT_GENERATOR,
        correlationId: request.correlationId ?? newCorrelationId(),
        recordCount: sanitizedPaged.length,
        page,
        totalRecords,
        nextCursor: cursorPage.nextCursor,
        hasMore: cursorPage.hasMore,
        fieldsFiltered: totalFieldsFiltered,
        records: sanitizedPaged
      };

      auditExport(request, "allowed", {
        recordCount: envelope.recordCount,
        totalRecords: envelope.totalRecords,
        schemaVersion: envelope.schemaVersion,
        expiresAt: envelope.expiresAt,
        fieldsFiltered: totalFieldsFiltered
      });

      if (protectedRequest) {
        const completed = exportIdempotencyRef.current.complete(protectedRequest, envelope);
        if (!completed.ok) {
          exportIdempotencyRef.current.abandon(protectedRequest);
          return completed;
        }
      }

      return ok(envelope);
    }
  );
}

/** True once an export's retention window has elapsed. */
export function isExportExpired(envelope: ExportEnvelope, now: number = Date.now()): boolean {
  return now > Date.parse(envelope.expiresAt);
}