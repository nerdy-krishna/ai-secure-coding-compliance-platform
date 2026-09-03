import { C13_CONTRACT_MAJOR, C13_EVENT_MAJOR, type C13CockpitSnapshot, type C13Event, type C13Resource, type ConnectionState, type OwnerTuple, type SourcePin } from "./types";

export interface VerifiedCursor {
  sequence: number;
  digest: string;
}

export type EventDecision =
  | { kind: "duplicate" }
  | { kind: "accept"; cursor: VerifiedCursor }
  | { kind: "reconcile"; state: Extract<ConnectionState, "catching_up" | "conflict" | "unsupported">; reason: string };

const sameOwner = (left: OwnerTuple, right: OwnerTuple): boolean =>
  left.tenant_id === right.tenant_id &&
  left.project_id === right.project_id &&
  left.engagement_id === right.engagement_id &&
  left.attempt_id === right.attempt_id;

const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseC13Event(value: unknown): C13Event | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  const payload = raw.payload as Record<string, unknown> | undefined;
  if (raw.schema_version !== "sccap.pentest.event-envelope.v7" || !payload) return null;
  const owner: OwnerTuple = {
    tenant_id: String(raw.tenant_id ?? ""), project_id: String(raw.project_id ?? ""),
    engagement_id: String(raw.engagement_id ?? ""), attempt_id: String(raw.attempt_id ?? ""),
  };
  if (Object.values(owner).some((part) => !part)) return null;
  const sequence = Number(raw.aggregate_sequence);
  const eventDigest = String(raw.canonical_digest ?? "");
  const previous = raw.previous_event_digest === null ? "" : String(raw.previous_event_digest ?? "");
  const projectionDigest = String(payload.projection_digest ?? "");
  if (!Number.isSafeInteger(sequence) || sequence < 1 || !/^[0-9a-f]{64}$/.test(eventDigest) ||
    !/^[0-9a-f]{64}$/.test(projectionDigest) || (previous && !/^[0-9a-f]{64}$/.test(previous))) return null;
  const resourceMap: Record<string, C13Resource[]> = {
    cockpit_snapshot: ["snapshot"], report_request: ["reports"], report_snapshot: ["reports"],
    report_publication: ["reports"], evidence_export: ["exports"], governance_request: ["governance", "audit"],
    governance_decision: ["governance", "audit"], waiver: ["governance", "audit"],
    retest_request: ["retests"], retest_link: ["retests", "deltas"], delta_snapshot: ["deltas"],
  };
  return {
    contract_major: 7, event_id: String(raw.event_id ?? ""), event_type: String(raw.event_type ?? ""),
    owner, aggregate_sequence: sequence, predecessor_digest: previous, event_digest: eventDigest,
    resource_type: String(payload.resource_type ?? ""), resource_id: String(payload.resource_id ?? ""),
    state: String(payload.state ?? ""), generation_or_revision: Number(payload.generation_or_revision),
    occurred_at: String(payload.occurred_at ?? raw.occurred_at ?? ""),
    invalidates: resourceMap[String(raw.aggregate_kind ?? "")] ?? ["snapshot"],
  };
}

export type ExpectedOwner = Pick<OwnerTuple, "tenant_id" | "engagement_id" | "attempt_id"> & { project_id?: string };

export function validateSnapshot(snapshot: C13CockpitSnapshot, expected: ExpectedOwner): string | null {
  if (!snapshot || typeof snapshot !== "object" || !snapshot.owner || !snapshot.source_cutoff || !Array.isArray(snapshot.source_pins)) return "invalid_snapshot_shape";
  if (snapshot.contract_major !== C13_CONTRACT_MAJOR) return "unsupported_contract_major";
  if (snapshot.owner.tenant_id !== expected.tenant_id || snapshot.owner.engagement_id !== expected.engagement_id ||
    snapshot.owner.attempt_id !== expected.attempt_id || (expected.project_id && snapshot.owner.project_id !== expected.project_id)) {
    return "owner_mismatch";
  }
  if (!Number.isSafeInteger(snapshot.source_cutoff.aggregate_sequence) || snapshot.source_cutoff.aggregate_sequence < 0) {
    return "invalid_sequence";
  }
  const ownerIds = [
    snapshot.owner.tenant_id,
    snapshot.owner.project_id,
    snapshot.owner.engagement_id,
    snapshot.owner.attempt_id,
  ];
  if (!UUID.test(snapshot.snapshot_id) || ownerIds.some((id) => !UUID.test(id)) ||
    (snapshot.owner.resource_owner_user_id !== undefined &&
      (!Number.isSafeInteger(snapshot.owner.resource_owner_user_id) || snapshot.owner.resource_owner_user_id < 1))) {
    return "invalid_identifier";
  }
  if (!SHA256.test(snapshot.source_cutoff.event_digest) || !SHA256.test(snapshot.snapshot_digest)) return "invalid_digest";
  if (!Number.isFinite(Date.parse(snapshot.source_cutoff.captured_at))) return "invalid_cutoff_time";
  const owners = new Set(snapshot.source_pins.map((pin) => pin.owner));
  if (!["C6", "C9", "C10", "C11"].every((owner) => owners.has(owner as SourcePin["owner"]))) return "missing_required_source_pin";
  if (owners.size !== snapshot.source_pins.length) return "duplicate_source_pin";
  if (snapshot.source_pins.some((pin) =>
    !UUID.test(pin.projection_id) || !SHA256.test(pin.digest) ||
    !Number.isSafeInteger(pin.revision_or_generation) || pin.revision_or_generation < 1 ||
    pin.cutoff !== snapshot.source_cutoff.aggregate_sequence
  )) return "invalid_source_pin";
  return null;
}

export function decideEvent(event: C13Event, owner: OwnerTuple, cursor: VerifiedCursor): EventDecision {
  if (event.contract_major !== C13_EVENT_MAJOR) {
    return { kind: "reconcile", state: "unsupported", reason: "unsupported_event_major" };
  }
  if (!sameOwner(event.owner, owner)) {
    return { kind: "reconcile", state: "conflict", reason: "owner_mismatch" };
  }
  if (event.aggregate_sequence < cursor.sequence) return { kind: "duplicate" };
  if (event.aggregate_sequence === cursor.sequence) {
    return event.event_digest === cursor.digest
      ? { kind: "duplicate" }
      : { kind: "reconcile", state: "conflict", reason: "sequence_digest_fork" };
  }
  if (event.aggregate_sequence !== cursor.sequence + 1) {
    return { kind: "reconcile", state: "catching_up", reason: "sequence_gap" };
  }
  if (!(cursor.sequence === 0 && event.predecessor_digest === "") && event.predecessor_digest !== cursor.digest) {
    return { kind: "reconcile", state: "conflict", reason: "predecessor_digest_mismatch" };
  }
  return {
    kind: "accept",
    cursor: { sequence: event.aggregate_sequence, digest: event.event_digest },
  };
}

export function shouldAcceptReplacement(previous: C13CockpitSnapshot, next: C13CockpitSnapshot): boolean {
  if (!sameOwner(previous.owner, next.owner)) return false;
  if (next.attempt_generation < previous.attempt_generation) return false;
  if (next.source_cutoff.aggregate_sequence < previous.source_cutoff.aggregate_sequence) return false;
  if (next.source_cutoff.aggregate_sequence === previous.source_cutoff.aggregate_sequence &&
    (next.source_cutoff.event_digest !== previous.source_cutoff.event_digest ||
      next.snapshot_digest !== previous.snapshot_digest ||
      next.attempt_generation !== previous.attempt_generation)) return false;
  return validateSnapshot(next, previous.owner) === null;
}
