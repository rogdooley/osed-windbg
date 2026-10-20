import { PROOF_RECORD_SCHEMA_VERSION, type ProofEvent, type ProofRecordV1, type ProofSession } from "./types";

function hex32(value: bigint | undefined): string | undefined {
  return value === undefined ? undefined : `0x${BigInt.asUintN(32, value).toString(16).padStart(8, "0")}`;
}

function jsonSafe(value: unknown): unknown {
  if (typeof value === "bigint") return hex32(value);
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, jsonSafe(entry)]));
  }
  return value;
}

export function serializeProofRecord(session: ProofSession): ProofRecordV1 {
  return {
    schemaVersion: PROOF_RECORD_SCHEMA_VERSION,
    sessionId: session.id,
    mode: session.mode,
    state: session.state,
    executionStatus: session.executionStatus,
    objectiveStatus: session.objectiveStatus,
    objectiveReason: session.objectiveReason,
    targetPath: session.baselineFingerprint.targetPath,
    targetSha256: session.baselineFingerprint.targetSha256,
    observations: session.observations.map((observation) => ({
      checkpointId: observation.checkpointId,
      timestamp: observation.timestamp,
      outcome: observation.outcome,
      reason: observation.reason,
      assertions: observation.assertions.map((assertion) => ({
        subject: assertion.subject,
        expectedExpression: assertion.expectedExpression,
        expectedValue: hex32(assertion.expectedValue),
        observedValue: hex32(assertion.observedValue),
        status: assertion.status,
        reason: assertion.reason,
        differenceBytes: assertion.differenceBytes,
      })),
    })),
    events: session.events.map((event) => ({ ...event, detail: jsonSafe(event.detail) as Record<string, unknown> })),
  };
}

export function renderProofMarkdown(record: ProofRecordV1): string {
  const lines = [
    `# ROP proof ${record.sessionId}`,
    "",
    `- Execution status: **${record.executionStatus}**`,
    `- Objective status: **${record.objectiveStatus}** — ${record.objectiveReason}`,
    `- Session state: ${record.state}`,
    `- Target: ${record.targetPath || "unavailable"}`,
    `- SHA-256: ${record.targetSha256 ?? "unavailable"}`,
    "",
    "## Checkpoints",
    "",
  ];
  for (const observation of record.observations) {
    lines.push(`### Checkpoint ${observation.checkpointId}: ${observation.outcome}`, "", observation.reason, "");
    for (const assertion of observation.assertions) {
      const values = assertion.expectedValue === undefined && assertion.observedValue === undefined
        ? ""
        : ` (expected ${assertion.expectedValue ?? "unavailable"}, observed ${assertion.observedValue ?? "unavailable"})`;
      lines.push(`- ${assertion.subject}: **${assertion.status}**${values} — ${assertion.reason}`);
    }
    lines.push("");
  }
  lines.push("## Event log", "");
  for (const event of record.events) lines.push(`- ${event.sequence}: ${event.kind} (${event.timestamp})`);
  return `${lines.join("\n")}\n`;
}

const ACTIVE_STATES = new Set([
  "ARMED",
  "CHECKPOINT_REACHED",
  "POSTCONDITION_ARMED",
  "POSTCONDITION_OBSERVED",
]);

export class ProofSessionStore {
  private readonly sessions: ProofSession[] = [];
  private eventSequence = 0;

  add(session: ProofSession): ProofSession {
    if (this.active()) throw new Error("A ROP proof session is already active.");
    this.sessions.push(session);
    return session;
  }

  active(): ProofSession | undefined {
    const session = this.sessions[this.sessions.length - 1];
    return session && ACTIVE_STATES.has(session.state) ? session : undefined;
  }

  latest(): ProofSession | undefined {
    return this.sessions[this.sessions.length - 1];
  }

  history(): readonly ProofSession[] {
    return this.sessions;
  }

  appendEvent(session: ProofSession, kind: string, detail: Record<string, unknown> = {}): ProofEvent {
    const event: ProofEvent = {
      sequence: this.eventSequence,
      timestamp: new Date().toISOString(),
      kind,
      detail,
    };
    this.eventSequence += 1;
    session.events.push(event);
    return event;
  }
}
