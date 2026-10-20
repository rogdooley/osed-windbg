import { describe, expect, test } from "vitest";
import {
  PROOF_RECORD_SCHEMA_VERSION,
  ProofController,
  ProofSessionStore,
  renderProofMarkdown,
  serializeProofRecord,
  type ProofSession,
} from "../src/rop/proof";
import fixture from "./fixtures/proof/linear-good.json";
import { ReplayProofAdapter, type ReplayFixture } from "./helpers/replay_proof_adapter";

function recordedSession(): ProofSession {
  return {
    id: "evidence-1",
    mode: "guided",
    state: "FAILED",
    plan: { steps: [], checkpoints: [], incompleteReasons: [] },
    checkpointIndex: 1,
    baselineFingerprint: {
      processId: 1n, threadId: 2n, architecture: "x86", pointerSize: 4,
      targetPath: "C:\\labs\\target.exe", targetSha256: "a".repeat(64), complete: true,
      incompleteReasons: [], modules: [], gadgets: [], protections: [],
    },
    observations: [{
      checkpointId: 0,
      timestamp: "2026-01-01T00:00:00.000Z",
      outcome: "FAILED",
      registers: { eip: 0x10001000n, esp: 0x12ff04n, registers: {} },
      assertions: [{
        subject: "ESP", expectedExpression: "ESP@before+8", expectedValue: 0x12ff00n,
        observedValue: 0x12ff04n, status: "FAILED", confidence: "EXACT", evidence: ["ret"],
        reason: "ESP differs by +4 bytes", differenceBytes: 4,
      }],
      reason: "ESP differs by +4 bytes",
    }],
    events: [
      { sequence: 0, timestamp: "2026-01-01T00:00:00.000Z", kind: "breakpoint-armed", detail: { id: 7 } },
      { sequence: 1, timestamp: "2026-01-01T00:00:01.000Z", kind: "checkpoint-observed", detail: { outcome: "FAILED" } },
    ],
    executionStatus: "FAILED",
    objectiveStatus: "UNVERIFIED",
    objectiveReason: "not requested",
  };
}

describe("proof evidence export", () => {
  test("serializes both outcomes and retains failed assertions and events", () => {
    const record = serializeProofRecord(recordedSession());
    expect(record.schemaVersion).toBe(PROOF_RECORD_SCHEMA_VERSION);
    expect(record.executionStatus).toBe("FAILED");
    expect(record.objectiveStatus).toBe("UNVERIFIED");
    expect(record.observations[0].assertions[0]).toMatchObject({ status: "FAILED", differenceBytes: 4 });
    expect(record.events.map((event) => event.kind)).toEqual(["breakpoint-armed", "checkpoint-observed"]);
    expect(JSON.stringify(record)).toContain("0x0012ff04");
  });

  test("renders deterministic Markdown with the evidence boundary", () => {
    const markdown = renderProofMarkdown(serializeProofRecord(recordedSession()));
    expect(markdown).toContain("Execution status: **FAILED**");
    expect(markdown).toContain("Objective status: **UNVERIFIED** — not requested");
    expect(markdown).toContain("ESP differs by +4 bytes");
  });

  test("requires an explicit export path and does not mutate session state", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const store = new ProofSessionStore();
    const session = recordedSession();
    store.add(session);
    const writes: Array<{ path: string; content: string }> = [];
    const controller = new ProofController({ adapter, store, getDefaultInput: () => undefined, writeText: (path, content) => writes.push({ path, content }) });
    expect(controller.execute({ action: "export" }).error).toMatch(/explicit path/i);
    const exported = controller.execute({ action: "export", path: "C:\\notes\\proof.json" });
    expect(exported.exportedPath).toBe("C:\\notes\\proof.json");
    expect(writes[0].content).toContain('"executionStatus": "FAILED"');
    expect(session.state).toBe("FAILED");
  });

  test("does not claim command success when execution is verified but objective was not requested", () => {
    const session = recordedSession();
    session.state = "EXECUTION_COMPLETE";
    session.executionStatus = "VERIFIED";
    const store = new ProofSessionStore();
    store.add(session);
    const controller = new ProofController({ adapter: new ReplayProofAdapter(fixture as ReplayFixture), store, getDefaultInput: () => undefined });
    const outcome = controller.execute({ action: "status" });
    expect(outcome.success).toBe(false);
    expect(outcome.session).toMatchObject({ executionStatus: "VERIFIED", objectiveStatus: "UNVERIFIED", objectiveReason: "not requested" });
  });
});
