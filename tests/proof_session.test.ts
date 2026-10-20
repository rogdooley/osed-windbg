import { describe, expect, test } from "vitest";
import {
  ProofSessionMachine,
  ProofSessionStore,
  type ProofCheckpoint,
  type ProofPlan,
} from "../src/rop/proof";
import goodFixture from "./fixtures/proof/linear-good.json";
import unexpectedFixture from "./fixtures/proof/unexpected-stop.json";
import { ReplayProofAdapter, type ReplayFixture } from "./helpers/replay_proof_adapter";

function checkpoint(id: number, target: bigint, assertions: ProofCheckpoint["assertions"] = []): ProofCheckpoint {
  return { id, stepIndex: id, label: `checkpoint ${id}`, target: { kind: "constant", value: target }, assertions, provenance: [], dynamic: false };
}

function linearPlan(): ProofPlan {
  return {
    steps: [],
    checkpoints: [
      checkpoint(0, 0x10001000n),
      checkpoint(1, 0x10002000n, [{
        subject: "ESP",
        expected: { kind: "register-offset", register: "esp", checkpoint: "before", offset: 8 },
        confidence: "EXACT",
        evidence: ["pop eax", "ret"],
        required: true,
      }]),
    ],
    incompleteReasons: [],
  };
}

describe("ProofSessionMachine", () => {
  test("consumes the current entry and owns only the next guided breakpoint", () => {
    const adapter = new ReplayProofAdapter(goodFixture as ReplayFixture);
    const store = new ProofSessionStore();
    const machine = new ProofSessionMachine(adapter, store);
    const started = machine.start({ mode: "guided", plan: linearPlan(), sessionId: "s1", nonce: "n1" });

    expect(started.checkpointIndex).toBe(1);
    expect(started.state).toBe("ARMED");
    expect(adapter.actions).toEqual([expect.objectContaining({ kind: "set", address: 0x10002000n })]);
    expect(adapter.listBreakpoints()).toMatchObject({ ok: true, value: [expect.objectContaining({ oneShot: true })] });

    adapter.advanceStop();
    const completed = machine.observeAndAdvance();
    expect(completed.state).toBe("EXECUTION_COMPLETE");
    expect(completed.executionStatus).toBe("VERIFIED");
    expect(completed.checkpointIndex).toBe(2);
  });

  test("unexpected stops do not advance or surrender breakpoint ownership", () => {
    const adapter = new ReplayProofAdapter(unexpectedFixture as ReplayFixture);
    const store = new ProofSessionStore();
    const machine = new ProofSessionMachine(adapter, store);
    machine.start({ mode: "guided", plan: linearPlan(), sessionId: "s2", nonce: "n2" });
    adapter.advanceStop();

    const session = machine.observeAndAdvance();
    expect(session.checkpointIndex).toBe(1);
    expect(session.state).toBe("ARMED");
    expect(session.observations.at(-1)?.outcome).toBe("UNEXPECTED_STOP");
    expect(session.ownedBreakpoint).toBeDefined();
  });

  test("observe mode never installs a breakpoint and never skips ahead", () => {
    const adapter = new ReplayProofAdapter(unexpectedFixture as ReplayFixture);
    const machine = new ProofSessionMachine(adapter, new ProofSessionStore());
    const session = machine.start({ mode: "observe", plan: linearPlan(), sessionId: "s3", nonce: "n3" });
    expect(session.checkpointIndex).toBe(1);
    expect(adapter.actions).toEqual([]);
    adapter.advanceStop();
    const stopped = machine.observeAndAdvance();
    expect(stopped.checkpointIndex).toBe(1);
    expect(stopped.observations.at(-1)?.outcome).toBe("UNEXPECTED_STOP");
    expect(adapter.actions).toEqual([]);
  });

  test("resolves a pivot target and absolute ESP from the observed source register", () => {
    const adapter = new ReplayProofAdapter(goodFixture as ReplayFixture);
    const machine = new ProofSessionMachine(adapter, new ProofSessionStore());
    const plan: ProofPlan = {
      steps: [],
      checkpoints: [
        checkpoint(0, 0x10001000n),
        {
          ...checkpoint(1, 0n, [{
            subject: "ESP",
            expected: { kind: "register-offset", register: "eax", checkpoint: "before", offset: 4 },
            confidence: "EXACT",
            evidence: ["xchg eax, esp", "ret"],
            required: true,
          }]),
          target: { kind: "memory-dword", address: { kind: "register", register: "eax", checkpoint: "before" } },
          dynamic: true,
        },
      ],
      incompleteReasons: [],
    };
    const session = machine.start({ mode: "guided", plan, sessionId: "pivot", nonce: "np" });
    expect(session.ownedBreakpoint?.address).toBe(0x12345678n);
    expect(session.events.some((event) => event.kind === "dynamic-target-resolved")).toBe(true);
  });

  test("cancellation deletes only the active owned breakpoint", () => {
    const adapter = new ReplayProofAdapter(goodFixture as ReplayFixture);
    const machine = new ProofSessionMachine(adapter, new ProofSessionStore());
    machine.start({ mode: "guided", plan: linearPlan(), sessionId: "s4", nonce: "n4" });
    const session = machine.cancel();
    expect(session?.state).toBe("CANCELLED");
    expect(adapter.actions.map((action) => action.kind)).toEqual(["set", "delete"]);
  });

  test("reports and explicitly reclaims exact orphan markers", () => {
    const adapter = new ReplayProofAdapter(goodFixture as ReplayFixture);
    const owned = adapter.setOneShot(0x10002000n, "osed-proof:v1:old:n:1");
    expect(owned.ok).toBe(true);
    const machine = new ProofSessionMachine(adapter, new ProofSessionStore());
    expect(() => machine.start({ mode: "guided", plan: linearPlan() })).toThrow(/orphan/i);
    const results = machine.cancelOrphans();
    expect(results).toEqual([expect.objectContaining({ status: "deleted" })]);
  });

  test("refuses marker prefixes and unsupported marker versions during orphan cleanup", () => {
    const adapter = new ReplayProofAdapter(goodFixture as ReplayFixture);
    adapter.setOneShot(0x10002000n, "osed-proof:");
    adapter.setOneShot(0x10003000n, "osed-proof:v2:old:n:1");
    const machine = new ProofSessionMachine(adapter, new ProofSessionStore());
    const results = machine.cancelOrphans();
    expect(results).toEqual([expect.objectContaining({ status: "unsupported-marker-version" })]);
    expect(adapter.actions.filter((action) => action.kind === "delete")).toHaveLength(0);
  });
});
