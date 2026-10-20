import { describe, expect, test } from "vitest";
import {
  captureStdcallFrame,
  evaluatePostcondition,
  resolveDynamicDispatch,
  ProofSessionMachine,
  ProofSessionStore,
  type CheckpointObservation,
  type ProofCheckpoint,
} from "../src/rop/proof";
import fixture from "./fixtures/proof/slot-call-virtualprotect.json";
import { ReplayProofAdapter, type ReplayFixture } from "./helpers/replay_proof_adapter";

function observation(registers: CheckpointObservation["registers"]): CheckpointObservation {
  return { checkpointId: 0, timestamp: "2026-01-01T00:00:00.000Z", outcome: "VERIFIED", registers, assertions: [], reason: "fixture" };
}

describe("IAT dispatch and DEP postconditions", () => {
  test("resolves the API entry by reading four little-endian bytes from the slot", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const registers = adapter.readRegisters();
    const checkpoint: ProofCheckpoint = {
      id: 1,
      stepIndex: 2,
      label: "VirtualProtect API entry",
      target: { kind: "memory-dword", address: { kind: "register", register: "eax", checkpoint: "before" } },
      assertions: [{
        subject: "ESP",
        expected: { kind: "register-offset", register: "esp", checkpoint: "before", offset: 4 },
        confidence: "EXACT",
        evidence: ["mov eax, [eax] ; ret", "jmp eax"],
        required: true,
      }],
      provenance: [
        { address: 0x10006000n, instructions: ["mov eax, [eax]", "ret"] },
        { address: 0x10007000n, instructions: ["jmp eax"] },
      ],
      dynamic: true,
    };
    const resolved = resolveDynamicDispatch(checkpoint, observation(registers), adapter);
    expect(resolved).toMatchObject({ status: "VERIFIED", slotAddress: 0x20002000n, target: 0x12345678n });
    expect(resolved.expectedEsp).toBe(0x0012ff04n);
    expect(resolved.rawBytes).toEqual(Uint8Array.from([0x78, 0x56, 0x34, 0x12]));
  });

  test("captures authoritative VirtualProtect arguments from the runtime stack", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    adapter.advanceStop();
    const frame = captureStdcallFrame("VirtualProtect", adapter.readRegisters().esp, adapter);
    expect(frame.status).toBe("VERIFIED");
    expect(frame.returnAddress).toBe(0x10009000n);
    expect(frame.arguments.slice(0, 2)).toEqual([0x41414000n, 0x1000n]);
  });

  test("verifies VirtualProtect success and executable coverage over its runtime range", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    adapter.advanceStop();
    const frame = captureStdcallFrame("VirtualProtect", adapter.readRegisters().esp, adapter);
    adapter.advanceStop();
    const result = evaluatePostcondition({ api: "VirtualProtect" }, frame, adapter.readRegisters(), adapter);
    expect(result).toMatchObject({ status: "VERIFIED", rangeBase: 0x41414000n, rangeSize: 0x1000n });
  });

  test("uses the VirtualAlloc return value as the authoritative allocation base", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const frame = {
      status: "VERIFIED" as const,
      api: "VirtualAlloc",
      esp: 0x12ff00n,
      returnAddress: 0x10009000n,
      arguments: [0n, 0x1000n, 0x3000n, 0x40n],
      rawBytes: new Uint8Array(20),
      reason: "captured",
    };
    const registers = { ...adapter.readRegisters(), eip: 0x10009000n, esp: 0x12ff20n, registers: { ...adapter.readRegisters().registers, eax: 0x41414000n } };
    const result = evaluatePostcondition({ api: "VirtualAlloc" }, frame, registers, adapter);
    expect(result.rangeBase).toBe(0x41414000n);
  });

  test("keeps unsupported APIs and zero-sized ranges unverified or failed", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    expect(captureStdcallFrame("WinExec", 0x12ff00n, adapter).status).toBe("UNVERIFIED");
    const result = evaluatePostcondition({ api: "VirtualProtect" }, {
      status: "VERIFIED", api: "VirtualProtect", esp: 0n, returnAddress: 0x10001000n,
      arguments: [0x41414000n, 0n, 0x40n, 0x30000000n], rawBytes: new Uint8Array(20), reason: "captured",
    }, { ...adapter.readRegisters(), eip: 0x10001000n }, adapter);
    expect(result.status).toBe("FAILED");
  });

  test("keeps gadget execution and the postcondition as separate session outcomes", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const machine = new ProofSessionMachine(adapter, new ProofSessionStore());
    const dispatch: ProofCheckpoint = {
      id: 1, stepIndex: 1, label: "VirtualProtect API entry",
      target: { kind: "memory-dword", address: { kind: "register", register: "eax", checkpoint: "before" } },
      assertions: [{ subject: "ESP", expected: { kind: "register-offset", register: "esp", checkpoint: "before", offset: 4 }, confidence: "EXACT", evidence: [], required: true }],
      provenance: [], dynamic: true,
    };
    const session = machine.start({
      mode: "guided",
      postcondition: true,
      sessionId: "post",
      nonce: "n",
      plan: {
        steps: [], api: "VirtualProtect", incompleteReasons: [],
        checkpoints: [{ id: 0, stepIndex: 0, label: "deref", target: { kind: "constant", value: 0x10006000n }, assertions: [], provenance: [], dynamic: false }, dispatch],
      },
    });
    expect(session.state).toBe("ARMED");
    adapter.advanceStop();
    const armed = machine.observeAndAdvance();
    expect(armed.state).toBe("POSTCONDITION_ARMED");
    expect(armed.executionStatus).toBe("VERIFIED");
    expect(armed.objectiveStatus).toBe("UNVERIFIED");
    expect(armed.runtimeFrame?.arguments.slice(0, 2)).toEqual([0x41414000n, 0x1000n]);
    adapter.advanceStop();
    const completed = machine.observeAndAdvance();
    expect(completed.state).toBe("POSTCONDITION_OBSERVED");
    expect(completed.executionStatus).toBe("VERIFIED");
    expect(completed.objectiveStatus).toBe("VERIFIED");
  });
});
