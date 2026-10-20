import { describe, expect, test } from "vitest";
import { compareCheckpoint, type ProofCheckpoint } from "../src/rop/proof";
import fixture from "./fixtures/proof/esp-divergence.json";
import linearFixture from "./fixtures/proof/linear-good.json";
import { ReplayProofAdapter, type ReplayFixture } from "./helpers/replay_proof_adapter";

function checkpoint(overrides: Partial<ProofCheckpoint> = {}): ProofCheckpoint {
  return {
    id: 1,
    stepIndex: 2,
    label: "next gadget",
    target: { kind: "constant", value: 0x10002000n },
    assertions: [
      {
        subject: "ESP",
        expected: { kind: "register-offset", register: "esp", checkpoint: "before", offset: 8 },
        confidence: "EXACT",
        evidence: ["pop eax", "ret"],
        required: true,
      },
      {
        subject: "EAX",
        expected: { kind: "constant", value: 0x22222222n },
        confidence: "EXACT",
        evidence: ["pop eax"],
        required: true,
      },
    ],
    provenance: [],
    dynamic: false,
    ...overrides,
  };
}

describe("compareCheckpoint", () => {
  test("stops at the first ESP divergence after matching EIP", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const previous = adapter.readRegisters();
    adapter.advanceStop();

    const observation = compareCheckpoint({ checkpoint: checkpoint(), previous }, adapter);

    expect(observation.outcome).toBe("FAILED");
    expect(observation.assertions.map((assertion) => assertion.subject)).toEqual(["EIP", "ESP"]);
    expect(observation.assertions[0].status).toBe("VERIFIED");
    expect(observation.assertions[1]).toMatchObject({
      status: "FAILED",
      expectedValue: 0x0012ff08n,
      observedValue: 0x0012ff0cn,
      differenceBytes: 4,
    });
  });

  test("reports an unexpected stop before evaluating state assertions", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const previous = adapter.readRegisters();
    adapter.advanceStop();

    const observation = compareCheckpoint({
      checkpoint: checkpoint({ target: { kind: "constant", value: 0x77777777n } }),
      previous,
    }, adapter);

    expect(observation.outcome).toBe("UNEXPECTED_STOP");
    expect(observation.assertions).toHaveLength(1);
    expect(observation.assertions[0]).toMatchObject({ subject: "EIP", status: "FAILED" });
  });

  test("reports unknown memory aliasing as unverified", () => {
    const adapter = new ReplayProofAdapter(linearFixture as ReplayFixture);
    const previous = adapter.readRegisters();
    const observation = compareCheckpoint({
      checkpoint: checkpoint({
        target: { kind: "constant", value: 0x10001000n },
        assertions: [{
          subject: "MEMORY[unknown]",
          expected: { kind: "unknown", reason: "memory alias is unknown" },
          observed: { kind: "unknown", reason: "memory alias is unknown" },
          confidence: "UNKNOWN",
          evidence: ["unsupported effective address"],
          required: false,
        }],
      }),
      previous,
    }, adapter);

    expect(observation.outcome).toBe("UNVERIFIED");
    expect(observation.assertions[1]).toMatchObject({
      subject: "MEMORY[unknown]",
      status: "UNVERIFIED",
    });
  });

  test("compares a known-width memory observation exactly", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const previous = adapter.readRegisters();
    adapter.advanceStop();
    const observation = compareCheckpoint({
      checkpoint: checkpoint({
        assertions: [{
          subject: "MEMORY[0x30000000]",
          expected: { kind: "constant", value: 0x12345678n },
          observed: { kind: "memory-dword", address: { kind: "constant", value: 0x30000000n } },
          confidence: "EXACT",
          evidence: ["mov [eax], ecx"],
          required: true,
        }],
      }),
      previous,
    }, adapter);

    expect(observation.outcome).toBe("VERIFIED");
    expect(observation.assertions[1]).toMatchObject({
      subject: "MEMORY[0x30000000]",
      status: "VERIFIED",
      expectedValue: 0x12345678n,
      observedValue: 0x12345678n,
    });
  });
});
