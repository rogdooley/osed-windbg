import { describe, expect, test } from "vitest";
import fixture from "./fixtures/proof/linear-good.json";
import { ReplayProofAdapter, type ReplayFixture } from "./helpers/replay_proof_adapter";
import { PROOF_RECORD_SCHEMA_VERSION, type ProofDebuggerAdapter } from "../src/rop/proof";

function useAdapter(adapter: ProofDebuggerAdapter): ProofDebuggerAdapter {
  return adapter;
}

describe("ProofDebuggerAdapter replay contract", () => {
  test("reads exact registers and memory from the active stop", () => {
    const adapter = useAdapter(new ReplayProofAdapter(fixture as ReplayFixture));

    expect(PROOF_RECORD_SCHEMA_VERSION).toBe("v1");
    expect(adapter.readRegisters().eip).toBe(0x10001000n);
    expect(adapter.readRegisters().esp).toBe(0x0012ff00n);
    expect(adapter.readMemory(0x20002000n, 4)).toEqual({
      ok: true,
      value: Uint8Array.from([0x78, 0x56, 0x34, 0x12]),
    });
    expect(adapter.readMemory(0x20002000n, 5)).toMatchObject({
      ok: false,
      error: { code: "memory-unreadable" },
    });
  });

  test("advances only when the replay harness requests the next stop", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);

    expect(adapter.readRegisters().eip).toBe(0x10001000n);
    expect("resume" in adapter).toBe(false);
    expect("continue" in adapter).toBe(false);

    adapter.advanceStop();

    expect(adapter.readRegisters().eip).toBe(0x10002000n);
  });

  test("deletes only an exact owned breakpoint tuple", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const created = adapter.setOneShot(0x10002000n, "osed.prove:v1:session:nonce:1");
    expect(created.ok).toBe(true);
    if (!created.ok) return;

    expect(adapter.deleteOwned(created.value).status).toBe("deleted");
    expect(adapter.actions.map((action) => action.kind)).toEqual(["set", "delete"]);
  });

  test("refuses deletion after breakpoint ID reuse", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const created = adapter.setOneShot(0x10002000n, "osed.prove:v1:session:nonce:1");
    expect(created.ok).toBe(true);
    if (!created.ok) return;

    adapter.replaceManagedBreakpoint(created.value.id, {
      id: created.value.id,
      address: 0x77777777n,
      enabled: true,
      oneShot: true,
      marker: "unrelated",
      command: "unrelated",
    });

    expect(adapter.deleteOwned(created.value)).toMatchObject({ status: "identity-mismatch" });
    expect(adapter.actions.map((action) => action.kind)).toEqual(["set"]);
  });
});
