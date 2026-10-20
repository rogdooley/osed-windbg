import { describe, expect, test } from "vitest";
import { initializeScript } from "../src/index";
import { buildCapabilityIndexFromRpPlusText } from "../src/rop";
import {
  ProofController,
  ProofSessionStore,
  isAllowedProofCommand,
  type ProofPlanInput,
} from "../src/rop/proof";
import fixture from "./fixtures/proof/linear-good.json";
import { ReplayProofAdapter, type ReplayFixture } from "./helpers/replay_proof_adapter";

function installMinimalHost(): void {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: () => undefined },
    currentProcess: { Is64Bit: false, Modules: [] },
    currentThread: { Registers: { User: {} } },
    memory: { readMemoryValues: () => [] },
  };
}

describe("ProofController", () => {
  const corpus = buildCapabilityIndexFromRpPlusText("0x10001000: pop eax ; ret ;\n0x10002000: ret ;", {
    provenance: { module: "proof.dll", executable: "EXACT", writable: "CONSERVATIVE", aslr: "CONSERVATIVE", rebaseable: "CONSERVATIVE" },
  });
  test("bare prove requires an active session", () => {
    const controller = new ProofController({
      adapter: new ReplayProofAdapter(fixture as ReplayFixture),
      store: new ProofSessionStore(),
      getDefaultInput: () => undefined,
    });
    const outcome = controller.execute();
    expect(outcome.success).toBe(false);
    expect(outcome.error).toMatch(/No active proof session/);
  });

  test("defaults a start request to guided mode and consumes the generated chain input", () => {
    const input: ProofPlanInput = { chain: "10001000 41414141 10002000", corpus };
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const controller = new ProofController({ adapter, store: new ProofSessionStore(), getDefaultInput: () => input });
    const outcome = controller.execute({});
    expect(outcome.session?.mode).toBe("guided");
    expect(outcome.session?.state).toBe("ARMED");
    expect(adapter.actions).toContainEqual(expect.objectContaining({ kind: "set", address: 0x10002000n }));
  });

  test("dispatches status, cancel, history, and explicit orphan cleanup", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const store = new ProofSessionStore();
    const controller = new ProofController({
      adapter,
      store,
      getDefaultInput: () => ({ chain: "10001000 41414141 10002000", corpus }),
    });
    controller.execute({ mode: "guided" });
    expect(controller.execute({ action: "status" }).session?.state).toBe("ARMED");
    expect(controller.execute({ action: "history" }).history).toHaveLength(1);
    expect(controller.execute({ action: "cancel" }).session?.state).toBe("CANCELLED");
    expect(controller.execute({ action: "cancel", orphans: true }).orphanResults).toEqual([]);
  });
});

describe("WinDbg proof command allowlist", () => {
  test.each(["bl", "r @eip @esp @eax", "u 0x10001000 L4", "!vprot 0x10001000", "bp /1 0x10002000 \".echo osed-proof:v1:s:n:1\"", "bc 7"])("accepts %s", (command) => {
    expect(isAllowedProofCommand(command)).toBe(true);
  });

  test.each(["g", "gc", "p", "t", "r eax=1", "eb 0x1000 90", "bc *", ".shell calc"])("rejects %s", (command) => {
    expect(isAllowedProofCommand(command)).toBe(false);
  });
});

test("public namespace exposes rop.prove", () => {
  installMinimalHost();
  initializeScript();
  const api = (globalThis as unknown as { osed: { rop: { prove?: (...args: unknown[]) => unknown } } }).osed;
  expect(api.rop.prove).toBeTypeOf("function");
  api.rop.prove?.();
});
