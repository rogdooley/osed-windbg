import { describe, expect, it } from "vitest";
import { planRegisterSetupPacking } from "../src/rop/register_setup";
import type { CapabilityIndex } from "../src/rop/capabilities";
import type { RopGadget } from "../src/rop/types";

function insn(mnemonic: string, operands: string[]) {
  return { mnemonic, operands };
}

function makeGadget(instructions: Array<{ mnemonic: string; operands: string[] }>, address: number, score = 50): RopGadget {
  const first = instructions[0];
  return {
    schemaVersion: "v1",
    canonicalId: `mock_${address}`,
    instructions,
    locations: [{ module: "test", virtualAddress: address, executable: true }],
    semanticSummary: { instructions: [], effects: [], unknowns: [], netTransform: {} },
    categories: [],
    score,
    scoreReasons: [],
    classificationReasons: [],
    capabilities: [{ kind: "LOAD_REGISTER", register: first.operands[0] ?? "eax", evidence: "mock" }],
  } as unknown as RopGadget;
}

function buildMockIndex(gadgets: RopGadget[]): CapabilityIndex {
  const capabilityMap = new Map<string, RopGadget[]>();
  for (const g of gadgets) {
    for (const cap of g.capabilities) {
      const key = [cap.kind, cap.register ?? "", cap.targetRegister ?? ""].join(":");
      const existing = capabilityMap.get(key) ?? [];
      existing.push(g);
      capabilityMap.set(key, existing);
    }
  }
  return {
    gadgets,
    capabilityMap,
    loadRegister: () => [],
    zeroRegister: () => [],
    moveIntoRegister: () => [],
    exchangeWithRegister: () => [],
    stackPivotCandidates: () => [],
    memoryReadCandidates: () => [],
    memoryWriteCandidates: () => [],
    query: () => [],
  };
}

describe("register setup packing", () => {
  it("packs two targets into one multi-pop gadget", () => {
    const index = buildMockIndex([
      makeGadget([insn("pop", ["ecx"]), insn("pop", ["ebx"]), insn("ret", [])], 0x11110000),
    ]);
    const plan = planRegisterSetupPacking(index, { ecx: 0x11111111, ebx: 0x22222222 }, []);
    expect(plan.success).toBe(true);
    // one gadget + two value slots
    expect(plan.steps).toHaveLength(3);
    expect(plan.steps[0].kind).toBe("gadget");
    expect(plan.steps[1].value).toBe(0x11111111);
    expect(plan.steps[2].value).toBe(0x22222222);
    expect(new Set(plan.ordered)).toEqual(new Set(["ecx", "ebx"]));
  });

  it("junk-fills a pop that is not a target", () => {
    const index = buildMockIndex([
      makeGadget([insn("pop", ["ecx"]), insn("pop", ["ebx"]), insn("ret", [])], 0x11110000),
    ]);
    const plan = planRegisterSetupPacking(index, { ecx: 0x11111111 }, []);
    expect(plan.success).toBe(true);
    expect(plan.steps).toHaveLength(3);
    expect(plan.steps[1].value).toBe(0x11111111);
    expect(plan.steps[2].value).toBe(0x41414141); // ebx slot junked
    expect(plan.steps[2].comment).toContain("ebx");
  });

  it("orders gadgets so a collateral write lands before its target is finalized", () => {
    const index = buildMockIndex([
      // sets esi but incidentally writes eax
      makeGadget([insn("pop", ["esi"]), insn("add", ["eax", "0x4"]), insn("ret", [])], 0x11110000),
      // sets eax cleanly
      makeGadget([insn("pop", ["eax"]), insn("ret", [])], 0x22220000),
    ]);
    const plan = planRegisterSetupPacking(index, { esi: 0x11111111, eax: 0x22222222 }, []);
    expect(plan.success).toBe(true);
    // esi must be finalized before eax, so the add-eax collateral is harmless
    expect(plan.ordered.indexOf("esi")).toBeLessThan(plan.ordered.indexOf("eax"));
    // and eax ends up correct
    const eaxSlot = plan.steps.find((s) => s.comment === "eax = 0x22222222");
    expect(eaxSlot).toBeDefined();
  });

  it("reports an honest conflict when no ordering avoids a clobber", () => {
    const index = buildMockIndex([
      makeGadget([insn("pop", ["esi"]), insn("mov", ["ebx", "eax"]), insn("ret", [])], 0x11110000),
      makeGadget([insn("pop", ["ebx"]), insn("mov", ["esi", "eax"]), insn("ret", [])], 0x22220000),
    ]);
    const plan = planRegisterSetupPacking(index, { esi: 0x11111111, ebx: 0x22222222 }, []);
    expect(plan.success).toBe(false);
    expect(plan.unresolved).toHaveLength(1);
    expect(plan.unresolved[0].reason).toMatch(/already-finalized/);
  });

  it("flags a badchar-tainted value and points at rop.construct", () => {
    const index = buildMockIndex([
      makeGadget([insn("pop", ["ebx"]), insn("ret", [])], 0x11223344),
    ]);
    const plan = planRegisterSetupPacking(index, { ebx: 0x00000041 }, [0x00]);
    expect(plan.success).toBe(false);
    expect(plan.unresolved[0].register).toBe("ebx");
    expect(plan.unresolved[0].reason).toMatch(/rop\.construct/);
  });

  it("excludes gadgets whose address contains a badchar", () => {
    const index = buildMockIndex([
      makeGadget([insn("pop", ["ebx"]), insn("ret", [])], 0x10001000), // 0x00 bytes in address
    ]);
    const plan = planRegisterSetupPacking(index, { ebx: 0x11111111 }, [0x00]);
    expect(plan.success).toBe(false);
    expect(plan.unresolved[0].register).toBe("ebx");
  });

  it("emits filler for an add esp skip inside a setup gadget", () => {
    const index = buildMockIndex([
      makeGadget([insn("pop", ["esi"]), insn("add", ["esp", "0x4"]), insn("ret", [])], 0x11110000),
    ]);
    const plan = planRegisterSetupPacking(index, { esi: 0x11111111 }, []);
    expect(plan.success).toBe(true);
    // gadget, esi value, one filler word for the 4-byte skip
    expect(plan.steps).toHaveLength(3);
    expect(plan.steps[2].comment).toContain("add esp");
  });

  it("does not use a gadget that pops then overwrites the same register", () => {
    // pop esi ; xor esi, esi -> esi ends up zero, not the popped value
    const index = buildMockIndex([
      makeGadget([insn("pop", ["esi"]), insn("xor", ["esi", "esi"]), insn("ret", [])], 0x11110000),
    ]);
    const plan = planRegisterSetupPacking(index, { esi: 0x11111111 }, []);
    expect(plan.success).toBe(false);
  });
});
