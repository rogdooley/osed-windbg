import { describe, expect, it } from "vitest";
import { planRegisterSetupPacking } from "../src/rop/register_setup";
import type { CapabilityIndex } from "../src/rop/capabilities";
import type { RopGadget } from "../src/rop/types";

function insn(mnemonic: string, operands: string[]) {
  return { mnemonic, operands };
}

function inferCapabilities(instructions: Array<{ mnemonic: string; operands: string[] }>) {
  const caps: Array<Record<string, string>> = [];
  for (const insn of instructions) {
    const m = insn.mnemonic.toLowerCase();
    const dst = insn.operands[0]?.trim().toLowerCase();
    if (!dst) continue;
    if (m === "pop") caps.push({ kind: "LOAD_REGISTER", register: dst, evidence: "mock" });
    else if (m === "neg") caps.push({ kind: "REGISTER_NEGATE", register: dst, evidence: "mock" });
    else if (m === "not") caps.push({ kind: "REGISTER_NOT", register: dst, evidence: "mock" });
    else if (m === "add") caps.push({ kind: "REGISTER_ADD", register: dst, targetRegister: insn.operands[1]?.trim().toLowerCase() ?? "", evidence: "mock" });
    else if (m === "sub") caps.push({ kind: "REGISTER_SUB", register: dst, targetRegister: insn.operands[1]?.trim().toLowerCase() ?? "", evidence: "mock" });
  }
  return caps.length > 0 ? caps : [{ kind: "LOAD_REGISTER", register: "eax", evidence: "mock" }];
}

function makeGadget(instructions: Array<{ mnemonic: string; operands: string[] }>, address: number, score = 50): RopGadget {
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
    capabilities: inferCapabilities(instructions),
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
    expect(plan.unresolved[0].reason).toMatch(/finalized/);
  });

  it("builds a badchar-tainted value via arithmetic construction", () => {
    // 0x40 = 0x00000040 has null bytes; negate = 0xFFFFFFC0 is clean.
    const index = buildMockIndex([
      makeGadget([insn("pop", ["ecx"]), insn("ret", [])], 0x11223344),
      makeGadget([insn("neg", ["ecx"]), insn("ret", [])], 0x22334455),
    ]);
    const plan = planRegisterSetupPacking(index, { ecx: 0x00000040 }, [0x00]);
    expect(plan.success).toBe(true);
    expect(plan.ordered).toContain("ecx");
    // the popped intermediate is the badchar-free negation
    expect(plan.steps.some((s) => s.value === 0xffffffc0)).toBe(true);
  });

  it("builds a register before the pending target it borrows as scratch", () => {
    // edx can only be built via two-add using ebx as scratch; ebx uses esi.
    // The planner must build edx BEFORE ebx is finalized.
    const index = buildMockIndex([
      makeGadget([insn("pop", ["edx"]), insn("ret", [])], 0x11223344),
      makeGadget([insn("pop", ["ebx"]), insn("ret", [])], 0x22334455),
      makeGadget([insn("pop", ["esi"]), insn("ret", [])], 0x33445566),
      makeGadget([insn("add", ["edx", "ebx"]), insn("ret", [])], 0x44556677),
      makeGadget([insn("add", ["ebx", "esi"]), insn("ret", [])], 0x55667788),
    ]);
    const plan = planRegisterSetupPacking(index, { edx: 0x00001000, ebx: 0x00001000 }, [0x00]);
    expect(plan.success).toBe(true);
    expect(plan.ordered.indexOf("edx")).toBeLessThan(plan.ordered.indexOf("ebx"));
  });

  it("reports an unbuildable tainted value honestly", () => {
    // Only a direct pop; 0x41 is null-heavy and there is no neg/add gadget.
    const index = buildMockIndex([
      makeGadget([insn("pop", ["ebx"]), insn("ret", [])], 0x11223344),
    ]);
    const plan = planRegisterSetupPacking(index, { ebx: 0x00000041 }, [0x00]);
    expect(plan.success).toBe(false);
    expect(plan.unresolved[0].register).toBe("ebx");
    expect(plan.unresolved[0].reason).toMatch(/no pop\/arithmetic construction/);
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
