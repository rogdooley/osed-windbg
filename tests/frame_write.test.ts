import { describe, expect, it } from "vitest";
import { planWriteFrame } from "../src/rop/frame_write";
import type { CapabilityIndex } from "../src/rop/capabilities";
import type { RopGadget } from "../src/rop/types";

function insn(mnemonic: string, operands: string[]) {
  return { mnemonic, operands };
}

function inferCaps(instructions: Array<{ mnemonic: string; operands: string[] }>) {
  const caps: Array<Record<string, string>> = [];
  for (const i of instructions) {
    const m = i.mnemonic.toLowerCase();
    const d = i.operands[0]?.trim().toLowerCase();
    if (!d) continue;
    if (m === "pop") caps.push({ kind: "LOAD_REGISTER", register: d, evidence: "mock" });
    else if (m === "add" && !d.startsWith("[")) caps.push({ kind: "REGISTER_ADD", register: d, targetRegister: i.operands[1]?.trim().toLowerCase() ?? "", evidence: "mock" });
  }
  return caps.length ? caps : [{ kind: "NONE", evidence: "mock" }];
}

function g(instructions: Array<{ mnemonic: string; operands: string[] }>, address: number): RopGadget {
  return {
    schemaVersion: "v1",
    canonicalId: `mock_${address}`,
    instructions,
    locations: [{ module: "test", virtualAddress: address, executable: true }],
    semanticSummary: { instructions: [], effects: [], unknowns: [], netTransform: {} },
    categories: [],
    score: 50,
    scoreReasons: [],
    classificationReasons: [],
    capabilities: inferCaps(instructions),
  } as unknown as RopGadget;
}

function index(gadgets: RopGadget[]): CapabilityIndex {
  const capabilityMap = new Map<string, RopGadget[]>();
  for (const gadget of gadgets) {
    for (const cap of gadget.capabilities) {
      const key = [cap.kind, cap.register ?? "", cap.targetRegister ?? ""].join(":");
      const arr = capabilityMap.get(key) ?? [];
      arr.push(gadget);
      capabilityMap.set(key, arr);
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

const core = [
  g([insn("pop", ["eax"]), insn("ret", [])], 0x11110001),
  g([insn("pop", ["ecx"]), insn("ret", [])], 0x11110002),
  g([insn("mov", ["dword ptr [eax]", "ecx"]), insn("ret", [])], 0x11110003),
  g([insn("add", ["eax", "0x4"]), insn("ret", [])], 0x11110004),
  g([insn("xchg", ["eax", "esp"]), insn("ret", [])], 0x11110005),
];

describe("write-based frame", () => {
  it("assembles a badchar-free frame and pivots", () => {
    const plan = planWriteFrame(
      index(core),
      { placeholder: "BUF" },
      [{ value: 0x11111111, comment: "api" }, { value: 0x22222222, comment: "post" }],
      [],
    );
    expect(plan.success).toBe(true);
    expect(plan.gadgets.store).toBe(0x11110003n);
    expect(plan.gadgets.pivot).toBe(0x11110005n);
    expect(plan.gadgets.advance).toBe(0x11110004n);
    // two stores (one per word), one advance (only before word 1)
    expect(plan.steps.filter((s) => s.comment.startsWith("mov [eax], ecx"))).toHaveLength(2);
    expect(plan.steps.filter((s) => s.comment.startsWith("add eax, 4"))).toHaveLength(1);
    // the BUF placeholder is used (as pointer, and again before the pivot)
    expect(plan.placeholders).toContain("BUF");
    // last gadget step is the pivot
    const gadgetSteps = plan.steps.filter((s) => s.kind === "gadget");
    expect(gadgetSteps[gadgetSteps.length - 1].address).toBe(0x11110005n);
  });

  it("reports missing primitives instead of half a chain", () => {
    const noStore = core.filter((x) => x.canonicalId !== "mock_286326787"); // drop the mov[eax] store
    const plan = planWriteFrame(index(noStore), { placeholder: "BUF" }, [{ value: 0x11111111, comment: "api" }], []);
    expect(plan.success).toBe(false);
    expect(plan.unsatisfied.some((u) => u.includes("mov [eax], <reg>"))).toBe(true);
    expect(plan.steps).toHaveLength(0);
  });

  it("dereferences an IAT slot at runtime for an ASLR'd API", () => {
    const derefIdx = index([
      g([insn("pop", ["eax"]), insn("ret", [])], 0x11110001),
      g([insn("pop", ["ebx"]), insn("ret", [])], 0x11110002),
      g([insn("pop", ["edx"]), insn("ret", [])], 0x11110003),
      g([insn("mov", ["edx", "[ebx]"]), insn("ret", [])], 0x11110009), // mov edx, [ebx]
      g([insn("mov", ["dword ptr [eax]", "edx"]), insn("ret", [])], 0x1111000a), // store edx
      g([insn("add", ["eax", "0x4"]), insn("ret", [])], 0x11110004),
      g([insn("xchg", ["eax", "esp"]), insn("ret", [])], 0x11110005),
    ]);
    const plan = planWriteFrame(
      derefIdx,
      { placeholder: "BUF" },
      [{ derefSlot: 0x1005d060, comment: "VirtualAlloc IAT" }, { value: 0x43434343, comment: "post" }],
      [],
    );
    expect(plan.success).toBe(true);
    const comments = plan.steps.map((s) => s.comment);
    // pointer set to the slot, then loaded, then stored — no raw API address placed
    expect(plan.steps.some((s) => s.value === 0x1005d060)).toBe(true);
    expect(comments.some((c) => c.includes("mov edx, [ebx]"))).toBe(true);
    expect(comments.some((c) => c.startsWith("mov [eax], edx"))).toBe(true);
  });

  it("synthesises a null/badchar word in ecx instead of placing it raw", () => {
    // 0 is null-heavy; build via two-add using edx as scratch (not eax).
    const withArith = [
      ...core,
      g([insn("pop", ["edx"]), insn("ret", [])], 0x11110006),
      g([insn("add", ["ecx", "edx"]), insn("ret", [])], 0x11110007),
    ];
    const plan = planWriteFrame(
      index(withArith),
      { placeholder: "BUF" },
      [{ value: 0x11111111, comment: "api" }, { value: 0x00000000, comment: "lpAddress NULL" }],
      [0x00, 0x0a, 0x0d],
    );
    expect(plan.success).toBe(true);
    // no literal 0x00000000 word was placed in the payload
    const literals = plan.steps.filter((s) => s.kind === "value" && s.value !== undefined).map((s) => s.value!);
    expect(literals).not.toContain(0x00000000);
    // the null slot is still written (two stores total)
    expect(plan.steps.filter((s) => s.comment.startsWith("mov [eax], ecx"))).toHaveLength(2);
  });
});
