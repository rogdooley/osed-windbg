import { describe, expect, test } from "vitest";
import { verifyChain, parseManualChain, type VerifyInput } from "../src/rop/chain_verifier";
import type { ChainStep } from "../src/rop/chain";
import type { CapabilityIndex } from "../src/rop/capabilities";
import type { RopGadget } from "../src/rop/types";
import { buildExploitFrame } from "../src/rop/exploit_frame";
import { planSlotDispatch } from "../src/rop/slot_dispatch";
import type { FrameWord } from "../src/rop/frame_write";

function gadgetStep(addr: number, comment: string): ChainStep {
  return { kind: "gadget", address: BigInt(addr >>> 0), comment };
}

function valueStep(val: number, comment: string): ChainStep {
  return { kind: "value", value: val >>> 0, comment };
}

function placeholderStep(name: string, comment: string): ChainStep {
  return { kind: "value", placeholder: name, comment };
}

// ── Mock corpus helpers (same pattern as slot_dispatch.test.ts) ─────────

function insn(mnemonic: string, operands: string[]) {
  return {
    mnemonic,
    operands,
    originalText: `${mnemonic} ${operands.join(", ")}`,
    normalizedText: `${mnemonic} ${operands.join(", ")}`,
  };
}

function g(instructions: Array<ReturnType<typeof insn>>, address: number): RopGadget {
  return {
    schemaVersion: "v1",
    canonicalId: `mock_${address.toString(16)}`,
    instructions,
    locations: [{ module: "test", virtualAddress: address, executable: true }],
    semanticSummary: { instructions: [], effects: [], unknowns: [], netTransform: {} },
    categories: [],
    score: 50,
    scoreReasons: [],
    classificationReasons: [],
    capabilities: [],
  } as unknown as RopGadget;
}

function mockCorpus(gadgets: RopGadget[]): CapabilityIndex {
  return {
    gadgets,
    capabilityMap: new Map(),
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

// ── Static analysis ─────────────────────────────────────────────────────

describe("verifyChain — static analysis", () => {
  test("clean chain with no badchars passes", () => {
    const report = verifyChain({
      steps: [gadgetStep(0x10022D64, "pop eax ; ret"), valueStep(0x41414141, "eax = BUF")],
      badchars: [],
    });
    expect(report.static.valid).toBe(true);
    expect(report.static.dwordCount).toBe(2);
    expect(report.static.totalStackBytes).toBe(8);
    expect(report.static.badcharHits).toHaveLength(0);
    expect(report.static.unresolvedPlaceholders).toHaveLength(0);
  });

  test("detects badchar in gadget address (LSB)", () => {
    const report = verifyChain({
      steps: [gadgetStep(0x1002000A, "bad gadget")],
      badchars: [0x0A],
    });
    expect(report.static.valid).toBe(false);
    expect(report.static.badcharHits).toHaveLength(1);
    expect(report.static.badcharHits[0].byte).toBe(0x0A);
    expect(report.static.badcharHits[0].bytePosition).toBe(0);
  });

  test("detects multiple null bytes in value", () => {
    const report = verifyChain({
      steps: [valueStep(0x00001000, "size")],
      badchars: [0x00],
    });
    expect(report.static.valid).toBe(false);
    expect(report.static.badcharHits.filter(h => h.byte === 0x00).length).toBeGreaterThanOrEqual(2);
  });

  test("all four bytes of a DWORD checked independently", () => {
    const report = verifyChain({
      steps: [valueStep(0x0D0A0D0A, "double trouble")],
      badchars: [0x0A, 0x0D],
    });
    expect(report.static.badcharHits).toHaveLength(4);
  });

  test("reports unresolved placeholders and marks invalid", () => {
    const report = verifyChain({
      steps: [gadgetStep(0x10022D64, "pop eax"), placeholderStep("SHELLCODE", "shellcode address")],
      badchars: [],
    });
    expect(report.static.valid).toBe(false);
    expect(report.static.unresolvedPlaceholders).toHaveLength(1);
    expect(report.static.unresolvedPlaceholders[0].placeholder).toBe("SHELLCODE");
  });

  test("empty chain is valid", () => {
    const report = verifyChain({ steps: [], badchars: [] });
    expect(report.static.valid).toBe(true);
    expect(report.static.dwordCount).toBe(0);
  });

  test("assumptions note when no badchars specified", () => {
    const report = verifyChain({ steps: [valueStep(0x00000000, "zero")], badchars: [] });
    expect(report.static.assumptions.some(a => a.includes("skipped"))).toBe(true);
  });

  test("assumptions note for gadget address stability", () => {
    const report = verifyChain({
      steps: [gadgetStep(0x10022D64, "pop eax")],
      badchars: [],
    });
    expect(report.static.assumptions.some(a => a.includes("gadget address"))).toBe(true);
  });
});

// ── Frame validation ────────────────────────────────────────────────────

describe("verifyChain — frame validation", () => {
  test("VirtualAlloc frame with correct arg count passes", () => {
    // VirtualAlloc: 4 args, so frame = 1 retaddr + 4 args = 5 value words
    const report = verifyChain({
      steps: [
        valueStep(0xDEADBEEF, "retaddr"),
        valueStep(0x00420000, "lpAddress"),
        valueStep(0x00001000, "dwSize"),
        valueStep(0x00001000, "flAllocationType"),
        valueStep(0x00000040, "flProtect"),
      ],
      badchars: [],
      api: "VirtualAlloc",
    });
    expect(report.static.frameCheck).toBeDefined();
    expect(report.static.frameCheck!.status).toBe("ok");
    expect(report.static.frameCheck!.expectedArgCount).toBe(4);
    expect(report.static.frameCheck!.expectedFrameWords).toBe(5);
  });

  test("too few args for VirtualProtect fails", () => {
    // VirtualProtect needs 4 args (5 frame words), but we only give 3
    const report = verifyChain({
      steps: [
        valueStep(0xDEADBEEF, "retaddr"),
        valueStep(0x00420000, "lpAddress"),
        valueStep(0x00000201, "dwSize"),
      ],
      badchars: [],
      api: "VirtualProtect",
    });
    expect(report.static.frameCheck).toBeDefined();
    expect(report.static.frameCheck!.status).toBe("too_few");
    expect(report.static.valid).toBe(false);
  });

  test("unknown API reports unknown_api status", () => {
    const report = verifyChain({
      steps: [valueStep(0xDEADBEEF, "something")],
      badchars: [],
      api: "FakeApi",
    });
    expect(report.static.frameCheck).toBeDefined();
    expect(report.static.frameCheck!.status).toBe("unknown_api");
    expect(report.static.valid).toBe(false);
  });

  test("WriteProcessMemory expects 5 args", () => {
    const report = verifyChain({
      steps: [
        valueStep(0xDEADBEEF, "retaddr"),
        valueStep(0xFFFFFFFF, "hProcess"),
        valueStep(0x00420000, "lpBaseAddress"),
        valueStep(0x00430000, "lpBuffer"),
        valueStep(0x00000100, "nSize"),
        valueStep(0x41414141, "lpNumberOfBytesWritten"),
      ],
      badchars: [],
      api: "WriteProcessMemory",
    });
    expect(report.static.frameCheck!.status).toBe("ok");
    expect(report.static.frameCheck!.expectedArgCount).toBe(5);
  });

  test("too many args for WinExec on bare frame fails", () => {
    // WinExec: 2 args → 3 frame words, but we give 5
    const report = verifyChain({
      steps: [
        valueStep(0xDEADBEEF, "retaddr"),
        valueStep(0x00420000, "lpCmdLine"),
        valueStep(0x00000001, "uCmdShow"),
        valueStep(0x41414141, "extra 1"),
        valueStep(0x42424242, "extra 2"),
      ],
      badchars: [],
      api: "WinExec",
    });
    expect(report.static.frameCheck!.status).toBe("too_many");
    expect(report.static.valid).toBe(false);
    expect(report.static.frameCheck!.detail).toContain("5");
    expect(report.static.frameCheck!.detail).toContain("3");
  });

  test("chain with gadgets reports not_checked for frame validation", () => {
    // A slot_call chain has many value steps (pop operands, IAT addresses, etc.)
    // beyond the API frame. The verifier cannot count frame words in this case.
    const report = verifyChain({
      steps: [
        gadgetStep(0x10022D64, "pop eax ; ret"),
        valueStep(0x00420000, "eax = BUF"),
        gadgetStep(0x10011002, "pop ecx ; ret"),
        valueStep(0xDEADBEEF, "ecx = retaddr"),
        gadgetStep(0x10010E83, "mov [eax], ecx ; ret"),
      ],
      badchars: [],
      api: "VirtualAlloc",
    });
    expect(report.static.frameCheck).toBeDefined();
    expect(report.static.frameCheck!.status).toBe("not_checked");
    // not_checked is neutral — should not block overall validity
    expect(report.static.valid).toBe(true);
  });

  test("expectedArgCount overrides API lookup on bare frame", () => {
    const report = verifyChain({
      steps: [valueStep(0x41, "a"), valueStep(0x42, "b"), valueStep(0x43, "c")],
      badchars: [],
      api: "VirtualAlloc",
      expectedArgCount: 2,  // override: expect 3 total (retaddr + 2 args)
    });
    expect(report.static.frameCheck!.expectedArgCount).toBe(2);
    expect(report.static.frameCheck!.expectedFrameWords).toBe(3);
    expect(report.static.frameCheck!.status).toBe("ok");
  });

  test("no frameCheck when api is omitted", () => {
    const report = verifyChain({
      steps: [valueStep(0x41414141, "whatever")],
      badchars: [],
    });
    expect(report.static.frameCheck).toBeUndefined();
  });
});

// ── Runtime trace with corpus ───────────────────────────────────────────

describe("verifyChain — runtime trace", () => {
  test("unavailable without corpus", () => {
    const report = verifyChain({ steps: [valueStep(0x41414141, "test")], badchars: [] });
    expect(report.runtime.available).toBe(false);
    expect(report.runtime.reason).toContain("corpus");
  });

  test("traces pop gadget: consumes next DWORD into register", () => {
    const popEax = g([insn("pop", ["eax"]), insn("ret", [])], 0x10022D64);
    const corpus = mockCorpus([popEax]);

    const report = verifyChain({
      steps: [
        gadgetStep(0x10022D64, "pop eax ; ret"),
        valueStep(0xBBBBBBBB, "eax = target"),
      ],
      badchars: [],
      corpus,
    });

    expect(report.runtime.available).toBe(true);
    expect(report.runtime.trace).toHaveLength(2);

    // First entry: the gadget itself
    expect(report.runtime.trace[0].kind).toBe("gadget");
    expect(report.runtime.trace[0].espOffset).toBe(0);
    expect(report.runtime.trace[0].action).toContain("pop eax");

    // Second entry: the popped operand
    expect(report.runtime.trace[1].kind).toBe("pop-operand");
    expect(report.runtime.trace[1].espOffset).toBe(4);

    // Final register state: eax should have the popped value
    expect(report.runtime.finalRegisters.eax).toBe("0xBBBBBBBB");
  });

  test("traces xchg gadget: swaps register values", () => {
    const popEax = g([insn("pop", ["eax"]), insn("ret", [])], 0x1001);
    const xchg = g([insn("xchg", ["eax", "esp"]), insn("ret", [])], 0x1002);
    const corpus = mockCorpus([popEax, xchg]);

    const report = verifyChain({
      steps: [
        gadgetStep(0x1001, "pop eax ; ret"),
        valueStep(0xAABBCCDD, "eax = BUF"),
        gadgetStep(0x1002, "xchg eax, esp ; ret"),
      ],
      badchars: [],
      corpus,
    });

    expect(report.runtime.available).toBe(true);
    // After pop eax: eax = 0xAABBCCDD
    // After xchg eax, esp: eax = old esp (?), esp = 0xAABBCCDD
    const xchgEntry = report.runtime.trace.find(t => t.action.includes("xchg"));
    expect(xchgEntry).toBeDefined();
    expect(xchgEntry!.sideEffects.some(e => e.includes("xchg"))).toBe(true);
  });

  test("tracks mov reg, [reg] as runtime deref", () => {
    const popEcx = g([insn("pop", ["ecx"]), insn("ret", [])], 0x2001);
    const deref = g([insn("mov", ["eax", "dword ptr [ecx]"]), insn("ret", [])], 0x2002);
    const corpus = mockCorpus([popEcx, deref]);

    const report = verifyChain({
      steps: [
        gadgetStep(0x2001, "pop ecx ; ret"),
        valueStep(0x1005D060, "ecx = IAT slot"),
        gadgetStep(0x2002, "mov eax, [ecx] ; ret"),
      ],
      badchars: [],
      corpus,
    });

    expect(report.runtime.available).toBe(true);
    // ecx should be the IAT slot address
    expect(report.runtime.finalRegisters.ecx).toBe("0x1005D060");
    // eax should be a runtime deref marker
    expect(report.runtime.finalRegisters.eax).toContain("*[");
  });

  test("ret N padding steps appear in trace", () => {
    // pop eax ; ret 4 — consumes 1 DWORD for eax, then ret 4 skips 1 more
    const popRetN = g([insn("pop", ["eax"]), insn("ret", ["0x4"])], 0x3001);
    const corpus = mockCorpus([popRetN]);

    const report = verifyChain({
      steps: [
        gadgetStep(0x3001, "pop eax ; ret 4"),
        valueStep(0xAAAAAAAA, "eax value"),
        valueStep(0x41414141, "padding (ret 4 compensation)"),
      ],
      badchars: [],
      corpus,
    });

    expect(report.runtime.available).toBe(true);
    expect(report.runtime.trace).toHaveLength(3);
    expect(report.runtime.trace[2].kind).toBe("padding");
  });

  test("register clobber warning when same register set twice", () => {
    const popEax1 = g([insn("pop", ["eax"]), insn("ret", [])], 0x4001);
    const popEax2 = g([insn("pop", ["eax"]), insn("ret", [])], 0x4002);
    const corpus = mockCorpus([popEax1, popEax2]);

    const report = verifyChain({
      steps: [
        gadgetStep(0x4001, "pop eax ; ret (first)"),
        valueStep(0x11111111, "first eax"),
        gadgetStep(0x4002, "pop eax ; ret (second)"),
        valueStep(0x22222222, "second eax"),
      ],
      badchars: [],
      corpus,
    });

    expect(report.runtime.available).toBe(true);
    expect(report.runtime.registerClobbers.length).toBeGreaterThan(0);
    expect(report.runtime.registerClobbers[0]).toContain("eax");
    // Final value should be the last write
    expect(report.runtime.finalRegisters.eax).toBe("0x22222222");
  });

  test("gadget not in corpus gets noted in trace", () => {
    const corpus = mockCorpus([]);  // empty corpus

    const report = verifyChain({
      steps: [gadgetStep(0x5001, "unknown gadget")],
      badchars: [],
      corpus,
    });

    expect(report.runtime.available).toBe(true);
    expect(report.runtime.trace).toHaveLength(1);
    expect(report.runtime.trace[0].notes.some(n => n.includes("not found"))).toBe(true);
    expect(report.runtime.assumptions.some(a => a.includes("not in corpus"))).toBe(true);
  });

  test("placeholder in trace is labeled correctly", () => {
    const popEax = g([insn("pop", ["eax"]), insn("ret", [])], 0x6001);
    const corpus = mockCorpus([popEax]);

    const report = verifyChain({
      steps: [
        gadgetStep(0x6001, "pop eax ; ret"),
        placeholderStep("BUF", "buffer address"),
      ],
      badchars: [],
      corpus,
    });

    expect(report.runtime.available).toBe(true);
    // The pop consumes the placeholder as an operand
    expect(report.runtime.trace.length).toBeGreaterThanOrEqual(2);
    // eax gets the placeholder name since it can't be resolved
    expect(report.runtime.finalRegisters.eax).toBe("BUF");
  });

  test("xor reg, reg sets register to zero", () => {
    const xorEax = g([insn("xor", ["eax", "eax"]), insn("ret", [])], 0x7001);
    const corpus = mockCorpus([xorEax]);

    const report = verifyChain({
      steps: [gadgetStep(0x7001, "xor eax, eax ; ret")],
      badchars: [],
      corpus,
    });

    expect(report.runtime.finalRegisters.eax).toBe("0x00000000");
  });

  test("add instruction updates tracked value", () => {
    const popEax = g([insn("pop", ["eax"]), insn("ret", [])], 0x8001);
    const addEax = g([insn("add", ["eax", "0x4"]), insn("ret", [])], 0x8002);
    const corpus = mockCorpus([popEax, addEax]);

    const report = verifyChain({
      steps: [
        gadgetStep(0x8001, "pop eax ; ret"),
        valueStep(0x00420000, "eax = base"),
        gadgetStep(0x8002, "add eax, 4 ; ret"),
      ],
      badchars: [],
      corpus,
    });

    expect(report.runtime.finalRegisters.eax).toBe("0x00420004");
  });
});

// ── parseManualChain ────────────────────────────────────────────────────

describe("parseManualChain", () => {
  test("parses hex DWORDs", () => {
    const steps = parseManualChain("10022D64 1005D060 DEADBEEF");
    expect(steps).toHaveLength(3);
    expect(steps[0].value).toBe(0x10022D64);
    expect(steps[1].value).toBe(0x1005D060);
    expect(steps[2].value).toBe(0xDEADBEEF);
  });

  test("handles 0x prefix", () => {
    const steps = parseManualChain("0x10022D64 0x1005D060");
    expect(steps).toHaveLength(2);
    expect(steps[0].value).toBe(0x10022D64);
  });

  test("non-hex tokens become placeholders", () => {
    const steps = parseManualChain("10022D64 SHELLCODE 1005D060");
    expect(steps).toHaveLength(3);
    expect(steps[1].placeholder).toBe("SHELLCODE");
    expect(steps[1].value).toBeUndefined();
  });

  test("empty input returns empty array", () => {
    expect(parseManualChain("")).toHaveLength(0);
    expect(parseManualChain("   ")).toHaveLength(0);
  });

  test("parsed chain badchar check works end-to-end", () => {
    const steps = parseManualChain("10022D64 1005000A DEADBEEF");
    const report = verifyChain({ steps, badchars: [0x0A] });
    expect(report.static.badcharHits).toHaveLength(1);
    expect(report.static.badcharHits[0].stepIndex).toBe(1);
  });
});

// ── Badchar byte position ───────────────────────────────────────────────

describe("verifyChain — badchar byte position", () => {
  test("byte position 0 is LSB", () => {
    const report = verifyChain({
      steps: [valueStep(0xFFFFFF0D, "has 0x0D in LSB")],
      badchars: [0x0D],
    });
    expect(report.static.badcharHits[0].bytePosition).toBe(0);
  });

  test("byte position 3 is MSB", () => {
    const report = verifyChain({
      steps: [valueStep(0x0AFFFFFF, "has 0x0A in MSB")],
      badchars: [0x0A],
    });
    expect(report.static.badcharHits[0].bytePosition).toBe(3);
  });

  test("byteOffset accounts for step position", () => {
    const report = verifyChain({
      steps: [valueStep(0x41414141, "clean"), valueStep(0x0AFFFFFF, "bad in byte 3")],
      badchars: [0x0A],
    });
    expect(report.static.badcharHits[0].byteOffset).toBe(4 + 3);
    expect(report.static.badcharHits[0].stepIndex).toBe(1);
  });
});

// ── Summary / result contract ───────────────────────────────────────────
// These mirror the logic in executeRopVerify that produces the summary row
// and the `success` field returned to WinDbg. The three states:
//   PASS:       static.valid && frameCheck?.status !== "not_checked"
//   INCOMPLETE: static.valid && frameCheck?.status === "not_checked"
//   FAIL:       !static.valid

describe("verifyChain — summary contract", () => {
  // Helper: compute the same staticStatus and success that executeRopVerify does
  function summaryOf(report: ReturnType<typeof verifyChain>) {
    const hasNotChecked = report.static.frameCheck?.status === "not_checked";
    const staticStatus = !report.static.valid ? "FAIL"
      : hasNotChecked ? "INCOMPLETE"
      : "PASS";
    const success = report.static.valid && !hasNotChecked;
    return { staticStatus, success };
  }

  test("PASS: bare frame, all checks clean, frame validated", () => {
    const report = verifyChain({
      steps: [
        valueStep(0xDEADBEEF, "retaddr"),
        valueStep(0x00420000, "lpAddress"),
        valueStep(0x00001000, "dwSize"),
        valueStep(0x00001000, "flAllocationType"),
        valueStep(0x00000040, "flProtect"),
      ],
      badchars: [0x0a, 0x0d],
      api: "VirtualAlloc",
    });
    const { staticStatus, success } = summaryOf(report);
    expect(staticStatus).toBe("PASS");
    expect(success).toBe(true);
    expect(report.static.valid).toBe(true);
    expect(report.static.frameCheck!.status).toBe("ok");
  });

  test("PASS: no API specified, clean chain, no frame check at all", () => {
    const report = verifyChain({
      steps: [valueStep(0x41414141, "data")],
      badchars: [0x00],
    });
    const { staticStatus, success } = summaryOf(report);
    expect(staticStatus).toBe("PASS");
    expect(success).toBe(true);
    expect(report.static.frameCheck).toBeUndefined();
  });

  test("INCOMPLETE: generated chain with gadgets, frame not_checked", () => {
    const report = verifyChain({
      steps: [
        gadgetStep(0x10022D64, "pop eax ; ret"),
        valueStep(0x41414141, "operand"),
      ],
      badchars: [],
      api: "VirtualAlloc",
    });
    const { staticStatus, success } = summaryOf(report);
    expect(staticStatus).toBe("INCOMPLETE");
    expect(success).toBe(false);
    expect(report.static.valid).toBe(true);
    expect(report.static.frameCheck!.status).toBe("not_checked");
  });

  test("FAIL: badchar violation", () => {
    const report = verifyChain({
      steps: [valueStep(0x0000BEEF, "has nulls")],
      badchars: [0x00],
    });
    const { staticStatus, success } = summaryOf(report);
    expect(staticStatus).toBe("FAIL");
    expect(success).toBe(false);
    expect(report.static.valid).toBe(false);
  });

  test("FAIL: unresolved placeholder", () => {
    const report = verifyChain({
      steps: [placeholderStep("SHELLCODE", "needs resolution")],
      badchars: [],
    });
    const { staticStatus, success } = summaryOf(report);
    expect(staticStatus).toBe("FAIL");
    expect(success).toBe(false);
  });

  test("FAIL: frame too_few on bare frame", () => {
    const report = verifyChain({
      steps: [valueStep(0xDEADBEEF, "retaddr")],
      badchars: [],
      api: "VirtualAlloc",
    });
    const { staticStatus, success } = summaryOf(report);
    expect(staticStatus).toBe("FAIL");
    expect(success).toBe(false);
    expect(report.static.frameCheck!.status).toBe("too_few");
  });

  test("FAIL: frame too_many on bare frame", () => {
    const report = verifyChain({
      steps: [
        valueStep(0xDEADBEEF, "retaddr"),
        valueStep(0x00420000, "lpCmdLine"),
        valueStep(0x00000001, "uCmdShow"),
        valueStep(0x41414141, "extra"),
      ],
      badchars: [],
      api: "WinExec",
    });
    const { staticStatus, success } = summaryOf(report);
    expect(staticStatus).toBe("FAIL");
    expect(success).toBe(false);
    expect(report.static.frameCheck!.status).toBe("too_many");
  });
});

// ── Builder integration: real planSlotDispatch output ────────────────────

describe("verifyChain — builder integration", () => {
  // Reproduce the Mini-stream gadget set that planSlotDispatch actually uses.
  function builderInsn(mnemonic: string, operands: string[]) {
    return {
      mnemonic,
      operands,
      originalText: `${mnemonic} ${operands.join(", ")}`,
      normalizedText: `${mnemonic} ${operands.join(", ")}`,
    };
  }

  function builderGadget(instructions: Array<ReturnType<typeof builderInsn>>, address: number): RopGadget {
    const caps: Array<Record<string, string>> = [];
    for (const i of instructions) {
      const m = i.mnemonic.toLowerCase();
      const d = i.operands[0]?.trim().toLowerCase();
      if (!d) continue;
      if (m === "pop") caps.push({ kind: "LOAD_REGISTER", register: d, evidence: "mock" });
      else if (m === "add" && !d.startsWith("[")) caps.push({ kind: "REGISTER_ADD", register: d, targetRegister: i.operands[1]?.trim().toLowerCase() ?? "", evidence: "mock" });
      else if (m === "jmp") caps.push({ kind: "DISPATCH_JMP_REGISTER", register: d, evidence: "mock" });
    }
    return {
      schemaVersion: "v1",
      canonicalId: `builder_${address.toString(16)}`,
      instructions,
      locations: [{ module: "test", virtualAddress: address, executable: true }],
      semanticSummary: { instructions: [], effects: [], unknowns: [], netTransform: {} },
      categories: [],
      score: 50,
      scoreReasons: [],
      classificationReasons: [],
      capabilities: caps.length ? caps : [{ kind: "NONE", evidence: "mock" }],
    } as unknown as RopGadget;
  }

  function builderIndex(gadgets: RopGadget[]): CapabilityIndex {
    const capabilityMap = new Map<string, RopGadget[]>();
    for (const gadget of gadgets) {
      for (const cap of gadget.capabilities) {
        const key = [(cap as Record<string, string>).kind, (cap as Record<string, string>).register ?? "", (cap as Record<string, string>).targetRegister ?? ""].join(":");
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

  const coreGadgets = [
    builderGadget([builderInsn("pop", ["eax"]), builderInsn("ret", [])], 0x100115aa),
    builderGadget([builderInsn("pop", ["ecx"]), builderInsn("ret", [])], 0x10011002),
    builderGadget([builderInsn("mov", ["dword ptr [eax]", "ecx"]), builderInsn("ret", [])], 0x10010e83),
    builderGadget([builderInsn("add", ["eax", "0x4"]), builderInsn("ret", [])], 0x100192dc),
    builderGadget([builderInsn("xchg", ["eax", "esp"]), builderInsn("ret", [])], 0x1002fe81),
    builderGadget([builderInsn("mov", ["eax", "[eax]"]), builderInsn("ret", [])], 0x10027f59),
    builderGadget([builderInsn("jmp", ["eax"])], 0x100371e9),
    builderGadget([builderInsn("pop", ["edx"]), builderInsn("ret", [])], 0x10011006),
    builderGadget([builderInsn("add", ["ecx", "edx"]), builderInsn("ret", [])], 0x10011007),
  ];

  test("real planSlotDispatch output: reports not_checked for frame, clean badchars, no unresolved", () => {
    const corpus = builderIndex(coreGadgets);
    const retAddr: FrameWord = { value: 0xDEADBEEF, comment: "return address" };
    const writable: FrameWord = { value: 0x00420100, comment: "writable dword" };
    const frame = buildExploitFrame("VirtualAlloc", retAddr, writable);

    const plan = planSlotDispatch(
      corpus,
      { value: 0x00420000 },
      0x1005D060,
      frame,
    );

    expect(plan.success).toBe(true);
    expect(plan.steps.length).toBeGreaterThan(0);

    // Verify the real builder output
    const report = verifyChain({
      steps: plan.steps,
      badchars: [],
      api: "VirtualAlloc",
      corpus,
    });

    // Static: no badchar violations
    expect(report.static.badcharHits).toHaveLength(0);
    // VirtualAlloc frame has a SHELLCODE placeholder for lpAddress —
    // that's correct: the verifier must report it as unresolved
    expect(report.static.unresolvedPlaceholders.length).toBeGreaterThanOrEqual(1);
    expect(report.static.unresolvedPlaceholders.some(p => p.placeholder === "SHELLCODE")).toBe(true);
    // Frame check: not_checked because chain has gadgets
    expect(report.static.frameCheck).toBeDefined();
    expect(report.static.frameCheck!.status).toBe("not_checked");
    // Placeholders make static.valid false — the chain needs resolution before deploy
    expect(report.static.valid).toBe(false);
  });

  test("real planSlotDispatch output: badchar violations detected in builder output", () => {
    const corpus = builderIndex(coreGadgets);
    const retAddr: FrameWord = { value: 0xDEADBEEF, comment: "return address" };
    const writable: FrameWord = { value: 0x00420100, comment: "writable dword" };
    const frame = buildExploitFrame("VirtualAlloc", retAddr, writable);

    const plan = planSlotDispatch(
      corpus,
      { value: 0x00420000 },
      0x1005D060,
      frame,
    );
    expect(plan.success).toBe(true);

    // Verify with badchars that hit addresses in the real chain.
    // The gadget at 0x100115aa contains byte 0xaa.
    const report = verifyChain({
      steps: plan.steps,
      badchars: [0xaa],
      api: "VirtualAlloc",
      corpus,
    });

    expect(report.static.badcharHits.length).toBeGreaterThan(0);
    expect(report.static.valid).toBe(false);
    // At least one hit should be on the 0xaa byte
    expect(report.static.badcharHits.some(h => h.byte === 0xaa)).toBe(true);
  });

  test("real planSlotDispatch output: runtime trace has entries for every step", () => {
    const corpus = builderIndex(coreGadgets);
    const retAddr: FrameWord = { value: 0xDEADBEEF, comment: "return address" };
    const writable: FrameWord = { value: 0x00420100, comment: "writable dword" };
    const frame = buildExploitFrame("VirtualAlloc", retAddr, writable);

    const plan = planSlotDispatch(
      corpus,
      { value: 0x00420000 },
      0x1005D060,
      frame,
    );
    expect(plan.success).toBe(true);

    const report = verifyChain({
      steps: plan.steps,
      badchars: [],
      corpus,
    });

    expect(report.runtime.available).toBe(true);
    // Every step should appear in the trace
    expect(report.runtime.trace.length).toBe(plan.steps.length);
    // Trace should contain both gadget and pop-operand entries
    expect(report.runtime.trace.some(t => t.kind === "gadget")).toBe(true);
    expect(report.runtime.trace.some(t => t.kind === "pop-operand")).toBe(true);
  });
});
