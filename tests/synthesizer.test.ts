import { describe, expect, test } from "vitest";
import {
  buildCapabilityIndexFromRpPlusText,
  formatExportPython,
  planExploitStrategy,
  synthesize,
  synthesisRows,
  validateExploitState,
  type ExploitState,
  type ExportableEmission,
  type ExportableSynthesis,
  type SynthesisResult,
} from "../src/rop";

const provenance = {
  module: "target.dll",
  executable: "EXACT" as const,
  writable: "CONSERVATIVE" as const,
  aslr: "CONSERVATIVE" as const,
  rebaseable: "CONSERVATIVE" as const,
};

function minimalSavedRetState(overrides: Partial<ExploitState> = {}): ExploitState {
  return {
    control: {
      mechanism: "saved-ret",
      instructionPointerControlled: true,
    },
    stack: {
      controlledBeforeEsp: 0,
      controlledAfterEsp: 1024,
      contiguousControlledBytes: 1024,
      readable: true,
      writable: true,
      executable: false,
    },
    registers: {},
    constraints: {
      badchars: [0x00, 0x0a, 0x0d],
      apiResolution: "direct",
    },
    ...overrides,
  };
}

// 1. DIRECT_API and RET_TO_FRAME produce different stack layouts.

describe("DIRECT_API vs RET_TO_FRAME produce different layouts", () => {
  test("DIRECT_API has no ret gadget slot; saved-eip is the API placeholder", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: nop ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState();

    const result = synthesize(index, plan, state);
    expect(result.entryPath).toBe("DIRECT_API");
    const savedEip = result.slots.find((s) => s.role === "saved-eip");
    expect(savedEip?.step.kind).toBe("value");
    expect(savedEip?.step.placeholder).toBe("VIRTUALPROTECT");
    expect(result.slots.every((s) => s.role !== "ret-gadget")).toBe(true);
  });

  test("RET_TO_FRAME has a ret gadget as saved-eip and API address in the frame", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState();

    const result = synthesize(index, plan, state);
    expect(result.entryPath).toBe("RET_TO_FRAME");
    const savedEip = result.slots.find((s) => s.role === "saved-eip");
    expect(savedEip?.step.kind).toBe("gadget");
    expect(savedEip?.step.address).toBe(BigInt(0x1000));
    const apiSlot = result.slots.find((s) => s.role === "api-address");
    expect(apiSlot?.step.placeholder).toBe("VIRTUALPROTECT");
  });

  test("DIRECT_API frame is 4 bytes shorter than RET_TO_FRAME for the same strategy", () => {
    const indexNoRet = buildCapabilityIndexFromRpPlusText("0x1000: nop ;", { provenance });
    const indexWithRet = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan1 = planExploitStrategy(indexNoRet, { strategy: "VirtualProtect" });
    const plan2 = planExploitStrategy(indexWithRet, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState();

    const direct = synthesize(indexNoRet, plan1, state);
    const retTo = synthesize(indexWithRet, plan2, state);
    expect(direct.entryPath).toBe("DIRECT_API");
    expect(retTo.entryPath).toBe("RET_TO_FRAME");
    expect(retTo.slots.length - direct.slots.length).toBe(1);
  });
});

// 2. Concrete bad-character violation yields complete-with-violations.

describe("concrete badchar violation yields complete-with-violations", () => {
  test("dwSize 0x201 with 0x00 forbidden produces a violation", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      constraints: { badchars: [0x00], apiResolution: "direct" },
    });

    const result = synthesize(index, plan, state);
    expect(result.status).toBe("complete-with-violations");
    expect(result.layoutProduced).toBe(true);
    expect(result.constraintCompatible).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations.every((v) => v.kind === "violation")).toBe(true);
  });

  test("flNewProtect 0x40 with 0x40 forbidden is a violation", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      constraints: { badchars: [0x40], apiResolution: "direct" },
    });

    const result = synthesize(index, plan, state);
    expect(result.status).toBe("complete-with-violations");
    expect(result.violations.some((v) => v.message.includes("0x40"))).toBe(true);
  });

  test("clean badchars produce status complete", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      constraints: { badchars: [0x0a, 0x0d], apiResolution: "direct" },
    });

    const result = synthesize(index, plan, state);
    expect(result.status).toBe("complete");
    expect(result.constraintCompatible).toBe(true);
    expect(result.violations).toEqual([]);
  });
});

// 3. Unresolved placeholder yields a warning, not a violation.

describe("placeholder produces warning not violation", () => {
  test("VIRTUALPROTECT placeholder is a warning", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState();

    const result = synthesize(index, plan, state);
    expect(result.warnings.some((w) => w.message.includes("VIRTUALPROTECT"))).toBe(true);
    expect(result.violations.every((v) => !v.message.includes("VIRTUALPROTECT"))).toBe(true);
    expect(result.warnings.every((w) => w.kind === "warning")).toBe(true);
  });
});

// 4. Pivot gadget whose source register is unknown is rejected.

describe("pivot register state validation", () => {
  test("pivot with unknown source register is rejected", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: xchg eax, esp ; ret ;\n0x2000: ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state: ExploitState = {
      control: { mechanism: "function-pointer", instructionPointerControlled: true },
      stack: {
        controlledBeforeEsp: 0,
        controlledAfterEsp: 16,
        contiguousControlledBytes: 16,
        readable: true,
        writable: true,
        executable: false,
      },
      registers: { eax: { kind: "unknown" } },
      memory: [
        { name: "spray", base: { kind: "absolute", address: 0x0c0c0c0c }, size: 4096, controlled: true, readable: true, writable: true, executable: false },
      ],
      constraints: { badchars: [0x00], apiResolution: "direct" },
    };

    const result = synthesize(index, plan, state);
    expect(result.status).toBe("blocked");
    expect(result.blockers.some((b) => b.message.includes("register") || b.message.includes("pivot") || b.message.includes("Pivot"))).toBe(true);
  });

  // 5. Pivot gadget whose source register points into controlled region is accepted.

  test("pivot with source register pointing into controlled region succeeds", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: xchg eax, esp ; ret ;\n0x2000: ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state: ExploitState = {
      control: { mechanism: "function-pointer", instructionPointerControlled: true },
      stack: {
        controlledBeforeEsp: 0,
        controlledAfterEsp: 16,
        contiguousControlledBytes: 16,
        readable: true,
        writable: true,
        executable: false,
      },
      registers: { eax: { kind: "pointer-into-controlled", offset: 0 } },
      memory: [
        { name: "spray", base: { kind: "absolute", address: 0x0c0c0c0c }, size: 4096, controlled: true, readable: true, writable: true, executable: false },
      ],
      constraints: { badchars: [0x00], apiResolution: "direct" },
    };

    const result = synthesize(index, plan, state);
    expect(result.entryPath).toBe("PIVOT_TO_FRAME");
    expect(result.layoutProduced).toBe(true);
    expect(result.pivot).toBeDefined();
    expect(result.pivot!.sourceRegister).toBe("eax");
    expect(result.pivot!.source).toBe("register");
  });
});

// 6. Final layout respects maximumPayloadLength.

describe("payload length enforcement", () => {
  test("layout exceeding maximumPayloadLength is blocked", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      constraints: { badchars: [], apiResolution: "direct", maximumPayloadLength: 8 },
    });

    const result = synthesize(index, plan, state);
    expect(result.status).toBe("blocked");
    expect(result.layoutProduced).toBe(false);
    expect(result.blockers.some((b) => b.message.includes("maximumPayloadLength"))).toBe(true);
  });

  test("layout within maximumPayloadLength succeeds", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      constraints: { badchars: [], apiResolution: "direct", maximumPayloadLength: 4000 },
    });

    const result = synthesize(index, plan, state);
    expect(result.layoutProduced).toBe(true);
  });
});

// 7. Stack alignment checked.

describe("stack alignment", () => {
  test("non-4-byte alignment produces a warning", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      stack: {
        controlledBeforeEsp: 0,
        controlledAfterEsp: 1024,
        contiguousControlledBytes: 1024,
        readable: true,
        writable: true,
        executable: false,
        alignment: 2,
      },
    });

    const validation = validateExploitState(index, plan, state);
    expect(validation.warnings.some((w) => w.message.includes("alignment"))).toBe(true);
  });
});

// 8. Synthesizer rejects plan whose API-resolution mode conflicts with ExploitState.

describe("API resolution mode conflict", () => {
  test("IAT plan with direct-only state is blocked", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect", apiResolution: "iat" });
    const state = minimalSavedRetState({
      constraints: { badchars: [], apiResolution: "direct" },
    });

    const result = synthesize(index, plan, state);
    expect(result.status).toBe("blocked");
    expect(result.blockers.some((b) => b.message.includes("IAT") && b.message.includes("direct"))).toBe(true);
  });

  test("direct plan with iat-only state is blocked", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect", apiResolution: "direct" });
    const state = minimalSavedRetState({
      constraints: { badchars: [], apiResolution: "iat" },
    });

    const result = synthesize(index, plan, state);
    expect(result.status).toBe("blocked");
    expect(result.blockers.some((b) => b.message.includes("direct") && b.message.includes("IAT"))).toBe(true);
  });

  test("direct plan with either-mode state succeeds", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect", apiResolution: "direct" });
    const state = minimalSavedRetState({
      constraints: { badchars: [], apiResolution: "either" },
    });

    const result = synthesize(index, plan, state);
    expect(result.layoutProduced).toBe(true);
  });
});

// 9. Every emitted address is checked against bad characters.

describe("all emitted addresses checked against badchars", () => {
  test("ret gadget address containing badchar is a violation", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x00001000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      constraints: { badchars: [0x00], apiResolution: "direct" },
    });

    const result = synthesize(index, plan, state);
    expect(result.violations.some((v) => v.message.includes("ret gadget"))).toBe(true);
  });

  test("pivot gadget address containing badchar is a violation", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x00005000: xchg eax, esp ; ret ;\n0x00006000: ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state: ExploitState = {
      control: { mechanism: "function-pointer", instructionPointerControlled: true },
      stack: {
        controlledBeforeEsp: 0,
        controlledAfterEsp: 16,
        contiguousControlledBytes: 16,
        readable: true,
        writable: true,
        executable: false,
      },
      registers: { eax: { kind: "pointer-into-controlled", offset: 0 } },
      memory: [
        { name: "spray", base: { kind: "absolute", address: 0x0c0c0c0c }, size: 4096, controlled: true, readable: true, writable: true, executable: false },
      ],
      constraints: { badchars: [0x00], apiResolution: "direct" },
    };

    const result = synthesize(index, plan, state);
    expect(result.violations.some((v) => v.message.includes("pivot gadget"))).toBe(true);
  });
});

// 10. SEH mechanism explicitly rejected.

describe("SEH mechanism not yet supported", () => {
  test("SEH control mechanism is blocked with clear reasons", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state: ExploitState = {
      control: { mechanism: "seh", instructionPointerControlled: true },
      stack: {
        controlledBeforeEsp: 3000,
        controlledAfterEsp: 800,
        contiguousControlledBytes: 3800,
        readable: true,
        writable: true,
        executable: false,
      },
      registers: {},
      seh: {
        nsehOffset: 0,
        sehOffset: 4,
        postSehControlledBytes: 800,
        preSehControlledBytes: 3000,
      },
      constraints: { badchars: [0x00], apiResolution: "direct" },
    };

    const result = synthesize(index, plan, state);
    expect(result.status).toBe("blocked");
    expect(result.blockers.some((b) => b.message.includes("saved-ret"))).toBe(true);
  });
});

// Additional: WriteProcessMemory has 7-slot frame.

describe("WriteProcessMemory frame geometry", () => {
  test("WPM RET_TO_FRAME has 8 slots (saved-eip + 7 frame)", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "WriteProcessMemory" });
    const state = minimalSavedRetState({
      constraints: { badchars: [], apiResolution: "direct" },
    });

    const result = synthesize(index, plan, state);
    expect(result.entryPath).toBe("RET_TO_FRAME");
    expect(result.slots).toHaveLength(8);
    expect(result.slots.find((s) => s.role === "arg1-hProcess")?.step.value).toBe(0xffffffff);
  });
});

// Display rows.

describe("synthesis display", () => {
  test("complete result has summary row plus slot rows plus violation rows", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      constraints: { badchars: [0x00], apiResolution: "direct" },
    });

    const result = synthesize(index, plan, state);
    const rows = synthesisRows(result);
    expect(rows[0].Status).toBe("complete-with-violations");
    expect(rows[0].Compatible).toBe("no");
    const violationRows = rows.filter((r) => r.Diagnostic === "VIOLATION");
    expect(violationRows.length).toBeGreaterThan(0);
  });

  test("blocked result shows blockers", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const state = minimalSavedRetState({
      control: { mechanism: "saved-ret", instructionPointerControlled: false },
    });

    const result = synthesize(index, plan, state);
    const rows = synthesisRows(result);
    expect(rows).toHaveLength(1);
    expect(rows[0].Status).toBe("blocked");
    expect(rows[0].Diagnostic).toContain("EIP");
  });
});

describe("formatExportPython", () => {
  const emitFixture: ExportableEmission = {
    planId: 1,
    strategy: "VirtualProtect",
    shape: "PUSHAD_DISPATCH",
    gadgets: [
      { capability: "LOAD_REGISTER", address: BigInt(0x10001000), module: "target.dll", sequence: "pop eax ; ret ;" },
      { capability: "STACK_PIVOT", address: BigInt(0x10002000), module: "target.dll", sequence: "pushad ; ret ;" },
    ],
  };

  test("emit-only export produces valid Python with gadget addresses", () => {
    const lines = formatExportPython(emitFixture);
    const text = lines.join("\n");
    expect(text).toContain("#!/usr/bin/env python3");
    expect(text).toContain("from struct import pack");
    expect(text).toContain("0x10001000");
    expect(text).toContain("pop eax ; ret ;");
    expect(text).toContain("[target.dll]");
    expect(text).toContain("rop.synthesize()");
  });

  test("export with synthesis includes stack layout", () => {
    const synth: ExportableSynthesis = {
      planId: 1,
      strategy: "VirtualProtect",
      shape: "PUSHAD_DISPATCH",
      entryPath: "RET_TO_FRAME",
      status: "complete",
      slots: [
        { offset: 0, role: "saved-eip", step: { kind: "gadget", address: BigInt(0x10001000), comment: "ret gadget" } },
        { offset: 4, role: "api-address", step: { kind: "value", value: 0x7C801AD0, comment: "VirtualProtect" } },
      ],
      placeholders: [],
      violations: [],
    };
    const lines = formatExportPython(emitFixture, synth);
    const text = lines.join("\n");
    expect(text).toContain("payload += pack");
    expect(text).toContain("Entry path: RET_TO_FRAME");
    expect(text).toContain("0x7C801AD0");
    expect(text).not.toContain("rop.synthesize()");
  });

  test("export with violations includes warnings", () => {
    const synth: ExportableSynthesis = {
      planId: 1,
      strategy: "VirtualProtect",
      shape: "PUSHAD_DISPATCH",
      entryPath: "DIRECT_API",
      status: "complete-with-violations",
      slots: [
        { offset: 0, role: "api-address", step: { kind: "value", value: 0x00401000, comment: "VirtualProtect (contains null)" } },
      ],
      placeholders: [],
      violations: ["address 0x00401000 contains badchar 0x00"],
    };
    const lines = formatExportPython(emitFixture, synth);
    const text = lines.join("\n");
    expect(text).toContain("WARNING: address 0x00401000 contains badchar 0x00");
  });

  test("export with placeholders includes TODO", () => {
    const synth: ExportableSynthesis = {
      planId: 1,
      strategy: "VirtualProtect",
      shape: "PUSHAD_DISPATCH",
      entryPath: "RET_TO_FRAME",
      status: "complete",
      slots: [
        { offset: 0, role: "saved-eip", step: { kind: "value", placeholder: "RET_GADGET", comment: "ret gadget (resolve)" } },
      ],
      placeholders: ["RET_GADGET"],
      violations: [],
    };
    const lines = formatExportPython(emitFixture, synth);
    const text = lines.join("\n");
    expect(text).toContain("TODO: resolve placeholders: RET_GADGET");
    expect(text).toContain("RET_GADGET");
  });
});
