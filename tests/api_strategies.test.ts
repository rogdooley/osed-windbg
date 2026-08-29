import { describe, expect, test } from "vitest";
import {
  apiFrameSlots,
  buildCapabilityIndexFromRpPlusText,
  normalizeExploitStrategy,
  planExploitStrategy,
  STDCALL_ARG_COUNT,
  type ApiExploitStrategy,
} from "../src/rop";

const provenance = {
  module: "target.dll",
  executable: "EXACT" as const,
  writable: "CONSERVATIVE" as const,
  aslr: "CONSERVATIVE" as const,
  rebaseable: "CONSERVATIVE" as const,
};

const API_STRATEGIES: ApiExploitStrategy[] = [
  "VirtualProtect",
  "VirtualAlloc",
  "WriteProcessMemory",
  "VirtualProtectEx",
  "VirtualAllocEx",
  "WinExec",
];

describe("API strategy registration", () => {
  test("normalizes the new strategy names case-insensitively", () => {
    expect(normalizeExploitStrategy("WinExec")).toBe("WinExec");
    expect(normalizeExploitStrategy("winexec")).toBe("WinExec");
    expect(normalizeExploitStrategy("virtualprotectex")).toBe("VirtualProtectEx");
    expect(normalizeExploitStrategy("VirtualAllocEx")).toBe("VirtualAllocEx");
  });

  test("rejects unknown strategy names", () => {
    expect(normalizeExploitStrategy("HeapCreate")).toBeUndefined();
  });
});

describe("apiFrameSlots frame layout", () => {
  // The frame-sizing math in the synthesizer relies on apiFrameSlots yielding
  // exactly STDCALL_ARG_COUNT + 2 slots (API address + return address + args).
  test.each(API_STRATEGIES)("%s has arg-count + 2 slots", (strategy) => {
    const slots = apiFrameSlots(strategy);
    expect(slots).toHaveLength(STDCALL_ARG_COUNT[strategy] + 2);
    expect(slots[0].role).toBe("api-address");
    expect(slots[1].role).toBe("return-address");
  });

  test("WinExec is a two-argument command-execution frame", () => {
    const slots = apiFrameSlots("WinExec");
    expect(slots.map((s) => s.role)).toEqual([
      "api-address",
      "return-address",
      "arg1-lpCmdLine",
      "arg2-uCmdShow",
    ]);
    // uCmdShow defaults to SW_SHOWNORMAL.
    expect(slots.find((s) => s.role === "arg2-uCmdShow")?.value).toBe(0x1);
  });

  test("Ex variants add a leading GetCurrentProcess handle", () => {
    for (const strategy of ["VirtualProtectEx", "VirtualAllocEx"] as const) {
      const slots = apiFrameSlots(strategy);
      const hProcess = slots.find((s) => s.role === "arg1-hProcess");
      expect(hProcess?.value).toBe(0xffffffff);
    }
  });

  test("VirtualProtectEx mirrors VirtualProtect with an inserted handle", () => {
    const base = apiFrameSlots("VirtualProtect").map((s) => s.role.replace(/^arg\d+-/, ""));
    const ex = apiFrameSlots("VirtualProtectEx").map((s) => s.role.replace(/^arg\d+-/, ""));
    // Same roles, plus a leading hProcess argument.
    expect(ex).toEqual(["api-address", "return-address", "hProcess", ...base.slice(2)]);
  });
});

describe("new strategies plan feasibly", () => {
  const index = buildCapabilityIndexFromRpPlusText(
    "0x1000: pop eax ; ret ;\n0x2000: mov esi, eax ; ret ;",
    { provenance },
  );

  test.each(API_STRATEGIES)("%s produces a feasible ret-dispatch shape", (strategy) => {
    const plan = planExploitStrategy(index, { strategy, apiResolution: "direct" });
    expect(plan.strategy).toBe(strategy);
    const retDispatch = plan.strategies.find((s) => s.shape === "RET_DISPATCH");
    expect(retDispatch?.possible).toBe(true);
  });

  test("synthetic-frame precondition reports the correct byte requirement", () => {
    const plan = planExploitStrategy(index, { strategy: "WinExec", apiResolution: "direct" });
    const synthetic = plan.strategies.find((s) => s.shape === "SYNTHETIC_STDCALL_FRAME")!;
    // WinExec: (2 args + 2) * 4 = 16 bytes.
    expect(synthetic.preconditions.some((p) => p.includes("16+ contiguous controlled bytes"))).toBe(true);
  });

  test("WriteProcessMemory synthetic-frame precondition stays at 28 bytes", () => {
    const plan = planExploitStrategy(index, { strategy: "WriteProcessMemory", apiResolution: "direct" });
    const synthetic = plan.strategies.find((s) => s.shape === "SYNTHETIC_STDCALL_FRAME")!;
    expect(synthetic.preconditions.some((p) => p.includes("28+ contiguous controlled bytes"))).toBe(true);
  });
});
