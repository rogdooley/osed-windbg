import { describe, expect, test } from "vitest";
import {
  buildCapabilityIndexFromRpPlusText,
  planExploitStrategy,
  RankedSemanticEmitter,
} from "../src/rop";

const provenance = {
  module: "target.dll",
  executable: "EXACT" as const,
  writable: "CONSERVATIVE" as const,
  aslr: "CONSERVATIVE" as const,
  rebaseable: "CONSERVATIVE" as const,
};

describe("semantic ROP planning and emission", () => {
  test("planner reports feasible and missing strategies without gadget addresses", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n0x2000: mov esi, eax ; ret ;",
      { provenance },
    );

    const plan = planExploitStrategy(index, {
      strategy: "VirtualAlloc",
      apiResolution: "direct",
    }, 7);

    expect(plan.id).toBe(7);
    expect(JSON.stringify(plan)).not.toContain("0x1000");
    expect(plan.strategies.find((strategy) => strategy.shape === "RET_DISPATCH")).toMatchObject({
      possible: true,
      missing: [],
    });
    expect(plan.strategies.find((strategy) => strategy.shape === "PUSHAD_DISPATCH")).toMatchObject({
      possible: false,
      missing: ["DISPATCH_PUSHAD"],
    });
  });

  test("IAT planning adds a semantic dereference requirement to non-exempt shapes", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n0x2000: mov esi, eax ; ret ;",
      { provenance },
    );

    const plan = planExploitStrategy(index, {
      strategy: "VirtualProtect",
      apiResolution: "iat",
    });
    const pushad = plan.strategies.find((strategy) => strategy.shape === "PUSHAD_DISPATCH");
    expect(pushad?.required).toContain("LOAD_MEMORY");

    const retDispatch = plan.strategies.find((strategy) => strategy.shape === "RET_DISPATCH");
    expect(retDispatch?.required).not.toContain("LOAD_MEMORY");
  });

  test("emitter selects concrete gadgets only after strategy selection", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n"
      + "0x2000: mov esi, eax ; ret ;\n"
      + "0x3000: pop ebx ; pop ecx ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const strategy = plan.strategies.find((candidate) => candidate.shape === "RET_DISPATCH")!;

    const result = new RankedSemanticEmitter().emit(index, plan, strategy.id);

    expect(result.success).toBe(true);
    expect(result.gadgets.map((gadget) => gadget.capability)).toEqual(strategy.required);
    expect(result.gadgets.every((gadget) => gadget.address > 0n)).toBe(true);
  });

  test("emitter preserves planner failure diagnostics", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const pushad = plan.strategies.find((candidate) => candidate.shape === "PUSHAD_DISPATCH")!;

    const result = new RankedSemanticEmitter().emit(index, plan, pushad.id);

    expect(result.success).toBe(false);
    expect(result.missing).toContain("DISPATCH_PUSHAD");
    expect(result.diagnostics[0]).toContain("Missing semantic capabilities");
  });
});
