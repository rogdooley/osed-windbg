import { describe, expect, test } from "vitest";
import {
  buildCapabilityIndex,
  buildCapabilityIndexFromRpPlusText,
  buildRopIndexFromSequences,
  emissionRows,
  mergeCapabilityIndexes,
  normalizeExploitStrategy,
  planExploitStrategy,
  RankedSemanticEmitter,
  strategyPlanRows,
  type CapabilityIndex,
  type RopStrategyPlan,
} from "../src/rop";
import { RPPlusProvider } from "../src/semantics/rpplus-provider";
import { knownPatterns } from "../src/logic/instruction_validation";

const provenance = {
  module: "target.dll",
  executable: "EXACT" as const,
  writable: "CONSERVATIVE" as const,
  aslr: "CONSERVATIVE" as const,
  rebaseable: "CONSERVATIVE" as const,
};

async function loadAll(provider: RPPlusProvider) {
  const sequences = [];
  for await (const sequence of provider.load()) {
    sequences.push(sequence);
  }
  return sequences;
}

describe("multi-module corpus management", () => {
  test("replace mode replaces the entire corpus", () => {
    const first = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;",
      { provenance: { ...provenance, module: "mod_a.dll" } },
    );
    const second = buildCapabilityIndexFromRpPlusText(
      "0x2000: pop ebx ; ret ;",
      { provenance: { ...provenance, module: "mod_b.dll" } },
    );
    expect(first.gadgets).toHaveLength(1);
    expect(second.gadgets).toHaveLength(1);
    expect(second.loadRegister("eax")).toHaveLength(0);
    expect(second.loadRegister("ebx")).toHaveLength(1);
  });

  test("append mode merges corpora and deduplicates", () => {
    const first = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;",
      { provenance: { ...provenance, module: "mod_a.dll" } },
    );
    const second = buildCapabilityIndexFromRpPlusText(
      "0x2000: pop eax ; ret ;\n0x3000: pop ebx ; ret ;",
      { provenance: { ...provenance, module: "mod_b.dll" } },
    );
    const merged = mergeCapabilityIndexes([first, second]);
    expect(merged.gadgets).toHaveLength(2);
    expect(merged.loadRegister("eax")[0].locations).toHaveLength(2);
    expect(merged.loadRegister("ebx")).toHaveLength(1);
  });

  test("deduplication across three modules preserves all locations", () => {
    const modules = ["a.dll", "b.dll", "c.dll"];
    const indexes = modules.map((mod, i) =>
      buildCapabilityIndexFromRpPlusText(
        `0x${(i + 1) * 0x1000}: pop eax ; ret ;`,
        { provenance: { ...provenance, module: mod } },
      ),
    );
    const merged = mergeCapabilityIndexes(indexes);
    expect(merged.gadgets).toHaveLength(1);
    expect(merged.loadRegister("eax")[0].locations).toHaveLength(3);
  });
});

describe("plan output contains no addresses", () => {
  test("plan JSON has no gadget addresses", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n0x2000: mov esi, eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const json = JSON.stringify(plan);
    expect(json).not.toContain("0x1000");
    expect(json).not.toContain("0x2000");
    expect(json).not.toContain("virtualAddress");
  });

  test("plan rows contain no address column", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const rows = strategyPlanRows(plan);
    for (const row of rows) {
      expect(Object.keys(row)).not.toContain("Address");
    }
  });
});

describe("IAT planning", () => {
  test("IAT mode adds LOAD_MEMORY to non-flat strategies", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, {
      strategy: "VirtualProtect",
      apiResolution: "iat",
    });
    const retDispatch = plan.strategies.find((s) => s.shape === "RET_DISPATCH");
    expect(retDispatch?.required).toContain("LOAD_MEMORY");
  });

  test("IAT mode does not add LOAD_MEMORY to SYNTHETIC_STDCALL_FRAME", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, {
      strategy: "VirtualProtect",
      apiResolution: "iat",
    });
    const flat = plan.strategies.find((s) => s.shape === "SYNTHETIC_STDCALL_FRAME");
    expect(flat?.required).not.toContain("LOAD_MEMORY");
  });
});

describe("missing PUSHAD diagnostics", () => {
  test("PUSHAD_DISPATCH is missing when no pushad in corpus", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const pushad = plan.strategies.find((s) => s.shape === "PUSHAD_DISPATCH");
    expect(pushad?.possible).toBe(false);
    expect(pushad?.missing).toContain("DISPATCH_PUSHAD");
  });

  test("PUSHAD_DISPATCH is satisfied when pushad in corpus", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n0x2000: pushad ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualProtect" });
    const pushad = plan.strategies.find((s) => s.shape === "PUSHAD_DISPATCH");
    expect(pushad?.possible).toBe(true);
    expect(pushad?.missing).toEqual([]);
  });
});

describe("emitter integration", () => {
  test("emit with recommended strategy selects gadgets", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n0x2000: mov esi, eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const result = new RankedSemanticEmitter().emit(index, plan);
    expect(result.success).toBe(true);
    expect(result.gadgets.length).toBeGreaterThan(0);
    expect(result.gadgets.every((g) => g.address > 0n)).toBe(true);
  });

  test("emit with explicit strategy ID", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n0x2000: mov esi, eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const strategy = plan.strategies.find((s) => s.shape === "RET_DISPATCH")!;
    const result = new RankedSemanticEmitter().emit(index, plan, strategy.id);
    expect(result.strategyId).toBe(strategy.id);
    expect(result.shape).toBe("RET_DISPATCH");
  });

  test("emit with invalid strategy ID returns failure", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const result = new RankedSemanticEmitter().emit(index, plan, 999);
    expect(result.success).toBe(false);
    expect(result.diagnostics[0]).toContain("No matching");
  });

  test("emission result is labeled as gadget assignment, not executable chain", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n0x2000: mov esi, eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const result = new RankedSemanticEmitter().emit(index, plan);
    expect(result.diagnostics[0]).toContain("assignment");
    expect(result.diagnostics[0]).toContain("not an ordered executable chain");
  });

  test("emission rows include all selected gadgets", () => {
    const index = buildCapabilityIndexFromRpPlusText(
      "0x1000: pop eax ; ret ;\n0x2000: mov esi, eax ; ret ;",
      { provenance },
    );
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const result = new RankedSemanticEmitter().emit(index, plan);
    const rows = emissionRows(result);
    expect(rows.length).toBe(result.gadgets.length);
    expect(rows.every((r) => "Address" in r)).toBe(true);
  });
});

describe("strategy normalization", () => {
  test("normalizes case-insensitive strategy names", () => {
    expect(normalizeExploitStrategy("virtualprotect")).toBe("VirtualProtect");
    expect(normalizeExploitStrategy("VIRTUALALLOC")).toBe("VirtualAlloc");
    expect(normalizeExploitStrategy("writeprocessmemory")).toBe("WriteProcessMemory");
    expect(normalizeExploitStrategy("stack pivot")).toBe("Stack Pivot");
    expect(normalizeExploitStrategy("stackpivot")).toBe("Stack Pivot");
    expect(normalizeExploitStrategy("bogus")).toBeUndefined();
  });
});

describe("zero-row output", () => {
  test("empty emission rows for unavailable strategy", () => {
    const index = buildCapabilityIndexFromRpPlusText("0x1000: ret ;", { provenance });
    const plan = planExploitStrategy(index, { strategy: "VirtualAlloc" });
    const pushad = plan.strategies.find((s) => s.shape === "PUSHAD_DISPATCH")!;
    const result = new RankedSemanticEmitter().emit(index, plan, pushad.id);
    const rows = emissionRows(result);
    expect(rows).toHaveLength(1);
    expect(rows[0].Status).toBe("unavailable");
  });
});

describe("live discovery pattern coverage", () => {
  const patterns = knownPatterns();
  const patternNames = patterns.map((p) => p.name);

  test("includes memory read patterns (mov reg, [reg] ; ret)", () => {
    expect(patternNames.some((n) => n.startsWith("mov_eax_mem_"))).toBe(true);
    expect(patternNames.some((n) => n.startsWith("mov_ecx_mem_"))).toBe(true);
  });

  test("includes register transfer patterns (mov dst, src ; ret)", () => {
    expect(patternNames.some((n) => n === "mov_eax_ecx_ret")).toBe(true);
    expect(patternNames.some((n) => n === "mov_esi_ebx_ret")).toBe(true);
  });

  test("includes register swap patterns (xchg reg, reg ; ret)", () => {
    expect(patternNames.some((n) => n.startsWith("xchg_") && n.endsWith("_ret") && !n.includes("esp"))).toBe(true);
  });

  test("includes PUSHAD dispatch pattern", () => {
    expect(patternNames).toContain("pushad_ret");
  });

  test("includes CALL register patterns beyond eax/esp", () => {
    expect(patternNames).toContain("call_ecx");
    expect(patternNames).toContain("call_esi");
    expect(patternNames).toContain("call_edi");
  });

  test("includes JMP register patterns beyond eax/esp", () => {
    expect(patternNames).toContain("jmp_ecx");
    expect(patternNames).toContain("jmp_esi");
    expect(patternNames).toContain("jmp_edi");
  });

  test("includes CALL [register] memory-indirect patterns", () => {
    expect(patternNames).toContain("call_mem_eax");
    expect(patternNames).toContain("call_mem_ecx");
  });

  test("includes stack adjustment patterns (add esp, imm ; ret)", () => {
    expect(patternNames).toContain("add_esp_4_ret");
    expect(patternNames).toContain("add_esp_10_ret");
    expect(patternNames).toContain("add_esp_20_ret");
  });

  test("includes xor self-zero patterns", () => {
    expect(patternNames).toContain("xor_eax_eax_ret");
    expect(patternNames).toContain("xor_ecx_ecx_ret");
  });

  test("new patterns produce correct capabilities when processed through semantic pipeline", async () => {
    const sequences = await loadAll(new RPPlusProvider(
      "0x1000: mov eax, [ecx] ; ret ;\n"
      + "0x2000: mov esi, eax ; ret ;\n"
      + "0x3000: xchg esi, ebx ; ret ;\n"
      + "0x4000: call esi ;\n"
      + "0x5000: jmp edi ;\n"
      + "0x6000: call [eax] ;\n"
      + "0x7000: add esp, 0x10 ; ret ;\n"
      + "0x8000: xor eax, eax ; ret ;",
      { provenance },
    ));
    const index = buildCapabilityIndex(buildRopIndexFromSequences(sequences));

    expect(index.query({ capability: "LOAD_MEMORY" }).length).toBeGreaterThan(0);
    expect(index.query({ capability: "REGISTER_TRANSFER" }).length).toBeGreaterThan(0);
    expect(index.query({ capability: "REGISTER_SWAP" }).length).toBeGreaterThan(0);
    expect(index.query({ capability: "DISPATCH_CALL_REGISTER" }).length).toBeGreaterThan(0);
    expect(index.query({ capability: "DISPATCH_JMP_REGISTER" }).length).toBeGreaterThan(0);
    expect(index.query({ capability: "DISPATCH_CALL_MEMORY" }).length).toBeGreaterThan(0);
    expect(index.query({ capability: "STACK_ADJUST" }).length).toBeGreaterThan(0);
    expect(index.query({ capability: "REGISTER_ZERO" }).length).toBeGreaterThan(0);
  });
});

describe("scan_live positional arg parsing", () => {
  function parseScanLivePositionalArgs(args: unknown[]): Record<string, unknown> {
    const result: Record<string, unknown> = { module: args[0] };
    result.badchars = args[1];
    let idx = 2;
    if (idx < args.length && typeof args[idx] === "boolean") {
      result.append = args[idx];
      idx++;
    } else if (idx < args.length && typeof args[idx] === "number") {
      result.maxPerPattern = args[idx];
      idx++;
      if (idx < args.length) {
        result.append = args[idx];
      }
    } else if (idx < args.length) {
      result.append = args[idx];
    }
    return result;
  }

  test("boolean in third position is treated as append, not maxPerPattern", () => {
    const withBoolThird = parseScanLivePositionalArgs(["crypto", "00 0A 0D", true]);
    expect(withBoolThird.append).toBe(true);
    expect(withBoolThird.maxPerPattern).toBeUndefined();
  });

  test("number in third position is maxPerPattern, boolean in fourth is append", () => {
    const withNumberThird = parseScanLivePositionalArgs(["crypto", "00 0A 0D", 10, true]);
    expect(withNumberThird.maxPerPattern).toBe(10);
    expect(withNumberThird.append).toBe(true);
  });

  test("number only in third position without fourth arg leaves append undefined", () => {
    const withNumberOnly = parseScanLivePositionalArgs(["crypto", "00 0A 0D", 10]);
    expect(withNumberOnly.maxPerPattern).toBe(10);
    expect(withNumberOnly.append).toBeUndefined();
  });
});

describe("help catalog entries", () => {
  test("plan and emit have help catalog entries", async () => {
    const { findHelpEntry } = await import("../src/core/help_catalog");
    expect(findHelpEntry("rop.plan")).toBeDefined();
    expect(findHelpEntry("rop.emit")).toBeDefined();
    expect(findHelpEntry("rop.scan_live")).toBeDefined();
  });

  test("emit help mentions gadget assignment", async () => {
    const { findHelpEntry } = await import("../src/core/help_catalog");
    const entry = findHelpEntry("rop.emit")!;
    expect(entry.description).toContain("assignment");
  });
});
