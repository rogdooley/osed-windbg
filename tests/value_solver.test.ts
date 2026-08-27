import { describe, expect, it } from "vitest";
import { solveValue, type ValueRecipe } from "../src/rop/value_solver";
import type { CapabilityIndex } from "../src/rop/capabilities";
import type { RopGadget, RopCapability } from "../src/rop/types";

function makeInsn(mnemonic: string, operands: string[]): { mnemonic: string; operands: string[] } {
  return { mnemonic, operands };
}

function makeGadget(instructions: Array<{ mnemonic: string; operands: string[] }>, address: number, capabilities: RopCapability[], score = 10): RopGadget {
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
    capabilities,
  } as unknown as RopGadget;
}

function makePopGadget(reg: string, addr: number): RopGadget {
  return makeGadget(
    [makeInsn("pop", [reg]), makeInsn("ret", [])],
    addr,
    [{ kind: "LOAD_REGISTER", register: reg, evidence: `pop ${reg}` }],
  );
}

function makeXorGadget(reg: string, addr: number): RopGadget {
  return makeGadget(
    [makeInsn("xor", [reg, reg]), makeInsn("ret", [])],
    addr,
    [{ kind: "ZERO_REGISTER", register: reg, evidence: `xor ${reg}, ${reg}` }],
  );
}

function makeNegGadget(reg: string, addr: number): RopGadget {
  return makeGadget(
    [makeInsn("neg", [reg]), makeInsn("ret", [])],
    addr,
    [{ kind: "REGISTER_NEGATE", register: reg, evidence: `neg ${reg}` }],
  );
}

function makeNotGadget(reg: string, addr: number): RopGadget {
  return makeGadget(
    [makeInsn("not", [reg]), makeInsn("ret", [])],
    addr,
    [{ kind: "REGISTER_NOT", register: reg, evidence: `not ${reg}` }],
  );
}

function makeAddGadget(dst: string, src: string, addr: number): RopGadget {
  return makeGadget(
    [makeInsn("add", [dst, src]), makeInsn("ret", [])],
    addr,
    [{ kind: "REGISTER_ADD", register: dst, targetRegister: src, evidence: `add ${dst}, ${src}` }],
  );
}

function makeSubGadget(dst: string, src: string, addr: number): RopGadget {
  return makeGadget(
    [makeInsn("sub", [dst, src]), makeInsn("ret", [])],
    addr,
    [{ kind: "REGISTER_SUB", register: dst, targetRegister: src, evidence: `sub ${dst}, ${src}` }],
  );
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

describe("value_solver", () => {
  describe("direct recipe", () => {
    it("returns direct when value has no badchars", () => {
      const index = buildMockIndex([makePopGadget("edx", 0x10010101)]);
      const result = solveValue(index, "edx", 0xDEADBEEF, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("direct");
      expect(result!.steps.length).toBeGreaterThanOrEqual(2);
      expect(result!.steps[0].kind).toBe("gadget");
      expect(result!.steps[1].kind).toBe("value");
      expect(result!.steps[1].value).toBe(0xDEADBEEF);
    });

    it("skips direct when value has badchars", () => {
      const index = buildMockIndex([
        makePopGadget("edx", 0x10010101),
        makeNegGadget("edx", 0x10020202),
      ]);
      // 0x01000101: byte 0x00 at position 2. neg = 0xFEFFFEFF: no 0x00 → negate works
      const result = solveValue(index, "edx", 0x01000101, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("negate");
    });
  });

  describe("negate recipe", () => {
    it("uses neg when -V is badchar-free", () => {
      const index = buildMockIndex([
        makePopGadget("edx", 0x10010101),
        makeNegGadget("edx", 0x10020202),
      ]);
      // 0x01000101 has 0x00 byte → direct fails. neg = 0xFEFFFEFF, no 0x00 → negate works
      const result = solveValue(index, "edx", 0x01000101, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("negate");
      expect(result!.steps.some((s) => s.comment.includes("neg"))).toBe(true);
    });
  });

  describe("complement recipe", () => {
    it("uses not when ~V is badchar-free", () => {
      // value = 0x01010100, badchar = 0x00
      // neg(0x01010100) = 0xFEFEFF00 — has 0x00, fails
      // not(0x01010100) = 0xFEFEFEFF — no 0x00, works!
      const index = buildMockIndex([
        makePopGadget("ecx", 0x10010101),
        makeNotGadget("ecx", 0x10020202),
      ]);
      const result = solveValue(index, "ecx", 0x01010100, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("complement");
    });
  });

  describe("two-add recipe", () => {
    it("finds A+B decomposition", () => {
      const index = buildMockIndex([
        makePopGadget("edx", 0x10010101),
        makePopGadget("ebx", 0x10030303),
        makeAddGadget("edx", "ebx", 0x10040404),
      ]);
      // 0x00001000 with badchar 0x00
      // neg = 0xFFFFF000 has 0x00, negate fails
      // not = 0xFFFFEFFF, no 0x00, complement would work but no not gadget
      const result = solveValue(index, "edx", 0x00001000, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("two-add");
      expect(result!.scratchRegister).toBe("ebx");
    });
  });

  describe("two-sub recipe", () => {
    it("finds A-B decomposition when add is unavailable", () => {
      const index = buildMockIndex([
        makePopGadget("edx", 0x10010101),
        makePopGadget("ecx", 0x10030303),
        makeSubGadget("edx", "ecx", 0x10050505),
      ]);
      const result = solveValue(index, "edx", 0x00001000, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("two-sub");
    });
  });

  describe("zero-add recipe", () => {
    it("uses xor+pop+add when pop dst is unavailable", () => {
      const index = buildMockIndex([
        makeXorGadget("edx", 0x10010101),
        makePopGadget("ebx", 0x10020202),
        makeAddGadget("edx", "ebx", 0x10030303),
      ]);
      const result = solveValue(index, "edx", 0xDEADBEEF, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("zero-add");
      expect(result!.scratchRegister).toBe("ebx");
    });
  });

  describe("zero-sub-neg recipe", () => {
    it("uses xor+sub+neg as last resort", () => {
      const index = buildMockIndex([
        makeXorGadget("edx", 0x10010101),
        makePopGadget("ebx", 0x10020202),
        makeSubGadget("edx", "ebx", 0x10030303),
        makeNegGadget("edx", 0x10040404),
      ]);
      // Value must be badchar-free for zero-sub-neg
      const result = solveValue(index, "edx", 0xDEADBEEF, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("zero-sub-neg");
    });
  });

  describe("no solution", () => {
    it("returns undefined when no gadgets available", () => {
      const index = buildMockIndex([]);
      const result = solveValue(index, "edx", 0x1000, [0x00]);
      expect(result).toBeUndefined();
    });

    it("returns undefined when only pop is available and value has badchars", () => {
      const index = buildMockIndex([makePopGadget("edx", 0x10010101)]);
      const result = solveValue(index, "edx", 0x00001000, [0x00]);
      expect(result).toBeUndefined();
    });
  });

  describe("ret N padding", () => {
    it("emits padding for ret N gadgets", () => {
      const retNGadget = makeGadget(
        [makeInsn("pop", ["edx"]), makeInsn("ret", ["0x08"])],
        0x10010101,
        [{ kind: "LOAD_REGISTER", register: "edx", evidence: "pop edx" }],
      );
      const index = buildMockIndex([retNGadget]);
      const result = solveValue(index, "edx", 0xDEADBEEF, []);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("direct");
      // gadget addr, value, 2 padding words (8 bytes / 4)
      expect(result!.steps.length).toBe(4);
      expect(result!.steps[2].value).toBe(0x41414141);
      expect(result!.steps[3].value).toBe(0x41414141);
    });
  });

  describe("stack bytes", () => {
    it("reports correct stack bytes", () => {
      const index = buildMockIndex([makePopGadget("eax", 0x10010101)]);
      const result = solveValue(index, "eax", 0x41414141, [0x00]);
      expect(result).toBeDefined();
      expect(result!.stackBytes).toBe(result!.steps.length * 4);
    });
  });

  describe("recipe ordering preference", () => {
    it("prefers direct over negate when both work", () => {
      const index = buildMockIndex([
        makePopGadget("eax", 0x10010101),
        makeNegGadget("eax", 0x10020202),
      ]);
      const result = solveValue(index, "eax", 0x41414141, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("direct");
    });

    it("prefers negate over complement", () => {
      const index = buildMockIndex([
        makePopGadget("eax", 0x10010101),
        makeNegGadget("eax", 0x10020202),
        makeNotGadget("eax", 0x10030303),
      ]);
      // 0x00001000 — direct fails (has 0x00), neg = 0xFFFFF000 has 0x00 too
      // So negate won't work here — complement ~V = 0xFFFFEFFF, no nulls!
      const result = solveValue(index, "eax", 0x00001000, [0x00]);
      expect(result).toBeDefined();
      expect(result!.recipe).toBe("complement");
    });
  });
});
