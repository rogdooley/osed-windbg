import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { canonicalizeInstructionSequence, normalizeInstructionText } from "../src/semantics/canonicalize";
import { composeSemanticSequence } from "../src/semantics/compose";
import { RPPlusProvider } from "../src/semantics/rpplus-provider";
import { analyzeInstruction } from "../src/semantics/instruction-semantics";
import { buildCapabilityIndex, buildCapabilityIndexFromRpPlusText, buildRopGadgetFromSequence, buildRopIndexFromProvider, buildRopIndexFromSequences } from "../src/rop";

const fixture = readFileSync(new URL("./fixtures/rpplus/basic.txt", import.meta.url), "utf8");

async function loadAll(provider: RPPlusProvider) {
  const sequences = [];
  for await (const sequence of provider.load()) {
    sequences.push(sequence);
  }
  return sequences;
}

describe("semantic pipeline", () => {
  test("RP++ provider parses gadget lines and ignores banners", async () => {
    const sequences = await loadAll(new RPPlusProvider(fixture, { provenance: { module: "FastBackServer.exe", executable: "EXACT", writable: "CONSERVATIVE", aslr: "CONSERVATIVE", rebaseable: "CONSERVATIVE" } }));
    expect(sequences.length).toBe(9);
    expect(sequences[0].originalText).toContain("pop eax ; ret");
    expect(sequences[0].instructions[0].mnemonic).toBe("pop");
    expect(sequences[0].instructions[0].operands).toEqual(["eax"]);
  });

  test("instruction normalization is stable", () => {
    expect(normalizeInstructionText("  POP   EAX  ; ")).toBe("pop eax");
    expect(normalizeInstructionText("retn 0x10")).toBe("ret 0x10");
    expect(normalizeInstructionText("RETN 16")).toBe("ret 0x10");
  });

  test("canonicalization ignores case and whitespace", async () => {
    const sequences = await loadAll(new RPPlusProvider(fixture));
    expect(canonicalizeInstructionSequence(sequences[0])).toBe(canonicalizeInstructionSequence(sequences[8]));
  });

  test("composeSemanticSequence calculates stack delta for pop pop ret", async () => {
    const provider = new RPPlusProvider("0x1000: pop eax ; pop ecx ; ret ;");
    const [sequence] = await loadAll(provider);
    const semantic = composeSemanticSequence(sequence);
    expect(semantic.summary.stackDelta.values.exact.has(12)).toBe(true);
  });

  test("net transforms rebase sequential pop stack slots to entry ESP", async () => {
    const provider = new RPPlusProvider("0x1000: pop esi ; pop edi ; ret ;");
    const [sequence] = await loadAll(provider);
    const semantic = composeSemanticSequence(sequence);

    expect(semantic.summary.registerTransforms.esi).toEqual({
      kind: "memory",
      confidence: "EXACT",
      address: { kind: "affine", base: "esp", offset: { kind: "constant", value: 0 } },
    });
    expect(semantic.summary.registerTransforms.edi).toEqual({
      kind: "memory",
      confidence: "EXACT",
      address: { kind: "affine", base: "esp", offset: { kind: "constant", value: 4 } },
    });
    expect(semantic.summary.registerTransforms.esp).toEqual({
      kind: "affine",
      base: "esp",
      offset: { kind: "constant", value: 12 },
    });
  });

  test("net transforms fold xchg atomically and preserve restored registers", async () => {
    const provider = new RPPlusProvider("0x1000: xchg esi, eax ; add eax, 4 ; xchg esi, eax ; ret ;");
    const [sequence] = await loadAll(provider);
    const semantic = composeSemanticSequence(sequence);

    expect(semantic.summary.registerTransforms.eax).toEqual({
      kind: "affine",
      base: "eax",
      offset: { kind: "constant", value: 0 },
    });
    expect(semantic.summary.registerTransforms.esi).toEqual({
      kind: "affine",
      base: "esi",
      offset: { kind: "constant", value: 4 },
    });
  });

  test("net transforms model lea as register plus constant", async () => {
    const provider = new RPPlusProvider("0x1000: lea esi, [eax+4] ; ret ;");
    const [sequence] = await loadAll(provider);
    const semantic = composeSemanticSequence(sequence);

    expect(semantic.summary.registerTransforms.esi).toEqual({
      kind: "affine",
      base: "eax",
      offset: { kind: "constant", value: 4 },
    });
  });

  test("net transforms degrade beyond one register offset plus constant boundary", async () => {
    const provider = new RPPlusProvider("0x1000: add esi, ecx ; add esi, 4 ; ret ;");
    const [sequence] = await loadAll(provider);
    const semantic = composeSemanticSequence(sequence);

    expect(semantic.summary.registerTransforms.esi).toEqual({ kind: "unknown" });
  });

  test("composeSemanticSequence calculates stack delta for ret imm", async () => {
    const provider = new RPPlusProvider("0x1000: ret 0x10 ;");
    const [sequence] = await loadAll(provider);
    const semantic = composeSemanticSequence(sequence);
    expect(semantic.summary.stackDelta.values.exact.has(20)).toBe(true);
  });

  test("esp arithmetic stack delta matches net esp transform", async () => {
    const cases = [
      { text: "0x1000: add esp, 16 ; ret ;", delta: 20 },
      { text: "0x1000: add esp, -4 ; ret ;", delta: 0 },
      { text: "0x1000: sub esp, 4 ; ret ;", delta: 0 },
    ];

    for (const item of cases) {
      const [sequence] = await loadAll(new RPPlusProvider(item.text));
      const semantic = composeSemanticSequence(sequence);
      expect(semantic.summary.stackDelta.values.exact.has(item.delta)).toBe(true);
      expect(semantic.summary.registerTransforms.esp).toEqual({
        kind: "affine",
        base: "esp",
        offset: { kind: "constant", value: item.delta },
      });
    }
  });

  test("pop esp keeps stack delta unknown to match its esp transform", async () => {
    const provider = new RPPlusProvider("0x1000: pop esp ; ret ;");
    const [sequence] = await loadAll(provider);
    const semantic = composeSemanticSequence(sequence);
    // POP ESP loads an arbitrary value; neither the delta nor the transform is knowable.
    expect(semantic.summary.stackDelta.values.unknown).toBe(true);
    expect(semantic.summary.registerTransforms.esp).toEqual({ kind: "unknown" });
  });

  test("xchg eax, esp is classified as STACK_PIVOT", async () => {
    const provider = new RPPlusProvider("0x1000: xchg eax, esp ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    expect(gadget.categories).toContain("STACK_PIVOT");
    expect(gadget.classificationReasons.some((reason) => reason.rule === "stack-pivot")).toBe(true);
  });

  test("pop eax ; ret is classified as LOAD_REGISTER", async () => {
    const provider = new RPPlusProvider("0x1000: pop eax ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    expect(gadget.categories).toContain("LOAD_REGISTER");
  });

  test("pop esp ; ret is not a register load", async () => {
    const provider = new RPPlusProvider("0x1000: pop esp ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    expect(gadget.categories).not.toContain("LOAD_REGISTER");
  });

  test("add/sub esp, imm is classified as STACK_ADJUST", async () => {
    for (const text of ["0x1000: add esp, 0x10 ; ret ;", "0x1000: sub esp, 4 ; ret ;"]) {
      const [sequence] = await loadAll(new RPPlusProvider(text));
      const gadget = buildRopGadgetFromSequence(sequence);
      expect(gadget.categories).toContain("STACK_ADJUST");
    }
  });

  test("leave ; ret is a STACK_PIVOT (esp becomes ebp-relative)", async () => {
    const provider = new RPPlusProvider("0x1000: leave ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    // leave sets esp := ebp + 4, so its net effect is a pivot, not a fixed adjust.
    expect(gadget.categories).toContain("STACK_PIVOT");
    expect(gadget.categories).not.toContain("STACK_ADJUST");
  });

  test("mov esp, eax ; ret is a transform-driven STACK_PIVOT", async () => {
    const provider = new RPPlusProvider("0x1000: mov esp, eax ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    expect(gadget.categories).toContain("STACK_PIVOT");
    expect(gadget.categories).not.toContain("LOAD_REGISTER");
  });

  test("a round-trip xchg with esp is not a STACK_PIVOT (net identity)", async () => {
    const provider = new RPPlusProvider("0x1000: xchg esp, eax ; xchg esp, eax ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    // Net esp transform is identity, so the text-level "xchg touches esp" false
    // positive is gone.
    expect(gadget.categories).not.toContain("STACK_PIVOT");
  });

  test("xor eax, eax ; inc eax ; ret is not ZERO_REGISTER (nets to 1)", async () => {
    const provider = new RPPlusProvider("0x1000: xor eax, eax ; inc eax ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    expect(gadget.categories).not.toContain("ZERO_REGISTER");
  });

  test("xor eax, eax ; ret is classified as ZERO_REGISTER", async () => {
    const provider = new RPPlusProvider("0x1000: xor eax, eax ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    expect(gadget.categories).toContain("ZERO_REGISTER");
  });

  test("mov [ecx], eax ; ret is marked as memory write", async () => {
    const provider = new RPPlusProvider("0x1000: mov [ecx], eax ; ret ;");
    const [sequence] = await loadAll(provider);
    const semantic = composeSemanticSequence(sequence);
    expect(semantic.summary.memoryWrites.values.exact.has("[ecx]")).toBe(true);
  });

  test("call eax is penalized as a flow transfer", async () => {
    const provider = new RPPlusProvider("0x1000: call eax ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    expect(gadget.categories).toContain("FLOW_TRANSFER");
    expect(gadget.score).toBeLessThan(100);
  });

  test("unsupported instruction yields unknown semantics", () => {
    const semantic = analyzeInstruction({
      originalText: "mul eax",
      normalizedText: "mul eax",
      mnemonic: "mul",
      operands: ["eax"],
    }, 0);
    expect(semantic.supported).toBe(false);
    expect(semantic.reads.values.unknown).toBe(true);
    expect(semantic.writes.values.unknown).toBe(true);
  });

  test("score reasons and classification reasons are attached", async () => {
    const provider = new RPPlusProvider("0x1000: pop eax ; ret ;");
    const [sequence] = await loadAll(provider);
    const gadget = buildRopGadgetFromSequence(sequence);
    expect(gadget.scoreReasons.length).toBeGreaterThan(0);
    expect(gadget.classificationReasons.length).toBeGreaterThan(0);
  });

  test("duplicate gadgets merge locations", async () => {
    const provider = new RPPlusProvider(fixture);
    const index = await buildRopIndexFromProvider(provider);
    const canonical = index.gadgets.find((gadget) => gadget.categories.includes("LOAD_REGISTER"));
    expect(canonical?.locations.length).toBeGreaterThan(1);
  });

  test("capability index supports load and pivot queries", async () => {
    const index = await buildRopIndexFromProvider(new RPPlusProvider(fixture));
    const capabilityIndex = buildCapabilityIndex(index);
    expect(capabilityIndex.loadRegister("eax").length).toBeGreaterThan(0);
    expect(capabilityIndex.stackPivotCandidates().length).toBeGreaterThan(0);
  });

  test("RP++ text builds a capability index and supports semantic queries", () => {
    const capabilityIndex = buildCapabilityIndexFromRpPlusText(fixture, {
      provenance: {
        executable: "EXACT",
        writable: "CONSERVATIVE",
        aslr: "CONSERVATIVE",
        rebaseable: "CONSERVATIVE",
      },
    });
    expect(capabilityIndex.gadgets.length).toBeGreaterThan(0);
    expect(capabilityIndex.query({ capability: "STACK_PIVOT", executableOnly: true }).length).toBeGreaterThan(0);
  });

  test("query writes matches exact register writes", async () => {
    const provider = new RPPlusProvider("0x1000: pop eax ; ret ;", {
      provenance: {
        executable: "EXACT",
        writable: "CONSERVATIVE",
        aslr: "CONSERVATIVE",
        rebaseable: "CONSERVATIVE",
      },
    });
    const sequences = await loadAll(provider);
    const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
    expect([...capabilityIndex.gadgets[0].semanticSummary.summary.writes.values.exact]).toContain("eax");
    expect(capabilityIndex.query({ writes: ["eax"] }).length).toBe(1);
  });

  test("preserves does not treat unknown semantics as preserved", async () => {
    const provider = new RPPlusProvider("0x1000: mul eax ; ret ;");
    const sequences = await loadAll(provider);
    const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
    expect(capabilityIndex.query({ preserves: ["eax"] }).length).toBe(0);
  });

  test("preserves admits gadgets that clobber and restore a register", async () => {
    const provider = new RPPlusProvider("0x1000: xchg esi, eax ; add eax, 4 ; xchg esi, eax ; ret ;");
    const sequences = await loadAll(provider);
    const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
    // eax is written transiently by the middle ADD but restored at gadget exit.
    expect(capabilityIndex.query({ preserves: ["eax"] }).length).toBe(1);
    // esi nets to +4, so it is not preserved.
    expect(capabilityIndex.query({ preserves: ["esi"] }).length).toBe(0);
  });

  test("preservesThroughout is strict where preserves is net", async () => {
    const provider = new RPPlusProvider("0x1000: xchg esi, eax ; add eax, 4 ; xchg esi, eax ; ret ;");
    const sequences = await loadAll(provider);
    const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
    expect(capabilityIndex.query({ preserves: ["eax"] }).length).toBe(1);
    expect(capabilityIndex.query({ preservesThroughout: ["eax"] }).length).toBe(0);
  });

  test("transforms match a self-relative +4 across add/inc/lea equivalents", async () => {
    const forms = [
      "0x1000: add esi, 4 ; ret ;",
      "0x1000: inc esi ; inc esi ; inc esi ; inc esi ; ret ;",
      "0x1000: lea esi, [esi+4] ; ret ;",
    ];
    for (const text of forms) {
      const sequences = await loadAll(new RPPlusProvider(text));
      const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
      expect(capabilityIndex.query({ transforms: [{ register: "esi", base: "esi", offset: 4 }] }).length).toBe(1);
    }
  });

  test("transforms match a memory load and a register copy", async () => {
    const popIndex = buildCapabilityIndex(buildRopIndexFromSequences(await loadAll(new RPPlusProvider("0x1000: pop esi ; ret ;"))));
    expect(popIndex.query({ transforms: [{ register: "esi", fromMemory: true }] }).length).toBe(1);

    const movIndex = buildCapabilityIndex(buildRopIndexFromSequences(await loadAll(new RPPlusProvider("0x1000: mov esi, eax ; ret ;"))));
    expect(movIndex.query({ transforms: [{ register: "esi", base: "eax", offset: 0 }] }).length).toBe(1);
  });

  test("transforms reject unknown nets but match exact parametric offsets", async () => {
    // Two accumulations across register and constant exceed the affine closure → unknown.
    const degraded = buildCapabilityIndex(buildRopIndexFromSequences(await loadAll(new RPPlusProvider("0x1000: add esi, ecx ; add esi, 4 ; ret ;"))));
    expect(degraded.query({ transforms: [{ register: "esi", base: "esi", offset: 4 }] }).length).toBe(0);

    // A single register add is an exact, queryable parametric transform.
    const parametric = buildCapabilityIndex(buildRopIndexFromSequences(await loadAll(new RPPlusProvider("0x1000: add esi, ecx ; ret ;"))));
    expect(parametric.query({ transforms: [{ register: "esi", base: "esi", offsetRegister: "ecx" }] }).length).toBe(1);
  });

  test("memoryWrite: false excludes gadgets with unknown memory effects", async () => {
    const provider = new RPPlusProvider("0x1000: mul eax ; ret ;");
    const sequences = await loadAll(provider);
    const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
    // mul is unsupported → memory-write behavior is unknown → must not satisfy a
    // "no memory writes" constraint, since an unproven gadget might write memory.
    expect(capabilityIndex.query({ memoryWrite: false }).length).toBe(0);
  });

  test("memoryWrite: false includes gadgets with proven-empty memory effects", async () => {
    const provider = new RPPlusProvider("0x1000: pop eax ; ret ;");
    const sequences = await loadAll(provider);
    const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
    expect(capabilityIndex.query({ memoryWrite: false }).length).toBe(1);
  });

  test("memoryWrite: true matches a proven memory-write gadget", async () => {
    const provider = new RPPlusProvider("0x1000: mov [ecx], eax ; ret ;");
    const sequences = await loadAll(provider);
    const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
    expect(capabilityIndex.query({ memoryWrite: true }).length).toBe(1);
    expect(capabilityIndex.query({ memoryWrite: false }).length).toBe(0);
  });

  test("memoryRead: false excludes gadgets with unknown memory effects", async () => {
    const provider = new RPPlusProvider("0x1000: mul eax ; ret ;");
    const sequences = await loadAll(provider);
    const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequences));
    expect(capabilityIndex.query({ memoryRead: false }).length).toBe(0);
  });
});
