import { describe, expect, test } from "vitest";
import { sequencesFromLiveHits } from "../src/semantics/live-provider";
import { buildCapabilityIndexFromSequences } from "../src/rop";
import { tryDecodeInsn } from "../src/core/backward_scanner";

// Exercises the full live -> semantic index -> effect query path with synthetic
// hits, so the bridge is verified without a debugger host.
const hits = [
  { mnemonic: "pop eax ; ret", address: BigInt(0x00401000), module: "vuln" },
  { mnemonic: "xor esi, esi ; ret", address: BigInt(0x00401010), module: "vuln" },
  { mnemonic: "add esi, 4 ; ret", address: BigInt(0x00401020), module: "vuln" },
  { mnemonic: "xchg eax, esp ; ret", address: BigInt(0x00401030), module: "vuln" },
];

describe("live gadget -> semantic index bridge", () => {
  const index = buildCapabilityIndexFromSequences(sequencesFromLiveHits(hits));

  test("live pop gadget becomes a LOAD_REGISTER capability at its real address", () => {
    const loaders = index.loadRegister("eax");
    expect(loaders.length).toBe(1);
    expect(loaders[0].locations[0].virtualAddress).toBe(0x00401000);
    expect(loaders[0].locations[0].module).toBe("vuln");
  });

  test("semantic write query resolves the live pop gadget", () => {
    const results = index.query({ writes: ["eax"], capability: "LOAD_REGISTER" });
    expect(results.length).toBe(1);
    expect(results[0].locations[0].virtualAddress).toBe(0x00401000);
  });

  test("transform query resolves the live add gadget's net effect", () => {
    const results = index.query({ transforms: [{ register: "esi", base: "esi", offset: 4 }] });
    expect(results.length).toBe(1);
    expect(results[0].locations[0].virtualAddress).toBe(0x00401020);
  });

  test("zeroed register and stack pivot are indexed from live hits", () => {
    expect(index.zeroRegister("esi").length).toBe(1);
    expect(index.query({ capability: "STACK_PIVOT" }).length).toBe(1);
  });

  test("executableOnly query passes because live provenance is proven executable", () => {
    // Would be 0 if live provenance were UNKNOWN; EXACT executability keeps it.
    expect(index.query({ writes: ["eax"], capability: "LOAD_REGISTER", executableOnly: true }).length).toBe(1);
  });

  test("byte MOV RET hits distinguish an exact byte write from an exact byte read", () => {
    const store = tryDecodeInsn(Uint8Array.from([0x88, 0x01, 0xc3]), 0);
    const load = tryDecodeInsn(Uint8Array.from([0x8a, 0x01, 0xc3]), 0);
    const byteIndex = buildCapabilityIndexFromSequences(sequencesFromLiveHits([
      { mnemonic: `${store?.mnemonic} ; ret`, address: BigInt(0x00401100), module: "libspp.dll" },
      { mnemonic: `${load?.mnemonic} ; ret`, address: BigInt(0x00401110), module: "libspp.dll" },
    ]));
    const writers = byteIndex.query({ capability: "MEMORY_WRITE", memoryWrite: true });
    const readers = byteIndex.query({ capability: "MEMORY_READ", memoryRead: true });
    expect(writers.map((gadget) => gadget.locations[0].virtualAddress)).toEqual([0x00401100]);
    expect(writers[0].semanticSummary.summary.memoryWrites.values.exact.has("byte [ecx]")).toBe(true);
    expect(readers.map((gadget) => gadget.locations[0].virtualAddress)).toEqual([0x00401110]);
    expect(readers[0].semanticSummary.summary.memoryReads.values.exact.has("byte [ecx]")).toBe(true);
  });
});
