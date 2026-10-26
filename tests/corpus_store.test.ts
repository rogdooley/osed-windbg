import { describe, expect, test } from "vitest";
import { buildCapabilityIndexFromRpPlusText } from "../src/rop";
import {
  CORPUS_EXPORT_SCHEMA_VERSION,
  exportCorpus,
  importCorpus,
  validateCorpus,
  type CorpusFingerprint,
} from "../src/rop/corpus_store";

const corpus = buildCapabilityIndexFromRpPlusText("0x401000: pop eax ; ret ;", {
  provenance: { module: "target.exe", executable: "EXACT" },
});

const fingerprint: CorpusFingerprint = {
  modules: [{ name: "target.exe", path: "C:\\labs\\target.exe", base: 0x400000, size: 0x5000 }],
  samples: [{ address: 0x401000, bytes: [0x58, 0xc3] }],
};

describe("ROP corpus store", () => {
  test("round-trips a semantic corpus and its validation fingerprint", () => {
    const imported = importCorpus(exportCorpus(corpus, fingerprint));
    expect(imported.schemaVersion).toBe(CORPUS_EXPORT_SCHEMA_VERSION);
    expect(imported.index.gadgets).toHaveLength(1);
    expect(imported.index.query({ capability: "LOAD_REGISTER" })).toHaveLength(1);
    expect(validateCorpus(imported, fingerprint)).toEqual({ valid: true, reasons: [] });
  });

  test("rejects incompatible corpus schema", () => {
    expect(() => importCorpus(JSON.stringify({ schemaVersion: "v0" }))).toThrow("Unsupported ROP corpus schema");
  });

  test("rejects a corpus whose gadgets lack the semantic fields required by queries", () => {
    expect(() => importCorpus(JSON.stringify({
      schemaVersion: CORPUS_EXPORT_SCHEMA_VERSION,
      gadgets: [{ canonicalId: "pop eax ; ret" }],
      fingerprint,
    }))).toThrow("missing gadgets or fingerprint");
  });

  test("rejects a changed module mapping", () => {
    const imported = importCorpus(exportCorpus(corpus, fingerprint));
    const changed: CorpusFingerprint = {
      ...fingerprint,
      modules: [{ ...fingerprint.modules[0], base: 0x500000 }],
    };
    expect(validateCorpus(imported, changed)).toEqual({ valid: false, reasons: ["module target.exe mapping changed"] });
  });

  test("rejects a changed sampled gadget byte", () => {
    const imported = importCorpus(exportCorpus(corpus, fingerprint));
    const changed: CorpusFingerprint = {
      ...fingerprint,
      samples: [{ address: 0x401000, bytes: [0xcc, 0xc3] }],
    };
    expect(validateCorpus(imported, changed)).toEqual({ valid: false, reasons: ["gadget bytes changed at 0x401000"] });
  });
});
