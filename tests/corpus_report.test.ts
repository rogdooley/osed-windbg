import { describe, expect, test } from "vitest";
import { buildCapabilityIndexFromRpPlusText } from "../src/rop";
import { formatCorpusReport } from "../src/rop/corpus_report";

function corpus(text: string) {
  return buildCapabilityIndexFromRpPlusText(text, {
    provenance: { module: "osedhelper.dll" },
  });
}

describe("ROP corpus report", () => {
  test("renders one complete deterministic line per gadget with semantic ESP deltas", () => {
    const index = corpus([
      "0x10001267: jmp esp ;",
      "0x1000121e: pop esi ; pop edi ; ret ;",
      "0x10001263: xchg esp, eax ; ret ;",
    ].join("\n"));
    const report = formatCorpusReport(index, {
      pointerSize: 4,
      origin: "live",
      validation: "sampled",
      badchars: [0, 0x0a, 0x0d],
      modules: [{ name: "osedhelper.dll", base: BigInt(0x10000000), aslr: "disabled" }],
    });

    expect(report).toContain("Architecture: x86");
    expect(report).toContain("Corpus: LIVE | Validation: SAMPLED");
    expect(report).toContain("Badchars: 00 0A 0D");
    expect(report).toContain("0x1000121E  +00121E  pop esi ; pop edi ; ret  LOAD(ESI,EDI)  +12");
    expect(report).toMatch(/0x10001263\s+\+001263\s+xchg esp, eax ; ret\s+PIVOT\(EAX\)\s+DYN/);
    expect(report.split("\n").filter((line) => line.startsWith("0x")).length).toBe(3);
    expect(report.indexOf("0x1000121E")).toBeLessThan(report.indexOf("0x10001263"));
  });

  test("uses x64 widths and unknown markers without inventing metadata", () => {
    const index = corpus("0x10001267: jmp esp ;");
    const report = formatCorpusReport(index, {
      pointerSize: 8,
      origin: "imported",
      validation: "unverified",
    });

    expect(report).toContain("Architecture: x64");
    expect(report).toContain("Corpus: IMPORTED | Validation: UNVERIFIED");
    expect(report).toContain("Badchars: ?");
    expect(report).toContain("Base: ? | ASLR: ?");
    expect(report).toContain("0x0000000010001267");
  });

  test("reports an empty corpus without mutating it", () => {
    const index = corpus("");
    expect(formatCorpusReport(index, {
      pointerSize: 4,
      origin: "rpplus",
      validation: "unknown",
    })).toContain("No gadgets in corpus.");
    expect(index.gadgets).toEqual([]);
  });
});
