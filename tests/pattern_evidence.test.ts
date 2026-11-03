import { describe, expect, test } from "vitest";
import { analyzePatternEvidence } from "../src/analysis/pattern_evidence";
import { generateMsfPattern } from "../src/logic/pattern_logic";

const address = BigInt(0x14dd28);
const bytes = (text: string) => Uint8Array.from([...text].map((value) => value.charCodeAt(0)));

describe("shared pattern evidence", () => {
  test("reports an exact MSF sample with length and offset", () => {
    const sample = generateMsfPattern(600).slice(304, 336);
    expect(analyzePatternEvidence(address, bytes(sample))).toMatchObject({
      address, patternFamily: "msf", matched: true, matchLength: 32, patternOffset: 304, confidence: 0.9,
    });
  });

  test("finds an unaligned pattern window without claiming total capacity", () => {
    const sample = `XX${generateMsfPattern(600).slice(304, 336)}YY`;
    expect(analyzePatternEvidence(address, bytes(sample))).toMatchObject({
      address: address + BigInt(2), patternFamily: "msf", matched: true, matchLength: 32, patternOffset: 304,
    });
  });

  test("does not report corrupted, partial, or unrelated samples as matches", () => {
    const source = generateMsfPattern(600).slice(304, 336);
    expect(analyzePatternEvidence(address, bytes(source.slice(0, 7)))).toMatchObject({ matched: false, matchLength: 0 });
    const corrupted = [...source].map((value, index) => index % 7 === 0 ? "!" : value).join("");
    expect(analyzePatternEvidence(address, bytes(corrupted))).toMatchObject({ matched: false, matchLength: 0 });
    expect(analyzePatternEvidence(address, bytes("not a cyclic pattern at all"))).toMatchObject({ matched: false, matchLength: 0 });
  });
});
