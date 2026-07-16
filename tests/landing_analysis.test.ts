import { describe, expect, test } from "vitest";
import { analyzeLandingBytes, calculateLandingConfidence, observationIdentity, type Observation } from "../src/analysis/landing";
import { normalizeMemoryRegion } from "../src/analysis/memory";

const address = BigInt("0x12f800");

describe("landing analysis", () => {
  test("emits NOP provenance and normalized memory observations", () => {
    const memory = normalizeMemoryRegion(address, { state: 0x1000, protection: 0x20, type: 0x20000 });
    const bytes = Uint8Array.from([...Array(12).fill(0x90), 0xcc, 0xcc]);
    const evidence = analyzeLandingBytes(address, bytes, memory, 14, true);
    const nop = evidence.observations.find((item) => item.kind === "nop_sled_detected");

    expect(nop).toMatchObject({ address, length: 12, confidence: 0.95, details: { offset: 0, byte: 0x90 } });
    expect(evidence.observations.map((item) => item.kind)).toContain("readable_region");
    expect(evidence.observations.map((item) => item.kind)).toContain("executable_region");
    expect(evidence.observations.map((item) => item.kind)).toContain("disassembly_succeeded");
  });

  test("reports marker byte ranges and truncation separately", () => {
    const memory = normalizeMemoryRegion(address, { protection: 0x04 });
    const evidence = analyzeLandingBytes(address, Uint8Array.from([0x41, 0x41, 0x41, 0x41, 0x41]), memory, 16, null);

    expect(evidence.observations).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "repeated_marker_bytes", address, length: 5 }),
      expect.objectContaining({ kind: "bytes_truncated", address: address + BigInt(5), length: 11 }),
      expect.objectContaining({ kind: "non_executable_region" }),
    ]));
    expect(evidence.recommendation).toContain("will fault");
  });

  test("does not convert unknown memory evidence into negative observations", () => {
    const memory = normalizeMemoryRegion(address, {}, "unavailable");
    const evidence = analyzeLandingBytes(address, new Uint8Array(), memory, 16, null);
    const kinds = evidence.observations.map((item) => item.kind);

    expect(kinds).not.toContain("unreadable_region");
    expect(kinds).not.toContain("non_executable_region");
    expect(kinds).toContain("bytes_inaccessible");
  });

  test("normalizes the legacy triage low-printability window as evidence", () => {
    const memory = normalizeMemoryRegion(address, { protection: 0x04 });
    const bytes = Uint8Array.from(Array.from({ length: 32 }, (_, index) => (index % 8) + 1));
    const evidence = analyzeLandingBytes(address, bytes, memory);

    expect(evidence.observations).toContainEqual(expect.objectContaining({
      kind: "payload_like_bytes",
      address,
      length: 32,
      details: expect.objectContaining({ offset: 0, zeroes: 0, printable: 0 }),
    }));
  });

  test("keeps aggregate confidence bounded and independent of observation order", () => {
    const observations: Observation[] = [
      { kind: "nop_sled_detected", confidence: 0.95, address, length: 8, details: {} },
      { kind: "payload_like_bytes", confidence: 5, address, length: 32, details: {} },
      { kind: "disassembly_succeeded", confidence: Number.NaN, address, length: 1, details: {} },
    ];

    expect(calculateLandingConfidence(observations)).toBe(0.975);
    expect(calculateLandingConfidence([...observations].reverse())).toBe(0.975);
    expect(calculateLandingConfidence([{ ...observations[0], confidence: -10 }])).toBe(0);
  });

  test("derives stable observation identity independent of details key order", () => {
    const left: Observation = { kind: "payload_like_bytes", confidence: 0.4, address, length: 32, details: { printable: 2, zeroes: 0 } };
    const right: Observation = { kind: "payload_like_bytes", confidence: 0.9, address, length: 32, details: { zeroes: 0, printable: 2 } };

    expect(observationIdentity(left)).toBe(observationIdentity(right));
  });
});
