import { describe, expect, test } from "vitest";
import { isInstructionPointerControlled, landingCandidateAddresses, selectTriageModules, ScoredModule } from "../src/commands/triage";
import { normalizeMemoryRegion } from "../src/analysis/memory";

describe("triage control detection", () => {
  test("reports control when a pattern offset is matched", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: true,
        ip: BigInt("0x41414141"),
        ipBackedByModule: false,
      }),
    ).toBe(true);
  });

  test("reports control when ip is outside loaded modules", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: false,
        ip: BigInt("0x41414141"),
        ipBackedByModule: false,
      }),
    ).toBe(true);
  });

  test("reports control on access violations even when the ip is module-backed", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: false,
        ip: BigInt("0x10001000"),
        ipBackedByModule: true,
        exceptionCode: BigInt("0xc0000005"),
      }),
    ).toBe(true);
  });

  test("does not report control when ip is in a loaded module", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: false,
        ip: BigInt("0x10001000"),
        ipBackedByModule: true,
      }),
    ).toBe(false);
  });

  test("does not report control when ip is unavailable", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: false,
        ipBackedByModule: false,
      }),
    ).toBe(false);
  });
});

describe("triage module selection", () => {
  const mod = (name: string, aslr: ScoredModule["aslr"], score: number): ScoredModule => ({
    module: name,
    score,
    aslr,
    nxcompat: "disabled",
    safeseh: "disabled",
    system: aslr === "enabled",
  });

  test("keeps every attacker-controlled module even when more than the tail limit are tied", () => {
    // Ten ASLR-disabled modules all tied at the top score, mirroring the
    // Mini-stream target where a fixed slice(0, 6) dropped four valuable modules.
    const controlled = Array.from({ length: 10 }, (_, i) => mod(`ctrl${i}.dll`, "disabled", 100));
    const selected = selectTriageModules(controlled);
    expect(selected.map((m) => m.module)).toEqual(controlled.map((m) => m.module));
    expect(selected).toHaveLength(10);
  });

  test("caps only the ASLR-enabled tail so hardened targets stay bounded", () => {
    const hardened = Array.from({ length: 12 }, (_, i) => mod(`sys${i}.dll`, "enabled", 45));
    const selected = selectTriageModules(hardened);
    expect(selected).toHaveLength(6);
    expect(selected.every((m) => m.aslr === "enabled")).toBe(true);
  });

  test("lists all controlled modules ahead of a bounded enabled tail", () => {
    const modules = [
      ...Array.from({ length: 8 }, (_, i) => mod(`ctrl${i}.dll`, "disabled", 100)),
      ...Array.from({ length: 9 }, (_, i) => mod(`sys${i}.dll`, "enabled", 45)),
    ];
    const selected = selectTriageModules(modules);
    const controlledCount = selected.filter((m) => m.aslr === "disabled").length;
    const enabledCount = selected.filter((m) => m.aslr === "enabled").length;
    expect(controlledCount).toBe(8);
    expect(enabledCount).toBe(6);
    // Controlled modules sort ahead of the enabled tail.
    expect(selected.slice(0, 8).every((m) => m.aslr === "disabled")).toBe(true);
  });

  test("orders by score descending", () => {
    const selected = selectTriageModules([
      mod("low.dll", "enabled", 10),
      mod("high.dll", "enabled", 70),
      mod("mid.dll", "enabled", 45),
    ]);
    expect(selected.map((m) => m.module)).toEqual(["high.dll", "mid.dll", "low.dll"]);
  });
});

describe("triage landing projection", () => {
  test("renders candidates from shared landing observations without rescanning bytes", () => {
    const base = BigInt("0x12f800");
    const memory = normalizeMemoryRegion(base, { protection: 0x04 });
    expect(landingCandidateAddresses({
      address: base,
      memory,
      bytes: [],
      requestedBytes: 64,
      confidence: 0,
      recommendation: "",
      observations: [
        { kind: "readable_region", confidence: 1, address: base, length: 64, details: {} },
        { kind: "payload_like_bytes", confidence: 0.4, address: base + BigInt(8), length: 32, details: {} },
        { kind: "nop_sled_detected", confidence: 0.95, address: base, length: 12, details: {} },
      ],
    })).toEqual([base, base + BigInt(8)]);
  });
});
