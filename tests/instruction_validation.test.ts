import { describe, expect, test } from "vitest";
import {
  knownPatterns,
  knownPatternsForPointerSize,
  validateInstructionCandidate,
  validateInstructionCandidateForPointerSize,
} from "../src/logic/instruction_validation";

describe("instruction_validation", () => {
  test("knownPatterns includes all 8 pop-reg ; ret gadgets", () => {
    const patterns = knownPatterns();
    const popRets = ["pop eax", "pop ecx", "pop edx", "pop ebx", "pop esp", "pop ebp", "pop esi", "pop edi"];
    for (const reg of popRets) {
      const mnemonic = `${reg} ; ret`;
      expect(patterns.some((p) => p.mnemonic === mnemonic)).toBe(true);
    }
  });

  test("knownPatterns includes jmp esp and call esp", () => {
    const patterns = knownPatterns();
    expect(patterns.some((p) => p.mnemonic === "jmp esp")).toBe(true);
    expect(patterns.some((p) => p.mnemonic === "call esp")).toBe(true);
  });

  test("knownPatterns includes jmp eax and call eax", () => {
    const patterns = knownPatterns();
    expect(patterns.some((p) => p.mnemonic === "jmp eax")).toBe(true);
    expect(patterns.some((p) => p.mnemonic === "call eax")).toBe(true);
  });

  test("knownPatterns includes leave ; ret", () => {
    const patterns = knownPatterns();
    expect(patterns.some((p) => p.mnemonic === "leave ; ret")).toBe(true);
  });

  test("knownPatterns includes xchg variants for all non-eax registers", () => {
    const patterns = knownPatterns();
    for (const reg of ["ecx", "edx", "ebx", "esi", "edi", "ebp"]) {
      expect(patterns.some((p) => p.mnemonic === `xchg ${reg}, esp ; ret`)).toBe(true);
    }
  });

  test("validateInstructionCandidate matches jmp esp bytes", () => {
    const result = validateInstructionCandidate(Uint8Array.from([0xff, 0xe4]), true, true);
    expect(result.flags.decoded).toBe(true);
    expect(result.mnemonic).toBe("jmp esp");
  });

  test("validateInstructionCandidate matches leave ; ret bytes", () => {
    const result = validateInstructionCandidate(Uint8Array.from([0xc9, 0xc3]), true, true);
    expect(result.flags.decoded).toBe(true);
    expect(result.mnemonic).toBe("leave ; ret");
  });

  test("validateInstructionCandidate does not match unknown bytes", () => {
    const result = validateInstructionCandidate(Uint8Array.from([0x90, 0x90]), true, true);
    expect(result.flags.decoded).toBe(false);
    expect(result.mnemonic).toBeUndefined();
  });

  test("PPR patterns are still 64 entries covering all pop-pop-ret combos", () => {
    const pprs = knownPatterns().filter((p) => /^pop \w+ ; pop \w+ ; ret$/.test(p.mnemonic));
    expect(pprs.length).toBe(64);
  });

  test("knownPatterns includes inc and dec for all 8 GP registers", () => {
    const patterns = knownPatterns();
    for (const reg of ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]) {
      expect(patterns.some((p) => p.mnemonic === `inc ${reg} ; ret`)).toBe(true);
      expect(patterns.some((p) => p.mnemonic === `dec ${reg} ; ret`)).toBe(true);
    }
  });

  test("knownPatterns includes neg for all 8 GP registers", () => {
    const patterns = knownPatterns();
    for (const reg of ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]) {
      expect(patterns.some((p) => p.mnemonic === `neg ${reg} ; ret`)).toBe(true);
    }
  });

  test("knownPatterns includes pushad ; ret with correct bytes", () => {
    const p = knownPatterns().find((p) => p.mnemonic === "pushad ; ret");
    expect(p).toBeDefined();
    expect(p?.bytes).toEqual([0x60, 0xc3]);
  });

  test("knownPatterns includes 48 mov [dst], src ; ret patterns (6 dsts × 8 srcs)", () => {
    const writes = knownPatterns().filter((p) => p.mnemonic.startsWith("mov ["));
    expect(writes.length).toBe(48);
  });

  test("validateInstructionCandidate matches inc eax ; ret bytes (40 C3)", () => {
    const result = validateInstructionCandidate(Uint8Array.from([0x40, 0xc3]), true, true);
    expect(result.flags.decoded).toBe(true);
    expect(result.mnemonic).toBe("inc eax ; ret");
  });

  test("validateInstructionCandidate matches neg eax ; ret bytes (F7 D8 C3)", () => {
    const result = validateInstructionCandidate(Uint8Array.from([0xf7, 0xd8, 0xc3]), true, true);
    expect(result.flags.decoded).toBe(true);
    expect(result.mnemonic).toBe("neg eax ; ret");
  });

  test("validateInstructionCandidate matches mov [eax], ecx ; ret bytes (89 08 C3)", () => {
    const result = validateInstructionCandidate(Uint8Array.from([0x89, 0x08, 0xc3]), true, true);
    expect(result.flags.decoded).toBe(true);
    expect(result.mnemonic).toBe("mov [eax], ecx ; ret");
  });

  test("x64 pattern catalog includes rsp dispatch and 64-bit pivots", () => {
    const patterns = knownPatternsForPointerSize(8);
    expect(patterns.some((p) => p.mnemonic === "jmp rsp" && p.bytes.join(" ") === "255 228")).toBe(true);
    expect(patterns.some((p) => p.mnemonic === "call rsp")).toBe(true);
    expect(patterns.some((p) => p.mnemonic === "xchg rax, rsp ; ret")).toBe(true);
    expect(patterns.some((p) => p.mnemonic === "mov rsp, rbp ; ret")).toBe(true);
  });

  test("x64 validator does not classify REX prefix 40 C3 as x86 inc eax ; ret", () => {
    const x86 = validateInstructionCandidateForPointerSize(Uint8Array.from([0x40, 0xc3]), true, true, 4);
    const x64 = validateInstructionCandidateForPointerSize(Uint8Array.from([0x40, 0xc3]), true, true, 8);
    expect(x86.mnemonic).toBe("inc eax ; ret");
    expect(x64.flags.decoded).toBe(false);
  });

  test("x64 validator classifies FF E4 as jmp rsp", () => {
    const result = validateInstructionCandidateForPointerSize(Uint8Array.from([0xff, 0xe4]), true, true, 8);
    expect(result.flags.decoded).toBe(true);
    expect(result.mnemonic).toBe("jmp rsp");
  });
});
