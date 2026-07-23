import { describe, expect, test } from "vitest";
import { sequencesFromLiveHits } from "../src/semantics/live-provider";
import { buildCapabilityIndexFromSequences, formatChainPython, planRegisterSetup, planVirtualAlloc, planVirtualProtect, planWriteProcessMemory } from "../src/rop";

// Chain construction over an index built from (synthetic) live gadget hits, so it
// exercises the full live -> index -> plan path.
const index = buildCapabilityIndexFromSequences(
  sequencesFromLiveHits([
    { mnemonic: "pop eax ; ret", address: BigInt(0x00401000), module: "vuln" },
    { mnemonic: "pop ebx ; ret", address: BigInt(0x00401010), module: "vuln" },
    { mnemonic: "pop ecx ; pop edx ; ret", address: BigInt(0x00401020), module: "vuln" },
  ]),
);

describe("register-setup chain construction", () => {
  test("emits gadget/value pairs at real addresses for satisfiable registers", () => {
    const plan = planRegisterSetup(index, [
      { register: "eax", value: 0xdeadbeef },
      { register: "ebx", value: 0x00001000 },
    ]);
    expect(plan.satisfied).toEqual(["eax", "ebx"]);
    expect(plan.unsatisfied).toEqual([]);
    expect(plan.stackBytes).toBe(16);
    expect(plan.steps).toEqual([
      { kind: "gadget", address: BigInt(0x00401000), comment: "pop eax ; ret" },
      { kind: "value", value: 0xdeadbeef, comment: "eax = 0xDEADBEEF" },
      { kind: "gadget", address: BigInt(0x00401010), comment: "pop ebx ; ret" },
      { kind: "value", value: 0x00001000, comment: "ebx = 0x00001000" },
    ]);
  });

  test("reports registers with only multi-pop gadgets as unsatisfied, with reason", () => {
    const plan = planRegisterSetup(index, [{ register: "ecx", value: 0x41414141 }]);
    expect(plan.satisfied).toEqual([]);
    expect(plan.unsatisfied).toEqual([
      { register: "ecx", reason: "only multi-pop or address-less load gadgets available" },
    ]);
  });

  test("reports registers with no load gadget at all", () => {
    const plan = planRegisterSetup(index, [{ register: "edi", value: 0 }]);
    expect(plan.unsatisfied).toEqual([{ register: "edi", reason: "no pop gadget found for register" }]);
  });

  test("formatChainPython renders paste-ready pack() lines", () => {
    const plan = planRegisterSetup(index, [{ register: "eax", value: 0xdeadbeef }]);
    expect(formatChainPython(plan)).toEqual([
      "from struct import pack",
      'rop = b""',
      'rop += pack("<I", 0x00401000)  # pop eax ; ret',
      'rop += pack("<I", 0xDEADBEEF)  # eax = 0xDEADBEEF',
    ]);
  });
});

describe("smarter chain construction: multi-pop and zeroing", () => {
  test("co-satisfies two registers with a single multi-pop gadget", () => {
    const multi = buildCapabilityIndexFromSequences(
      sequencesFromLiveHits([
        { mnemonic: "pop eax ; pop ebx ; ret", address: BigInt(0x00402000), module: "vuln" },
        { mnemonic: "pop eax ; ret", address: BigInt(0x00402100), module: "vuln" },
        { mnemonic: "pop ebx ; ret", address: BigInt(0x00402110), module: "vuln" },
      ]),
    );
    const plan = planRegisterSetup(multi, [
      { register: "eax", value: 0x11111111 },
      { register: "ebx", value: 0x22222222 },
    ]);
    expect(plan.satisfied).toEqual(["eax", "ebx"]);
    expect(plan.stackBytes).toBe(12); // one gadget slot + two value slots
    expect(plan.steps).toEqual([
      { kind: "gadget", address: BigInt(0x00402000), comment: "pop eax ; pop ebx ; ret" },
      { kind: "value", value: 0x11111111, comment: "eax = 0x11111111" },
      { kind: "value", value: 0x22222222, comment: "ebx = 0x22222222" },
    ]);
  });

  test("zeroes a value-0 target with xor, preferring it over a pop", () => {
    const both = buildCapabilityIndexFromSequences(
      sequencesFromLiveHits([
        { mnemonic: "xor eax, eax ; ret", address: BigInt(0x00404000), module: "vuln" },
        { mnemonic: "pop eax ; ret", address: BigInt(0x00404010), module: "vuln" },
      ]),
    );
    const plan = planRegisterSetup(both, [{ register: "eax", value: 0 }]);
    expect(plan.satisfied).toEqual(["eax"]);
    expect(plan.stackBytes).toBe(4); // xor gadget only, no value slot
    expect(plan.steps).toEqual([
      { kind: "gadget", address: BigInt(0x00404000), comment: "xor eax, eax ; ret (eax = 0)" },
    ]);
  });

  test("mixes zeroing and pop across targets", () => {
    const mixed = buildCapabilityIndexFromSequences(
      sequencesFromLiveHits([
        { mnemonic: "xor eax, eax ; ret", address: BigInt(0x00405000), module: "vuln" },
        { mnemonic: "pop ebx ; ret", address: BigInt(0x00405010), module: "vuln" },
      ]),
    );
    const plan = planRegisterSetup(mixed, [
      { register: "eax", value: 0 },
      { register: "ebx", value: 0x5 },
    ]);
    expect(plan.satisfied).toEqual(["eax", "ebx"]);
    expect(plan.steps).toEqual([
      { kind: "gadget", address: BigInt(0x00405000), comment: "xor eax, eax ; ret (eax = 0)" },
      { kind: "gadget", address: BigInt(0x00405010), comment: "pop ebx ; ret" },
      { kind: "value", value: 0x5, comment: "ebx = 0x00000005" },
    ]);
  });
});

describe("VirtualProtect goal template (PUSHAD technique)", () => {
  const vpIndex = buildCapabilityIndexFromSequences(
    sequencesFromLiveHits([
      { mnemonic: "pop edi ; ret", address: BigInt(0x00401000), module: "vuln" },
      { mnemonic: "pop esi ; ret", address: BigInt(0x00401010), module: "vuln" },
      { mnemonic: "pop ebp ; ret", address: BigInt(0x00401020), module: "vuln" },
      { mnemonic: "pop ebx ; ret", address: BigInt(0x00401030), module: "vuln" },
      { mnemonic: "pop edx ; ret", address: BigInt(0x00401040), module: "vuln" },
      { mnemonic: "pop ecx ; ret", address: BigInt(0x00401050), module: "vuln" },
      { mnemonic: "pop eax ; ret", address: BigInt(0x00401060), module: "vuln" },
      { mnemonic: "pushad ; ret", address: BigInt(0x00401070), module: "vuln" },
    ]),
  );

  test("resolves every gadget and constant when addresses are supplied", () => {
    const plan = planVirtualProtect(vpIndex, {
      virtualProtect: 0x7c801ad0,
      returnAddress: 0x080414d3,
      lpAddress: 0x00110000,
      writable: 0x0040a000,
    });
    expect(plan.satisfied).toEqual(["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"]);
    expect(plan.unsatisfied).toEqual([]);
    expect(plan.placeholders).toEqual([]);
    expect(plan.hasPushad).toBe(true);
    expect(plan.stackBytes).toBe(60); // 7 pops + 7 values + pushad
    // Constants are concrete; the frame terminates with the pushad gadget.
    expect(plan.steps[7]).toEqual({ kind: "value", value: 0x40, comment: "ebx = 0x00000040 (flNewProtect = PAGE_EXECUTE_READWRITE)" });
    expect(plan.steps[plan.steps.length - 1]).toEqual({
      kind: "gadget",
      address: BigInt(0x00401070),
      comment: "pushad ; ret (builds the VirtualProtect call frame and dispatches)",
    });
  });

  test("emits named placeholders for runtime-dependent values", () => {
    const plan = planVirtualProtect(vpIndex, {});
    expect(plan.placeholders).toEqual(["VIRTUALPROTECT", "RETURN_ADDR", "LP_ADDRESS", "WRITABLE"]);
    const python = formatChainPython(plan);
    expect(python).toContain('rop += pack("<I", VIRTUALPROTECT)  # edi = VIRTUALPROTECT (VirtualProtect (RET dispatches here))');
    expect(python).toContain('rop += pack("<I", 0x00000040)  # ebx = 0x00000040 (flNewProtect = PAGE_EXECUTE_READWRITE)');
  });

  test("reports missing pushad and missing pop gadgets honestly", () => {
    const partial = buildCapabilityIndexFromSequences(
      sequencesFromLiveHits([{ mnemonic: "pop edi ; ret", address: BigInt(0x00401000), module: "vuln" }]),
    );
    const plan = planVirtualProtect(partial, { virtualProtect: 0x7c801ad0 });
    expect(plan.hasPushad).toBe(false);
    expect(plan.unsatisfied.some((entry) => entry.register === "pushad")).toBe(true);
    expect(plan.unsatisfied.some((entry) => entry.register === "esi")).toBe(true);
    expect(plan.satisfied).toEqual(["edi"]);
  });
});

// Reuse the same full-gadget corpus for WPM and VA tests.
const fullCorpusHits = [
  { mnemonic: "pop edi ; ret", address: BigInt(0x00401000), module: "vuln" },
  { mnemonic: "pop esi ; ret", address: BigInt(0x00401010), module: "vuln" },
  { mnemonic: "pop ebp ; ret", address: BigInt(0x00401020), module: "vuln" },
  { mnemonic: "pop ebx ; ret", address: BigInt(0x00401030), module: "vuln" },
  { mnemonic: "pop edx ; ret", address: BigInt(0x00401040), module: "vuln" },
  { mnemonic: "pop ecx ; ret", address: BigInt(0x00401050), module: "vuln" },
  { mnemonic: "pop eax ; ret", address: BigInt(0x00401060), module: "vuln" },
  { mnemonic: "pushad ; ret", address: BigInt(0x00401070), module: "vuln" },
];
const fullIndex = buildCapabilityIndexFromSequences(sequencesFromLiveHits(fullCorpusHits));

describe("WriteProcessMemory goal template (PUSHAD technique)", () => {
  test("resolves all gadgets with hProcess = 0xFFFFFFFF hard-coded", () => {
    const plan = planWriteProcessMemory(fullIndex, {
      writeProcessMemory: 0x7c802213,
      returnAddress: 0x080414d3,
      lpBuffer: 0x00110000,
      nSize: 0x200,
      writable: 0x0040a000,
    });
    expect(plan.satisfied).toEqual(["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"]);
    expect(plan.unsatisfied).toEqual([]);
    expect(plan.hasPushad).toBe(true);
    // EBP is always 0xFFFFFFFF (GetCurrentProcess pseudo-handle).
    const ebpValue = plan.steps.find((s) => s.comment.includes("hProcess"));
    expect(ebpValue?.value).toBe(0xFFFFFFFF >>> 0);
  });

  test("emits placeholders for runtime-dependent WPM values", () => {
    const plan = planWriteProcessMemory(fullIndex, {});
    expect(plan.placeholders).toContain("WRITEPROCESSMEMORY");
    expect(plan.placeholders).toContain("LP_BUFFER");
    expect(plan.placeholders).toContain("NSIZE");
    expect(plan.placeholders).toContain("WRITABLE");
    // EBP is always concrete (0xFFFFFFFF), so no placeholder for hProcess.
    expect(plan.placeholders).not.toContain("HPROCESS");
    const python = formatChainPython(plan);
    expect(python.some((line) => line.includes("WRITEPROCESSMEMORY"))).toBe(true);
    expect(python.some((line) => line.includes("0xFFFFFFFF"))).toBe(true);
  });

  test("pushad comment names WriteProcessMemory", () => {
    const plan = planWriteProcessMemory(fullIndex, {});
    const last = plan.steps[plan.steps.length - 1];
    expect(last.comment).toContain("WriteProcessMemory");
  });
});

describe("VirtualAlloc goal template (PUSHAD technique)", () => {
  test("resolves all gadgets with default MEM_COMMIT and PAGE_EXECUTE_READWRITE", () => {
    const plan = planVirtualAlloc(fullIndex, {
      virtualAlloc: 0x7c809ae1,
      returnAddress: 0x080414d3,
      lpAddress: 0,
    });
    expect(plan.satisfied).toEqual(["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"]);
    expect(plan.unsatisfied).toEqual([]);
    expect(plan.hasPushad).toBe(true);
    // EBX = MEM_COMMIT (0x1000), EDX = PAGE_EXECUTE_READWRITE (0x40).
    const ebxValue = plan.steps.find((s) => s.comment.includes("flAllocationType"));
    expect(ebxValue?.value).toBe(0x1000);
    const edxValue = plan.steps.find((s) => s.comment.includes("flProtect"));
    expect(edxValue?.value).toBe(0x40);
  });

  test("allows overriding flAllocationType and flProtect", () => {
    const plan = planVirtualAlloc(fullIndex, {
      virtualAlloc: 0x7c809ae1,
      flAllocationType: 0x3000,
      flProtect: 0x04,
    });
    const ebxValue = plan.steps.find((s) => s.comment.includes("flAllocationType"));
    expect(ebxValue?.value).toBe(0x3000);
    const edxValue = plan.steps.find((s) => s.comment.includes("flProtect"));
    expect(edxValue?.value).toBe(0x04);
  });

  test("emits placeholders for VirtualAlloc runtime values", () => {
    const plan = planVirtualAlloc(fullIndex, {});
    expect(plan.placeholders).toContain("VIRTUALALLOC");
    expect(plan.placeholders).toContain("RETURN_ADDR");
    expect(plan.placeholders).toContain("LP_ADDRESS");
    // flAllocationType and flProtect have defaults — no placeholders.
    expect(plan.placeholders).not.toContain("FL_ALLOCATION_TYPE");
  });

  test("pushad comment names VirtualAlloc", () => {
    const plan = planVirtualAlloc(fullIndex, {});
    const last = plan.steps[plan.steps.length - 1];
    expect(last.comment).toContain("VirtualAlloc");
  });
});
