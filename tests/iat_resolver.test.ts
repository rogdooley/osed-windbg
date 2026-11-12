import { describe, expect, test, vi, beforeEach } from "vitest";

// ── Mock memory ──────────────────────────────────────────────────────────────
// A byte-addressable map that the mocked core/memory functions read from.
const mem = new Map<number, number>();

function memWriteU16(address: bigint, value: number): void {
  const a = Number(address);
  mem.set(a, value & 0xff);
  mem.set(a + 1, (value >>> 8) & 0xff);
}

function memWriteU32(address: bigint, value: number): void {
  const a = Number(address);
  mem.set(a, value & 0xff);
  mem.set(a + 1, (value >>> 8) & 0xff);
  mem.set(a + 2, (value >>> 16) & 0xff);
  mem.set(a + 3, (value >>> 24) & 0xff);
}

function memWriteString(address: bigint, text: string): void {
  let a = Number(address);
  for (let i = 0; i < text.length; i += 1) {
    mem.set(a++, text.charCodeAt(i));
  }
  mem.set(a, 0);
}

function memReadBytes(address: bigint, length: number): Uint8Array {
  const a = Number(address);
  const result = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    const byte = mem.get(a + i);
    if (byte === undefined) throw new Error(`Unmapped read at 0x${(a + i).toString(16)}`);
    result[i] = byte;
  }
  return result;
}

function memTryReadBytes(address: bigint, length: number): Uint8Array | undefined {
  const a = Number(address);
  const result = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    const byte = mem.get(a + i);
    if (byte === undefined) {
      return i === 0 ? undefined : result.slice(0, i);
    }
    result[i] = byte;
  }
  return result;
}

vi.mock("../src/core/memory", () => ({
  getPointerSize: () => 4 as 4 | 8,
  readMemory: (address: bigint, length: number) => memReadBytes(address, length),
  tryReadMemory: (address: bigint, length: number) => memTryReadBytes(address, length),
  readUint16LE: (address: bigint) => {
    const b = memReadBytes(address, 2);
    return b[0] | (b[1] << 8);
  },
  readUint32LE: (address: bigint) => {
    const b = memReadBytes(address, 4);
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  },
  readUint64LE: (address: bigint) => {
    const b = memReadBytes(address, 8);
    let result = BigInt(0);
    for (let i = 0; i < 8; i += 1) result |= BigInt(b[i]) << BigInt(i * 8);
    return result;
  },
  readPointer: (address: bigint, pointerSize: 4 | 8) => {
    if (pointerSize === 8) {
      const b = memReadBytes(address, 8);
      let r = BigInt(0);
      for (let i = 0; i < 8; i += 1) r |= BigInt(b[i]) << BigInt(i * 8);
      return r;
    }
    const b = memReadBytes(address, 4);
    return BigInt((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0);
  },
  executeDebuggerCommand: () => [],
  parseProtectFromVprot: () => undefined,
  decodeProtectValue: () => "UNKNOWN",
}));

vi.mock("../src/core/output", () => ({
  formatAddress: (addr: bigint) => `0x${addr.toString(16).toUpperCase()}`,
}));

import { IATResolver, PEParser, ExportResolver, type ModuleInfo } from "../src/shellcode/index";

// ── PE builder ───────────────────────────────────────────────────────────────
// Lays out a minimal PE32 image in the mock memory so PEParser.parseHeaders and
// IATResolver.enumerateIat work end to end.

interface PeLayout {
  ntHeaderOffset: number;
  sizeOfOptionalHeader: number;
  importDirRva: number;
}

function buildMinimalPe(base: bigint, layout: PeLayout): void {
  // DOS header
  memWriteU16(base, 0x5a4d); // MZ
  memWriteU32(base + BigInt(0x3c), layout.ntHeaderOffset); // e_lfanew

  const nt = base + BigInt(layout.ntHeaderOffset);
  // NT signature
  memWriteU32(nt, 0x00004550);
  // COFF header
  memWriteU16(nt + BigInt(0x4), 0x014c); // Machine: i386
  memWriteU16(nt + BigInt(0x6), 1);      // NumberOfSections
  memWriteU16(nt + BigInt(0x14), layout.sizeOfOptionalHeader);

  // Optional header
  const opt = nt + BigInt(0x18);
  memWriteU16(opt, 0x10b); // PE32 magic
  memWriteU32(opt + BigInt(0x10), 0x1000); // AddressOfEntryPoint
  memWriteU32(opt + BigInt(0x1c), Number(base)); // ImageBase
  memWriteU32(opt + BigInt(0x38), 0x200000); // SizeOfImage

  // Data directory[0] — export (zeroed = no exports)
  const dataDirOffset = opt + BigInt(0x60);
  memWriteU32(dataDirOffset, 0);
  memWriteU32(dataDirOffset + BigInt(4), 0);

  // Data directory[1] — import
  memWriteU32(dataDirOffset + BigInt(8), layout.importDirRva);
  memWriteU32(dataDirOffset + BigInt(12), 40);

  // Section header (one section covering the module's .text)
  const sectionHeader = nt + BigInt(0x18 + layout.sizeOfOptionalHeader);
  memWriteU32(sectionHeader + BigInt(0x8), 0x1ff000);   // VirtualSize
  memWriteU32(sectionHeader + BigInt(0xc), 0x1000);     // VirtualAddress
  memWriteU32(sectionHeader + BigInt(0x24), 0x60000020); // IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE
}

interface IatSetup {
  base: bigint;
  importDirRva: number;
  descriptors: Array<{
    dllName: string;
    dllNameRva: number;
    intRva: number;
    iatRva: number;
    entries: Array<{
      nameRva: number;
      importName: string;
      targetValue: number;
    }>;
  }>;
}

function buildIat(setup: IatSetup): void {
  let descAddr = setup.base + BigInt(setup.importDirRva);
  for (const desc of setup.descriptors) {
    memWriteU32(descAddr, desc.intRva);                      // OriginalFirstThunk
    memWriteU32(descAddr + BigInt(0x4), 0);                   // TimeDateStamp
    memWriteU32(descAddr + BigInt(0x8), 0);                   // ForwarderChain
    memWriteU32(descAddr + BigInt(0xc), desc.dllNameRva);     // Name RVA
    memWriteU32(descAddr + BigInt(0x10), desc.iatRva);        // FirstThunk (IAT)
    descAddr += BigInt(0x14);

    // DLL name
    memWriteString(setup.base + BigInt(desc.dllNameRva), desc.dllName);

    // INT entries
    let intPtr = setup.base + BigInt(desc.intRva);
    for (const entry of desc.entries) {
      memWriteU32(intPtr, entry.nameRva);
      intPtr += BigInt(4);
      // IMAGE_IMPORT_BY_NAME: hint (u16) + name
      memWriteU16(setup.base + BigInt(entry.nameRva), 0);
      memWriteString(setup.base + BigInt(entry.nameRva) + BigInt(2), entry.importName);
    }
    memWriteU32(intPtr, 0); // null terminator

    // IAT entries
    let iatPtr = setup.base + BigInt(desc.iatRva);
    for (const entry of desc.entries) {
      memWriteU32(iatPtr, entry.targetValue);
      iatPtr += BigInt(4);
    }
    memWriteU32(iatPtr, 0); // null terminator
  }
  // Null descriptor terminator
  for (let i = 0; i < 5; i += 1) memWriteU32(descAddr + BigInt(i * 4), 0);
}

// ── Test fixtures ────────────────────────────────────────────────────────────

const LIBSPP_BASE = BigInt("0x10000000");
const LIBSPP_END = BigInt("0x10200000");

const KERNEL32_BASE = BigInt("0x76210000");
const KERNEL32_END = BigInt("0x762F0000");

const libspp: ModuleInfo = { name: "libspp.dll", path: "libspp.dll", base: LIBSPP_BASE, end: LIBSPP_END, size: LIBSPP_END - LIBSPP_BASE };
const kernel32: ModuleInfo = { name: "kernel32.dll", path: "kernel32.dll", base: KERNEL32_BASE, end: KERNEL32_END, size: KERNEL32_END - KERNEL32_BASE };

function makeResolver(modules: ModuleInfo[]): IATResolver {
  const parser = new PEParser(4);
  const exportResolver = new ExportResolver(parser);
  return new IATResolver(4, parser, exportResolver, () => modules);
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("IATResolver", () => {
  beforeEach(() => {
    mem.clear();
  });

  test("target equals the raw DWORD stored in the IAT slot", () => {
    const iatRva = 0x168040;
    const getLastErrorTarget = 0x7622f020;
    const getProcessHeapTarget = 0x76230590;

    buildMinimalPe(LIBSPP_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0x2000 });
    buildIat({
      base: LIBSPP_BASE,
      importDirRva: 0x2000,
      descriptors: [{
        dllName: "KERNEL32.dll",
        dllNameRva: 0x4000,
        intRva: 0x3000,
        iatRva: iatRva,
        entries: [
          { nameRva: 0x5000, importName: "GetLastError", targetValue: getLastErrorTarget },
          { nameRva: 0x5020, importName: "GetProcessHeap", targetValue: getProcessHeapTarget },
        ],
      }],
    });

    // kernel32 needs a PE header for isExecutable; build a minimal one.
    buildMinimalPe(KERNEL32_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0 });
    // isMapped needs at least 1 byte readable at each target address.
    mem.set(getLastErrorTarget, 0xcc);
    mem.set(getProcessHeapTarget, 0xcc);

    const resolver = makeResolver([libspp, kernel32]);
    const entries = resolver.enumerateIat(libspp);

    expect(entries).toHaveLength(2);
    expect(entries[0].slot).toBe(LIBSPP_BASE + BigInt(iatRva));
    expect(entries[0].target).toBe(BigInt(getLastErrorTarget));
    expect(entries[0].symbol).toBe("GetLastError");
    expect(entries[0].status).toBe("ok");

    expect(entries[1].slot).toBe(LIBSPP_BASE + BigInt(iatRva + 4));
    expect(entries[1].target).toBe(BigInt(getProcessHeapTarget));
    expect(entries[1].symbol).toBe("GetProcessHeap");
    expect(entries[1].status).toBe("ok");
  });

  test("target reflects new values after simulated process restart", () => {
    const iatRva = 0x168040;
    const oldTarget = 0x750b0330;

    buildMinimalPe(LIBSPP_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0x2000 });
    buildIat({
      base: LIBSPP_BASE,
      importDirRva: 0x2000,
      descriptors: [{
        dllName: "KERNEL32.dll",
        dllNameRva: 0x4000,
        intRva: 0x3000,
        iatRva: iatRva,
        entries: [
          { nameRva: 0x5000, importName: "GetLastError", targetValue: oldTarget },
        ],
      }],
    });

    // old kernel32 at 0x750A0000 range
    const oldK32: ModuleInfo = { name: "kernel32.dll", path: "kernel32.dll", base: BigInt("0x750A0000"), end: BigInt("0x751A0000"), size: BigInt("0x100000") };
    buildMinimalPe(oldK32.base, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0 });
    mem.set(oldTarget, 0xcc);

    const resolver = makeResolver([libspp, oldK32]);
    const before = resolver.enumerateIat(libspp);
    expect(before[0].target).toBe(BigInt(oldTarget));

    // Simulate process restart: new kernel32 at current base, new IAT value
    const newTarget = 0x7622f020;
    memWriteU32(LIBSPP_BASE + BigInt(iatRva), newTarget);

    buildMinimalPe(KERNEL32_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0 });
    mem.set(newTarget, 0xcc);

    const resolver2 = makeResolver([libspp, kernel32]);
    const after = resolver2.enumerateIat(libspp);
    expect(after[0].target).toBe(BigInt(newTarget));
    expect(after[0].status).toBe("ok");
  });

  test("mixed entries: some in-module, some out-of-range", () => {
    const iatRva = 0x168040;
    const heapFreeTarget = 0x7622ef70;   // in kernel32 range → ok
    const unmappedTarget = 0x44444444;   // no module, unmapped → unmapped

    buildMinimalPe(LIBSPP_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0x2000 });
    mem.set(heapFreeTarget, 0xcc); // make target mappable
    buildIat({
      base: LIBSPP_BASE,
      importDirRva: 0x2000,
      descriptors: [{
        dllName: "KERNEL32.dll",
        dllNameRva: 0x4000,
        intRva: 0x3000,
        iatRva: iatRva,
        entries: [
          { nameRva: 0x5000, importName: "HeapFree", targetValue: heapFreeTarget },
          { nameRva: 0x5020, importName: "BadFunc", targetValue: unmappedTarget },
        ],
      }],
    });

    buildMinimalPe(KERNEL32_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0 });

    const resolver = makeResolver([libspp, kernel32]);
    const entries = resolver.enumerateIat(libspp);

    expect(entries[0].target).toBe(BigInt(heapFreeTarget));
    expect(entries[0].status).toBe("ok");

    expect(entries[1].target).toBe(BigInt(unmappedTarget));
    expect(entries[1].status).toBe("unmapped");
  });

  test("status evaluates executability against the raw target, not a resolved address", () => {
    // Place the IAT target at a non-executable RVA within kernel32.
    // Section .text covers RVA 0x1000..0x200000 with EXECUTE.
    // An address in the PE header area (RVA < 0x1000) would be non-exec.
    const nonExecTarget = Number(KERNEL32_BASE) + 0x100; // RVA 0x100, in headers
    const iatRva = 0x168040;

    buildMinimalPe(LIBSPP_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0x2000 });
    buildIat({
      base: LIBSPP_BASE,
      importDirRva: 0x2000,
      descriptors: [{
        dllName: "KERNEL32.dll",
        dllNameRva: 0x4000,
        intRva: 0x3000,
        iatRva: iatRva,
        entries: [
          { nameRva: 0x5000, importName: "SomeFunc", targetValue: nonExecTarget },
        ],
      }],
    });

    buildMinimalPe(KERNEL32_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0 });
    // Map 1 byte at the target so isMapped returns true
    mem.set(nonExecTarget, 0x90);

    const resolver = makeResolver([libspp, kernel32]);
    const entries = resolver.enumerateIat(libspp);

    expect(entries[0].target).toBe(BigInt(nonExecTarget));
    expect(entries[0].status).toBe("non-exec");
  });

  test("outside-module status when target is in a different module than the import DLL", () => {
    const iatRva = 0x168040;
    // Target in kernel32 range but import DLL is libpal.dll
    const k32Target = 0x7622f020;

    const libpal: ModuleInfo = { name: "libpal.dll", path: "libpal.dll", base: BigInt("0x20000000"), end: BigInt("0x20100000"), size: BigInt("0x100000") };

    buildMinimalPe(LIBSPP_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0x2000 });
    buildIat({
      base: LIBSPP_BASE,
      importDirRva: 0x2000,
      descriptors: [{
        dllName: "libpal.dll",
        dllNameRva: 0x4000,
        intRva: 0x3000,
        iatRva: iatRva,
        entries: [
          { nameRva: 0x5000, importName: "SCA_GetLastError", targetValue: k32Target },
        ],
      }],
    });

    buildMinimalPe(KERNEL32_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0 });
    buildMinimalPe(libpal.base, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0 });
    mem.set(k32Target, 0xcc);

    const resolver = makeResolver([libspp, kernel32, libpal]);
    const entries = resolver.enumerateIat(libspp);

    expect(entries[0].target).toBe(BigInt(k32Target));
    expect(entries[0].importDll).toBe("libpal.dll");
    expect(entries[0].actualModule?.name).toBe("kernel32.dll");
    expect(entries[0].status).toBe("outside-module");
  });

  test("unresolved target (null pointer) is classified correctly", () => {
    const iatRva = 0x168040;

    buildMinimalPe(LIBSPP_BASE, { ntHeaderOffset: 0x80, sizeOfOptionalHeader: 0xe0, importDirRva: 0x2000 });

    // Build a descriptor with a manually null IAT entry.
    // We need at least one non-null INT entry to avoid the double-zero early exit.
    buildIat({
      base: LIBSPP_BASE,
      importDirRva: 0x2000,
      descriptors: [{
        dllName: "KERNEL32.dll",
        dllNameRva: 0x4000,
        intRva: 0x3000,
        iatRva: iatRva,
        entries: [
          { nameRva: 0x5000, importName: "LazyFunc", targetValue: 0 },
        ],
      }],
    });
    // Override: put a non-zero INT value so the loop doesn't break on both-zero.
    memWriteU32(LIBSPP_BASE + BigInt(0x3000), 0x5000);

    const resolver = makeResolver([libspp, kernel32]);
    const entries = resolver.enumerateIat(libspp);

    expect(entries).toHaveLength(1);
    expect(entries[0].target).toBe(BigInt(0));
    expect(entries[0].status).toBe("unresolved");
  });
});
