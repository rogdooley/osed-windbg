import { describe, expect, test } from "vitest";
import { findCodeCaves, classifyCapabilities, parseBadChars, addressBadBytes, findSafeOffset } from "../src/commands/code_caves";

function writeUint16LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeUint32LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;
const IMAGE_SCN_MEM_READ = 0x40000000;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;

const PAGE_NOACCESS = 0x01;
const PAGE_READONLY = 0x02;
const PAGE_READWRITE = 0x04;
const PAGE_WRITECOPY = 0x08;
const PAGE_EXECUTE_READ = 0x20;
const PAGE_EXECUTE_READWRITE = 0x40;
const PAGE_EXECUTE_WRITECOPY = 0x80;
const PAGE_GUARD = 0x100;

type VprotHandler = (cmd: string) => string[];

function vprotLines(baseAddr: bigint, regionSize: number, protect: number): string[] {
  return [
    `BaseAddress: ${baseAddr.toString(16).padStart(8, "0")}`,
    `RegionSize: ${regionSize.toString(16).padStart(8, "0")}`,
    "State: 00001000",
    `Protect: ${protect.toString(16).padStart(8, "0")}`,
    "Type: 01000000",
  ];
}

function makeVprotMap(base: bigint, regions: Array<{ offset: number; size: number; protect: number }>): VprotHandler {
  return (cmd: string) => {
    const addrMatch = cmd.match(/0x([0-9a-fA-F]+)/);
    if (!addrMatch) return vprotLines(base, 0x10000, PAGE_READWRITE);
    const addr = BigInt(`0x${addrMatch[1]}`);
    for (const region of regions) {
      const regionBase = base + BigInt(region.offset);
      const regionEnd = regionBase + BigInt(region.size);
      if (addr >= regionBase && addr < regionEnd) {
        return vprotLines(regionBase, region.size, region.protect);
      }
    }
    return vprotLines(base, 0x10000, PAGE_READWRITE);
  };
}

function makeImageWithSections(
  sections: Array<{ name: string; rva: number; virtualSize: number; characteristics: number }>,
  imageSize: number,
  options?: { dllCharacteristics?: number; imageBase?: number },
): { image: Uint8Array; base: bigint } {
  const base = BigInt(options?.imageBase ?? 0x400000);
  const image = new Uint8Array(imageSize);
  const peOffset = 0x80;
  const sectionTable = peOffset + 0x18 + 0xe0;

  writeUint16LE(image, 0x0, 0x5a4d);
  writeUint32LE(image, 0x3c, peOffset);
  writeUint32LE(image, peOffset, 0x4550);
  writeUint16LE(image, peOffset + 0x6, sections.length);
  writeUint16LE(image, peOffset + 0x14, 0xe0);
  writeUint16LE(image, peOffset + 0x18, 0x10b);
  writeUint32LE(image, peOffset + 0x34, Number(base));
  writeUint32LE(image, peOffset + 0x38, 0x1000);
  writeUint16LE(image, peOffset + 0x5e, options?.dllCharacteristics ?? 0);

  for (let i = 0; i < sections.length; i++) {
    const s = sections[i];
    const entry = sectionTable + i * 40;
    const nameBytes = Array.from(s.name).map((c) => c.charCodeAt(0));
    image.set(nameBytes, entry);
    writeUint32LE(image, entry + 0x8, s.virtualSize);
    writeUint32LE(image, entry + 0xc, s.rva);
    writeUint32LE(image, entry + 0x24, s.characteristics);
  }

  return { image, base };
}

function installPeBackedHost(image: Uint8Array, base: bigint, vprot?: VprotHandler): void {
  (globalThis as unknown as { host: unknown }).host = {
    currentProcess: {
      Modules: [
        {
          Name: "target.exe",
          Path: "C:\\labs\\target.exe",
          BaseAddress: base,
          EndAddress: base + BigInt(image.length),
        },
      ],
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        const current = typeof address === "bigint" ? address : BigInt(address);
        const offset = Number(current - base);
        if (offset < 0 || offset + length > image.length) {
          throw new Error("out of range");
        }
        return Array.from(image.slice(offset, offset + length));
      },
    },
    namespace: {
      Debugger: {
        Utility: {
          Control: {
            ExecuteCommand(cmd: string) {
              if (vprot) return vprot(cmd);
              return ["BaseAddress: 00400000", "RegionSize: 00005000", "State: 00001000", "Protect: 00000004", "Type: 01000000"];
            },
          },
        },
      },
    },
    diagnostics: { debugLog() {} },
  };
}

describe("findCodeCaves", () => {
  // === Original discovery tests ===

  test("finds a contiguous null region in .text", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ }],
      0x5000,
    );
    for (let i = 0x1000; i < 0x3000; i++) image[i] = 0xc3;
    for (let i = 0x1100; i < 0x1140; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);

    expect(caves.length).toBe(1);
    expect(caves[0].pattern).toBe("NULL");
    expect(caves[0].address).toBe(base + BigInt(0x1100));
    expect(caves[0].size).toBe(64);
    expect(caves[0].module).toBe("target.exe");
    expect(caves[0].section).toBe(".text");
    expect(caves[0].sectionExecutable).toBe(true);
  });

  test("detects pure int3 caves", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1250; i++) image[i] = 0xcc;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].pattern).toBe("INT3");
    expect(caves[0].size).toBe(80);
    expect(caves[0].address).toBe(base + BigInt(0x1200));
  });

  test("detects mixed null/int3 as PADDING", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1300; i < 0x133c; i++) image[i] = i % 2 === 0 ? 0x00 : 0xcc;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].pattern).toBe("PADDING");
    expect(caves[0].size).toBe(60);
  });

  test("ignores runs shorter than minSize", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x121e; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(0);
  });

  test("finds caves in non-executable sections", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".data", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xaa;
    for (let i = 0x1500; i < 0x1564; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].section).toBe(".data");
    expect(caves[0].sectionExecutable).toBe(false);
    expect(caves[0].size).toBe(100);
    expect(caves[0].pattern).toBe("NULL");
  });

  test("finds multiple caves sorted by ranking", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x5000,
    );
    for (let i = 0x1000; i < 0x3000; i++) image[i] = 0xc3;
    for (let i = 0x1100; i < 0x113c; i++) image[i] = 0x00;
    for (let i = 0x1800; i < 0x18c8; i++) image[i] = 0xcc;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(2);
    expect(caves[0].size).toBeGreaterThanOrEqual(caves[1].size);
  });

  test("respects module filter", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    installPeBackedHost(image, base);

    const { caves, warnings } = findCodeCaves("nonexistent", 50, 25);
    expect(caves.length).toBe(0);
    expect(warnings.length).toBeGreaterThan(0);
  });

  test("module filter matches by substring", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves("target", 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].module).toBe("target.exe");
  });

  test("respects maxResults limit", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x3000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x5000,
    );
    for (let i = 0x1000; i < 0x4000; i++) image[i] = 0xc3;
    for (let cave = 0; cave < 5; cave++) {
      const start = 0x1100 + cave * 0x200;
      for (let i = start; i < start + 60; i++) image[i] = 0x00;
    }
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 3);
    expect(caves.length).toBe(3);
  });

  test("handles cave spanning a chunk boundary", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x4000,
    );
    for (let i = 0x1000; i < 0x3000; i++) image[i] = 0xc3;
    for (let i = 0x1fc0; i < 0x2040; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].size).toBe(128);
    expect(caves[0].address).toBe(base + BigInt(0x1fc0));
  });

  test("detects pure nop caves", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1400; i < 0x1446; i++) image[i] = 0x90;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].pattern).toBe("NOP");
    expect(caves[0].size).toBe(70);
  });

  test("detects mixed null/int3/nop as PADDING", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1500; i < 0x1514; i++) image[i] = 0x00;
    for (let i = 0x1514; i < 0x1528; i++) image[i] = 0xcc;
    for (let i = 0x1528; i < 0x153c; i++) image[i] = 0x90;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].pattern).toBe("PADDING");
    expect(caves[0].size).toBe(60);
  });

  test("finds padding beyond VirtualSize up to section alignment boundary", () => {
    const { image, base } = makeImageWithSections(
      [
        { name: ".text", rva: 0x1000, virtualSize: 0xe70, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
        { name: ".data", rva: 0x2000, virtualSize: 0x100, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
      ],
      0x4000,
    );
    for (let i = 0x1000; i < 0x1e70; i++) image[i] = 0xc3;
    for (let i = 0x1e70; i < 0x2000; i++) image[i] = 0xcc;
    for (let i = 0x2000; i < 0x2100; i++) image[i] = 0x42;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    const textCave = caves.find((c) => c.section === ".text");
    expect(textCave).toBeDefined();
    expect(textCave!.address).toBe(base + BigInt(0x1e70));
    expect(textCave!.size).toBe(0x190);
    expect(textCave!.pattern).toBe("INT3");
  });

  test("int3 cave spanning a chunk boundary stays contiguous", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x4000,
    );
    for (let i = 0x1000; i < 0x3000; i++) image[i] = 0xc3;
    for (let i = 0x1fce; i < 0x2032; i++) image[i] = 0xcc;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].size).toBe(100);
    expect(caves[0].pattern).toBe("INT3");
  });

  // === New fields: RVA and module metadata ===

  test("reports correct RVA and module metadata", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].rva).toBe(0x1200);
    expect(caves[0].moduleBase).toBe(base);
    expect(caves[0].modulePath).toBe("C:\\labs\\target.exe");
  });

  // === ASLR detection ===

  test("reports ASLR disabled when DYNAMIC_BASE is not set", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
      { dllCharacteristics: 0 },
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].aslr).toBe("disabled");
  });

  test("reports ASLR enabled when DYNAMIC_BASE is set", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
      { dllCharacteristics: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT },
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].aslr).toBe("enabled");
  });

  // === Exploitation classification ===

  test("classifies RX region as EXEC", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0xcc;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_EXECUTE_READ },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].capabilities).toContain("EXEC");
    expect(caves[0].capabilities).not.toContain("STAGING");
    expect(caves[0].readable).toBe(true);
    expect(caves[0].writable).toBe(false);
    expect(caves[0].executable).toBe(true);
  });

  test("classifies RW region as STAGING and ROP_WORKSPACE", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".data", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xaa;
    for (let i = 0x1200; i < 0x12c8; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_READWRITE },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].capabilities).toContain("STAGING");
    expect(caves[0].capabilities).toContain("ROP_WORKSPACE");
    expect(caves[0].capabilities).not.toContain("EXEC");
  });

  test("classifies small RW cave as STAGING without ROP_WORKSPACE", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".data", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xaa;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_READWRITE },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].capabilities).toContain("STAGING");
    expect(caves[0].capabilities).not.toContain("ROP_WORKSPACE");
    expect(caves[0].size).toBe(64);
  });

  test("classifies RWX region", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x12c8; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_EXECUTE_READWRITE },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].capabilities).toContain("RWX");
    expect(caves[0].capabilities).toContain("STAGING");
    expect(caves[0].capabilities).toContain("ROP_WORKSPACE");
  });

  test("classifies read-only region as READ_ONLY", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".rdata", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xaa;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_READONLY },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].capabilities).toEqual(["READ_ONLY"]);
  });

  test("classifies no-access region as UNUSABLE", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_NOACCESS },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].capabilities).toEqual(["UNUSABLE"]);
  });

  test("classifies guard page as UNUSABLE", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0xcc;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_READWRITE | PAGE_GUARD },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].capabilities).toEqual(["UNUSABLE"]);
  });

  test("handles WRITECOPY as writable", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".data", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xaa;
    for (let i = 0x1200; i < 0x12c8; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_WRITECOPY },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].writable).toBe(true);
    expect(caves[0].capabilities).toContain("STAGING");
  });

  test("handles EXECUTE_WRITECOPY as RWX", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x12c8; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_EXECUTE_WRITECOPY },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].capabilities).toContain("RWX");
    expect(caves[0].readable).toBe(true);
    expect(caves[0].writable).toBe(true);
    expect(caves[0].executable).toBe(true);
  });

  // === Cross-page protection split ===

  test("splits cave at protection boundary", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ }],
      0x4000,
    );
    for (let i = 0x1000; i < 0x3000; i++) image[i] = 0xc3;
    for (let i = 0x1f00; i < 0x2100; i++) image[i] = 0xcc;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_EXECUTE_READ },
      { offset: 0x2000, size: 0x1000, protect: PAGE_READWRITE },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    const rxCave = caves.find((c) => c.capabilities.includes("EXEC"));
    const rwCave = caves.find((c) => c.capabilities.includes("STAGING"));
    expect(rxCave).toBeDefined();
    expect(rwCave).toBeDefined();
    expect(rxCave!.size).toBe(0x100);
    expect(rwCave!.size).toBe(0x100);
    expect(rxCave!.address).toBe(base + BigInt(0x1f00));
    expect(rwCave!.address).toBe(base + BigInt(0x2000));
  });

  test("does not split when protection is uniform", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ }],
      0x4000,
    );
    for (let i = 0x1000; i < 0x3000; i++) image[i] = 0xc3;
    for (let i = 0x1f00; i < 0x2100; i++) image[i] = 0xcc;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x2000, protect: PAGE_EXECUTE_READ },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].size).toBe(0x200);
  });

  // === Bad character filtering ===

  test("marks address as safe when no bad bytes found", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
      { imageBase: 0x401000 },
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25, "0a 0d");
    expect(caves.length).toBe(1);
    expect(caves[0].addrSafe).toBe(true);
    expect(caves[0].badBytes).toEqual([]);
  });

  test("detects bad bytes in address", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
      { imageBase: 0x400000 },
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25, "00");
    expect(caves.length).toBe(1);
    expect(caves[0].addrSafe).toBe(false);
    expect(caves[0].badBytes).toContain(0x00);
  });

  test("reports no safe offset when entire cave has bad bytes", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
      { imageBase: 0x400000 },
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x12c8; i++) image[i] = 0xcc;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25, "00");
    expect(caves.length).toBe(1);
    expect(caves[0].addrSafe).toBe(false);
    expect(caves[0].safeOffset).toBeNull();
    expect(caves[0].safeVa).toBeNull();
  });

  test("finds safe offset when one exists", () => {
    const imgBase = 0x11110000;
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
      { imageBase: imgBase },
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x12c8; i++) image[i] = 0xcc;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25, "00");
    expect(caves.length).toBe(1);
    expect(caves[0].addrSafe).toBe(false);
    expect(caves[0].safeOffset).toBe(1);
    expect(caves[0].safeVa).toBe(base + BigInt(0x1201));
  });

  test("bad byte at each address byte position", () => {
    const badChars = new Set([0x22]);
    const bad = addressBadBytes(BigInt(0x44332211), 4, badChars);
    expect(bad).toEqual([0x22]);

    expect(addressBadBytes(BigInt(0x44332211), 4, new Set([0x44]))).toEqual([0x44]);
    expect(addressBadBytes(BigInt(0x44332211), 4, new Set([0x11]))).toEqual([0x11]);
    expect(addressBadBytes(BigInt(0x44332211), 4, new Set([0x33]))).toEqual([0x33]);
  });

  // === Capability filtering ===

  test("filters caves by EXEC capability", () => {
    const { image, base } = makeImageWithSections(
      [
        { name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
        { name: ".data", rva: 0x2000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
      ],
      0x4000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0xcc;
    for (let i = 0x2000; i < 0x3000; i++) image[i] = 0xaa;
    for (let i = 0x2200; i < 0x22c8; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_EXECUTE_READ },
      { offset: 0x2000, size: 0x1000, protect: PAGE_READWRITE },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves: allCaves } = findCodeCaves(undefined, 50, 25);
    expect(allCaves.length).toBe(2);

    const { caves: execOnly } = findCodeCaves(undefined, 50, 25, undefined, "EXEC");
    expect(execOnly.length).toBe(1);
    expect(execOnly[0].section).toBe(".text");
  });

  test("filters caves by STAGING capability", () => {
    const { image, base } = makeImageWithSections(
      [
        { name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
        { name: ".data", rva: 0x2000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
      ],
      0x4000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0xcc;
    for (let i = 0x2000; i < 0x3000; i++) image[i] = 0xaa;
    for (let i = 0x2200; i < 0x22c8; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_EXECUTE_READ },
      { offset: 0x2000, size: 0x1000, protect: PAGE_READWRITE },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves: stagingOnly } = findCodeCaves(undefined, 50, 25, undefined, "STAGING");
    expect(stagingOnly.length).toBe(1);
    expect(stagingOnly[0].section).toBe(".data");
  });

  // === Ranking ===

  test("ranks non-ASLR caves before ASLR caves", () => {
    const { image, base } = makeImageWithSections(
      [
        { name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
        { name: ".data", rva: 0x2000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
      ],
      0x4000,
      { dllCharacteristics: 0 },
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0xcc;
    for (let i = 0x2000; i < 0x3000; i++) image[i] = 0xaa;
    for (let i = 0x2200; i < 0x2240; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(2);
    for (const c of caves) {
      expect(c.aslr).toBe("disabled");
    }
  });

  test("ranks addr-safe before addr-unsafe", () => {
    const imgBase = 0x11110000;
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x4000,
      { imageBase: imgBase },
    );
    for (let i = 0x1000; i < 0x3000; i++) image[i] = 0xc3;
    for (let i = 0x1100; i < 0x1164; i++) image[i] = 0xcc;
    for (let i = 0x1201; i < 0x1265; i++) image[i] = 0xcc;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25, "00");
    expect(caves.length).toBe(2);
    expect(caves[0].addrSafe).toBe(true);
    expect(caves[1].addrSafe).toBe(false);
  });

  test("ranks usable above read-only above unusable", () => {
    const { image, base } = makeImageWithSections(
      [
        { name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
        { name: ".rdata", rva: 0x2000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ },
        { name: ".guard", rva: 0x3000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ },
      ],
      0x5000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0xcc;
    for (let i = 0x2000; i < 0x3000; i++) image[i] = 0xaa;
    for (let i = 0x2200; i < 0x2240; i++) image[i] = 0x00;
    for (let i = 0x3000; i < 0x4000; i++) image[i] = 0xbb;
    for (let i = 0x3200; i < 0x3240; i++) image[i] = 0x00;

    const vprot = makeVprotMap(base, [
      { offset: 0x1000, size: 0x1000, protect: PAGE_EXECUTE_READ },
      { offset: 0x2000, size: 0x1000, protect: PAGE_READONLY },
      { offset: 0x3000, size: 0x1000, protect: PAGE_NOACCESS },
    ]);
    installPeBackedHost(image, base, vprot);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(3);
    expect(caves[0].capabilities).toContain("EXEC");
    expect(caves[1].capabilities).toContain("READ_ONLY");
    expect(caves[2].capabilities).toContain("UNUSABLE");
  });

  // === Legacy compatibility ===

  test("works with original 3-arg invocation", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0xcc;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves("target", 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].addrSafe).toBeNull();
    expect(caves[0].capabilities.length).toBeGreaterThan(0);
  });

  test("no-arg invocation still works", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) image[i] = 0xc3;
    for (let i = 0x1200; i < 0x1240; i++) image[i] = 0x00;
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].addrSafe).toBeNull();
  });
});

describe("classifyCapabilities", () => {
  test("RWX region", () => {
    const caps = classifyCapabilities(true, true, true, 200);
    expect(caps).toContain("RWX");
    expect(caps).toContain("STAGING");
    expect(caps).toContain("ROP_WORKSPACE");
    expect(caps).not.toContain("EXEC");
  });

  test("RX region", () => {
    const caps = classifyCapabilities(true, false, true, 200);
    expect(caps).toEqual(["EXEC"]);
  });

  test("RW region large enough for ROP", () => {
    const caps = classifyCapabilities(true, true, false, 200);
    expect(caps).toContain("STAGING");
    expect(caps).toContain("ROP_WORKSPACE");
  });

  test("RW region too small for ROP", () => {
    const caps = classifyCapabilities(true, true, false, 64);
    expect(caps).toContain("STAGING");
    expect(caps).not.toContain("ROP_WORKSPACE");
  });

  test("R only", () => {
    expect(classifyCapabilities(true, false, false, 200)).toEqual(["READ_ONLY"]);
  });

  test("no access", () => {
    expect(classifyCapabilities(false, false, false, 200)).toEqual(["UNUSABLE"]);
  });

  test("all null", () => {
    expect(classifyCapabilities(null, null, null, 200)).toEqual(["UNUSABLE"]);
  });
});

describe("parseBadChars", () => {
  test("parses space-separated hex", () => {
    const set = parseBadChars("00 0A 0D 23");
    expect(set.size).toBe(4);
    expect(set.has(0x00)).toBe(true);
    expect(set.has(0x0a)).toBe(true);
    expect(set.has(0x0d)).toBe(true);
    expect(set.has(0x23)).toBe(true);
  });

  test("handles empty string", () => {
    expect(parseBadChars("").size).toBe(0);
    expect(parseBadChars("  ").size).toBe(0);
  });

  test("handles comma-separated", () => {
    const set = parseBadChars("00,0A,0D");
    expect(set.size).toBe(3);
  });
});

describe("addressBadBytes", () => {
  test("LE byte order for 32-bit", () => {
    const bad = addressBadBytes(BigInt(0x44332211), 4, new Set([0x11, 0x33]));
    expect(bad).toContain(0x11);
    expect(bad).toContain(0x33);
    expect(bad.length).toBe(2);
  });

  test("safe address returns empty", () => {
    const bad = addressBadBytes(BigInt(0x44332211), 4, new Set([0x00, 0x0a]));
    expect(bad).toEqual([]);
  });

  test("deduplicates repeated bad bytes", () => {
    const bad = addressBadBytes(BigInt(0x11001100), 4, new Set([0x00]));
    expect(bad).toEqual([0x00]);
  });
});

describe("findSafeOffset", () => {
  test("returns null when no safe offset exists", () => {
    const result = findSafeOffset(BigInt(0x00400000), 256, 4, new Set([0x00]));
    expect(result).toBeNull();
  });

  test("finds first safe offset", () => {
    const result = findSafeOffset(BigInt(0x11111100), 200, 4, new Set([0x00]));
    expect(result).not.toBeNull();
    expect(result!.offset).toBe(1);
    expect(result!.va).toBe(BigInt(0x11111101));
  });
});
