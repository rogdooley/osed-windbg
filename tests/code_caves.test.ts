import { describe, expect, test } from "vitest";
import { findCodeCaves } from "../src/commands/code_caves";

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

function installPeBackedHost(image: Uint8Array, base: bigint): void {
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
            ExecuteCommand() {
              return ["BaseAddress: 00400000", "RegionSize: 00005000", "State: 00001000", "Protect: 00000004", "Type: 01000000"];
            },
          },
        },
      },
    },
    diagnostics: { debugLog() {} },
  };
}

const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;
const IMAGE_SCN_MEM_READ = 0x40000000;

function makeImageWithSections(
  sections: Array<{ name: string; rva: number; virtualSize: number; characteristics: number }>,
  imageSize: number,
): { image: Uint8Array; base: bigint } {
  const base = BigInt(0x400000);
  const image = new Uint8Array(imageSize);
  const peOffset = 0x80;
  const sectionTable = peOffset + 0x18 + 0xe0;

  writeUint16LE(image, 0x0, 0x5a4d);
  writeUint32LE(image, 0x3c, peOffset);
  writeUint32LE(image, peOffset, 0x4550);
  writeUint16LE(image, peOffset + 0x6, sections.length);
  writeUint16LE(image, peOffset + 0x14, 0xe0);

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

describe("findCodeCaves", () => {
  test("finds a contiguous null region in .text", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ }],
      0x5000,
    );
    for (let i = 0x1000; i < 0x3000; i++) {
      image[i] = 0x90;
    }
    for (let i = 0x1100; i < 0x1140; i++) {
      image[i] = 0x00;
    }
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
    // Fill section with real code bytes
    for (let i = 0x1000; i < 0x2000; i++) {
      image[i] = 0x90; // nop
    }
    // 80-byte int3 cave
    for (let i = 0x1200; i < 0x1250; i++) {
      image[i] = 0xcc;
    }
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
    for (let i = 0x1000; i < 0x2000; i++) {
      image[i] = 0x90;
    }
    // Mixed run: alternating 0x00 and 0xCC for 60 bytes
    for (let i = 0x1300; i < 0x133c; i++) {
      image[i] = i % 2 === 0 ? 0x00 : 0xcc;
    }
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
    for (let i = 0x1000; i < 0x2000; i++) {
      image[i] = 0x90;
    }
    // 30-byte null run -- below the 50-byte default
    for (let i = 0x1200; i < 0x121e; i++) {
      image[i] = 0x00;
    }
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(0);
  });

  test("finds caves in non-executable sections", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".data", rva: 0x1000, virtualSize: 0x1000, characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE }],
      0x3000,
    );
    for (let i = 0x1000; i < 0x2000; i++) {
      image[i] = 0xaa;
    }
    // 100-byte cave in .data
    for (let i = 0x1500; i < 0x1564; i++) {
      image[i] = 0x00;
    }
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].section).toBe(".data");
    expect(caves[0].sectionExecutable).toBe(false);
    expect(caves[0].size).toBe(100);
    expect(caves[0].pattern).toBe("NULL");
  });

  test("finds multiple caves sorted by size descending", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x5000,
    );
    for (let i = 0x1000; i < 0x3000; i++) {
      image[i] = 0x90;
    }
    // Small cave: 60 null bytes at 0x1100
    for (let i = 0x1100; i < 0x113c; i++) {
      image[i] = 0x00;
    }
    // Large cave: 200 int3 bytes at 0x1800
    for (let i = 0x1800; i < 0x18c8; i++) {
      image[i] = 0xcc;
    }
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(2);
    expect(caves[0].size).toBe(200);
    expect(caves[0].pattern).toBe("INT3");
    expect(caves[1].size).toBe(60);
    expect(caves[1].pattern).toBe("NULL");
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
    for (let i = 0x1000; i < 0x2000; i++) {
      image[i] = 0x90;
    }
    for (let i = 0x1200; i < 0x1240; i++) {
      image[i] = 0x00;
    }
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
    for (let i = 0x1000; i < 0x4000; i++) {
      image[i] = 0x90;
    }
    // Place 5 caves of 60 bytes each, spaced out
    for (let cave = 0; cave < 5; cave++) {
      const start = 0x1100 + cave * 0x200;
      for (let i = start; i < start + 60; i++) {
        image[i] = 0x00;
      }
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
    for (let i = 0x1000; i < 0x3000; i++) {
      image[i] = 0x90;
    }
    // 128-byte cave straddling the 0x2000 chunk boundary (0x1FC0..0x2040)
    for (let i = 0x1fc0; i < 0x2040; i++) {
      image[i] = 0x00;
    }
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].size).toBe(128);
    expect(caves[0].address).toBe(base + BigInt(0x1fc0));
  });

  test("int3 cave spanning a chunk boundary stays contiguous", () => {
    const { image, base } = makeImageWithSections(
      [{ name: ".text", rva: 0x1000, virtualSize: 0x2000, characteristics: IMAGE_SCN_MEM_EXECUTE }],
      0x4000,
    );
    for (let i = 0x1000; i < 0x3000; i++) {
      image[i] = 0x90;
    }
    // 100-byte int3 cave across chunk boundary
    for (let i = 0x1fce; i < 0x2032; i++) {
      image[i] = 0xcc;
    }
    installPeBackedHost(image, base);

    const { caves } = findCodeCaves(undefined, 50, 25);
    expect(caves.length).toBe(1);
    expect(caves[0].size).toBe(100);
    expect(caves[0].pattern).toBe("INT3");
  });
});
