import { describe, expect, test } from "vitest";
import { scanPattern } from "../src/core/scan_engine";

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
  };
}

function makeImageWithTextSection(): { image: Uint8Array; base: bigint; textStart: bigint } {
  const base = BigInt(0x400000);
  const image = new Uint8Array(0x5000);
  const peOffset = 0x80;
  const sectionTable = peOffset + 0x18 + 0xe0;

  writeUint16LE(image, 0x0, 0x5a4d);
  writeUint32LE(image, 0x3c, peOffset);
  writeUint32LE(image, peOffset, 0x4550);
  writeUint16LE(image, peOffset + 0x6, 1);
  writeUint16LE(image, peOffset + 0x14, 0xe0);

  image.set(Array.from(".text").map((char) => char.charCodeAt(0)), sectionTable);
  writeUint32LE(image, sectionTable + 0x8, 0x2000);
  writeUint32LE(image, sectionTable + 0xc, 0x1000);
  writeUint32LE(image, sectionTable + 0x24, 0x20000000);

  return { image, base, textStart: base + BigInt(0x1000) };
}

describe("scanPattern", () => {
  test("warns when the module filter matches no loaded module", () => {
    const { image, base } = makeImageWithTextSection();
    installPeBackedHost(image, base);

    const result = scanPattern(
      { module: "missing", executableOnly: true, maxResults: 10, chunkSize: 0x1000 },
      Uint8Array.from([0xff, 0xe4]),
    );

    expect(result.hits).toEqual([]);
    expect(result.stats.sectionsScanned).toBe(0);
    expect(result.warnings).toEqual([
      { region: "module", message: "No loaded modules matched 'missing'." },
    ]);
  });

  test("deduplicates matches visible in overlapping chunk reads", () => {
    const { image, base, textStart } = makeImageWithTextSection();
    const pattern = Uint8Array.from([0xff, 0xe4, 0xcc, 0xc3]);
    image.set(pattern, Number(textStart - base) + 0x1000);
    installPeBackedHost(image, base);

    const result = scanPattern(
      { executableOnly: true, maxResults: 10, chunkSize: 0x1000 },
      pattern,
    );

    expect(result.hits).toEqual([textStart + BigInt(0x1000)]);
    expect(result.stats.results).toBe(1);
  });
});
