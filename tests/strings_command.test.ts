import { describe, expect, test } from "vitest";
import { createStringCommands } from "../src/commands/strings";
import { initializeScript } from "../src";

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

function installHost(image: Uint8Array, base: bigint): void {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: () => undefined },
    currentProcess: {
      Is64Bit: false,
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

function makeImageWithSections(): { image: Uint8Array; base: bigint; textStart: bigint; dataStart: bigint } {
  const base = BigInt(0x400000);
  const image = new Uint8Array(0x7000);
  const peOffset = 0x80;
  const sectionTable = peOffset + 0x18 + 0xe0;

  writeUint16LE(image, 0x0, 0x5a4d);
  writeUint32LE(image, 0x3c, peOffset);
  writeUint32LE(image, peOffset, 0x4550);
  writeUint16LE(image, peOffset + 0x6, 2);
  writeUint16LE(image, peOffset + 0x14, 0xe0);

  image.set(Array.from(".text").map((char) => char.charCodeAt(0)), sectionTable);
  writeUint32LE(image, sectionTable + 0x8, 0x1000);
  writeUint32LE(image, sectionTable + 0xc, 0x1000);
  writeUint32LE(image, sectionTable + 0x24, 0x20000000);

  const dataSection = sectionTable + 40;
  image.set(Array.from(".rdata").map((char) => char.charCodeAt(0)), dataSection);
  writeUint32LE(image, dataSection + 0x8, 0x1000);
  writeUint32LE(image, dataSection + 0xc, 0x3000);
  writeUint32LE(image, dataSection + 0x24, 0x40000000);

  return {
    image,
    base,
    textStart: base + BigInt(0x1000),
    dataStart: base + BigInt(0x3000),
  };
}

function command(name: string) {
  const found = createStringCommands().find((item) => item.name === name);
  if (!found) throw new Error(`missing command ${name}`);
  return found;
}

function installDiagnosticsHost(): void {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: () => undefined },
    currentProcess: { Is64Bit: false, Modules: [] },
  };
}

describe("string commands", () => {
  test("str_bytes emits ascii bytes and bad-character offsets", () => {
    installDiagnosticsHost();
    const result = command("str_bytes").execute({
      text: "A\n",
      encoding: "ascii",
      terminator: true,
      exclude: [0, 10, 13],
    });

    expect(result.success).toBe(true);
    expect(result.findings[0]).toMatchObject({
      bytes: [0x41, 0x0a, 0x00],
      python: "b\"A\\x0a\\x00\"",
      badchars: [
        { byte: 0x0a, offset: 1 },
        { byte: 0x00, offset: 2 },
      ],
    });
  });

  test("str_bytes emits utf16le bytes with a wide terminator", () => {
    installDiagnosticsHost();
    const result = command("str_bytes").execute({
      text: "cmd",
      encoding: "utf16le",
      terminator: true,
      exclude: [0],
    });

    expect(result.findings[0]).toMatchObject({
      bytes: [0x63, 0x00, 0x6d, 0x00, 0x64, 0x00, 0x00, 0x00],
    });
  });

  test("str_read decodes null-terminated ascii memory", () => {
    const { image, base, dataStart } = makeImageWithSections();
    const offset = Number(dataStart - base) + 0x40;
    image.set(Array.from("VirtualProtect").map((char) => char.charCodeAt(0)), offset);
    image[offset + "VirtualProtect".length] = 0;
    installHost(image, base);

    const result = command("str_read").execute({
      address: `0x${(dataStart + BigInt(0x40)).toString(16)}`,
      max: 64,
      encoding: "ascii",
    });

    expect(result.success).toBe(true);
    expect(result.findings[0]).toMatchObject({
      text: "VirtualProtect",
      length: 14,
      terminated: true,
    });
  });

  test("str_find searches module sections for ascii and utf16le strings", () => {
    const { image, base, dataStart } = makeImageWithSections();
    image.set(Array.from("cmd.exe").map((char) => char.charCodeAt(0)), Number(dataStart - base) + 0x80);
    image.set([0x63, 0x00, 0x6d, 0x00, 0x64, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00], Number(dataStart - base) + 0x100);
    installHost(image, base);

    const result = command("str_find").execute({
      text: "cmd.exe",
      module: "target",
      encoding: "both",
      maxResults: 10,
    });

    expect(result.success).toBe(true);
    expect(result.findings).toEqual([
      { address: dataStart + BigInt(0x80), encoding: "ascii", text: "cmd.exe" },
      { address: dataStart + BigInt(0x100), encoding: "utf16le", text: "cmd.exe" },
    ]);
  });

  test("str namespace returns structured findings", () => {
    const { image, base, dataStart } = makeImageWithSections();
    image.set(Array.from("W00T").map((char) => char.charCodeAt(0)), Number(dataStart - base) + 0x20);
    image[Number(dataStart - base) + 0x24] = 0;
    installHost(image, base);
    initializeScript();

    const api = (globalThis as unknown as {
      osed: {
        str: {
          read: (address: bigint) => unknown;
          bytes: (text: string) => unknown;
        };
      };
    }).osed;

    expect(api.str.read(dataStart + BigInt(0x20))).toMatchObject({ text: "W00T" });
    expect(api.str.bytes("W00T")).toMatchObject({ bytes: [0x57, 0x30, 0x30, 0x54] });
  });
});
