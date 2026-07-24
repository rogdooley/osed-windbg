import { describe, expect, test } from "vitest";
import { createFindMspCommand } from "../src/commands/findmsp";
import { createRopCommands } from "../src/commands/rop";

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
    diagnostics: { debugLog: () => undefined },
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

describe("rop_suggest command", () => {
  test("publishes WinDbg-compatible positional examples", () => {
    const findMsp = createFindMspCommand();
    const findBytes = createRopCommands().find((command) => command.name === "find_bytes");

    expect(findMsp.usage).toBe("dx @$osed().findmsp(patternLength?, stackBytes?, probeBytes?)");
    expect(findMsp.examples).toContain("dx @$osed().findmsp(20000, 4096)");
    expect(findBytes?.usage).toBe(
      "dx @$osed().find_bytes(module, bytes, maxResults?, executableOnly?, mode?)",
    );
    expect(findBytes?.examples).toContain('dx @$osed().find_bytes("vulnserver", "FF E4")');
  });

  test("exposes an engine option with legacy and semantic modes", () => {
    const ropSuggest = createRopCommands().find((command) => command.name === "rop_suggest");

    expect(ropSuggest).toBeDefined();
    expect(ropSuggest?.schema.engine).toEqual({
      type: "string",
      enum: ["legacy", "semantic"],
      default: "legacy",
    });
    expect(ropSuggest?.examples).toContain(
      'dx @$osed().rop_suggest("essfunc", 50, true, "fast", "semantic")',
    );
  });

  test("find_bytes executes through the command adapter and returns unique hits", () => {
    const { image, base, textStart } = makeImageWithTextSection();
    image.set([0xff, 0xe4], Number(textStart - base) + 0x1000);
    installPeBackedHost(image, base);

    const findBytes = createRopCommands().find((command) => command.name === "find_bytes");
    const result = findBytes?.execute({
      module: "target",
      bytes: [0xff, 0xe4],
      executableOnly: true,
      maxResults: 10,
      mode: "fast",
    });

    expect(result?.success).toBe(true);
    expect(result?.findings).toEqual([textStart + BigInt(0x1000)]);
    expect(result?.stats?.results).toBe(1);
  });
});
