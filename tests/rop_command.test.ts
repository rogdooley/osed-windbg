import { describe, expect, test } from "vitest";
import { createFindMspCommand } from "../src/commands/findmsp";
import { createFindMemBytesCommand } from "../src/commands/find_mem_bytes";
import { createRopCommands } from "../src/commands/rop";
import { createFindStackBytesCommand } from "../src/commands/find_stack_bytes";
import { initializeScript } from "../src/index";

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

function installPartialRangeHost(base: bigint, bytes: Uint8Array, readableLength: number): void {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: () => undefined },
    currentProcess: { Is64Bit: false, Modules: [] },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        const current = typeof address === "bigint" ? address : BigInt(address);
        const offset = Number(current - base);
        if (offset < 0 || offset >= readableLength) {
          throw new Error("partial read success");
        }
        if (offset + length > readableLength) {
          throw new Error("partial read success");
        }
        return Array.from(bytes.slice(offset, offset + length));
      },
    },
  };
}

function installStackHost(stackBase: bigint, stackLimit: bigint, stackPointer: bigint, stack: Uint8Array): void {
  const teb = BigInt("0x7ffde000");
  const memory = new Map<string, number>();
  const write32 = (address: bigint, value: bigint) => {
    const raw = Number(value & BigInt(0xffffffff));
    memory.set(`0x${address.toString(16)}`, raw & 0xff);
    memory.set(`0x${(address + BigInt(1)).toString(16)}`, (raw >>> 8) & 0xff);
    memory.set(`0x${(address + BigInt(2)).toString(16)}`, (raw >>> 16) & 0xff);
    memory.set(`0x${(address + BigInt(3)).toString(16)}`, (raw >>> 24) & 0xff);
  };

  write32(teb + BigInt(0x4), stackBase);
  write32(teb + BigInt(0x8), stackLimit);
  write32(teb + BigInt(0x18), teb);
  stack.forEach((byte, index) => {
    memory.set(`0x${(stackPointer + BigInt(index)).toString(16)}`, byte);
  });

  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: () => undefined },
    currentProcess: { Is64Bit: false, Modules: [] },
    currentThread: {
      Environment: {
        EnvironmentBlock: { NtTib: { Self: teb } },
      },
      Registers: {
        User: {
          esp: { value: stackPointer },
          eip: { value: BigInt(0x41414141) },
        },
      },
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        const current = typeof address === "bigint" ? address : BigInt(address);
        const bytes: number[] = [];
        for (let i = 0; i < length; i += 1) {
          const byte = memory.get(`0x${(current + BigInt(i)).toString(16)}`);
          if (byte === undefined) {
            throw new Error("out of range");
          }
          bytes.push(byte);
        }
        return bytes;
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

  test("find_bytes no-hit output states that the scope excludes stack and heap memory", () => {
    const { image, base } = makeImageWithTextSection();
    const logs: string[] = [];
    installPeBackedHost(image, base);
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host.diagnostics = {
      debugLog: (line: string) => logs.push(line),
    };

    const findBytes = createRopCommands().find((command) => command.name === "find_bytes");
    const result = findBytes?.execute({
      module: "target",
      bytes: [0x43, 0x43, 0x43, 0x43],
      executableOnly: true,
      maxResults: 10,
      mode: "fast",
    });

    expect(result?.success).toBe(true);
    expect(result?.findings).toEqual([]);
    expect(logs.join("")).toContain("Scope: executable PE sections in the matched module only; this does not search stack, heap, or other live process buffers.");
  });

  test("find_bytes rejects ambiguous single-nibble byte tokens through the public adapter", () => {
    const { image, base } = makeImageWithTextSection();
    const logs: string[] = [];
    installPeBackedHost(image, base);
    (globalThis as unknown as {
      host: {
        diagnostics: { debugLog: (line: string) => void };
        functionAlias?: new (fn: (...args: unknown[]) => unknown, aliasName: string) => unknown;
      };
      osed?: {
        find_bytes: (module: string, bytes: string) => boolean;
        last_result: () => { success: boolean; errors: string[] };
      };
    }).host.diagnostics = {
      debugLog: (line: string) => logs.push(line),
    };

    initializeScript();
    const api = (globalThis as unknown as {
      osed: {
        find_bytes: (module: string, bytes: string) => boolean;
        last_result: () => { success: boolean; errors: string[] };
      };
    }).osed;

    expect(api.find_bytes("target", "C C C C")).toBe(false);
    expect(api.last_result().success).toBe(false);
    expect(api.last_result().errors[0]).toContain("bytes");
    expect(logs.join("")).toContain("Usage: dx @$osed().find_bytes(module, bytes, maxResults?, executableOnly?, mode?)");
  });

  test("find_stack_bytes finds live stack hits without searching heap memory", () => {
    const stackPointer = BigInt("0x12ff00");
    const stackBase = BigInt("0x130000");
    const stackLimit = BigInt("0x12f000");
    const stack = new Uint8Array(0x100);
    stack.set([0x43, 0x43, 0x43, 0x43], 0x20);
    stack.set([0x43, 0x43, 0x43, 0x43], 0x60);
    installStackHost(stackBase, stackLimit, stackPointer, stack);

    const command = createFindStackBytesCommand();
    const result = command.execute({
      bytes: [0x43, 0x43, 0x43, 0x43],
      maxResults: 10,
      stackBytes: 0x100,
    });

    expect(result.success).toBe(true);
    expect(result.findings).toEqual([
      stackPointer + BigInt(0x20),
      stackPointer + BigInt(0x60),
    ]);
  });

  test("find_stack_bytes executes through the public adapter", () => {
    const logs: string[] = [];
    const stackPointer = BigInt("0x12ff00");
    const stackBase = BigInt("0x130000");
    const stackLimit = BigInt("0x12f000");
    const stack = new Uint8Array(0x80);
    stack.set([0x43, 0x43, 0x43, 0x43], 0x10);
    installStackHost(stackBase, stackLimit, stackPointer, stack);
    ((globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host).diagnostics = {
      debugLog: (line: string) => logs.push(line),
    };

    initializeScript();
    const api = (globalThis as unknown as {
      osed: {
        find_stack_bytes: (bytes: string, maxResults?: number, stackBytes?: number) => boolean;
      };
    }).osed;

    expect(api.find_stack_bytes("43 43 43 43", 10, 0x80)).toBe(true);
    expect(logs.join("")).toContain("Scope: current thread stack only; this does not search heap, modules outside the stack window, or arbitrary process memory.");
  });

  test("find_mem_bytes finds hits in an explicit live-memory range", () => {
    const { image, base } = makeImageWithTextSection();
    image.set([0x43, 0x43, 0x43, 0x43], 0x120);
    image.set([0x43, 0x43, 0x43, 0x43], 0x1a0);
    installPeBackedHost(image, base);

    const command = createFindMemBytesCommand();
    const result = command.execute({
      address: Number(base),
      length: 0x400,
      bytes: [0x43, 0x43, 0x43, 0x43],
      maxResults: 10,
    });

    expect(result.success).toBe(true);
    expect(result.findings).toEqual([
      base + BigInt(0x120),
      base + BigInt(0x1a0),
    ]);
  });

  test("find_mem_bytes executes through the public adapter", () => {
    const logs: string[] = [];
    const { image, base } = makeImageWithTextSection();
    image.set([0x43, 0x43, 0x43, 0x43], 0x88);
    installPeBackedHost(image, base);
    ((globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host).diagnostics = {
      debugLog: (line: string) => logs.push(line),
    };

    initializeScript();
    const api = (globalThis as unknown as {
      osed: {
        find_mem_bytes: (address: number, length: number, bytes: string, maxResults?: number) => boolean;
      };
    }).osed;

    expect(api.find_mem_bytes(Number(base), 0x200, "43 43 43 43", 10)).toBe(true);
    expect(logs.join("")).toContain("Scope: explicit live-memory range only; this can search stack, heap, modules, or any readable region if you provide the correct address and length.");
  });

  test("find_mem_bytes scans readable prefixes inside a partially readable range", () => {
    const base = BigInt("0x363ff88");
    const bytes = new Uint8Array(0x80);
    bytes.set([0x43, 0x43, 0x43, 0x43], 0x0);
    installPartialRangeHost(base, bytes, 0x78);

    const command = createFindMemBytesCommand();
    const result = command.execute({
      address: Number(base),
      length: 0x500,
      bytes: [0x43, 0x43, 0x43, 0x43],
      maxResults: 10,
    });

    expect(result.success).toBe(true);
    expect(result.findings).toEqual([base]);
    expect(result.warnings.some((warning) => warning.includes("partially readable"))).toBe(true);
    expect(result.stats?.readableBytes).toBe(0x78);
  });

  test("legacy suggestions do not print sections for patterns with no matches", () => {
    const { image, base } = makeImageWithTextSection();
    const logs: string[] = [];
    installPeBackedHost(image, base);
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host.diagnostics = {
      debugLog: (line: string) => logs.push(line),
    };

    const ropSuggest = createRopCommands().find((command) => command.name === "rop_suggest");
    const result = ropSuggest?.execute({
      module: "target",
      executableOnly: true,
      maxResults: 10,
      mode: "fast",
      engine: "legacy",
    });

    expect(result?.success).toBe(true);
    expect(result?.findings).toEqual([]);
    expect(logs.join("")).not.toContain("ROP Suggest:");
    expect(logs.join("")).not.toContain("(no rows)");
  });
});
