import { describe, expect, test } from "vitest";
import { createHelpCommand } from "../src/commands/help";
import { findHelpEntry } from "../src/core/help_catalog";
import { CommandRegistry } from "../src/core/registry";
import { createShellcodeNamespace } from "../src/shellcode";

describe("help command", () => {
  test("catalog exposes IAT namespace helpers", () => {
    expect(findHelpEntry("sc.iat")).toMatchObject({
      name: "sc.iat",
      usage: "dx @$osed().sc.iat(module?, filter?)",
    });
    expect(findHelpEntry("sc.iat_find")?.examples).toContain("dx @$osed().sc.iat_find(\"VirtualAlloc\")");
    expect(findHelpEntry("sc.iat_ptr")?.description).toContain("IAT slot");
  });

  test("help lists namespace helpers and resolves sc.iat detail", () => {
    const logs: string[] = [];
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
    };

    const registry = new CommandRegistry();
    const help = createHelpCommand(registry);

    const list = help.execute({});
    expect(list.success).toBe(true);
    expect(list.findings).toEqual(expect.arrayContaining([expect.objectContaining({ name: "sc.iat" })]));
    const rendered = logs.join("");
    expect(rendered).toContain("sc Namespace Helpers");
    expect(rendered).toContain("Example");
    expect(rendered).toContain("dx @$osed().sc.iat()");

    const detail = help.execute({ command: "sc.iat" });
    expect(detail.success).toBe(true);
    expect(detail.findings).toEqual(expect.arrayContaining([expect.objectContaining({ Helper: "sc.iat" })]));
  });

  test("shellcode helpers accept help without reading debugger state", () => {
    const sc = createShellcodeNamespace();
    const result = sc.iat("help");
    expect(result.toString()).toBe("Help: sc.iat: 3 rows");
    expect(result.rows).toEqual(expect.arrayContaining([expect.objectContaining({ Helper: "sc.iat" })]));
  });

  test("shellcode modules use short names while preserving paths", () => {
    (globalThis as unknown as { host: unknown }).host = {
      diagnostics: { debugLog: () => undefined },
      currentProcess: {
        Modules: [
          {
            Name: "C:\\labs\\service.exe",
            Path: "C:\\labs\\service.exe",
            BaseAddress: BigInt(0x400000),
            EndAddress: BigInt(0x42e000),
          },
        ],
      },
    };

    const [row] = createShellcodeNamespace().modules().rows as Array<Record<string, string>>;
    expect(row.Name).toBe("service.exe");
    expect(row.Path).toBe("C:\\labs\\service.exe");
  });

  test("shellcode export without symbol returns actionable guidance", () => {
    (globalThis as unknown as { host: unknown }).host = {
      diagnostics: { debugLog: () => undefined },
      currentProcess: {
        Modules: [
          {
            Name: "bass.dll",
            Path: "C:\\Program Files\\VUPlayer\\BASS.dll",
            BaseAddress: BigInt(0x10000000),
            EndAddress: BigInt(0x10041000),
          },
        ],
      },
    };

    const result = createShellcodeNamespace().export("bass.dll");
    expect(result.rows[0]).toMatchObject({
      Error: "Symbol is required. Use sc.exports(\"bass.dll\") to list exported functions.",
    });
  });
});
