import { describe, expect, test } from "vitest";
import { createHelpCommand } from "../src/commands/help";
import { createVersionCommand } from "../src/commands/version";
import { toDxResult } from "../src/core/dx_result";
import { findHelpEntry } from "../src/core/help_catalog";
import { stripDml, table } from "../src/core/output";
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

  test("catalog exposes string namespace helpers", () => {
    expect(findHelpEntry("str.read")).toMatchObject({
      name: "str.read",
      usage: "dx @$osed().str.read(address, max?, encoding?)",
    });
    expect(findHelpEntry("str.find")?.examples).toContain("dx @$osed().str.find(\"VirtualProtect\")");
    expect(findHelpEntry("str.refs")?.usage).toBe("dx @$osed().str.refs(target, module?, encoding?, maxResults?)");
    expect(findHelpEntry("str.bytes")?.description).toContain("payload bytes");
  });

  test("help lists namespace helpers and resolves sc.iat detail", () => {
    const logs: string[] = [];
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
    };

    const registry = new CommandRegistry();
    registry.register(createVersionCommand());
    const help = createHelpCommand(registry);

    const list = help.execute({});
    expect(list.success).toBe(true);
    expect(list.findings).toEqual(expect.arrayContaining([expect.objectContaining({ name: "sc.iat" })]));
    expect(list.findings).toEqual(expect.arrayContaining([expect.objectContaining({ name: "version" })]));
    const rendered = logs.join("");
    expect(rendered).toContain("sc Namespace Helpers");
    expect(rendered).toContain("Example");
    expect(rendered).toContain("dx @$osed().sc.iat()");

    const detail = help.execute({ command: "sc.iat" });
    expect(detail.success).toBe(true);
    expect(detail.findings).toEqual(expect.arrayContaining([expect.objectContaining({ Helper: "sc.iat" })]));

    const versionDetail = help.execute({ command: "version" });
    expect(versionDetail.success).toBe(true);
    expect(versionDetail.findings).toEqual(expect.arrayContaining([expect.objectContaining({ name: "version" })]));
  });

  test("shellcode helpers accept help without reading debugger state", () => {
    const sc = createShellcodeNamespace();
    const result = sc.iat("help");
    expect(result.toString()).toBe("Help: sc.iat: 3 rows");
    expect(result.rows.toArray()).toEqual(expect.arrayContaining([expect.objectContaining({ Helper: "sc.iat" })]));
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

  test("Dx result rows stringify without raw DML markup", () => {
    const result = toDxResult("sc.exports", [
      {
        Ordinal: "1540",
        VA: '<link cmd="u 0x75537060">0x75537060</link>',
        Name: "WerpNotifyLoadStringResource",
      },
    ]);

    expect(result.rows[0].toString()).toContain("VA: 0x75537060");
    expect(result.rows[0].toString()).not.toContain("<link");
    expect(result.rows.toString()).toBe("sc.exports: 1 row; expand rows[N] for details");
  });

  test("table width calculation ignores DML markup", () => {
    const logs: string[] = [];
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
    };

    table(
      [
        { key: "VA", header: "VA" },
        { key: "Name", header: "Name" },
      ],
      [
        { VA: "0x75537060", Name: "first" },
        { VA: '<link cmd="u 0x1">0x1</link>', Name: "second" },
      ],
    );

    const rendered = logs.join("");
    expect(rendered).not.toContain("<link");
    expect(rendered).toContain("0x75537060  first");
    expect(rendered).toContain("0x1         second");
  });
});
