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
    expect(logs.join("")).toContain("sc Namespace Helpers");

    const detail = help.execute({ command: "sc.iat" });
    expect(detail.success).toBe(true);
    expect(detail.findings).toEqual(expect.arrayContaining([expect.objectContaining({ Helper: "sc.iat" })]));
  });

  test("shellcode helpers accept help without reading debugger state", () => {
    const sc = createShellcodeNamespace();
    expect(sc.iat("help")).toEqual(expect.arrayContaining([expect.objectContaining({ Helper: "sc.iat" })]));
  });
});
