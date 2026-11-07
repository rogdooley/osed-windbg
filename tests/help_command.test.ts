import { describe, expect, test } from "vitest";
import { createHelpCommand } from "../src/commands/help";
import { createVersionCommand } from "../src/commands/version";
import { toDxResult } from "../src/core/dx_result";
import { findHelpEntry, NAMESPACE_HELP_ENTRIES, normalizeHelpExamples } from "../src/core/help_catalog";
import { HELP_WIDTH, renderListing, renderCompactDetail, renderFullDetail } from "../src/core/help_render";
import { stripDml, table } from "../src/core/output";
import { CommandRegistry } from "../src/core/registry";
import { normalizeInvocation } from "../src/index";
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
    expect(list.findings).toEqual(expect.arrayContaining([expect.objectContaining({ name: "rop.plan" })]));
    const rendered = logs.join("");
    expect(rendered).toContain("OSED-WINDBG");
    expect(rendered).toContain("PE / API");
    expect(rendered).toContain("Complete command reference");

    logs.length = 0;
    const all = help.execute({ command: "all" });
    expect(all.success).toBe(true);
    expect(logs.join("")).toContain("=== All OSED Commands ===");
    expect(logs.join("")).toContain("rop.corpus.export");

    const detail = help.execute({ command: "sc.iat" });
    expect(detail.success).toBe(true);
    expect(detail.findings).toEqual(expect.arrayContaining([expect.objectContaining({ Helper: "sc.iat" })]));
    expect(logs.join("")).toContain("MORE → help(\"sc.iat\", \"full\")");

    const versionDetail = help.execute({ command: "version" });
    expect(versionDetail.success).toBe(true);
    expect(versionDetail.findings).toEqual(expect.arrayContaining([expect.objectContaining({ name: "version" })]));
    expect(logs.join("")).toContain("MORE → help(\"version\", \"full\")");
  });

  test("renderer keeps prose within 80 columns and preserves commands verbatim", () => {
    const entry = findHelpEntry("rop.corpus.export")!;
    const output = renderFullDetail(entry);
    for (const line of output) {
      if (!line.trimStart().startsWith("dx @$osed()")) expect(line.length).toBeLessThanOrEqual(HELP_WIDTH);
    }
    expect(output).toContain('  dx @$osed().rop.corpus.export("C:\\\\notes\\\\rop-corpus.json")');
    expect(output).toContain("  Saves the current corpus to disk.");
    const longName = "a.command.name.longer.than.the.listing.name.column";
    const longListing = renderListing([{ ...entry, name: longName }]);
    expect(longListing).toHaveLength(1);
    expect(longListing[0]).toContain(`${longName}(...)`);
    expect(longListing[0]).toContain("Exports a compact");
  });

  test("legacy and labelled examples normalize without changing catalog entries", () => {
    expect(normalizeHelpExamples([
      "dx @$osed().help()",
      { label: "full", command: 'dx @$osed().help("all")' },
    ])).toEqual([
      { command: "dx @$osed().help()" },
      { label: "full", command: 'dx @$osed().help("all")' },
    ]);
  });

  test("catalog references and examples have static documentation validity", () => {
    const names = new Set(NAMESPACE_HELP_ENTRIES.map((entry) => entry.name));
    for (const entry of NAMESPACE_HELP_ENTRIES) {
      for (const target of entry.seeAlso ?? []) expect(names.has(target)).toBe(true);
      for (const { command } of normalizeHelpExamples(entry.examples)) {
        const match = /^dx @\$osed\(\)\.([A-Za-z_][A-Za-z0-9_.]*)\(/.exec(command);
        expect(match).not.toBeNull();
        expect(names.has(match![1])).toBe(true);
        const expression = command.replace(/^dx @\$osed\(\)/, "osed()").replace(/\s*\/\/.*$/, "");
        expect(() => new Function("osed", `return (${expression});`)).not.toThrow();
      }
    }
  });

  test("golden compact and full corpus help retains Windows paths and details", () => {
    const entry = findHelpEntry("rop.corpus.export")!;
    const compact = renderCompactDetail(entry).join("\n");
    expect(compact).toContain("=== Help: rop.corpus.export ===");
    expect(compact).toContain('dx @$osed().rop.corpus.export("C:\\\\notes\\\\rop-corpus.json")');
    expect(compact).toContain("Saves the current corpus to disk.");
    expect(compact).toContain("rop.scan_live");
    expect(compact).toContain('MORE \u2192 help("rop.corpus.export", "full")');
    const full = renderFullDetail(entry).join("\n");
    expect(full).toContain("DETAILS\n  Saves the gadgets you scanned this session");
    expect(full).toContain('dx @$osed().rop.corpus.export("C:\\\\notes\\\\rop-corpus.json")\n  Saves the current corpus to disk.');
    expect(full).toContain("SEE ALSO\n  rop.scan_live, rop.corpus.report, rop.corpus.import,");
  });

  test("public help invocation preserves the requested detail mode", () => {
    const options = normalizeInvocation("help", ["rop.corpus.export", "full"]);
    expect(options).toEqual({
      command: "rop.corpus.export",
      mode: "full",
    });
    const logs: string[] = [];
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
    };
    expect(createHelpCommand(new CommandRegistry()).execute(options).success).toBe(true);
    expect(logs.join("")).toContain("DETAILS");
    expect(logs.join("")).toContain("EXAMPLES");
  });

  test("P1A namespace navigation is task-grouped and metadata-only", () => {
    const logs: string[] = [];
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
    };
    const help = createHelpCommand(new CommandRegistry());
    const rop = help.execute({ command: "rop" });
    expect(rop.success).toBe(true);
    expect(rop.findings).toEqual(expect.arrayContaining([expect.objectContaining({ name: "rop.scan_live" }), expect.objectContaining({ name: "rop.corpus.export" })]));
    expect(logs.join("")).toContain("DISCOVERY");
    expect(logs.join("")).toContain("PERSISTENCE");
    const rendered = logs.join("").split("\n");
    expect(rendered.some((line) => /rop\.scan_live/.test(line) && /scan_live\(/.test(line))).toBe(true);

    logs.length = 0;
    const sc = help.execute({ command: "sc" });
    expect(sc.success).toBe(true);
    expect(logs.join("")).toContain("IMPORTS");
    expect(logs.join("")).toContain("API RESOLUTION");

    logs.length = 0;
    const seh = help.execute({ command: "seh" });
    expect(seh.success).toBe(true);
    expect(seh.findings).toEqual(expect.arrayContaining([expect.objectContaining({ name: "seh.visualize" })]));
  });

  test("P1A search is comprehensive, category-grouped, and deterministic", () => {
    const logs: string[] = [];
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
    };
    const help = createHelpCommand(new CommandRegistry());
    const result = help.execute({ command: "?rop" });
    expect(result.success).toBe(true);
    expect(result.findings.length).toBeGreaterThan(15);
    expect(result.warnings).toEqual([]);
    const names = (result.findings as Array<{ name: string }>).map((entry) => entry.name);
    const directCount = names.filter((name) => name.includes("rop")).length;
    expect(names.slice(0, directCount).every((name) => name.includes("rop"))).toBe(true);
    expect(names.slice(0, directCount)).toEqual([...names.slice(0, directCount)].sort((a, b) => a.localeCompare(b)));
    expect(logs.join("")).toContain(`=== Search: rop (${result.findings.length} matches) ===`);
    expect(logs.join("")).toContain("ROP");

    logs.length = 0;
    const noMatches = help.execute({ command: "?does-not-exist" });
    expect(noMatches.success).toBe(true);
    expect(noMatches.findings).toEqual([]);
    expect(logs.join("")).toContain("No matching commands.");
    expect(help.execute({ command: "?" }).errors).toEqual(["Search query cannot be empty."]);
  });

  test("P1A resolves unambiguous suffixes and reports deterministic candidates", () => {
    const logs: string[] = [];
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
    };
    const help = createHelpCommand(new CommandRegistry());
    const resolved = help.execute({ command: "corpus.export" });
    expect(resolved.success).toBe(true);
    expect(resolved.findings).toEqual(expect.arrayContaining([expect.objectContaining({ Helper: "rop.corpus.export" })]));
    expect(logs.join("")).toContain("=== Help: rop.corpus.export ===");

    logs.length = 0;
    const ambiguous = help.execute({ command: "export" });
    expect(ambiguous.success).toBe(false);
    expect((ambiguous.findings as Array<{ name: string }>).map((entry) => entry.name)).toEqual(["rop.corpus.export", "rop.export", "sc.export"]);
    expect(logs.join("")).toContain("=== Ambiguous help: export ===");
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

  test("Dx result rows decode escaped DML labels for plain-text rendering", () => {
    const result = toDxResult("sc.iat", [
      {
        Module: '<link cmd="lmv m test">C:\\A&amp;B\\test.dll</link>',
        Symbol: '<link cmd="x test!operator&lt;">operator&lt;</link>',
      },
    ]);

    expect(result.rows[0].toString()).toContain("Module: C:\\A&B\\test.dll");
    expect(result.rows[0].toString()).toContain("Symbol: operator<");
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

  test("empty tables produce no output", () => {
    const logs: string[] = [];
    (globalThis as unknown as { host: { diagnostics: { debugLog: (line: string) => void } } }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
    };

    table([{ key: "Value", header: "Value" }], []);

    expect(logs).toEqual([]);
  });
});
