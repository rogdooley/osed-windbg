/*
Shellcode helper usage:
dx @$osed().sc.peb()
dx @$osed().sc.modules()
dx @$osed().sc.module_pages("kernel32")
dx @$osed().sc.page_summary("kernel32")
dx @$osed().sc.base("kernel")
dx @$osed().sc.pe("kernel32")
dx @$osed().sc.exports("kernel32")
dx @$osed().sc.resolve("kernel32","WinExec")
dx @$osed().sc.hashes("kernel32")
dx @$osed().sc.hashes("kernel32","crc32")
dx @$osed().sc.hash("WinExec","ROR13")
dx @$osed().sc.hashresolve("kernel32",0x7c0dfcaa)
dx @$osed().sc.algorithms()
dx @$osed().sc.exportdir("kernel32")
dx @$osed().sc.export("kernel32","GetProcAddress")
dx @$osed().sc.exportat("kernel32",842)
dx @$osed().sc.exportwalk("kernel32","GetProcAddress")
dx @$osed().sc.exportwalk("kernel32","GetProcAddress",true)
dx @$osed().sc.iat()
dx @$osed().sc.iat("app.exe")
dx @$osed().sc.iat_find("VirtualAlloc")
dx @$osed().sc.iat_ptr("app.exe","VirtualAlloc")
*/

import { Command, CommandRegistry, CommandResult } from "./core/registry";
import { createPatternCommands } from "./commands/pattern";
import { createBadcharsCommand } from "./commands/badchars";
import { createEgghunterCommand } from "./commands/egghunter";
import { createSehCommand } from "./commands/seh";
import { createModulesCommand } from "./commands/modules";
import { createRopCommands } from "./commands/rop";
import { createPivotCommand } from "./commands/pivot";
import { createHelpCommand } from "./commands/help";
import { createReloadCommand } from "./commands/reload";
import { createSehPprCommand } from "./commands/seh_ppr";
import { createExploitCommand } from "./commands/exploit";
import { createTriageCommand } from "./commands/triage";
import { createFindMspCommand } from "./commands/findmsp";
import { createEncodeCommand } from "./commands/encode";
import { createNopCommand } from "./commands/nop";
import { createRopTemplateCommand } from "./commands/rop_template";
import { createFmtCommands } from "./commands/fmtstr";
import { createShellcodeNamespace } from "./shellcode";
import { buildCapabilityIndexFromRpPlusText, summarizeCapabilities, type CapabilityIndex, type RopQuery } from "./rop";
import { RPPlusProviderOptions } from "./semantics/rpplus-provider";
import { formatAddress } from "./core/output";
import * as out from "./core/output";
import { DxResult, toDxResult } from "./core/dx_result";
import { getPointerSize } from "./core/memory";
import { findHelpEntry, helpRows } from "./core/help_catalog";
import { createMemoryCommand } from "./commands/memory";
import { createLandingCommand } from "./commands/landing";
import { createMathCommand } from "./commands/math";
import { createVersionCommand } from "./commands/version";
import { getVersionInfo } from "./core/version";

declare const self: Record<string, unknown> | undefined;

type OsedApi = {
  [name: string]: unknown;
};

const registry = new CommandRegistry();
let osed: OsedApi = {};
let lastResult: CommandResult | undefined;
let currentRopCorpus: CapabilityIndex | undefined;

function getGlobalObject(): Record<string, unknown> | undefined {
  if (typeof globalThis !== "undefined") {
    return globalThis as unknown as Record<string, unknown>;
  }
  if (typeof self !== "undefined") {
    return self as unknown as Record<string, unknown>;
  }
  return undefined;
}

function publishOsed(): void {
  const globalObject = getGlobalObject();
  if (globalObject) {
    globalObject.osed = osed;
  }
}

function registerAll(): void {
  const commands: Command[] = [
    ...createPatternCommands(),
    createBadcharsCommand(),
    createEgghunterCommand(),
    createSehCommand(),
    createModulesCommand(),
    ...createRopCommands(),
    createPivotCommand(),
    createSehPprCommand(),
    createTriageCommand(),
    createFindMspCommand(),
    createMemoryCommand(),
    createLandingCommand(),
    createMathCommand(),
    createVersionCommand(),
    createEncodeCommand(),
    createNopCommand(),
    createRopTemplateCommand(),
    ...createFmtCommands(),
    createExploitCommand(),
    createHelpCommand(registry),
    createReloadCommand(registry),
  ];

  for (const command of commands) {
    registry.register(command);
  }
}

function bindApi(): OsedApi {
  const api: OsedApi = {};
  const invoke = (commandName: string, args: unknown[]) => {
    if (args.length === 1 && args[0] === "help") {
      const result = registry.execute("help", { command: commandName });
      lastResult = result;
      return result.success;
    }
    const result = registry.execute(commandName, normalizeInvocation(commandName, args));
    lastResult = result;
    return result.success;
  };
  const setResult = (result: CommandResult): void => {
    lastResult = result;
  };

  const renderRows = (title: string, rows: Array<Record<string, string>>): void => {
    out.section(title);
    if (rows.length > 0 && "Error" in rows[0]) {
      out.error(rows[0].Error);
      return;
    }
    const keys = [...new Set(rows.flatMap((row) => Object.keys(row)))];
    out.table(keys.map((key) => ({ key, header: key })), rows);
  };

  const formatSet = (values: Set<unknown>): string => {
    return [...values].map((value) => String(value)).join(", ");
  };

  const formatSemanticField = (field: { confidence: string; values: { exact: Set<unknown>; conservative: Set<unknown>; unknown: boolean } }): string => {
    if (field.values.unknown) {
      return "unknown";
    }

    const parts: string[] = [];
    if (field.values.exact.size > 0) {
      parts.push(`exact=${formatSet(field.values.exact)}`);
    }
    if (field.values.conservative.size > 0) {
      parts.push(`conservative=${formatSet(field.values.conservative)}`);
    }
    return parts.length > 0 ? `${field.confidence.toLowerCase()}(${parts.join("; ")})` : "none";
  };

  const queryRows = (query: RopQuery): Array<Record<string, string>> => {
    if (!currentRopCorpus) {
      return [{ Error: "No RP++ corpus loaded. Run rop.scan(...) first." }];
    }

    const gadgets = currentRopCorpus.query(query);
    const pointerSize = getPointerSize();
    return gadgets.map((gadget) => {
      const location = gadget.locations[0];
      return {
        Address: location?.virtualAddress !== undefined ? formatAddress(BigInt(location.virtualAddress), pointerSize) : "n/a",
        Module: location?.module ?? "n/a",
        Score: gadget.score.toString(),
        Terminator: [...gadget.semanticSummary.summary.flowEffects.values.exact].join(", ") || "none",
        Reads: formatSemanticField(gadget.semanticSummary.summary.reads),
        Writes: formatSemanticField(gadget.semanticSummary.summary.writes),
        MemoryReads: formatSemanticField(gadget.semanticSummary.summary.memoryReads),
        MemoryWrites: formatSemanticField(gadget.semanticSummary.summary.memoryWrites),
        StackDelta: formatSemanticField(gadget.semanticSummary.summary.stackDelta),
        Capabilities: gadget.capabilities.map((capability) => capability.kind).join(", "),
        Sequence: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; "),
      };
    });
  };

  const capabilityRows = (): Array<Record<string, string>> => {
    if (!currentRopCorpus) {
      return [{ Error: "No RP++ corpus loaded. Run rop.scan(...) first." }];
    }
    return summarizeCapabilities(currentRopCorpus);
  };

  const helperHelp = (name: string): DxResult => {
    const entry = findHelpEntry(name);
    const rows = entry ? helpRows(entry) : [{ Error: `Unknown helper '${name}'.` }];
    renderRows(`Help: ${name}`, rows);
    setResult({
      command: "help",
      args: { command: name },
      success: entry !== undefined,
      findings: rows,
      warnings: [],
      errors: entry ? [] : [`Unknown helper '${name}'.`],
    });
    return toDxResult(`Help: ${name}`, rows);
  };

  const scanCorpus = (text: string, options: RPPlusProviderOptions = {}): DxResult => {
    currentRopCorpus = buildCapabilityIndexFromRpPlusText(text, options);
    const rows = summarizeCapabilities(currentRopCorpus);
    out.section("ROP Corpus Loaded");
    out.info(`Gadgets: ${currentRopCorpus.gadgets.length}`);
    out.info(`Capabilities: ${rows.length}`);
    setResult({
      command: "rop.scan",
      args: { text, ...options },
      success: true,
      findings: [{ gadgets: currentRopCorpus.gadgets.length, capabilities: rows.length }],
      warnings: [],
      errors: [],
    });
    return toDxResult("ROP Corpus Loaded", [
      { Corpus: "loaded", Gadgets: currentRopCorpus.gadgets.length.toString(), Capabilities: rows.length.toString() },
    ]);
  };

  const executeRopScan = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.scan");
    }
    if (args.length === 0) {
      const rows = [{ Error: "rop.scan requires RP++ text input." }];
      setResult({
        command: "rop.scan",
        args: {},
        success: false,
        findings: [],
        warnings: [],
        errors: ["RP++ text input is required."],
      });
      return toDxResult("ROP Scan", rows);
    }

    if (args.length === 1 && typeof args[0] === "string") {
      return scanCorpus(args[0]);
    }

    const options = isPlainObject(args[0]) ? args[0] : {};
    const text = (options.text ?? options.output ?? options.value ?? args[0]) as string | undefined;
    if (typeof text !== "string" || text.trim().length === 0) {
      const rows = [{ Error: "rop.scan requires a text property containing RP++ output." }];
      setResult({
        command: "rop.scan",
        args: options,
        success: false,
        findings: [],
        warnings: [],
        errors: ["RP++ text input is required."],
      });
      return toDxResult("ROP Scan", rows);
    }

    return scanCorpus(text, {
      source: options.source as RPPlusProviderOptions["source"],
      provenance: options.provenance as RPPlusProviderOptions["provenance"],
      preserveEmptyLines: options.preserveEmptyLines as boolean | undefined,
    });
  };

  const executeRopQuery = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.query");
    }
    const query = isPlainObject(args[0]) ? (args[0] as RopQuery) : undefined;
    if (!query) {
      const rows = [{ Error: "rop.query requires a query object." }];
      renderRows("ROP Query", rows);
      setResult({
        command: "rop.query",
        args: {},
        success: false,
        findings: [],
        warnings: [],
        errors: ["Query object is required."],
      });
      return toDxResult("ROP Query", rows);
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: "No RP++ corpus loaded. Run rop.scan(...) first." }];
      renderRows("ROP Query", rows);
      setResult({
        command: "rop.query",
        args: query as Record<string, unknown>,
        success: false,
        findings: [],
        warnings: [],
        errors: ["No RP++ corpus loaded."],
      });
      return toDxResult("ROP Query", rows);
    }

    const gadgets = currentRopCorpus.query(query);
    const rows = queryRows(query);
    renderRows("ROP Query", rows);
    setResult({
      command: "rop.query",
      args: query as Record<string, unknown>,
      success: true,
      findings: gadgets,
      warnings: [],
      errors: [],
    });
    return toDxResult("ROP Query", rows);
  };

  const executeRopCapabilities = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.capabilities");
    }
    const rows = capabilityRows();
    renderRows("ROP Capabilities", rows);
    setResult({
      command: "rop.capabilities",
      args: {},
      success: currentRopCorpus !== undefined,
      findings: currentRopCorpus ? currentRopCorpus.gadgets : [],
      warnings: [],
      errors: currentRopCorpus ? [] : ["No RP++ corpus loaded."],
    });
    return toDxResult("ROP Capabilities", rows);
  };

  for (const command of registry.getAll()) {
    api[command.name] = (...args: unknown[]) => {
      return invoke(command.name, args);
    };
  }

  api.rop = {
    find: (...args: unknown[]) => {
      if (args.length === 1 && args[0] === "help") {
        return helperHelp("rop.find");
      }
      return invoke("rop", args);
    },
    scan: executeRopScan,
    query: executeRopQuery,
    capabilities: executeRopCapabilities,
  };
  api.rop_find = (...args: unknown[]) => invoke("rop", args);

  api.pattern = {
    create: (...args: unknown[]) => invoke("pattern_create", args),
    offset: (...args: unknown[]) => invoke("pattern_offset", args),
  };
  api.seh = {
    visualize: (...args: unknown[]) => invoke("seh", args),
  };
  api.fmt = {
    build: (...args: unknown[]) => invoke("fmt_build", args),
    offset: (...args: unknown[]) => invoke("fmt_offset", args),
  };

  api.last_result = () => lastResult;
  api.version = (...args: unknown[]) => {
    if (args.length === 1 && args[0] === "help") {
      return invoke("version", args);
    }
    invoke("version", []);
    return getVersionInfo();
  };
  api.last_summary = () => {
    if (!lastResult) {
      return {
        success: false,
        command: "",
        warnings: 0,
        errors: 0,
        findings: 0,
      };
    }
    return {
      success: lastResult.success,
      command: lastResult.command,
      warnings: lastResult.warnings.length,
      errors: lastResult.errors.length,
      findings: lastResult.findings.length,
    };
  };
  api.clear_last_result = () => {
    lastResult = undefined;
    return true;
  };

  api.sc = createShellcodeNamespace();

  const analysisAddress = (value: unknown): bigint => {
    if (typeof value === "bigint" && value >= BigInt(0)) return value;
    if (typeof value === "number" && Number.isInteger(value) && value >= 0) return BigInt(value);
    if (typeof value === "string" && /^(0x)?[0-9a-f`]+$/i.test(value.trim())) {
      return BigInt(`0x${value.trim().replace(/^0x/i, "").replace(/`/g, "")}`);
    }
    throw new Error("Address must be a non-negative integer, bigint, or hex string.");
  };

  const commandAddress = (value: unknown): number | string => {
    const address = analysisAddress(value);
    return address <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(address) : `0x${address.toString(16)}`;
  };
  api.memory = (address: unknown) => {
    invoke("memory", [commandAddress(address)]);
    return lastResult?.findings[0];
  };
  api.can_execute = (address: unknown) => {
    const evidence = (api.memory as (value: unknown) => { executable: boolean | null })(address);
    return evidence.executable;
  };
  api.landing = (address?: unknown) => {
    invoke("landing", address === undefined ? [] : [commandAddress(address)]);
    return lastResult?.findings[0];
  };
  api.math = (...args: unknown[]) => {
    invoke("math", args);
    return lastResult?.findings[0];
  };

  return api;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseHexByteList(value: unknown): number[] | unknown {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value !== "string") {
    return value;
  }
  const tokens = value.split(/[,\s]+/).filter((token) => token.length > 0);
  if (tokens.length === 0) {
    return [];
  }
  const parsed: number[] = [];
  for (const token of tokens) {
    if (/^[0-9a-fA-F]{1,2}$/.test(token)) {
      parsed.push(parseInt(token, 16));
      continue;
    }

    if (/^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0) {
      for (let i = 0; i < token.length; i += 2) {
        parsed.push(parseInt(token.slice(i, i + 2), 16));
      }
      continue;
    }

    return value;
  }
  return parsed;
}

function normalizeInvocation(commandName: string, args: unknown[]): Record<string, unknown> {
  if (args.length === 0 || (args.length === 1 && args[0] === undefined)) {
    return {};
  }

  if (args.length === 1 && isPlainObject(args[0])) {
    return args[0];
  }

  switch (commandName) {
    case "help":
      return { command: args[0] };
    case "pattern_create":
      return { length: args[0], type: args[1] };
    case "pattern_offset":
      return { value: args[0], type: args[1] };
    case "badchars":
      return { address: args[0], exclude: parseHexByteList(args[1]) };
    case "egghunter":
      return { tag: args[0], mode: args[1], wow64: args[2] };
    case "exploit":
      return { mode: args[0], tag: args[1], offset: args[2], address: args[3] };
    case "modules":
      return { filter: args[0] };
    case "math":
      return { value: args[0], bits: args[1] };
    case "rop":
    case "rop_suggest":
    case "pivots":
    case "retn":
    case "add_esp":
      return commandName === "rop_suggest"
        ? {
            module: args[0],
            maxResults: args[1],
            executableOnly: args[2],
            mode: args[3],
            engine: args[4],
          }
        : {
            module: args[0],
            maxResults: args[1],
            executableOnly: args[2],
            mode: args[3],
          };
    case "nop":
      return { length: args[0], byte: args[1] };
    case "rop_template":
      return { api: args[0], module: args[1] };
    case "fmt_build":
      // Positional single-write form for the dx REPL, which cannot pass object/array literals.
      // Multi-write callers use the object form (handled by the isPlainObject passthrough above).
      return {
        writes: [{ addr: args[0], value: args[1] }],
        argIndex: args[2],
        width: args[3],
        exclude: parseHexByteList(args[4]),
        prefix: args[5],
      };
    case "fmt_offset":
      return { marker: args[0], count: args[1], firstArg: args[2] };
    case "encode":
      return {
        shellcode: args[0],
        exclude: parseHexByteList(args[1]),
        key: args[2],
      };
    case "find_bytes":
      return {
        module: args[0],
        bytes: parseHexByteList(args[1]),
        maxResults: args[2],
        executableOnly: args[3],
        mode: args[4],
      };
    case "reload":
    case "seh":
      return {};
    case "seh_ppr":
      return {
        module: args[0],
        exclude: parseHexByteList(args[1]),
        maxResults: args[2],
        executableOnly: args[3],
        mode: args[4],
      };
    case "triage":
      return {
        patternLength: args[0],
        badchars: parseHexByteList(args[1]),
        module: args[2],
        stackBytes: args[3],
      };
    case "memory":
    case "landing":
      return { address: args[0] };
    default:
      return { value: args[0] };
  }
}

function initialize(): void {
  currentRopCorpus = undefined;
  registry.setReloader(() => {
    currentRopCorpus = undefined;
    registerAll();
    osed = bindApi();
    publishOsed();
  });

  registerAll();
  osed = bindApi();
  publishOsed();
}

export function initializeScript(): unknown[] {
  const registrations: unknown[] = [];
  const hostAny = host as unknown as {
    apiVersionSupport?: new (major: number, minor: number) => unknown;
    functionAlias?: new (fn: (...args: unknown[]) => unknown, aliasName: string) => unknown;
  };

  if (hostAny.apiVersionSupport) {
    registrations.push(new hostAny.apiVersionSupport(1, 7));
  }

  initialize();

  if (hostAny.functionAlias) {
    try {
      registrations.push(new hostAny.functionAlias(() => osed, "osed"));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const globalObject = getGlobalObject();
      if (globalObject) {
        globalObject.osed = osed;
      }
      if (typeof host !== "undefined" && host.diagnostics && typeof host.diagnostics.debugLog === "function") {
        host.diagnostics.debugLog(`osed: functionAlias registration failed, using global object fallback: ${message}\n`);
      }
    }
  }

  return registrations;
}
