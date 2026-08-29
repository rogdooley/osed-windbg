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
import { createBadcharsCommand, createBadcharArrayCommand, createBadcharFindCommand } from "./commands/badchars";
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
import { createFindPtrCommand } from "./commands/find_ptr";
import { createEncodeCommand } from "./commands/encode";
import { createNopCommand } from "./commands/nop";
import { createRopTemplateCommand } from "./commands/rop_template";
import { createCodeCavesCommand } from "./commands/code_caves";
import { createFmtCommands } from "./commands/fmtstr";
import { createShellcodeNamespace } from "./shellcode";
import { buildCapabilityIndexFromRpPlusText, buildCapabilityIndexFromSequences, classifyPivotSource, emissionRows, filterCorpusByBadchars, firstKnownAddress, formatChainPython, formatExportPython, gadgetSequence, hex32, mergeCapabilityIndexes, normalizeExploitStrategy, planExploitStrategy, planRegisterSetup, planVirtualAlloc, planVirtualAllocFrame, planVirtualProtect, planVirtualProtectFrame, planWriteProcessMemory, planWriteProcessMemoryFrame, planRegisterSetupPacking, RankedSemanticEmitter, solveValue, strategyPlanRows, summarizeCapabilities, synthesize, synthesisRows, type ApiResolutionMode, type CapabilityIndex, type ChainTarget, type ControlMechanism, type EmissionResult, type ExploitState, type ExportableEmission, type ExportableSynthesis, type FlatFramePlan, type RegisterState, type RopQuery, type RopStrategyPlan, type SynthesisResult, type ValueRecipe, type VirtualAllocFrameParams, type VirtualAllocParams, type VirtualProtectFrameParams, type VirtualProtectParams, type WriteProcessMemoryFrameParams, type WriteProcessMemoryParams } from "./rop";
import { discoverLiveGadgets, type LiveDiscoveryOptions } from "./analysis/live_gadgets";
import { listModulesWithMitigations } from "./commands/modules";
import { sequencesFromLiveHits } from "./semantics/live-provider";
import { RPPlusProviderOptions } from "./semantics/rpplus-provider";
import { formatAddress } from "./core/output";
import * as out from "./core/output";
import { DxResult, toDxResult } from "./core/dx_result";
import { getPointerSize } from "./core/memory";
import { findHelpEntry, helpRows } from "./core/help_catalog";
import { createMemoryCommand } from "./commands/memory";
import { createLandingCommand, landingDxRows } from "./commands/landing";
import { createMathCommand } from "./commands/math";
import { createVersionCommand } from "./commands/version";
import { getVersionInfo } from "./core/version";
import { createStringCommands } from "./commands/strings";
import { createFindStackBytesCommand } from "./commands/find_stack_bytes";
import { createFindMemBytesCommand } from "./commands/find_mem_bytes";
import { createStackmapCommand } from "./commands/stackmap";
import type { SerializedLandingEvidence } from "./analysis/landing";

declare const self: Record<string, unknown> | undefined;

type OsedApi = {
  [name: string]: unknown;
};

const registry = new CommandRegistry();
let osed: OsedApi = {};
let lastResult: CommandResult | undefined;
let currentRopCorpus: CapabilityIndex | undefined;
let corpusGeneration = 0;
let nextRopPlanId = 1;
const ropPlans = new Map<number, { plan: RopStrategyPlan; generation: number }>();
interface CorpusModuleEntry {
  name: string;
  accepted: number;
  rejected: number;
  usable: boolean;
  reason?: string;
}
let corpusModules: CorpusModuleEntry[] = [];
const ropEmitter = new RankedSemanticEmitter();
let cachedExploitState: ExploitState | undefined;
const NO_ROP_CORPUS_MESSAGE = "No ROP corpus loaded. Run rop.scan(...) for RP++ text or rop.scan_live(...) for live target memory first.";
const NO_EXPLOIT_STATE_MESSAGE = "No exploit state available. Run triage() first to capture crash state.";

function buildExploitStateFromTriage(findings: Record<string, unknown>): ExploitState {
  const control = findings.control as Record<string, unknown> | undefined;
  const stack = findings.stack as Record<string, unknown> | undefined;
  const seh = findings.seh as Record<string, unknown> | undefined;
  const badcharStats = findings.badchars as Array<{ byte: number; count: number }> | undefined;

  const ipControlled = control?.ipControlled === true;

  let mechanism: ControlMechanism = "saved-ret";
  if (seh?.overwritten === "yes") {
    mechanism = "seh";
  }

  const badchars = (badcharStats ?? [])
    .filter((entry) => typeof entry.byte === "number")
    .map((entry) => entry.byte & 0xff);

  const sp = stack?.sp;
  const spValue = sp !== undefined && sp !== null ? Number(sp) : undefined;

  const landing = stack?.landing as Record<string, unknown> | undefined;
  const landingBytes = landing?.bytes as number[] | undefined;
  const controlledAfterEsp = landingBytes?.length ?? 0;

  const registers: Partial<Record<string, RegisterState>> = {};
  const regEntries = (control as Record<string, unknown>)?.registers as Array<{ name: string; value: unknown }> | undefined;
  if (Array.isArray(regEntries)) {
    for (const entry of regEntries) {
      const name = entry.name?.toLowerCase();
      if (name && name !== "eip" && name !== "esp") {
        registers[name] = { kind: "unknown" };
      }
    }
  }

  return {
    control: {
      mechanism,
      instructionPointerControlled: ipControlled,
    },
    stack: {
      espAtControl: spValue,
      controlledBeforeEsp: 0,
      controlledAfterEsp,
      contiguousControlledBytes: controlledAfterEsp,
      readable: true,
      writable: true,
      executable: typeof (stack as Record<string, unknown>)?.stackExecutable === "boolean" ? (stack as Record<string, unknown>).stackExecutable as boolean : false,
    },
    registers,
    constraints: {
      badchars,
      apiResolution: "either",
    },
  };
}

function mergeExploitStateOverrides(base: ExploitState, overrides: Record<string, unknown>): ExploitState {
  const merged = { ...base };

  if (overrides.mechanism !== undefined) {
    merged.control = { ...merged.control, mechanism: String(overrides.mechanism) as ControlMechanism };
  }
  if (overrides.eipControlled !== undefined) {
    merged.control = { ...merged.control, instructionPointerControlled: Boolean(overrides.eipControlled) };
  }

  if (overrides.controlledBytesAfterEsp !== undefined) {
    merged.stack = { ...merged.stack, controlledAfterEsp: Number(overrides.controlledBytesAfterEsp), contiguousControlledBytes: Number(overrides.controlledBytesAfterEsp) };
  }
  if (overrides.controlledBytesBeforeEsp !== undefined) {
    merged.stack = { ...merged.stack, controlledBeforeEsp: Number(overrides.controlledBytesBeforeEsp) };
  }
  if (overrides.stackWritable !== undefined) {
    merged.stack = { ...merged.stack, writable: Boolean(overrides.stackWritable) };
  }
  if (overrides.stackExecutable !== undefined) {
    merged.stack = { ...merged.stack, executable: Boolean(overrides.stackExecutable) };
  }

  if (overrides.badchars !== undefined) {
    merged.constraints = { ...merged.constraints, badchars: parseHexByteList(overrides.badchars) as number[] };
  }
  if (overrides.apiResolution !== undefined) {
    const resolution = String(overrides.apiResolution).toLowerCase();
    if (resolution === "direct" || resolution === "iat" || resolution === "either") {
      merged.constraints = { ...merged.constraints, apiResolution: resolution };
    }
  }
  if (overrides.maximumPayloadLength !== undefined) {
    merged.constraints = { ...merged.constraints, maximumPayloadLength: Number(overrides.maximumPayloadLength) };
  }

  return merged;
}

function diagnoseModuleBadchars(moduleName: string, badchars: number[]): string | undefined {
  try {
    const modules = listModulesWithMitigations(moduleName);
    const mod = modules.find((m) => m.name.toLowerCase().includes(moduleName.toLowerCase()));
    if (!mod) return undefined;
    const badSet = new Set(badchars);
    const base = mod.base;
    const baseBytes: number[] = [];
    const pointerSize = getPointerSize();
    for (let i = 0; i < pointerSize; i++) {
      baseBytes.push(Number((base >> BigInt(i * 8)) & BigInt(0xff)));
    }
    const offending = baseBytes
      .map((b, i) => ({ byte: b, position: i }))
      .filter((entry) => badSet.has(entry.byte));
    if (offending.length === 0) return undefined;
    const baseHex = `0x${base.toString(16).toUpperCase().padStart(pointerSize * 2, "0")}`;
    const packed = baseBytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
    const byByte = new Map<number, number[]>();
    for (const entry of offending) {
      const list = byByte.get(entry.byte) ?? [];
      list.push(entry.position);
      byByte.set(entry.byte, list);
    }
    const badSummary = [...byByte.entries()]
      .map(([byte, positions]) => {
        const hex = `0x${byte.toString(16).toUpperCase().padStart(2, "0")}`;
        const posStr = positions.length === 1
          ? `offset ${positions[0]}`
          : positions.length === positions[positions.length - 1] - positions[0] + 1
            ? `offsets ${positions[0]}-${positions[positions.length - 1]}`
            : `offsets ${positions.join(",")}`;
        return `${hex} (${posStr})`;
      })
      .join(", ");
    return `${mod.name} base ${baseHex} | packed: ${packed} | bad bytes: ${badSummary}. No usable gadget addresses.`;
  } catch {
    return undefined;
  }
}

function invalidateCorpusPlans(): void {
  corpusGeneration++;
  ropPlans.clear();
  nextRopPlanId = 1;
}

function resetCorpusModules(): void {
  corpusModules = [];
}

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
    createBadcharArrayCommand(),
    createBadcharFindCommand(),
    createEgghunterCommand(),
    createSehCommand(),
    createModulesCommand(),
    ...createRopCommands(),
    createPivotCommand(),
    createSehPprCommand(),
    createTriageCommand(),
    createFindMspCommand(),
    createFindPtrCommand(),
    createMemoryCommand(),
    createFindMemBytesCommand(),
    createFindStackBytesCommand(),
    createLandingCommand(),
    createStackmapCommand(),
    createMathCommand(),
    createVersionCommand(),
    ...createStringCommands(),
    createCodeCavesCommand(),
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
    if (commandName === "triage" && result.success && result.findings.length > 0) {
      cachedExploitState = buildExploitStateFromTriage(result.findings[0] as Record<string, unknown>);
    }
    if (!result.success) {
      for (const error of result.errors) {
        out.error(error);
      }
      const command = registry.get(commandName);
      if (command) {
        out.info(`Usage: ${command.usage}`);
      }
    }
    return result.success;
  };
  const setResult = (result: CommandResult): void => {
    lastResult = result;
  };

  const renderRows = (title: string, rows: Array<Record<string, string>>): void => {
    if (rows.length === 0) {
      return;
    }
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
      return [{ Error: NO_ROP_CORPUS_MESSAGE }];
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
      return [{ Error: NO_ROP_CORPUS_MESSAGE }];
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

  const scanCorpus = (text: string, options: RPPlusProviderOptions = {}, badchars?: number[]): DxResult => {
    invalidateCorpusPlans();
    resetCorpusModules();
    const raw = buildCapabilityIndexFromRpPlusText(text, options);
    const warnings: string[] = [];
    let filteredCount = 0;
    if (badchars && badchars.length > 0) {
      const { filtered, removedCount } = filterCorpusByBadchars(raw, badchars);
      filteredCount = removedCount;
      currentRopCorpus = filtered;
      if (removedCount > 0) {
        const byteList = badchars.map((b) => `0x${(b & 0xff).toString(16).toUpperCase().padStart(2, "0")}`).join(" ");
        warnings.push(`${removedCount} gadget(s) filtered — address contains badchar(s): ${byteList}`);
      }
    } else {
      currentRopCorpus = raw;
    }
    const rows = summarizeCapabilities(currentRopCorpus);
    out.section("ROP Corpus Loaded");
    out.info(`Gadgets: ${currentRopCorpus.gadgets.length}`);
    if (filteredCount > 0) out.info(`Filtered: ${filteredCount} (badchar address)`);
    out.info(`Capabilities: ${rows.length}`);
    for (const w of warnings) out.warn(w);
    setResult({
      command: "rop.scan",
      args: { text, ...options },
      success: true,
      findings: [{ gadgets: currentRopCorpus.gadgets.length, capabilities: rows.length, filtered: filteredCount }],
      warnings,
      errors: [],
    });
    return toDxResult("ROP Corpus Loaded", [
      { Corpus: "loaded", Gadgets: currentRopCorpus.gadgets.length.toString(), Filtered: filteredCount.toString(), Capabilities: rows.length.toString() },
    ]);
  };

  const scanLiveCorpus = (
    modules: Array<string | undefined>,
    options: Omit<LiveDiscoveryOptions, "module">,
    append: boolean,
  ): DxResult => {
    const discoveries = modules.map((module) => discoverLiveGadgets({ ...options, module }));
    const discoveredIndexes = discoveries.map((discovery) =>
      buildCapabilityIndexFromSequences(sequencesFromLiveHits(discovery.hits)));
    invalidateCorpusPlans();
    if (!append) resetCorpusModules();
    const indexes = append && currentRopCorpus
      ? [currentRopCorpus, ...discoveredIndexes]
      : discoveredIndexes;
    currentRopCorpus = mergeCapabilityIndexes(indexes);
    const capRows = summarizeCapabilities(currentRopCorpus);
    const stats = discoveries.reduce(
      (total, discovery) => ({
        patterns: total.patterns + discovery.stats.patterns,
        scanned: total.scanned + discovery.stats.scanned,
        discovered: total.discovered + discovery.stats.discovered,
        rejected: total.rejected + discovery.stats.rejected,
        backwardTerminators: total.backwardTerminators + (discovery.stats.backwardTerminators ?? 0),
        backwardGadgets: total.backwardGadgets + (discovery.stats.backwardGadgets ?? 0),
      }),
      { patterns: 0, scanned: 0, discovered: 0, rejected: 0, backwardTerminators: 0, backwardGadgets: 0 },
    );
    const warnings = discoveries.flatMap((discovery) => discovery.warnings);
    const badcharsArray = Array.isArray(options.badchars) ? options.badchars : [];
    for (let i = 0; i < modules.length; i++) {
      const mod = modules[i];
      const disc = discoveries[i];
      const accepted = disc.stats.discovered;
      const rejected = disc.stats.scanned - accepted;
      let reason: string | undefined;
      if (mod && disc.stats.scanned > 0 && accepted === 0 && badcharsArray.length > 0) {
        reason = diagnoseModuleBadchars(mod, badcharsArray);
        if (reason) warnings.push(reason);
      }
      const modName = mod ?? "<all>";
      const existing = corpusModules.find((m) => m.name === modName);
      if (existing) {
        existing.accepted = accepted;
        existing.rejected = rejected;
        existing.usable = accepted > 0;
        existing.reason = reason;
      } else {
        corpusModules.push({
          name: modName,
          accepted,
          rejected,
          usable: accepted > 0,
          reason,
        });
      }
    }

    out.section("Module Scan");
    for (let i = 0; i < modules.length; i++) {
      const mod = modules[i] ?? "<all>";
      const disc = discoveries[i];
      const accepted = disc.stats.discovered;
      const rejected = disc.stats.scanned - accepted;
      out.info(`${mod}: ${accepted} raw gadgets accepted, ${rejected} rejected`);
    }

    out.section("Corpus Summary");
    out.info(`Mode: ${append ? "append" : "replace"}`);
    out.info(`Modules: ${corpusModules.map((m) => m.name).join(", ")}`);
    out.info(`Semantic gadgets: ${currentRopCorpus.gadgets.length} (deduplicated)`);
    out.info(`Capabilities: ${capRows.length}`);
    if (stats.backwardTerminators > 0) {
      out.info(`Backward scanner: ${stats.backwardTerminators} terminators, ${stats.backwardGadgets} new gadgets`);
    }

    for (const warning of warnings) {
      out.warn(warning);
    }

    setResult({
      command: "rop.scan_live",
      args: { modules, append, ...options },
      success: true,
      findings: [{ modules: corpusModules.length, gadgets: currentRopCorpus.gadgets.length, capabilities: capRows.length, ...stats }],
      warnings,
      errors: [],
    });
    const uniqueModuleNames = corpusModules.map((m) => m.name).join(", ");
    return toDxResult("Live ROP Corpus", [
      ...modules.map((mod, i) => {
        const disc = discoveries[i];
        return {
          Section: "Module Scan",
          Module: mod ?? "<all>",
          "Raw Accepted": disc.stats.discovered.toString(),
          Rejected: (disc.stats.scanned - disc.stats.discovered).toString(),
        };
      }),
      {
        Section: "Corpus Summary",
        Module: uniqueModuleNames,
        "Raw Accepted": "",
        Rejected: "",
        "Semantic Gadgets": currentRopCorpus.gadgets.length.toString(),
        Capabilities: capRows.length.toString(),
      },
    ]);
  };

  const executeRopScanLive = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.scan_live");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : parseScanLivePositionalArgs(args);
    const requested = Array.isArray(options.modules)
      ? options.modules
      : Array.isArray(options.module)
        ? options.module
        : [options.module];
    const modules = requested
      .map((module) => module === undefined ? undefined : String(module).trim())
      .filter((module): module is string | undefined => module === undefined || module.length > 0);
    const parsedBadchars = parseHexByteList(options.badchars);
    return scanLiveCorpus(
      modules.length > 0 ? modules : [undefined],
      {
        badchars: Array.isArray(parsedBadchars) ? parsedBadchars : undefined,
        maxPerPattern: options.maxPerPattern as number | undefined,
      },
      Boolean(options.append),
    );
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

    if (args.length >= 1 && typeof args[0] === "string") {
      const scanBadchars = typeof args[1] === "string"
        ? parseHexByteList(args[1]) as number[] | undefined
        : undefined;
      return scanCorpus(args[0], {}, Array.isArray(scanBadchars) ? scanBadchars : undefined);
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

    const parsedBadchars = parseHexByteList(options.badchars);
    return scanCorpus(text, {
      source: options.source as RPPlusProviderOptions["source"],
      provenance: options.provenance as RPPlusProviderOptions["provenance"],
      preserveEmptyLines: options.preserveEmptyLines as boolean | undefined,
    }, Array.isArray(parsedBadchars) ? parsedBadchars : undefined);
  };

  const executeRopQuery = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.query");
    }
    let query: RopQuery | undefined;
    if (isPlainObject(args[0])) {
      query = args[0] as RopQuery;
    } else if (typeof args[0] === "string" && args[1] !== undefined) {
      const field = args[0] as keyof RopQuery;
      const listFields: Array<keyof RopQuery> = [
        "reads",
        "writes",
        "preserves",
        "preservesThroughout",
        "capability",
        "terminator",
      ];
      const scalarFields: Array<keyof RopQuery> = [
        "stackDelta",
        "memoryReads",
        "memoryWrites",
        "memoryRead",
        "memoryWrite",
        "executableOnly",
      ];
      if (listFields.includes(field)) {
        query = { [field]: [args[1]] } as RopQuery;
      } else if (scalarFields.includes(field)) {
        query = { [field]: args[1] } as RopQuery;
      }
      if (query && args[2] !== undefined) {
        query.executableOnly = Boolean(args[2]);
      }
    }
    if (!query) {
      const rows = [{ Error: "rop.query requires a supported field and value." }];
      renderRows("ROP Query", rows);
      setResult({
        command: "rop.query",
        args: {},
        success: false,
        findings: [],
        warnings: [],
        errors: ["Use rop.query(field, value, executableOnly?)."],
      });
      return toDxResult("ROP Query", rows);
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Query", rows);
      setResult({
        command: "rop.query",
        args: query as Record<string, unknown>,
        success: false,
        findings: [],
        warnings: [],
        errors: [NO_ROP_CORPUS_MESSAGE],
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
      errors: currentRopCorpus ? [] : [NO_ROP_CORPUS_MESSAGE],
    });
    return toDxResult("ROP Capabilities", rows);
  };

  const executeRopPlan = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.plan");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Plan", rows);
      return toDxResult("ROP Plan", rows);
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : { strategy: args[0], apiResolution: args[1] };
    const strategy = normalizeExploitStrategy(String(options.strategy ?? ""));
    if (!strategy) {
      const rows = [{ Error: "Unsupported strategy. Use VirtualProtect, VirtualAlloc, WriteProcessMemory, VirtualProtectEx, VirtualAllocEx, WinExec, or Stack Pivot." }];
      renderRows("ROP Plan", rows);
      return toDxResult("ROP Plan", rows);
    }
    const resolution = String(options.apiResolution ?? options.resolution ?? "direct").toLowerCase();
    if (resolution !== "direct" && resolution !== "iat") {
      const rows = [{ Error: "API resolution must be direct or iat." }];
      renderRows("ROP Plan", rows);
      return toDxResult("ROP Plan", rows);
    }
    const plan = planExploitStrategy(currentRopCorpus, {
      strategy,
      apiResolution: resolution as ApiResolutionMode,
    }, nextRopPlanId++);
    ropPlans.set(plan.id, { plan, generation: corpusGeneration });
    const rows = strategyPlanRows(plan);
    renderRows(`ROP Plan ${plan.id}: ${plan.strategy}`, rows);
    setResult({
      command: "rop.plan",
      args: options,
      success: plan.strategies.some((candidate) => candidate.possible),
      findings: [plan],
      warnings: [],
      errors: [],
    });
    return toDxResult(`ROP Plan ${plan.id}`, rows);
  };

  const executeRopEmit = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.emit");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Emit", rows);
      return toDxResult("ROP Emit", rows);
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : { planId: args[0], strategyId: args[1] };
    const planId = Number(options.planId ?? options.plan_id);
    const strategyId = options.strategyId ?? options.strategy_id;
    const entry = ropPlans.get(planId);
    if (!entry) {
      const rows = [{ Error: `ROP plan ${Number.isFinite(planId) ? planId : "<invalid>"} does not exist. Run rop.plan(...) first.` }];
      renderRows("ROP Emit", rows);
      return toDxResult("ROP Emit", rows);
    }
    if (entry.generation !== corpusGeneration) {
      const rows = [{ Error: `ROP plan ${planId} is stale (corpus was reloaded). Run rop.plan(...) again.` }];
      renderRows("ROP Emit", rows);
      return toDxResult("ROP Emit", rows);
    }
    const result = ropEmitter.emit(
      currentRopCorpus,
      entry.plan,
      strategyId === undefined ? undefined : Number(strategyId),
    );
    const rows = emissionRows(result);
    renderRows(`ROP Emit ${entry.plan.id}.${result.strategyId}`, rows);
    setResult({
      command: "rop.emit",
      args: options,
      success: result.success,
      findings: [result],
      warnings: [],
      errors: result.success ? [] : result.diagnostics,
    });
    return toDxResult(`ROP Emit ${entry.plan.id}.${result.strategyId}`, rows);
  };

  const executeRopSynthesize = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.synthesize");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Synthesize", rows);
      return toDxResult("ROP Synthesize", rows);
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : { planId: args[0], ...(isPlainObject(args[1]) ? args[1] as Record<string, unknown> : {}) };
    const planId = Number(options.planId ?? options.plan_id ?? args[0]);
    const entry = ropPlans.get(planId);
    if (!entry) {
      const rows = [{ Error: `ROP plan ${Number.isFinite(planId) ? planId : "<invalid>"} does not exist. Run rop.plan(...) first.` }];
      renderRows("ROP Synthesize", rows);
      return toDxResult("ROP Synthesize", rows);
    }
    if (entry.generation !== corpusGeneration) {
      const rows = [{ Error: `ROP plan ${planId} is stale (corpus was reloaded). Run rop.plan(...) again.` }];
      renderRows("ROP Synthesize", rows);
      return toDxResult("ROP Synthesize", rows);
    }

    let state = cachedExploitState;
    if (!state) {
      const rows = [{ Error: NO_EXPLOIT_STATE_MESSAGE }];
      renderRows("ROP Synthesize", rows);
      return toDxResult("ROP Synthesize", rows);
    }

    const overrides = isPlainObject(args[1]) ? args[1] as Record<string, unknown> : {};
    if (Object.keys(overrides).length > 0) {
      state = mergeExploitStateOverrides(state, overrides);
    }

    const result = synthesize(currentRopCorpus, entry.plan, state);
    const title = `ROP Synthesize ${planId}`;

    out.section(title);
    out.info(`Path: ${result.entryPath}`);
    out.info(`Status: ${result.status}`);
    out.info(`Layout: ${result.layoutProduced ? "produced" : "none"}`);
    out.info(`Constraint compatible: ${result.constraintCompatible ? "yes" : "no"}`);

    if (result.layoutProduced) {
      out.info(`Strategy: ${result.strategy} / ${result.shape}`);
      out.info(`Total: ${result.totalBytes} bytes`);
      if (result.placeholders.length > 0) {
        out.info(`Resolve before use: ${result.placeholders.join(", ")}`);
      }
      if (result.pivot) {
        out.info(`Pivot: ${result.pivot.sequence} (source: ${result.pivot.source}${result.pivot.sourceRegister ? ` ${result.pivot.sourceRegister}` : ""})`);
      }
    }

    for (const v of result.violations) {
      out.warn(`VIOLATION: ${v.message}`);
    }
    for (const b of result.blockers) {
      out.error(`BLOCKER: ${b.message}`);
    }
    for (const w of result.warnings) {
      out.warn(w.message);
    }

    if (!result.constraintCompatible && result.layoutProduced && result.violations.length > 0) {
      out.info("Operator action: synthesize values arithmetically, use writable memory construction, or select an alternate strategy.");
    }

    const rows = synthesisRows(result);
    renderRows(title, rows);
    setResult({
      command: "rop.synthesize",
      args: options,
      success: result.status === "complete",
      findings: [result],
      warnings: [
        ...result.violations.map((v) => v.message),
        ...result.warnings.map((w) => w.message),
      ],
      errors: result.blockers.map((b) => b.message),
    });
    return toDxResult(title, rows);
  };

  const executeRopExport = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.export");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Export", rows);
      return toDxResult("ROP Export", rows);
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : { planId: args[0], path: args[1] };
    const planId = Number(options.planId ?? options.plan_id ?? args[0]);
    const filePath = options.path ?? options.file ?? (typeof args[1] === "string" ? args[1] : undefined);
    const entry = ropPlans.get(planId);
    if (!entry) {
      const rows = [{ Error: `ROP plan ${Number.isFinite(planId) ? planId : "<invalid>"} does not exist. Run rop.plan(...) first.` }];
      renderRows("ROP Export", rows);
      return toDxResult("ROP Export", rows);
    }
    if (entry.generation !== corpusGeneration) {
      const rows = [{ Error: `ROP plan ${planId} is stale (corpus was reloaded). Run rop.plan(...) again.` }];
      renderRows("ROP Export", rows);
      return toDxResult("ROP Export", rows);
    }

    const emitResult: EmissionResult = ropEmitter.emit(currentRopCorpus, entry.plan);
    if (!emitResult.success) {
      const rows = [{ Error: `Emit failed for plan ${planId}: ${emitResult.diagnostics.join("; ")}` }];
      renderRows("ROP Export", rows);
      return toDxResult("ROP Export", rows);
    }

    const exportEmit: ExportableEmission = {
      planId: emitResult.planId,
      strategy: emitResult.strategy,
      shape: emitResult.shape,
      gadgets: emitResult.gadgets.map((g) => ({
        capability: g.capability,
        address: g.address,
        module: g.module,
        sequence: g.sequence,
      })),
    };

    let exportSynth: ExportableSynthesis | undefined;
    if (cachedExploitState) {
      const synthResult: SynthesisResult = synthesize(currentRopCorpus, entry.plan, cachedExploitState);
      if (synthResult.layoutProduced) {
        exportSynth = {
          planId: synthResult.planId,
          strategy: synthResult.strategy,
          shape: synthResult.shape,
          entryPath: synthResult.entryPath,
          status: synthResult.status,
          slots: synthResult.slots,
          placeholders: synthResult.placeholders,
          violations: synthResult.violations.map((v) => v.message),
        };
      }
    }

    const pythonLines = formatExportPython(exportEmit, exportSynth);
    const title = `ROP Export ${planId}`;

    if (typeof filePath === "string" && filePath.length > 0) {
      const hostAny = host as unknown as {
        namespace?: { Debugger?: { Utility?: { Control?: { ExecuteCommand?: (cmd: string) => unknown } } } };
      };
      const exec = hostAny.namespace?.Debugger?.Utility?.Control?.ExecuteCommand;
      if (typeof exec === "function") {
        exec(`.logopen /u "${filePath}"`);
        for (const line of pythonLines) {
          host.diagnostics.debugLog(`${line}\n`);
        }
        exec(".logclose");
        out.section(title);
        out.info(`Written to ${filePath}`);
        out.info(`${pythonLines.length} lines, ${exportEmit.gadgets.length} gadgets`);
        if (exportSynth) {
          out.info(`Includes stack layout (${exportSynth.slots.length} slots, ${exportSynth.entryPath})`);
        }
      } else {
        out.section(title);
        out.warn("File write unavailable (not running in WinDbg). Printing to console instead.");
        for (const line of pythonLines) {
          out.print(line);
        }
      }
    } else {
      out.section(title);
      for (const line of pythonLines) {
        out.print(line);
      }
    }

    const rows = [
      {
        Plan: planId.toString(),
        Strategy: `${exportEmit.strategy} / ${exportEmit.shape}`,
        Gadgets: exportEmit.gadgets.length.toString(),
        Layout: exportSynth ? `${exportSynth.slots.length} slots` : "no exploit state",
        File: typeof filePath === "string" ? filePath : "(console)",
      },
    ];
    renderRows(title, rows);
    setResult({
      command: "rop.export",
      args: options,
      success: true,
      findings: [{ python: pythonLines, emit: exportEmit, synthesis: exportSynth }],
      warnings: [],
      errors: [],
    });
    return toDxResult(title, rows);
  };

  const formatExploitStateRows = (state: ExploitState): Array<Record<string, string>> => {
    const rows: Array<Record<string, string>> = [];
    rows.push({ Section: "Control", Field: "mechanism", Value: state.control.mechanism });
    rows.push({ Section: "Control", Field: "eipControlled", Value: String(state.control.instructionPointerControlled) });
    if (state.stack.espAtControl !== undefined) {
      rows.push({ Section: "Stack", Field: "espAtControl", Value: `0x${(state.stack.espAtControl >>> 0).toString(16).toUpperCase().padStart(8, "0")}` });
    }
    rows.push({ Section: "Stack", Field: "controlledBeforeEsp", Value: state.stack.controlledBeforeEsp.toString() });
    rows.push({ Section: "Stack", Field: "controlledAfterEsp", Value: state.stack.controlledAfterEsp.toString() });
    rows.push({ Section: "Stack", Field: "contiguousControlledBytes", Value: state.stack.contiguousControlledBytes.toString() });
    rows.push({ Section: "Stack", Field: "readable", Value: String(state.stack.readable) });
    rows.push({ Section: "Stack", Field: "writable", Value: String(state.stack.writable) });
    rows.push({ Section: "Stack", Field: "executable", Value: String(state.stack.executable) });
    if (state.stack.alignment !== undefined) {
      rows.push({ Section: "Stack", Field: "alignment", Value: state.stack.alignment.toString() });
    }
    const regNames = Object.keys(state.registers);
    if (regNames.length > 0) {
      for (const reg of regNames) {
        const rs = state.registers[reg]!;
        const val = rs.kind === "constant"
          ? `constant: 0x${(rs.value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`
          : rs.kind === "pointer-into-controlled"
            ? `pointer-into-controlled: offset ${rs.offset}`
            : rs.kind;
        rows.push({ Section: "Registers", Field: reg, Value: val });
      }
    }
    const bc = state.constraints.badchars;
    if (bc.length > 0) {
      rows.push({ Section: "Constraints", Field: "badchars", Value: bc.map((b) => `0x${(b & 0xff).toString(16).toUpperCase().padStart(2, "0")}`).join(" ") });
    }
    rows.push({ Section: "Constraints", Field: "apiResolution", Value: state.constraints.apiResolution });
    if (state.constraints.maximumPayloadLength !== undefined) {
      rows.push({ Section: "Constraints", Field: "maximumPayloadLength", Value: state.constraints.maximumPayloadLength.toString() });
    }
    return rows;
  };

  const executeExploitState = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("exploit.state");
    }

    const overrides = isPlainObject(args[0]) ? args[0] as Record<string, unknown> : undefined;

    if (overrides && Object.keys(overrides).length > 0) {
      if (!cachedExploitState) {
        cachedExploitState = {
          control: {
            mechanism: "saved-ret",
            instructionPointerControlled: true,
          },
          stack: {
            controlledBeforeEsp: 0,
            controlledAfterEsp: 0,
            contiguousControlledBytes: 0,
            readable: true,
            writable: true,
            executable: false,
          },
          registers: {},
          constraints: {
            badchars: [],
            apiResolution: "either",
          },
        };
      }
      cachedExploitState = mergeExploitStateOverrides(cachedExploitState, overrides);
      out.section("Exploit State Updated");
    } else if (!cachedExploitState) {
      const rows = [{ Error: "No exploit state cached. Run triage() first, or set fields with exploit.state({...})." }];
      renderRows("Exploit State", rows);
      return toDxResult("Exploit State", rows);
    } else {
      out.section("Exploit State (cached)");
    }

    const rows = formatExploitStateRows(cachedExploitState);
    renderRows("Exploit State", rows);
    setResult({
      command: "exploit.state",
      args: overrides ?? {},
      success: true,
      findings: [cachedExploitState],
      warnings: [],
      errors: [],
    });
    return toDxResult("Exploit State", rows);
  };

  const executeExploitClear = (): DxResult => {
    cachedExploitState = undefined;
    const rows = [{ Status: "Exploit state cleared." }];
    out.section("Exploit State");
    out.info("Cached exploit state cleared.");
    renderRows("Exploit State", rows);
    return toDxResult("Exploit State", rows);
  };

  const executeRopPivots = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.pivots");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Pivots", rows);
      return toDxResult("ROP Pivots", rows);
    }
    const options = isPlainObject(args[0]) ? args[0] : { register: args[0], minDelta: args[1] };
    const filterRegister = typeof options.register === "string"
      ? options.register.toLowerCase().trim()
      : undefined;
    const minDelta = typeof options.minDelta === "number" ? options.minDelta : undefined;

    const candidates = currentRopCorpus.gadgets
      .filter((g) =>
        g.capabilities.some((c) => c.kind === "STACK_PIVOT" || c.kind === "STACK_ADJUST")
        && firstKnownAddress(g) !== undefined)
      .sort((a, b) => {
        const aLen = a.instructions.length;
        const bLen = b.instructions.length;
        if (aLen !== bLen) return aLen - bLen;
        return b.score - a.score;
      });

    const rows: Array<Record<string, string>> = [];
    for (const gadget of candidates) {
      const addr = firstKnownAddress(gadget)!;
      const { source, sourceRegister, adjustment, clobbers } = classifyPivotSource(gadget);
      const seq = gadgetSequence(gadget);
      const module = gadget.locations.find((l) => l.virtualAddress !== undefined)?.module ?? "unknown";

      if (filterRegister && sourceRegister !== filterRegister) continue;
      if (minDelta !== undefined && source === "esp-adjust") {
        if (adjustment === undefined || Math.abs(adjustment) < minDelta) continue;
      }

      const addrHex = `0x${addr.toString(16).toUpperCase().padStart(8, "0")}`;
      rows.push({
        Address: addrHex,
        Type: source,
        Source: sourceRegister ?? (adjustment !== undefined ? `ESP ${adjustment >= 0 ? "+" : ""}${adjustment}` : "indirect"),
        Clobbers: clobbers.join(", "),
        Module: module,
        Sequence: seq,
        Score: gadget.score.toString(),
      });
    }

    const title = `ROP Pivots (${rows.length} found)`;
    out.section(title);
    if (rows.length === 0) {
      out.warn("No pivot gadgets found in the corpus.");
    } else {
      out.info(`${rows.length} pivot gadget(s) ranked by instruction count and score.`);
    }
    renderRows(title, rows);
    setResult({
      command: "rop.pivots",
      args: options,
      success: rows.length > 0,
      findings: rows,
      warnings: [],
      errors: [],
    });
    return toDxResult(title, rows);
  };

  const parseChainTargets = (spec: unknown): ChainTarget[] => {
    if (Array.isArray(spec)) {
      return spec
        .filter((entry) => isPlainObject(entry))
        .map((entry) => ({ register: String((entry as Record<string, unknown>).register ?? ""), value: Number((entry as Record<string, unknown>).value ?? 0) }))
        .filter((target) => target.register.length > 0);
    }
    if (isPlainObject(spec)) {
      return Object.entries(spec).map(([register, value]) => ({ register, value: Number(value) }));
    }
    return [];
  };

  const parseBadcharsOption = (value: unknown): number[] => {
    const parsed = parseHexByteList(value);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.filter((entry): entry is number => Number.isInteger(entry) && entry >= 0 && entry <= 0xff);
  };

  const renderFlatFrame = (
    command: string,
    title: string,
    options: Record<string, unknown>,
    plan: FlatFramePlan,
  ): DxResult => {
    const python = formatChainPython(plan);
    out.section(title);
    out.info(`Words: ${plan.steps.length} | Stack: ${plan.stackBytes} bytes`);
    if (plan.badchars.length > 0) {
      out.info(`Badchars: ${plan.badchars.map((byte) => `0x${byte.toString(16).toUpperCase().padStart(2, "0")}`).join(", ")}`);
    }
    for (const line of python) {
      out.print(line);
    }
    for (const warning of plan.warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.placeholder ?? `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows(title, rows);
    setResult({
      command,
      args: options,
      success: plan.badcharViolations.length === 0,
      findings: [{ ...plan, python }],
      warnings: plan.warnings,
      errors: plan.badcharViolations,
    });
    return toDxResult(title, rows);
  };

  const executeRopChain = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.chain");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Chain", rows);
      setResult({ command: "rop.chain", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP Chain", rows);
    }

    const options = isPlainObject(args[0]) ? args[0] : {};
    const positionalTargets: ChainTarget[] = [];
    if (!isPlainObject(args[0])) {
      for (let i = 0; i + 1 < args.length; i += 2) {
        if (typeof args[i] === "string") {
          positionalTargets.push({ register: args[i] as string, value: Number(args[i + 1]) });
        }
      }
    }
    const targets = positionalTargets.length > 0
      ? positionalTargets
      : parseChainTargets(options.set ?? options.targets ?? options);
    if (targets.length === 0) {
      const rows = [{ Error: 'rop.chain requires register/value pairs, e.g. rop.chain("eax", 0xDEADBEEF).' }];
      renderRows("ROP Chain", rows);
      setResult({ command: "rop.chain", args: options, success: false, findings: [], warnings: [], errors: ["No chain targets provided."] });
      return toDxResult("ROP Chain", rows);
    }

    const plan = planRegisterSetup(currentRopCorpus, targets);
    const python = formatChainPython(plan);

    out.section("ROP Chain (register setup)");
    out.info(`Satisfied: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
    for (const line of python) {
      out.print(line);
    }
    const warnings = plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`);
    for (const warning of warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.kind === "gadget" ? `0x${step.address!.toString(16).toUpperCase().padStart(8, "0")}` : `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows("ROP Chain", rows);
    setResult({
      command: "rop.chain",
      args: options,
      success: plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult("ROP Chain", rows);
  };

  const executeRopConstruct = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.construct");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("Value Construction", rows);
      setResult({ command: "rop.construct", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("Value Construction", rows);
    }
    const register = typeof args[0] === "string" ? args[0].toLowerCase() : undefined;
    const rawValue = args[1] !== undefined ? Number(args[1]) : NaN;
    const value = Number.isFinite(rawValue) ? rawValue >>> 0 : undefined;
    const badchars = Array.isArray(parseHexByteList(args[2])) ? parseHexByteList(args[2]) as number[] : [];
    const preserve = parseRegisterList(args[3]);
    if (!register || value === undefined) {
      const rows = [{ Error: 'rop.construct requires register and value, e.g. rop.construct("edx", 0x1000, [0x00])' }];
      renderRows("Value Construction", rows);
      setResult({ command: "rop.construct", args: { register, value }, success: false, findings: [], warnings: [], errors: ["Missing register or value."] });
      return toDxResult("Value Construction", rows);
    }
    const recipe = solveValue(currentRopCorpus, register, value, badchars, preserve);
    if (!recipe) {
      const preserveNote = preserve.length > 0 ? ` while preserving ${preserve.join(", ")}` : "";
      const rows = [{ Error: `No arithmetic construction found for ${register} = ${hex32(value)}${preserveNote}` }];
      renderRows("Value Construction", rows);
      setResult({ command: "rop.construct", args: { register, value, badchars, preserve }, success: false, findings: [], warnings: [], errors: [`No recipe found for ${register} = ${hex32(value)}${preserveNote}`] });
      return toDxResult("Value Construction", rows);
    }
    out.section(`Value Construction: ${register} = ${hex32(value)}`);
    out.info(`Recipe: ${recipe.recipe} | Stack: ${recipe.stackBytes} bytes${recipe.scratchRegister ? ` | Scratch: ${recipe.scratchRegister}` : ""} | Clobbers: ${recipe.clobbers.join(", ")}`);
    const collateral = recipe.clobbers.filter((r) => r !== register);
    if (collateral.length > 0) {
      out.warn(`This recipe also alters ${collateral.join(", ")}. During PUSHAD or stack-frame setup, run it BEFORE those registers hold live values, or pass them in the preserve list (4th arg). construct() builds ONE register at a time; for a whole frame use rop.setup("reg=value ..."), which packs registers into multi-pop gadgets and orders them clobber-safely.`);
    }
    const python = formatChainPython({ steps: recipe.steps });
    for (const line of python) {
      out.print(line);
    }
    const rows = recipe.steps.map((step) => ({
      Type: step.kind,
      Value: step.address !== undefined ? hex32(step.address) : step.value !== undefined ? hex32(step.value) : step.placeholder ?? "",
      Meaning: step.comment,
    }));
    renderRows("Value Construction", rows);
    setResult({
      command: "rop.construct",
      args: { register, value, badchars },
      success: true,
      findings: [{ recipe: recipe.recipe, steps: recipe.steps, scratchRegister: recipe.scratchRegister, stackBytes: recipe.stackBytes, clobbers: recipe.clobbers }],
      warnings: [],
      errors: [],
    });
    return toDxResult("Value Construction", rows);
  };

  const executeRopSetup = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.setup");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("Register Setup", rows);
      setResult({ command: "rop.setup", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("Register Setup", rows);
    }
    const targets = parseRegisterTargets(args[0]);
    const badchars = Array.isArray(parseHexByteList(args[1])) ? parseHexByteList(args[1]) as number[] : [];
    if (Object.keys(targets).length === 0) {
      const rows = [{ Error: 'rop.setup requires register=value pairs, e.g. rop.setup("edi=0x10001000 ebx=0x40", "00 0A 0D")' }];
      renderRows("Register Setup", rows);
      setResult({ command: "rop.setup", args: {}, success: false, findings: [], warnings: [], errors: ["No target registers."] });
      return toDxResult("Register Setup", rows);
    }
    const plan = planRegisterSetupPacking(currentRopCorpus, targets, badchars);
    out.section(`Register Setup: ${Object.keys(targets).join(", ")}`);
    out.info(`Packed into ${plan.ordered.length} register(s) via multi-pop gadgets | Stack: ${plan.stackBytes} bytes | Order: ${plan.ordered.join(" -> ") || "n/a"}`);
    if (plan.steps.length > 0) {
      const python = formatChainPython({ steps: plan.steps });
      for (const line of python) out.print(line);
    }
    if (!plan.success) {
      out.warn("Some registers could not be set without clobbering a finalized one:");
      for (const item of plan.unresolved) out.warn(`  ${item.register}: ${item.reason}`);
    }
    const rows: Array<Record<string, string>> = plan.steps.map((step) => ({
      Type: step.kind,
      Value: step.address !== undefined ? hex32(step.address) : step.value !== undefined ? hex32(step.value) : step.placeholder ?? "",
      Meaning: step.comment,
    }));
    if (rows.length === 0) rows.push({ Type: "none", Value: "", Meaning: "no gadgets selected" });
    renderRows("Register Setup", rows);
    setResult({
      command: "rop.setup",
      args: { targets, badchars },
      success: plan.success,
      findings: [{ ordered: plan.ordered, unresolved: plan.unresolved, steps: plan.steps, stackBytes: plan.stackBytes }],
      warnings: plan.unresolved.map((item) => `${item.register}: ${item.reason}`),
      errors: [],
    });
    return toDxResult("Register Setup", rows);
  };

  const executeRopChainVp = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.chain_vp");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP VirtualProtect Chain", rows);
      setResult({ command: "rop.chain_vp", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP VirtualProtect Chain", rows);
    }

    const options = isPlainObject(args[0])
      ? args[0]
      : {
          virtualProtect: args[0],
          retGadget: args[1],
          returnAddress: args[2],
          lpAddress: args[3],
          dwSize: args[4],
          writable: args[5],
          flNewProtect: args[6],
          mode: args[7],
        };
    const params: VirtualProtectParams = {
      virtualProtect: options.virtualProtect !== undefined ? Number(options.virtualProtect) : undefined,
      retGadget: options.retGadget !== undefined ? Number(options.retGadget) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpAddress: options.lpAddress !== undefined ? Number(options.lpAddress) : undefined,
      dwSize: options.dwSize !== undefined ? Number(options.dwSize) : undefined,
      writable: options.writable !== undefined ? Number(options.writable) : undefined,
      flNewProtect: options.flNewProtect !== undefined ? Number(options.flNewProtect) : undefined,
      mode: options.mode === "direct" ? "direct" : "ret-slide",
    };

    const plan = planVirtualProtect(currentRopCorpus, params);
    const python = formatChainPython(plan);
    const sectionLabel = plan.hasPushad
      ? "ROP Chain — VirtualProtect (PUSHAD)"
      : "ROP Register Setup — VirtualProtect (PUSHAD missing)";

    out.section(sectionLabel);
    if (!plan.hasPushad) {
      out.warn("pushad ; ret gadget not found — output is a partial register-setup sketch, not an executable chain. Use frame_vp for a flat stdcall frame instead.");
    }
    out.info(`Mode: ${plan.mode} | Resolved gadgets: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
    if (plan.placeholders.length > 0) {
      out.info(`Define before use: ${plan.placeholders.join(", ")} (e.g. VIRTUALPROTECT via sc.iat_find("VirtualProtect"))`);
    }
    for (const line of python) {
      out.print(line);
    }
    const warnings = [...plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`), ...plan.constraints];
    for (const warning of warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.kind === "gadget"
        ? `0x${step.address!.toString(16).toUpperCase().padStart(8, "0")}`
        : step.placeholder ?? `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows(sectionLabel, rows);
    setResult({
      command: "rop.chain_vp",
      args: options,
      success: plan.hasPushad && plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult(sectionLabel, rows);
  };

  const executeRopChainWpm = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.chain_wpm");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP WriteProcessMemory Chain", rows);
      setResult({ command: "rop.chain_wpm", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP WriteProcessMemory Chain", rows);
    }

    const options = isPlainObject(args[0])
      ? args[0]
      : {
          writeProcessMemory: args[0],
          returnAddress: args[1],
          lpBuffer: args[2],
          nSize: args[3],
          writable: args[4],
        };
    const params: WriteProcessMemoryParams = {
      writeProcessMemory: options.writeProcessMemory !== undefined ? Number(options.writeProcessMemory) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpBuffer: options.lpBuffer !== undefined ? Number(options.lpBuffer) : undefined,
      nSize: options.nSize !== undefined ? Number(options.nSize) : undefined,
      writable: options.writable !== undefined ? Number(options.writable) : undefined,
    };

    const plan = planWriteProcessMemory(currentRopCorpus, params);
    const python = formatChainPython(plan);
    const sectionLabel = plan.hasPushad
      ? "ROP Chain — WriteProcessMemory (PUSHAD)"
      : "ROP Register Setup — WriteProcessMemory (PUSHAD missing)";

    out.section(sectionLabel);
    if (!plan.hasPushad) {
      out.warn("pushad ; ret gadget not found — output is a partial register-setup sketch, not an executable chain. Use frame_wpm for a flat stdcall frame instead.");
    }
    out.info(`Mode: ${plan.mode} | Resolved gadgets: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
    if (plan.placeholders.length > 0) {
      out.info(`Define before use: ${plan.placeholders.join(", ")}`);
    }
    for (const line of python) {
      out.print(line);
    }
    const warnings = [...plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`), ...plan.constraints];
    for (const warning of warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.kind === "gadget"
        ? `0x${step.address!.toString(16).toUpperCase().padStart(8, "0")}`
        : step.placeholder ?? `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows(sectionLabel, rows);
    setResult({
      command: "rop.chain_wpm",
      args: options,
      success: plan.hasPushad && plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult(sectionLabel, rows);
  };

  const executeRopChainVa = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.chain_va");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP VirtualAlloc Chain", rows);
      setResult({ command: "rop.chain_va", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP VirtualAlloc Chain", rows);
    }

    const options = isPlainObject(args[0])
      ? args[0]
      : {
          virtualAlloc: args[0],
          returnAddress: args[1],
          lpAddress: args[2],
          flAllocationType: args[3],
          flProtect: args[4],
        };
    const params: VirtualAllocParams = {
      virtualAlloc: options.virtualAlloc !== undefined ? Number(options.virtualAlloc) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpAddress: options.lpAddress !== undefined ? Number(options.lpAddress) : undefined,
      flAllocationType: options.flAllocationType !== undefined ? Number(options.flAllocationType) : undefined,
      flProtect: options.flProtect !== undefined ? Number(options.flProtect) : undefined,
    };

    const plan = planVirtualAlloc(currentRopCorpus, params);
    const python = formatChainPython(plan);
    const sectionLabel = plan.hasPushad
      ? "ROP Chain — VirtualAlloc (PUSHAD)"
      : "ROP Register Setup — VirtualAlloc (PUSHAD missing)";

    out.section(sectionLabel);
    if (!plan.hasPushad) {
      out.warn("pushad ; ret gadget not found — output is a partial register-setup sketch, not an executable chain. Use frame_va for a flat stdcall frame instead.");
    }
    out.info(`Mode: ${plan.mode} | Resolved gadgets: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
    if (plan.placeholders.length > 0) {
      out.info(`Define before use: ${plan.placeholders.join(", ")}`);
    }
    for (const line of python) {
      out.print(line);
    }
    const warnings = [...plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`), ...plan.constraints];
    for (const warning of warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.kind === "gadget"
        ? `0x${step.address!.toString(16).toUpperCase().padStart(8, "0")}`
        : step.placeholder ?? `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows(sectionLabel, rows);
    setResult({
      command: "rop.chain_va",
      args: options,
      success: plan.hasPushad && plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult(sectionLabel, rows);
  };

  const executeRopFrameVp = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.frame_vp");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : {
          virtualProtect: args[0],
          returnAddress: args[1],
          lpAddress: args[2],
          dwSize: args[3],
          flNewProtect: args[4],
          writable: args[5],
          badchars: parseHexByteList(args[6]),
        };
    const params: VirtualProtectFrameParams = {
      virtualProtect: options.virtualProtect !== undefined ? Number(options.virtualProtect) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpAddress: options.lpAddress !== undefined ? Number(options.lpAddress) : undefined,
      dwSize: options.dwSize !== undefined ? Number(options.dwSize) : undefined,
      flNewProtect: options.flNewProtect !== undefined ? Number(options.flNewProtect) : undefined,
      writable: options.writable !== undefined ? Number(options.writable) : undefined,
      badchars: parseBadcharsOption(options.badchars),
    };
    return renderFlatFrame("rop.frame_vp", "ROP Frame — VirtualProtect (stdcall)", options, planVirtualProtectFrame(params));
  };

  const executeRopFrameWpm = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.frame_wpm");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : {
          writeProcessMemory: args[0],
          returnAddress: args[1],
          hProcess: args[2],
          lpBaseAddress: args[3],
          lpBuffer: args[4],
          nSize: args[5],
          writable: args[6],
          badchars: parseHexByteList(args[7]),
        };
    const params: WriteProcessMemoryFrameParams = {
      writeProcessMemory: options.writeProcessMemory !== undefined ? Number(options.writeProcessMemory) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      hProcess: options.hProcess !== undefined ? Number(options.hProcess) : undefined,
      lpBaseAddress: options.lpBaseAddress !== undefined ? Number(options.lpBaseAddress) : undefined,
      lpBuffer: options.lpBuffer !== undefined ? Number(options.lpBuffer) : undefined,
      nSize: options.nSize !== undefined ? Number(options.nSize) : undefined,
      writable: options.writable !== undefined ? Number(options.writable) : undefined,
      badchars: parseBadcharsOption(options.badchars),
    };
    return renderFlatFrame("rop.frame_wpm", "ROP Frame — WriteProcessMemory (stdcall)", options, planWriteProcessMemoryFrame(params));
  };

  const executeRopFrameVa = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.frame_va");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : {
          virtualAlloc: args[0],
          returnAddress: args[1],
          lpAddress: args[2],
          dwSize: args[3],
          flAllocationType: args[4],
          flProtect: args[5],
          badchars: parseHexByteList(args[6]),
        };
    const params: VirtualAllocFrameParams = {
      virtualAlloc: options.virtualAlloc !== undefined ? Number(options.virtualAlloc) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpAddress: options.lpAddress !== undefined ? Number(options.lpAddress) : undefined,
      dwSize: options.dwSize !== undefined ? Number(options.dwSize) : undefined,
      flAllocationType: options.flAllocationType !== undefined ? Number(options.flAllocationType) : undefined,
      flProtect: options.flProtect !== undefined ? Number(options.flProtect) : undefined,
      badchars: parseBadcharsOption(options.badchars),
    };
    return renderFlatFrame("rop.frame_va", "ROP Frame — VirtualAlloc (stdcall)", options, planVirtualAllocFrame(params));
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
    scan_live: executeRopScanLive,
    query: executeRopQuery,
    capabilities: executeRopCapabilities,
    plan: executeRopPlan,
    emit: executeRopEmit,
    synthesize: executeRopSynthesize,
    export: executeRopExport,
    pivots: executeRopPivots,
    chain: executeRopChain,
    construct: executeRopConstruct,
    setup: executeRopSetup,
    chain_vp: executeRopChainVp,
    chain_wpm: executeRopChainWpm,
    chain_va: executeRopChainVa,
    frame_vp: executeRopFrameVp,
    frame_wpm: executeRopFrameWpm,
    frame_va: executeRopFrameVa,
  };
  api.rop_find = (...args: unknown[]) => invoke("rop", args);

  api.exploit = {
    state: executeExploitState,
    clear: executeExploitClear,
  };

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
  api.str = {
    read: (...args: unknown[]) => {
      invoke("str_read", args.length === 0 ? args : [commandAddress(args[0]), ...args.slice(1)]);
      return lastResult?.findings[0];
    },
    find: (...args: unknown[]) => {
      invoke("str_find", args);
      return lastResult?.findings;
    },
    refs: (...args: unknown[]) => {
      const target = typeof args[0] === "string" && /^(0x)?[0-9a-f`]+$/i.test(args[0].trim())
        ? commandAddress(args[0])
        : args[0];
      invoke("str_refs", args.length === 0 ? args : [target, ...args.slice(1)]);
      return lastResult?.findings;
    },
    bytes: (...args: unknown[]) => {
      invoke("str_bytes", args);
      return lastResult?.findings[0];
    },
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
    const evidence = (api.memory as (value: unknown) => { executable?: boolean | null } | undefined)(address);
    return evidence?.executable ?? null;
  };
  api.landing = (address?: unknown) => {
    invoke("landing", address === undefined ? [] : [commandAddress(address)]);
    const evidence = lastResult?.findings[0] as SerializedLandingEvidence | undefined;
    return evidence ? toDxResult("Landing Evidence", landingDxRows(evidence)) : undefined;
  };
  api.math = (...args: unknown[]) => {
    invoke("math", args);
    return lastResult?.findings[0];
  };

  return api;
}

function parseScanLivePositionalArgs(args: unknown[]): Record<string, unknown> {
  const result: Record<string, unknown> = { module: args[0] };
  result.badchars = parseHexByteList(args[1]);
  let idx = 2;
  if (idx < args.length && typeof args[idx] === "boolean") {
    result.append = args[idx];
    idx++;
  } else if (idx < args.length && typeof args[idx] === "number") {
    result.maxPerPattern = args[idx];
    idx++;
    if (idx < args.length) {
      result.append = args[idx];
    }
  } else if (idx < args.length) {
    result.append = args[idx];
  }
  return result;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseRegisterList(value: unknown): string[] {
  const raw = Array.isArray(value)
    ? value.map((v) => String(v))
    : typeof value === "string"
      ? value.split(/[,\s]+/)
      : [];
  return raw.map((r) => r.trim().toLowerCase()).filter((r) => r.length > 0);
}

function parseRegisterTargets(value: unknown): Record<string, number> {
  const targets: Record<string, number> = {};
  // Object form (programmatic / SDK use): {edi: 0x10001000, ebx: 0x40}
  if (isPlainObject(value)) {
    for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
      const n = Number(raw);
      if (Number.isFinite(n)) targets[key.trim().toLowerCase()] = n >>> 0;
    }
    return targets;
  }
  // String form (WinDbg dx-friendly): "edi=0x10001000 ebx=0x40" (= or :, any of space/comma/semicolon)
  if (typeof value === "string") {
    for (const pair of value.split(/[\s,;]+/).filter((p) => p.length > 0)) {
      const match = /^([a-zA-Z]+)\s*[=:]\s*(.+)$/.exec(pair);
      if (!match) continue;
      const reg = match[1].trim().toLowerCase();
      const raw = match[2].trim();
      const n = /^0x[0-9a-fA-F]+$/.test(raw) ? parseInt(raw, 16) : Number(raw);
      if (Number.isFinite(n)) targets[reg] = n >>> 0;
    }
  }
  return targets;
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
    if (/^[0-9a-fA-F]{2}$/.test(token)) {
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
    case "badchar_array":
      return { exclude: parseHexByteList(args[0]) };
    case "badchar_find":
      return {
        address: args[0],
        exclude: parseHexByteList(args[1]),
        windowBytes: args[2],
        minRun: args[3],
      };
    case "egghunter":
      return { tag: args[0], mode: args[1], wow64: args[2], badchars: parseHexByteList(args[3]) };
    case "exploit":
      return { mode: args[0], tag: args[1], offset: args[2], address: args[3] };
    case "modules":
      return { filter: args[0] };
    case "code_caves":
      return { module: args[0], minSize: args[1], maxResults: args[2] };
    case "math":
      return { value: args[0], bits: args[1] };
    case "str_read":
      return { address: args[0], max: args[1], encoding: args[2] };
    case "str_find":
      return { text: args[0], module: args[1], encoding: args[2], maxResults: args[3] };
    case "str_refs":
      return { target: args[0], module: args[1], encoding: args[2], maxResults: args[3] };
    case "str_bytes":
      return { text: args[0], encoding: args[1], terminator: args[2], exclude: parseHexByteList(args[3]) };
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
    case "find_stack_bytes":
      return {
        bytes: parseHexByteList(args[0]),
        maxResults: args[1],
        stackBytes: args[2],
      };
    case "find_mem_bytes":
      return {
        address: args[0],
        length: args[1],
        bytes: parseHexByteList(args[2]),
        maxResults: args[3],
      };
    case "find_ptr":
      return {
        instruction: args[0],
        module: args[1],
        badchars: parseHexByteList(args[2]),
        maxResults: args[3],
        executableOnly: args[4],
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
    case "stackmap":
      return {
        depth: args[0],
        patternLength: args[1],
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
  cachedExploitState = undefined;
  invalidateCorpusPlans();
  resetCorpusModules();
  registry.setReloader(() => {
    currentRopCorpus = undefined;
    cachedExploitState = undefined;
    invalidateCorpusPlans();
    resetCorpusModules();
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

  if (typeof host !== "undefined" && host.diagnostics && typeof host.diagnostics.debugLog === "function") {
    const version = getVersionInfo();
    const dirty = version.gitDirty ? "dirty" : "clean";
    host.diagnostics.debugLog(
      `[+] osed loaded: v${version.version} (${version.gitCommit}, ${dirty}, built ${version.buildTime})\n`,
    );
  }

  return registrations;
}
