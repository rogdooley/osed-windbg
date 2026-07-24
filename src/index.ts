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
import { createFmtCommands } from "./commands/fmtstr";
import { createShellcodeNamespace } from "./shellcode";
import { buildCapabilityIndexFromRpPlusText, buildCapabilityIndexFromSequences, formatChainPython, planRegisterSetup, planVirtualAlloc, planVirtualAllocFrame, planVirtualProtect, planVirtualProtectFrame, planWriteProcessMemory, planWriteProcessMemoryFrame, summarizeCapabilities, type CapabilityIndex, type ChainTarget, type FlatFramePlan, type RopQuery, type VirtualAllocFrameParams, type VirtualAllocParams, type VirtualProtectFrameParams, type VirtualProtectParams, type WriteProcessMemoryFrameParams, type WriteProcessMemoryParams } from "./rop";
import { discoverLiveGadgets, type LiveDiscoveryOptions } from "./analysis/live_gadgets";
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
import type { SerializedLandingEvidence } from "./analysis/landing";

declare const self: Record<string, unknown> | undefined;

type OsedApi = {
  [name: string]: unknown;
};

const registry = new CommandRegistry();
let osed: OsedApi = {};
let lastResult: CommandResult | undefined;
let currentRopCorpus: CapabilityIndex | undefined;
const NO_ROP_CORPUS_MESSAGE = "No ROP corpus loaded. Run rop.scan(...) for RP++ text or rop.scan_live(...) for live target memory first.";

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
    createLandingCommand(),
    createMathCommand(),
    createVersionCommand(),
    ...createStringCommands(),
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

  const scanLiveCorpus = (options: LiveDiscoveryOptions): DxResult => {
    const discovery = discoverLiveGadgets(options);
    currentRopCorpus = buildCapabilityIndexFromSequences(sequencesFromLiveHits(discovery.hits));
    const rows = summarizeCapabilities(currentRopCorpus);
    out.section("Live ROP Corpus Loaded");
    out.info(`Gadgets: ${currentRopCorpus.gadgets.length} (from ${discovery.stats.discovered} live hits)`);
    out.info(`Capabilities: ${rows.length}`);
    if (discovery.stats.rejected > 0) {
      out.info(`Rejected by bad chars: ${discovery.stats.rejected}`);
    }
    setResult({
      command: "rop.scan_live",
      args: options as Record<string, unknown>,
      success: true,
      findings: [{ gadgets: currentRopCorpus.gadgets.length, capabilities: rows.length, ...discovery.stats }],
      warnings: discovery.warnings,
      errors: [],
    });
    return toDxResult("Live ROP Corpus Loaded", [
      { Corpus: "live", Gadgets: currentRopCorpus.gadgets.length.toString(), Capabilities: rows.length.toString() },
    ]);
  };

  const executeRopScanLive = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.scan_live");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : { module: args[0], badchars: parseHexByteList(args[1]), maxPerPattern: args[2] };
    return scanLiveCorpus({
      module: options.module as string | undefined,
      badchars: options.badchars as number[] | undefined,
      maxPerPattern: options.maxPerPattern as number | undefined,
    });
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

    out.section("ROP Chain — VirtualProtect (PUSHAD)");
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
    renderRows("ROP VirtualProtect Chain", rows);
    setResult({
      command: "rop.chain_vp",
      args: options,
      success: plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult("ROP VirtualProtect Chain", rows);
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

    out.section("ROP Chain — WriteProcessMemory (PUSHAD)");
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
    renderRows("ROP WriteProcessMemory Chain", rows);
    setResult({
      command: "rop.chain_wpm",
      args: options,
      success: plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult("ROP WriteProcessMemory Chain", rows);
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

    out.section("ROP Chain — VirtualAlloc (PUSHAD)");
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
    renderRows("ROP VirtualAlloc Chain", rows);
    setResult({
      command: "rop.chain_va",
      args: options,
      success: plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult("ROP VirtualAlloc Chain", rows);
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
    chain: executeRopChain,
    chain_vp: executeRopChainVp,
    chain_wpm: executeRopChainWpm,
    chain_va: executeRopChainVa,
    frame_vp: executeRopFrameVp,
    frame_wpm: executeRopFrameWpm,
    frame_va: executeRopFrameVa,
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
