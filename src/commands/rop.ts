import { Command, CommandResult, ValidationFlags } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory, tryReadMemory } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { knownPatternsForPointerSize, type GadgetPattern, validateInstructionCandidateForPointerSize } from "../logic/instruction_validation";
import { buildRopIndexFromSequences } from "../rop";
import { parseInstruction } from "../semantics";
import { SEMANTIC_SCHEMA_VERSION, type InstructionSequence, type InstructionSequenceSource, type Provenance } from "../semantics/types";
import { findModuleByAddress, listModulesWithMitigations } from "./modules";

type ScanOptions = {
  module?: string;
  executableOnly: boolean;
  maxResults: number;
  mode: "fast" | "thorough";
};

type RopEngine = "legacy" | "semantic";

type RopSuggestOptions = ScanOptions & {
  engine: RopEngine;
};

type ValidatedPatternHit = {
  address: bigint;
  pattern: GadgetPattern;
  mnemonic: string;
  bytes: number[];
};

function readCandidate(address: bigint, size: number): Uint8Array | undefined {
  try {
    return readMemory(address, size);
  } catch (_error) {
    return undefined;
  }
}

function normalizeScan(options: Record<string, unknown>): ScanOptions {
  return {
    module: options.module as string | undefined,
    executableOnly: (options.executableOnly as boolean | undefined) ?? true,
    maxResults: Math.min((options.maxResults as number | undefined) ?? 50, 200),
    mode: (options.mode as "fast" | "thorough" | undefined) ?? "fast",
  };
}

function normalizeRopSuggest(options: Record<string, unknown>): RopSuggestOptions {
  return {
    ...normalizeScan(options),
    engine: (options.engine as RopEngine | undefined) ?? "legacy",
  };
}

function validationPass(flags: ValidationFlags): boolean {
  return flags.decoded && Boolean(flags.mnemonicMatch) && flags.executable;
}

function collectValidatedPatternHits(pattern: GadgetPattern, options: ScanOptions): { hits: ValidatedPatternHit[]; warnings: string[]; stats: Record<string, number> } {
  const pointerSize = getPointerSize();
  const scan = scanPattern(
    {
      module: options.module,
      executableOnly: options.executableOnly,
      maxResults: options.maxResults,
      chunkSize: options.mode === "thorough" ? 0x1000 : 0x4000,
    },
    Uint8Array.from(pattern.bytes),
  );

  const hits: ValidatedPatternHit[] = [];

  for (const hit of scan.hits) {
    const candidate = readCandidate(hit, pattern.bytes.length);
    if (!candidate) {
      continue;
    }

    const validated = validateInstructionCandidateForPointerSize(candidate, true, true, pointerSize);
    if (!validationPass(validated.flags)) {
      continue;
    }

    hits.push({
      address: hit,
      pattern,
      mnemonic: validated.mnemonic ?? pattern.mnemonic,
      bytes: pattern.bytes,
    });
  }

  return {
    hits,
    warnings: scan.warnings.map((warning) => `${warning.region}: ${warning.message}`),
    stats: scan.stats,
  };
}

function scanForPattern(name: string, pattern: GadgetPattern, options: ScanOptions): CommandResult {
  const pointerSize = getPointerSize();
  const { hits, warnings, stats } = collectValidatedPatternHits(pattern, options);
  const findings: unknown[] = hits.map((hit) => ({
    address: hit.address,
    bytes: hit.bytes,
    mnemonic: hit.mnemonic,
    pattern: hit.pattern.name,
  }));
  const rows = hits
    .map((hit) => ({
      address: out.formatAddress(hit.address, pointerSize),
      mnemonic: hit.mnemonic,
      bytes: hit.bytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" "),
      py: `0x${hit.address.toString(16).toUpperCase()}`,
    }))
    .sort((a, b) => (a.address < b.address ? -1 : 1));

  out.section(name);
  out.table(
    [
      { key: "address", header: "Address", width: 18 },
      { key: "mnemonic", header: "Mnemonic", width: 18 },
      { key: "bytes", header: "Bytes", width: 16 },
      { key: "py", header: "Python", width: 14 },
    ],
    rows,
  );

  return {
    command: name,
    args: options as unknown as Record<string, unknown>,
    success: true,
    findings,
    warnings,
    errors: [],
    stats,
  };
}

function buildSequenceFromHit(hit: ValidatedPatternHit): InstructionSequence {
  const instructions = hit.pattern.mnemonic
    .split(" ; ")
    .map((part) => parseInstruction(part));
  const moduleInfo = findModuleByAddress(hit.address);
  const provenance: Provenance = {
    module: moduleInfo?.name,
    section: moduleInfo ? ".text" : undefined,
    virtualAddress: Number(hit.address & BigInt(0xffffffff)),
    fileOffset: undefined,
    executable: "EXACT",
    writable: "UNKNOWN",
    aslr: "UNKNOWN",
    rebaseable: "UNKNOWN",
  };
  const source: InstructionSequenceSource = {
    kind: "rop-suggest",
    name: "semantic-backend",
    format: "synthetic",
    version: "v1",
  };

  return {
    schemaVersion: SEMANTIC_SCHEMA_VERSION,
    id: `rop-suggest:${hit.pattern.name}:${hit.address.toString(16)}:${instructions.map((instruction) => instruction.normalizedText).join(" | ")}`,
    source,
    originalText: hit.pattern.mnemonic,
    instructions,
    provenance,
  };
}

function runSemanticRopSuggest(options: RopSuggestOptions): CommandResult {
  const pointerSize = getPointerSize();
  const combinedWarnings: string[] = [];
  const allHits: ValidatedPatternHit[] = [];
  let combinedStats: Record<string, number> = { sectionsScanned: 0, chunksRead: 0, chunksSkipped: 0, results: 0, stoppedEarly: 0 };

  for (const pattern of knownPatternsForPointerSize(pointerSize)) {
    const result = collectValidatedPatternHits(pattern, options);
    allHits.push(...result.hits);
    combinedWarnings.push(...result.warnings);
    combinedStats = {
      sectionsScanned: combinedStats.sectionsScanned + (result.stats?.sectionsScanned ?? 0),
      chunksRead: combinedStats.chunksRead + (result.stats?.chunksRead ?? 0),
      chunksSkipped: combinedStats.chunksSkipped + (result.stats?.chunksSkipped ?? 0),
      results: combinedStats.results + (result.stats?.results ?? 0),
      stoppedEarly: combinedStats.stoppedEarly + (result.stats?.stoppedEarly ?? 0),
    };
  }

  const index = buildRopIndexFromSequences(allHits.map((hit) => buildSequenceFromHit(hit)));
  const gadgets = [...index.gadgets].sort((left, right) => {
    if (left.score !== right.score) {
      return right.score - left.score;
    }

    const leftAddress = left.locations[0]?.virtualAddress ?? 0;
    const rightAddress = right.locations[0]?.virtualAddress ?? 0;
    return leftAddress - rightAddress;
  });

  const rows = gadgets.map((gadget, index) => {
    const firstLocation = gadget.locations[0];
    const address = BigInt(firstLocation?.virtualAddress ?? 0);
    return {
      rank: `${index + 1}`,
      address: out.formatAddress(address, pointerSize),
      mnemonic: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; "),
      category: gadget.categories[0] ?? "UNKNOWN",
      score: `${gadget.score}`,
      python: `0x${address.toString(16).toUpperCase()}`,
      locations: `${gadget.locations.length}`,
    };
  });

  out.section("ROP Suggestions (semantic)");
  if (rows.length === 0) {
    out.print("No semantic gadget suggestions found.");
  } else {
    out.table(
      [
        { key: "rank", header: "Rank", width: 6 },
        { key: "address", header: "Address", width: 18 },
        { key: "mnemonic", header: "Mnemonic", width: 28 },
        { key: "category", header: "Category", width: 18 },
        { key: "score", header: "Score", width: 6 },
        { key: "locations", header: "Locs", width: 6 },
        { key: "python", header: "Python", width: 14 },
      ],
      rows,
    );
  }

  out.info("Semantic backend selected; duplicate gadgets are merged by canonical IR.");
  out.whyItMatters("Semantic gadget suggestions improve ranking, deduplication, and explainability.");

  return {
    command: "rop_suggest",
    args: options,
    success: true,
    findings: gadgets,
    warnings: combinedWarnings,
    errors: [],
    stats: { ...combinedStats, canonicalResults: gadgets.length },
  };
}

function runLegacyRopSuggest(options: RopSuggestOptions, initialWarnings: string[] = []): CommandResult {
  const combinedFindings: unknown[] = [];
  const combinedWarnings: string[] = [...initialWarnings];
  let combinedStats: Record<string, number> = { sectionsScanned: 0, chunksRead: 0, chunksSkipped: 0, results: 0, stoppedEarly: 0 };

  const pointerSize = getPointerSize();
  for (const pattern of knownPatternsForPointerSize(pointerSize)) {
    const result = scanForPattern(`ROP Suggest: ${pattern.name}`, pattern, options);
    combinedFindings.push(
      ...result.findings.map((finding) => ({ ...(finding as Record<string, unknown>), pattern: pattern.name })),
    );
    combinedWarnings.push(...result.warnings);
    combinedStats = {
      sectionsScanned: combinedStats.sectionsScanned + (result.stats?.sectionsScanned ?? 0),
      chunksRead: combinedStats.chunksRead + (result.stats?.chunksRead ?? 0),
      chunksSkipped: combinedStats.chunksSkipped + (result.stats?.chunksSkipped ?? 0),
      results: combinedStats.results + (result.stats?.results ?? 0),
      stoppedEarly: combinedStats.stoppedEarly + (result.stats?.stoppedEarly ?? 0),
    };
  }

  out.whyItMatters("Validated gadget suggestions reduce false positives during ROP chain construction.");

  return {
    command: "rop_suggest",
    args: options,
    success: true,
    findings: combinedFindings,
    warnings: combinedWarnings,
    errors: [],
    stats: combinedStats,
  };
}

export function createRopCommands(): Command[] {
  const rop: Command = {
    name: "rop",
    description: "ROP helper entrypoint and module triage.",
    usage: "dx @$osed().rop.find({ module: 'essfunc', maxResults: 50 })",
    examples: ["dx @$osed().rop.find({})", "dx @$osed().rop.find({ module: 'essfunc' })"],
    schema: {
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const modules = listModulesWithMitigations(options.module as string | undefined);
      out.section("ROP Module Scope");
      out.table(
        [
          { key: "name", header: "Module", width: 18 },
          { key: "base", header: "Base", width: 18 },
          { key: "size", header: "Size", width: 10 },
        ],
        modules.map((module) => ({
          name: module.name,
          base: out.formatAddress(module.base, 8),
          size: `0x${module.size.toString(16).toUpperCase()}`,
        })),
      );
      out.info("Use find_bytes or rop_suggest for bounded gadget discovery.");
      out.whyItMatters("ROP planning starts with selecting stable module memory ranges.");

      return {
        command: "rop",
        args: options,
        success: true,
        findings: modules,
        warnings: [],
        errors: [],
      };
    },
  };

  const findBytes: Command = {
    name: "find_bytes",
    description: "Find byte sequence hits in executable sections.",
    usage: "dx @$osed().find_bytes({ module: 'essfunc', bytes: [0xFF,0xE4] })",
    examples: [
      "dx @$osed().find_bytes({ module: 'essfunc', bytes: [0xFF, 0xE4] })",
      "dx @$osed().find_bytes({ module: 'essfunc', bytes: [0x58, 0xC3], maxResults: 25 })",
    ],
    schema: {
      module: { type: "string", required: true },
      bytes: { type: "array", elementType: "number", required: true },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const bytes = options.bytes as number[];
      if (bytes.length === 0 || bytes.some((value) => !Number.isInteger(value) || value < 0 || value > 0xff)) {
        throw new Error("bytes must contain 0x00..0xFF integers.");
      }

      const scanOpts = normalizeScan(options);
      const scan = scanPattern(
        {
          module: options.module as string,
          executableOnly: scanOpts.executableOnly,
          maxResults: scanOpts.maxResults,
          chunkSize: scanOpts.mode === "thorough" ? 0x1000 : 0x4000,
        },
        Uint8Array.from(bytes),
      );

      const pointerSize = getPointerSize();
      const rows = scan.hits.map((hit) => ({
        address: out.formatAddress(hit, pointerSize),
        python: `0x${hit.toString(16).toUpperCase()}`,
      }));

      out.section("Find Bytes");
      out.table(
        [
          { key: "address", header: "Address", width: 18 },
          { key: "python", header: "Python", width: 18 },
        ],
        rows,
      );
      out.whyItMatters("Targeted byte matches accelerate practical gadget and pivot discovery.");

      return {
        command: "find_bytes",
        args: options,
        success: true,
        findings: scan.hits,
        warnings: scan.warnings.map((warning) => `${warning.region}: ${warning.message}`),
        errors: [],
        stats: scan.stats,
      };
    },
  };

  const ropSuggest: Command = {
    name: "rop_suggest",
    description: "Suggest common exploit-friendly gadget patterns.",
    usage: "dx @$osed().rop_suggest({ module: 'essfunc', engine: 'semantic' })",
    examples: [
      "dx @$osed().rop_suggest({ module: 'essfunc' })",
      "dx @$osed().rop_suggest({ module: 'essfunc', engine: 'semantic' })",
      "dx @$osed().rop_suggest({ mode: 'thorough', engine: 'legacy' })",
    ],
    schema: {
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
      engine: { type: "string", enum: ["legacy", "semantic"], default: "legacy" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const scanOptions = normalizeRopSuggest(options);
      if (scanOptions.engine === "semantic") {
        if (getPointerSize() === 8) {
          return runLegacyRopSuggest(scanOptions, ["Semantic ROP backend is currently x86-only; used x64 byte-pattern scanner instead."]);
        }
        return runSemanticRopSuggest(scanOptions);
      }

      return runLegacyRopSuggest(scanOptions);
    },
  };

  const retnGadgets: Command = {
    name: "retn",
    description: "Scan for retn N gadgets that pop N bytes before returning.",
    usage: "dx @$osed().retn({ module: 'essfunc', maxResults: 50 })",
    examples: [
      "dx @$osed().retn({ module: 'essfunc' })",
      "dx @$osed().retn({ module: 'essfunc', maxResults: 100 })",
    ],
    schema: {
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const maxResults = Math.min((options.maxResults as number | undefined) ?? 50, 200);
      const executableOnly = (options.executableOnly as boolean | undefined) ?? true;
      const moduleFilter = options.module as string | undefined;
      const chunkSize = (options.mode as string) === "thorough" ? 0x1000 : 0x4000;

      // Scan for the retn opcode (C2) with a generous internal limit to capture diverse N values.
      const scan = scanPattern(
        { module: moduleFilter, executableOnly, maxResults: 200, chunkSize },
        Uint8Array.from([0xc2]),
      );

      const warnings: string[] = [...scan.warnings.map((w) => `${w.region}: ${w.message}`)];

      // Group hits by N value; keep the first address seen for each.
      type Group = { first: bigint; count: number };
      const groups = new Map<number, Group>();

      for (const hit of scan.hits) {
        const bytes = tryReadMemory(hit, 3);
        if (!bytes || bytes.length < 3 || bytes[0] !== 0xc2) continue;
        const n = bytes[1] | (bytes[2] << 8);
        if (n === 0) continue; // retn 0 is functionally ret — not useful for chain adjustment
        const existing = groups.get(n);
        if (existing) {
          existing.count += 1;
        } else {
          groups.set(n, { first: hit, count: 1 });
        }
      }

      const sorted = [...groups.entries()]
        .sort(([a], [b]) => a - b)
        .slice(0, maxResults);

      const findings = sorted.map(([n, { first, count }]) => ({ n, address: first, count }));
      const rows = findings.map(({ n, address, count }) => ({
        n: `0x${n.toString(16).toUpperCase().padStart(4, "0")}`,
        decimal: n.toString(),
        count: count.toString(),
        address: out.formatAddress(address, pointerSize),
        python: `0x${address.toString(16).toUpperCase()}`,
      }));

      out.section("RETN N Gadgets");
      if (rows.length === 0) {
        out.print("No retn N gadgets found.");
      } else {
        out.table(
          [
            { key: "n", header: "N (hex)", width: 8 },
            { key: "decimal", header: "N (dec)", width: 8 },
            { key: "count", header: "Count", width: 6 },
            { key: "address", header: "Address", width: 18 },
            { key: "python", header: "Python", width: 14 },
          ],
          rows,
        );
      }
      out.whyItMatters("retn N pops N bytes before returning — used to skip arguments in stdcall ROP chains.");

      return {
        command: "retn",
        args: options,
        success: true,
        findings,
        warnings,
        errors: [],
        stats: scan.stats,
      };
    },
  };

  const addEsp: Command = {
    name: "add_esp",
    description: "Scan for add esp, N ; ret gadgets used to skip stack slots in ROP chains.",
    usage: "dx @$osed().add_esp({ module: 'essfunc', maxResults: 50 })",
    examples: [
      "dx @$osed().add_esp({ module: 'essfunc' })",
      "dx @$osed().add_esp({ module: 'essfunc', maxResults: 100 })",
    ],
    schema: {
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const maxResults = Math.min((options.maxResults as number | undefined) ?? 50, 200);
      const executableOnly = (options.executableOnly as boolean | undefined) ?? true;
      const moduleFilter = options.module as string | undefined;
      const chunkSize = (options.mode as string) === "thorough" ? 0x1000 : 0x4000;

      const warnings: string[] = [];

      // Group hits by N; keep the first address found.
      type Group = { first: bigint; count: number; imm32: boolean };
      const groups = new Map<number, Group>();

      // Scan for ADD ESP, imm8 (83 C4 NN C3)
      const scan8 = scanPattern({ module: moduleFilter, executableOnly, maxResults: 200, chunkSize }, Uint8Array.from([0x83, 0xc4]));
      warnings.push(...scan8.warnings.map((w) => `${w.region}: ${w.message}`));
      for (const hit of scan8.hits) {
        const bytes = tryReadMemory(hit, 4);
        if (!bytes || bytes.length < 4 || bytes[0] !== 0x83 || bytes[1] !== 0xc4 || bytes[3] !== 0xc3) continue;
        const n = bytes[2]; // imm8 (treat as unsigned for display)
        if (n === 0) continue;
        const existing = groups.get(n);
        if (existing) { existing.count += 1; } else { groups.set(n, { first: hit, count: 1, imm32: false }); }
      }

      // Scan for ADD ESP, imm32 (81 C4 NN NN NN NN C3)
      const scan32 = scanPattern({ module: moduleFilter, executableOnly, maxResults: 200, chunkSize }, Uint8Array.from([0x81, 0xc4]));
      warnings.push(...scan32.warnings.map((w) => `${w.region}: ${w.message}`));
      for (const hit of scan32.hits) {
        const bytes = tryReadMemory(hit, 7);
        if (!bytes || bytes.length < 7 || bytes[0] !== 0x81 || bytes[1] !== 0xc4 || bytes[6] !== 0xc3) continue;
        const n = bytes[2] | (bytes[3] << 8) | (bytes[4] << 16) | (bytes[5] << 24);
        if (n <= 0) continue;
        // Only add if we don't already have it from the imm8 scan (n > 255 means imm32-only)
        if (!groups.has(n)) { groups.set(n, { first: hit, count: 1, imm32: true }); }
        else { groups.get(n)!.count += 1; }
      }

      const sorted = [...groups.entries()]
        .filter(([n]) => n > 0)
        .sort(([a], [b]) => a - b)
        .slice(0, maxResults);

      const findings = sorted.map(([n, { first, count, imm32 }]) => ({ n, address: first, count, imm32 }));
      const rows = findings.map(({ n, address, count, imm32 }) => ({
        n: `0x${n.toString(16).toUpperCase().padStart(imm32 ? 8 : 2, "0")}`,
        decimal: n.toString(),
        enc: imm32 ? "imm32" : "imm8",
        count: count.toString(),
        address: out.formatAddress(address, pointerSize),
        python: `0x${address.toString(16).toUpperCase()}`,
      }));

      out.section("ADD ESP, N ; RET Gadgets");
      if (rows.length === 0) {
        out.print("No add esp, N ; ret gadgets found.");
      } else {
        out.table(
          [
            { key: "n",       header: "N (hex)",  width: 10 },
            { key: "decimal", header: "N (dec)",  width: 8  },
            { key: "enc",     header: "Enc",      width: 6  },
            { key: "count",   header: "Count",    width: 6  },
            { key: "address", header: "Address",  width: 18 },
            { key: "python",  header: "Python",   width: 14 },
          ],
          rows,
        );
      }
      out.whyItMatters("add esp, N skips N bytes of ROP chain slots — essential for aligning stdcall argument frames.");

      const stats = {
        sectionsScanned: (scan8.stats?.sectionsScanned ?? 0) + (scan32.stats?.sectionsScanned ?? 0),
        chunksRead: (scan8.stats?.chunksRead ?? 0) + (scan32.stats?.chunksRead ?? 0),
        chunksSkipped: (scan8.stats?.chunksSkipped ?? 0) + (scan32.stats?.chunksSkipped ?? 0),
        results: findings.length,
        stoppedEarly: (scan8.stats?.stoppedEarly ?? 0) + (scan32.stats?.stoppedEarly ?? 0),
      };

      return { command: "add_esp", args: options, success: true, findings, warnings, errors: [], stats };
    },
  };

  return [rop, findBytes, ropSuggest, retnGadgets, addEsp];
}
