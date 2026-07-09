import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, tryReadMemory } from "../core/memory";
import { normalizeByteArray } from "../core/validation";
import { scanPattern } from "../core/scan_engine";
import { knownPatterns, validateInstructionCandidate } from "../logic/instruction_validation";
import { findModuleByAddress } from "./modules";

type TriState = "enabled" | "disabled" | "unknown";
type Mode = "fast" | "thorough";

type SehPprFinding = {
  address: bigint;
  module: string;
  module_offset: string;
  instructions: string;
  badchar_safe: boolean;
  aslr: TriState;
  safeseh: TriState;
  score: number;
  reasons: string[];
};

function addressBytes(address: bigint, pointerSize: 4 | 8): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < pointerSize; i += 1) {
    bytes.push(Number((address >> BigInt(i * 8)) & BigInt(0xff)));
  }
  return bytes;
}

function isBadcharSafe(address: bigint, pointerSize: 4 | 8, exclude: number[]): boolean {
  if (exclude.length === 0) {
    return true;
  }
  const blocked = new Set(exclude);
  return !addressBytes(address, pointerSize).some((value) => blocked.has(value));
}

function scoreFinding(badcharSafe: boolean, aslr: TriState, safeseh: TriState): { score: number; reasons: string[] } {
  let score = 0;
  const reasons: string[] = [];

  if (badcharSafe) {
    score += 35;
    reasons.push("address bytes avoid excluded badchars");
  } else {
    score -= 40;
    reasons.push("address bytes contain excluded badchars");
  }

  if (aslr === "disabled") {
    score += 25;
    reasons.push("module has ASLR disabled");
  } else if (aslr === "unknown") {
    score += 5;
    reasons.push("module ASLR state unknown");
  } else {
    score -= 20;
    reasons.push("module has ASLR enabled");
  }

  if (safeseh === "disabled") {
    score += 30;
    reasons.push("module SafeSEH is disabled");
  } else if (safeseh === "unknown") {
    score += 10;
    reasons.push("module SafeSEH state unknown");
  } else {
    score -= 40;
    reasons.push("module SafeSEH is enabled");
  }

  return { score, reasons };
}

function normalizeMode(value: unknown): Mode {
  return value === "thorough" ? "thorough" : "fast";
}

export function createSehPprCommand(): Command {
  return {
    name: "seh_ppr",
    description: "Find and rank pop-pop-ret candidates for SEH workflows.",
    usage: "dx @$osed().seh_ppr('libspp.dll', '00 0A 0D', 50, true, 'fast')",
    examples: ["dx @$osed().seh_ppr()", "dx @$osed().seh_ppr('libspp.dll', '00 0A 0D', 100, true, 'thorough')"],
    schema: {
      module: { type: "string" },
      exclude: { type: "array", elementType: "number", default: [] },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      executableOnly: { type: "boolean", default: true },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const normalizedExclude = normalizeByteArray((options.exclude as number[] | undefined) ?? []);
      const executableOnly = (options.executableOnly as boolean | undefined) ?? true;
      const maxResults = Math.min((options.maxResults as number | undefined) ?? 50, 200);
      const mode = normalizeMode(options.mode);
      const moduleFilter = options.module as string | undefined;

      const warnings: string[] = [];
      if (normalizedExclude.warning) {
        warnings.push(normalizedExclude.warning);
      }

      const findings: SehPprFinding[] = [];
      const seen = new Set<string>();
      const patterns = knownPatterns()
        .filter((p) => /^pop \w+ ; pop \w+ ; ret$/.test(p.mnemonic))
        .map((p) => p.bytes);

      for (const pattern of patterns) {
        if (findings.length >= maxResults) {
          break;
        }

        const remaining = Math.max(1, maxResults - findings.length);
        const scan = scanPattern(
          {
            module: moduleFilter,
            executableOnly,
            maxResults: remaining,
            chunkSize: mode === "thorough" ? 0x1000 : 0x4000,
          },
          Uint8Array.from(pattern),
        );

        warnings.push(...scan.warnings.map((warning) => `${warning.region}: ${warning.message}`));

        for (const hit of scan.hits) {
          const key = hit.toString();
          if (seen.has(key)) {
            continue;
          }
          seen.add(key);

          const candidate = tryReadMemory(hit, 3);
          if (!candidate) {
            continue;
          }
          const validated = validateInstructionCandidate(candidate, true, true);
          if (!validated.flags.decoded || !validated.flags.mnemonicMatch || !validated.flags.executable) {
            continue;
          }

          const moduleInfo = findModuleByAddress(hit);
          const moduleName = moduleInfo?.name ?? "<outside module>";
          const moduleOffset = moduleInfo ? `0x${(hit - moduleInfo.base).toString(16).toUpperCase()}` : "n/a";
          const aslr = moduleInfo?.aslr ?? "unknown";
          const safeseh = moduleInfo?.safeseh ?? "unknown";
          const badcharSafe = isBadcharSafe(hit, pointerSize, normalizedExclude.values);
          const scored = scoreFinding(badcharSafe, aslr, safeseh);

          findings.push({
            address: hit,
            module: moduleName,
            module_offset: moduleOffset,
            instructions: validated.mnemonic ?? "pop ? ; pop ? ; ret",
            badchar_safe: badcharSafe,
            aslr,
            safeseh,
            score: scored.score,
            reasons: scored.reasons,
          });

          if (findings.length >= maxResults) {
            break;
          }
        }
      }

      findings.sort((a, b) => {
        if (a.score !== b.score) {
          return b.score - a.score;
        }
        return a.address < b.address ? -1 : 1;
      });

      out.section("SEH PPR Candidates");
      out.table(
        [
          { key: "rank", header: "Rank", width: 6 },
          { key: "address", header: "Address", width: 18 },
          { key: "module", header: "Module", width: 18 },
          { key: "offset", header: "Offset", width: 12 },
          { key: "instr", header: "Instructions", width: 24 },
          { key: "badchar", header: "BadChar", width: 8 },
          { key: "aslr", header: "ASLR", width: 8 },
          { key: "safeseh", header: "SafeSEH", width: 8 },
          { key: "score", header: "Score", width: 6 },
        ],
        findings.map((finding, index) => ({
          rank: `${index + 1}`,
          address: out.formatAddress(finding.address, pointerSize),
          module: finding.module,
          offset: finding.module_offset,
          instr: finding.instructions,
          badchar: finding.badchar_safe ? "safe" : "bad",
          aslr: finding.aslr,
          safeseh: finding.safeseh,
          score: `${finding.score}`,
        })),
      );
      out.whyItMatters("Reliable pop-pop-ret selection is central to practical SEH overwrite exploitation.");

      return {
        command: "seh_ppr",
        args: {
          ...options,
          exclude: normalizedExclude.values,
          executableOnly,
          maxResults,
          mode,
        },
        success: true,
        findings,
        warnings,
        errors: [],
      };
    },
  };
}
