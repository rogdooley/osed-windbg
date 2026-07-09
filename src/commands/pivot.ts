import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { validateInstructionCandidate } from "../logic/instruction_validation";
import { buildCapabilityIndex, buildRopIndexFromSequences } from "../rop";
import { parseInstruction } from "../semantics";
import { SEMANTIC_SCHEMA_VERSION, type InstructionSequence, type InstructionSequenceSource, type Provenance } from "../semantics/types";
import { findModuleByAddress } from "./modules";

const PIVOT_PATTERNS: Array<{ sequence: string; bytes: number[] }> = [
  { sequence: "xchg eax, esp ; ret", bytes: [0x94, 0xc3] },
  { sequence: "xchg ecx, esp ; ret", bytes: [0x87, 0xcc, 0xc3] },
  { sequence: "xchg edx, esp ; ret", bytes: [0x87, 0xd4, 0xc3] },
  { sequence: "xchg ebx, esp ; ret", bytes: [0x87, 0xdc, 0xc3] },
  { sequence: "xchg esi, esp ; ret", bytes: [0x87, 0xf4, 0xc3] },
  { sequence: "xchg edi, esp ; ret", bytes: [0x87, 0xfc, 0xc3] },
  { sequence: "xchg ebp, esp ; ret", bytes: [0x87, 0xec, 0xc3] },
  { sequence: "push esp ; ret", bytes: [0x54, 0xc3] },
  { sequence: "mov esp, ebp ; ret", bytes: [0x8b, 0xe5, 0xc3] },
  { sequence: "mov esp, eax ; ret", bytes: [0x89, 0xc4, 0xc3] },
  { sequence: "leave ; ret", bytes: [0xc9, 0xc3] },
];

type PivotFinding = {
  address: bigint;
  sequence: string;
  offset: string;
  flags: Record<string, unknown>;
};

function buildSequence(address: bigint, sequence: string): InstructionSequence {
  const moduleInfo = findModuleByAddress(address);
  const provenance: Provenance = {
    module: moduleInfo?.name,
    section: moduleInfo ? ".text" : undefined,
    virtualAddress: Number(address & BigInt(0xffffffff)),
    fileOffset: undefined,
    executable: "EXACT",
    writable: "UNKNOWN",
    aslr: "UNKNOWN",
    rebaseable: "UNKNOWN",
  };
  const source: InstructionSequenceSource = {
    kind: "pivot-scan",
    name: "stack-pivot",
    format: "synthetic",
    version: "v1",
  };

  return {
    schemaVersion: SEMANTIC_SCHEMA_VERSION,
    id: `pivot:${sequence}:${address.toString(16)}`,
    source,
    originalText: sequence,
    instructions: sequence.split(" ; ").map((part) => parseInstruction(part)),
    provenance,
  };
}

export function createPivotCommand(): Command {
  return {
    name: "pivots",
    description: "Scan for stack pivot candidates.",
    usage: "dx @$osed.pivots({ module: 'essfunc', maxResults: 50 })",
    examples: ["dx @$osed.pivots({ module: 'essfunc' })", "dx @$osed.pivots({ mode: 'thorough' })"],
    schema: {
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const warnings: string[] = [];
      const sequenceHits: InstructionSequence[] = [];
      const detailsByAddress = new Map<bigint, { sequence: string; flags: Record<string, unknown> }>();

      for (const pivot of PIVOT_PATTERNS) {
        const scan = scanPattern(
          {
            module: options.module as string | undefined,
            executableOnly: (options.executableOnly as boolean | undefined) ?? true,
            maxResults: (options.maxResults as number | undefined) ?? 50,
            chunkSize: (options.mode as string) === "thorough" ? 0x1000 : 0x4000,
          },
          Uint8Array.from(pivot.bytes),
        );

        warnings.push(...scan.warnings.map((warning) => `${warning.region}: ${warning.message}`));

        for (const hit of scan.hits) {
          const candidate = readMemory(hit, pivot.bytes.length);
          const validated = validateInstructionCandidate(candidate, true, true);
          if (!validated.flags.decoded || !validated.flags.mnemonicMatch || !validated.flags.executable) {
            continue;
          }

          detailsByAddress.set(hit, {
            sequence: pivot.sequence,
            flags: validated.flags,
          });
          sequenceHits.push(buildSequence(hit, pivot.sequence));
        }
      }

      const capabilityIndex = buildCapabilityIndex(buildRopIndexFromSequences(sequenceHits));
      const findings: PivotFinding[] = capabilityIndex
        .query({
          capability: "STACK_PIVOT",
          executableOnly: true,
        })
        .map((gadget) => {
          const address = BigInt(gadget.locations[0]?.virtualAddress ?? 0);
          const detail = detailsByAddress.get(address);
          return {
            address,
            sequence: detail?.sequence ?? gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; "),
            offset: `0x${address.toString(16).toUpperCase()}`,
            flags: detail?.flags ?? {},
          };
        })
        .sort((left, right) => (left.address < right.address ? -1 : 1))
        .slice(0, Math.min((options.maxResults as number | undefined) ?? 50, 200));

      out.section("Stack Pivot Candidates");
      out.table(
        [
          { key: "address", header: "Address", width: 18 },
          { key: "sequence", header: "Sequence", width: 22 },
          { key: "python", header: "Python", width: 18 },
        ],
        findings.map((finding) => ({
          address: out.formatAddress(finding.address, pointerSize),
          sequence: finding.sequence,
          python: `0x${finding.address.toString(16).toUpperCase()}`,
        })),
      );
      out.whyItMatters("Stack pivots transition execution into attacker-controlled ROP chains.");

      return {
        command: "pivots",
        args: options,
        success: true,
        findings,
        warnings,
        errors: [],
      };
    },
  };
}
