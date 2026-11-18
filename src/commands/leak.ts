import { memoryRegion } from "../analysis/memory";
import { classifyPointer, deriveModuleBase, extractHexPointers, PointerClassification } from "../core/leak_evidence";
import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { normalizeAddress } from "../core/validation";
import { findModuleByAddress } from "./modules";
import { decodeProtectValue, getPointerSize, tryReadMemory } from "../core/memory";

const MAX_SCAN_BYTES = 0x10000;
const MAX_ANALYZE_CHARS = 0x10000;

function readPointerFromBytes(bytes: Uint8Array, pointerSize: 4 | 8): bigint {
  let value = BigInt(0);
  for (let index = 0; index < pointerSize; index += 1) {
    value |= BigInt(bytes[index]) << BigInt(index * 8);
  }
  return value;
}

function classificationLabel(result: PointerClassification): string {
  if (result.kind === "module_pointer" && result.module) {
    return `${result.module.name.split(/[\\/]/).pop() ?? result.module.name}+0x${result.module.rva.toString(16).toUpperCase()}`;
  }
  if (result.kind === "memory_pointer") return "Mapped memory";
  if (result.kind === "reserved") return "Reserved memory";
  if (result.kind === "unmapped") return "Unmapped";
  if (result.kind === "null") return "Null";
  return "Unknown";
}

export function createLeakClassifyCommand(): Command {
  return {
    name: "leak_classify",
    description: "Classify a pointer value without dereferencing it.",
    usage: "dx @$osed().leak_classify(value)",
    examples: ["dx @$osed().leak_classify(0x76A31240)"],
    schema: { value: { type: ["number", "string"], required: true } },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const value = normalizeAddress(options.value);
      const result = classifyPointer(value, pointerSize, findModuleByAddress, memoryRegion);
      out.section("POINTER CLASSIFICATION");
      out.print("VALUE");
      out.print("  Address: " + out.formatAddress(value, pointerSize));
      out.print("  Architecture: " + (pointerSize === 4 ? "x86" : "x64"));
      out.print("  Pointer width: " + String(pointerSize * 8) + " bits");
      if (result.module || result.memory) out.print("TARGET");
      out.print("  Classification: " + (result.kind === "module_pointer" ? "Loaded module" : result.kind === "memory_pointer" ? "Mapped memory" : result.kind === "reserved" ? "Reserved memory" : result.kind === "unmapped" ? "Unmapped" : result.kind === "null" ? "Null pointer" : "Unknown"));
      if (result.module) {
        out.print("  Module: " + (result.module.name.split(/[\\\\/]/).pop() ?? result.module.name));
        out.print("  Module RVA: 0x" + result.module.rva.toString(16).toUpperCase().padStart(pointerSize * 2, "0"));
        out.print("  ASLR: " + result.module.aslr);
      }
      if (result.memory) {
        out.print("  State: " + (result.memory.state === "commit" ? "MEM_COMMIT" : result.memory.state === "reserve" ? "MEM_RESERVE" : result.memory.state === "free" ? "MEM_FREE" : "unknown"));
        out.print("  Type: " + (result.memory.regionType === "unknown" ? "unknown" : "MEM_" + result.memory.regionType.toUpperCase()));
        out.print("  Protection: " + (result.memory.raw.protection === undefined ? "unknown" : decodeProtectValue(result.memory.raw.protection).name));
        out.print("  Executable: " + (result.memory.executable === true ? "Yes" : result.memory.executable === false ? "No" : "Unknown"));
      }
      out.print("PROVENANCE");
      out.print("  " + result.provenance);
      out.print("ASSESSMENT");
      out.print(result.kind === "module_pointer" ? "  Valid pointer into a loaded module." : result.kind === "null" ? "  Null pointer." : result.kind === "memory_pointer" ? "  Address resolves to committed memory." : result.kind === "reserved" ? "  Address is reserved but not committed." : result.kind === "unmapped" ? "  Address does not resolve to mapped memory." : "  Memory state could not be established.");
      out.print("  No information disclosure established.");
      return { command: "leak_classify", args: options, success: true, findings: [result], warnings: [], errors: [] };
    },
  };
}

export function createLeakScanCommand(): Command {
  return {
    name: "leak_scan",
    description: "Find pointer-sized candidates in an explicitly bounded memory range.",
    usage: "dx @$osed().leak.scan(address, length?)",
    examples: ["dx @$osed().leak.scan(0x0014DD28, 0x400)"],
    schema: {
      address: { type: ["number", "string"], required: true },
      length: { type: "number", min: 1, max: MAX_SCAN_BYTES, default: 0x400 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const address = normalizeAddress(options.address);
      const length = options.length as number;
      const rows: Array<{ source: bigint; value: bigint; result: PointerClassification }> = [];
      const warnings: string[] = [];
      let unreadable = 0;

      for (let offset = 0; offset + pointerSize <= length; offset += pointerSize) {
        const source = address + BigInt(offset);
        const bytes = tryReadMemory(source, pointerSize);
        if (!bytes) {
          unreadable++;
          continue;
        }
        const value = readPointerFromBytes(bytes, pointerSize);
        if (value === BigInt(0)) continue;
        const result = classifyPointer(value, pointerSize, findModuleByAddress, memoryRegion);
        if (result.kind === "module_pointer" || result.kind === "memory_pointer") {
          rows.push({ source, value, result });
        }
      }

      if (unreadable > 0) warnings.push(`${unreadable} pointer-sized cells could not be read.`);
      const modulePointers = rows.filter((row) => row.result.kind === "module_pointer").length;
      const aslrPointers = rows.filter((row) => row.result.module?.aslr === "enabled").length;
      out.section("POINTER CANDIDATES");
      out.table(
        [
          { key: "source", header: "Source", width: pointerSize === 8 ? 18 : 12 },
          { key: "value", header: "Value", width: pointerSize === 8 ? 18 : 12 },
          { key: "target", header: "Target", width: 34 },
          { key: "aslr", header: "ASLR", width: 8 },
        ],
        rows.map((row) => ({
          source: out.formatAddress(row.source, pointerSize),
          value: out.formatAddress(row.value, pointerSize),
          target: classificationLabel(row.result),
          aslr: row.result.module?.aslr?.toUpperCase() ?? "n/a",
        })),
      );
      out.section("SUMMARY");
      out.print(`  Pointer-sized cells examined: ${Math.floor(length / pointerSize)}`);
      out.print(`  Module pointers: ${modulePointers}`);
      out.print(`  Potential ASLR disclosures: ${aslrPointers}`);
      out.section("PROVENANCE");
      out.print("  debugger_observed");
      out.print("  No externally observable disclosure established.");
      return { command: "leak_scan", args: options, success: true, findings: rows, warnings, errors: [], stats: { examined: Math.floor(length / pointerSize), candidates: rows.length, modulePointers, aslrPointers, unreadable } };
    },
  };
}

export function createLeakAnalyzeCommand(): Command {
  return {
    name: "leak_analyze",
    description: "Extract and classify hexadecimal pointer candidates from supplied output text.",
    usage: "dx @$osed().leak.analyze(text)",
    examples: ['dx @$osed().leak.analyze("Error processing request at 76A31240")'],
    schema: { text: { type: "string", required: true } },
    execute(options: Record<string, unknown>): CommandResult {
      const text = options.text as string;
      if (text.length > MAX_ANALYZE_CHARS) throw new Error(`Text exceeds the ${MAX_ANALYZE_CHARS}-character analysis limit.`);
      const pointerSize = getPointerSize();
      const values = extractHexPointers(text, pointerSize);
      const findings = values.map((value) => ({
        ...classifyPointer(value, pointerSize, findModuleByAddress, memoryRegion),
        provenance: "leak_derived" as const,
      }));
      const modulePointers = findings.filter((finding) => finding.kind === "module_pointer").length;
      const aslrPointers = findings.filter((finding) => finding.module?.aslr === "enabled").length;
      out.section("OUTPUT POINTER ANALYSIS");
      out.table(
        [
          { key: "value", header: "Value", width: pointerSize === 8 ? 18 : 12 },
          { key: "target", header: "Target", width: 34 },
          { key: "aslr", header: "ASLR", width: 8 },
        ],
        findings.map((finding) => ({
          value: out.formatAddress(finding.value, pointerSize),
          target: classificationLabel(finding),
          aslr: finding.module?.aslr?.toUpperCase() ?? "n/a",
        })),
      );
      out.section("PROVENANCE");
      out.print("  leak_derived (parsed from supplied text)");
      out.print("  Attacker observability and exploit usability are not established.");
      return { command: "leak_analyze", args: options, success: true, findings, warnings: [], errors: [], stats: { extracted: values.length, modulePointers, aslrPointers } };
    },
  };
}

export function createLeakBaseCommand(): Command {
  return {
    name: "leak_base",
    description: "Derive and validate a module base from an observed pointer and known RVA.",
    usage: "dx @$osed().leak.base(pointer, rva)",
    examples: ["dx @$osed().leak.base(0x76A31240, 0x1240)"],
    schema: { pointer: { type: ["number", "string"], required: true }, rva: { type: ["number", "string"], required: true } },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const result = deriveModuleBase(normalizeAddress(options.pointer), normalizeAddress(options.rva), pointerSize, findModuleByAddress);
      out.section("LEAKED POINTER");
      out.print(`  Address: ${out.formatAddress(result.pointer, pointerSize)}`);
      out.print(`  Known RVA: 0x${result.rva.toString(16).toUpperCase()}`);
      out.section("CALCULATED BASE");
      out.print(`  ${result.base === undefined ? "unavailable" : out.formatAddress(result.base, pointerSize)}`);
      out.section("VALIDATION");
      out.print(`  PE alignment: ${result.alignmentPlausible ? "plausible" : "not plausible"}`);
      out.print(`  Module mapping: ${result.moduleMatched ? `matched (${result.module?.name.split(/[\\/]/).pop() ?? "module"})` : "not matched in current target"}`);
      if (result.reason) out.print(`  Note: ${result.reason}`);
      out.section("PROVENANCE");
      out.print("  leak_derived");
      out.print("  Exploit usability is not established.");
      return { command: "leak_base", args: options, success: result.base !== undefined, findings: [result], warnings: result.moduleMatched ? [] : ["Calculated base is not validated against a loaded module in the current target."], errors: result.base === undefined ? [result.reason ?? "Unable to calculate a base."] : [] };
    },
  };
}

export function createLeakCommands(): Command[] {
  return [createLeakClassifyCommand(), createLeakScanCommand(), createLeakAnalyzeCommand(), createLeakBaseCommand()];
}
