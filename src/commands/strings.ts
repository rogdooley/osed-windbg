import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, tryReadMemory } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { normalizeAddress, normalizeByteArray } from "../core/validation";
import { findModuleByAddress } from "./modules";

type StringEncoding = "ascii" | "utf16le";
type FindEncoding = StringEncoding | "both";

const DEFAULT_MAX_READ = 256;
const DEFAULT_MAX_RESULTS = 50;

function normalizeEncoding(value: unknown, fallback: StringEncoding = "ascii"): StringEncoding {
  const text = String(value ?? fallback).trim().toLowerCase();
  if (text === "ascii" || text === "ansi") {
    return "ascii";
  }
  if (text === "utf16" || text === "utf-16" || text === "utf16le" || text === "wide") {
    return "utf16le";
  }
  throw new Error("encoding must be ascii or utf16le.");
}

function normalizeFindEncoding(value: unknown): FindEncoding {
  const text = String(value ?? "both").trim().toLowerCase();
  if (text === "both") {
    return "both";
  }
  return normalizeEncoding(text);
}

function byteToPython(byte: number): string {
  if (byte >= 0x20 && byte <= 0x7e && byte !== 0x22 && byte !== 0x5c) {
    return String.fromCharCode(byte);
  }
  if (byte === 0x22) return "\\\"";
  if (byte === 0x5c) return "\\\\";
  return `\\x${byte.toString(16).padStart(2, "0")}`;
}

function bytesToPython(bytes: number[]): string {
  return `b"${bytes.map(byteToPython).join("")}"`;
}

function bytesToHex(bytes: number[]): string {
  return bytes.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
}

function littleEndianPointer(address: bigint, pointerSize: 4 | 8): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < pointerSize; i += 1) {
    bytes.push(Number((address >> BigInt(i * 8)) & BigInt(0xff)));
  }
  return bytes;
}

function encodeText(text: string, encoding: StringEncoding, terminator = false): number[] {
  const bytes: number[] = [];
  if (encoding === "ascii") {
    for (let i = 0; i < text.length; i += 1) {
      const code = text.charCodeAt(i);
      if (code > 0x7f) {
        throw new Error("ASCII strings may only contain 0x00..0x7F characters.");
      }
      bytes.push(code & 0xff);
    }
    if (terminator) bytes.push(0);
    return bytes;
  }

  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    bytes.push(code & 0xff, (code >>> 8) & 0xff);
  }
  if (terminator) bytes.push(0, 0);
  return bytes;
}

function decodeBytes(bytes: Uint8Array, encoding: StringEncoding): { text: string; length: number; terminated: boolean } {
  if (encoding === "ascii") {
    const chars: string[] = [];
    for (let i = 0; i < bytes.length; i += 1) {
      if (bytes[i] === 0) {
        return { text: chars.join(""), length: i, terminated: true };
      }
      chars.push(String.fromCharCode(bytes[i]));
    }
    return { text: chars.join(""), length: bytes.length, terminated: false };
  }

  const chars: string[] = [];
  const evenLength = bytes.length - (bytes.length % 2);
  for (let i = 0; i < evenLength; i += 2) {
    const code = bytes[i] | (bytes[i + 1] << 8);
    if (code === 0) {
      return { text: chars.join(""), length: i, terminated: true };
    }
    chars.push(String.fromCharCode(code));
  }
  return { text: chars.join(""), length: evenLength, terminated: false };
}

function addressRow(address: bigint, pointerSize: 4 | 8): string {
  return out.formatAddress(address, pointerSize);
}

function moduleOffset(address: bigint): string {
  const moduleInfo = findModuleByAddress(address);
  if (!moduleInfo) {
    return "n/a";
  }
  return `${moduleInfo.name}+0x${(address - moduleInfo.base).toString(16).toUpperCase()}`;
}

function readContext(address: bigint, pointerSize: 4 | 8): string {
  const before = BigInt(4);
  const start = address >= before ? address - before : BigInt(0);
  const bytes = tryReadMemory(start, pointerSize + 8);
  return bytes ? bytesToHex(Array.from(bytes)) : "unreadable";
}

function findStringOccurrences(
  text: string,
  module: string | undefined,
  encoding: FindEncoding,
  maxResults: number,
): {
  findings: Array<{ address: bigint; encoding: StringEncoding; text: string }>;
  warnings: string[];
} {
  const encodings: StringEncoding[] = encoding === "both" ? ["ascii", "utf16le"] : [encoding];
  const findings: Array<{ address: bigint; encoding: StringEncoding; text: string }> = [];
  const warnings: string[] = [];
  const seen = new Set<string>();

  for (const selected of encodings) {
    const pattern = Uint8Array.from(encodeText(text, selected, false));
    if (pattern.length === 0) {
      throw new Error("text must not be empty.");
    }
    const scan = scanPattern(
      {
        module,
        executableOnly: false,
        maxResults: Math.max(0, maxResults - findings.length),
        chunkSize: 0x4000,
      },
      pattern,
    );

    for (const address of scan.hits) {
      const key = `${address.toString()}:${selected}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      findings.push({ address, encoding: selected, text });
    }

    warnings.push(...scan.warnings.map((warning) => `${warning.region}: ${warning.message}`));
    if (findings.length >= maxResults) {
      break;
    }
  }

  return { findings: findings.slice(0, maxResults), warnings };
}

function parseAddressCandidate(value: unknown): bigint | undefined {
  if (typeof value === "number") {
    return normalizeAddress(value);
  }
  if (typeof value !== "string") {
    return undefined;
  }
  const text = value.trim();
  if (/^(0x)?[0-9a-f`]+$/i.test(text)) {
    return normalizeAddress(text.replace(/`/g, ""));
  }
  return undefined;
}

export function createStringCommands(): Command[] {
  const readString: Command = {
    name: "str_read",
    description: "Read a null-terminated ASCII or UTF-16LE string from memory.",
    usage: "dx @$osed().str.read(address, max?, encoding?)",
    examples: [
      "dx @$osed().str.read(0x0019F920)",
      "dx @$osed().str.read(0x0019F920, 128, \"utf16le\")",
    ],
    schema: {
      address: { type: ["number", "string"], required: true },
      max: { type: "number", min: 1, max: 4096, default: DEFAULT_MAX_READ },
      encoding: { type: "string", default: "ascii" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const address = normalizeAddress(options.address);
      const max = options.max as number;
      const encoding = normalizeEncoding(options.encoding);
      const bytes = tryReadMemory(address, max);

      if (!bytes) {
        throw new Error(`Could not read ${max} bytes at ${addressRow(address, pointerSize)}.`);
      }

      const decoded = decodeBytes(bytes, encoding);
      const finding = {
        address,
        encoding,
        text: decoded.text,
        length: decoded.length,
        terminated: decoded.terminated,
      };

      out.section("String Read");
      out.info(`Address:    ${addressRow(address, pointerSize)}`);
      out.info(`Encoding:   ${encoding}`);
      out.info(`Length:     ${decoded.length} bytes`);
      out.info(`Terminated: ${decoded.terminated ? "yes" : "no"}`);
      out.print(decoded.text);

      return {
        command: "str_read",
        args: options,
        success: true,
        findings: [finding],
        warnings: decoded.terminated ? [] : [`No terminator found within ${max} bytes.`],
        errors: [],
      };
    },
  };

  const findString: Command = {
    name: "str_find",
    description: "Find ASCII and/or UTF-16LE string bytes in loaded module sections.",
    usage: "dx @$osed().str.find(text, module?, encoding?, maxResults?)",
    examples: [
      "dx @$osed().str.find(\"VirtualProtect\")",
      "dx @$osed().str.find(\"cmd.exe\", \"target\", \"ascii\", 25)",
    ],
    schema: {
      text: { type: "string", required: true },
      module: { type: "string" },
      encoding: { type: "string", default: "both" },
      maxResults: { type: "number", min: 1, max: 200, default: DEFAULT_MAX_RESULTS },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const text = options.text as string;
      const module = options.module as string | undefined;
      const encoding = normalizeFindEncoding(options.encoding);
      const maxResults = options.maxResults as number;
      const pointerSize = getPointerSize();
      const { findings, warnings } = findStringOccurrences(text, module, encoding, maxResults);

      const rows = findings.slice(0, maxResults).map((finding) => ({
        address: addressRow(finding.address, pointerSize),
        encoding: finding.encoding,
        python: `0x${finding.address.toString(16).toUpperCase()}`,
      }));

      out.section("String Find");
      out.info(`Text:     ${text}`);
      out.info(`Encoding: ${encoding}`);
      out.table(
        [
          { key: "address", header: "Address", width: 18 },
          { key: "encoding", header: "Encoding", width: 9 },
          { key: "python", header: "Python", width: 14 },
        ],
        rows,
      );

      return {
        command: "str_find",
        args: options,
        success: true,
        findings: findings.slice(0, maxResults),
        warnings,
        errors: [],
        stats: { results: Math.min(findings.length, maxResults) },
      };
    },
  };

  const refsString: Command = {
    name: "str_refs",
    description: "Find executable absolute-pointer references to a string address or literal.",
    usage: "dx @$osed().str.refs(target, module?, encoding?, maxResults?)",
    examples: [
      "dx @$osed().str.refs(\"VirtualProtect\")",
      "dx @$osed().str.refs(0x00403080, \"target\", \"ascii\", 25)",
    ],
    schema: {
      target: { type: ["number", "string"], required: true },
      module: { type: "string" },
      encoding: { type: "string", default: "both" },
      maxResults: { type: "number", min: 1, max: 200, default: DEFAULT_MAX_RESULTS },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const target = options.target;
      const module = options.module as string | undefined;
      const encoding = normalizeFindEncoding(options.encoding);
      const maxResults = options.maxResults as number;
      const pointerSize = getPointerSize();
      const warnings: string[] = [];
      const strings: Array<{ address: bigint; encoding?: StringEncoding; text?: string }> = [];
      const explicitAddress = parseAddressCandidate(target);

      if (pointerSize === 8) {
        warnings.push("str.refs scans absolute 64-bit pointer bytes on x64; RIP-relative references are not covered.");
      }

      if (explicitAddress !== undefined) {
        strings.push({ address: explicitAddress });
      } else if (typeof target === "string") {
        const found = findStringOccurrences(target, module, encoding, maxResults);
        strings.push(...found.findings);
        warnings.push(...found.warnings);
      } else {
        throw new Error("target must be an address or string literal.");
      }

      const findings: Array<{
        refAddress: bigint;
        stringAddress: bigint;
        moduleOffset: string;
        encoding?: StringEncoding;
        text?: string;
        pointerBytes: number[];
        contextBytes: string;
      }> = [];
      const seenRefs = new Set<string>();

      for (const stringHit of strings) {
        if (findings.length >= maxResults) {
          break;
        }

        const pointerBytes = littleEndianPointer(stringHit.address, pointerSize);
        const scan = scanPattern(
          {
            module,
            executableOnly: true,
            maxResults: Math.max(0, maxResults - findings.length),
            chunkSize: 0x4000,
          },
          Uint8Array.from(pointerBytes),
        );
        warnings.push(...scan.warnings.map((warning) => `${warning.region}: ${warning.message}`));

        for (const refAddress of scan.hits) {
          const key = `${refAddress.toString()}:${stringHit.address.toString()}`;
          if (seenRefs.has(key)) {
            continue;
          }
          seenRefs.add(key);
          findings.push({
            refAddress,
            stringAddress: stringHit.address,
            moduleOffset: moduleOffset(refAddress),
            encoding: stringHit.encoding,
            text: stringHit.text,
            pointerBytes,
            contextBytes: readContext(refAddress, pointerSize),
          });
          if (findings.length >= maxResults) {
            break;
          }
        }
      }

      const rows = findings.map((finding) => ({
        ref: addressRow(finding.refAddress, pointerSize),
        string: addressRow(finding.stringAddress, pointerSize),
        module: finding.moduleOffset,
        encoding: finding.encoding ?? "address",
        context: finding.contextBytes,
      }));

      out.section("String References");
      out.info(`Target: ${String(target)}`);
      out.table(
        [
          { key: "ref", header: "Ref", width: 18 },
          { key: "string", header: "String", width: 18 },
          { key: "module", header: "Module+Offset", width: 22 },
          { key: "encoding", header: "Encoding", width: 9 },
          { key: "context", header: "Context" },
        ],
        rows,
      );

      return {
        command: "str_refs",
        args: options,
        success: true,
        findings,
        warnings,
        errors: [],
        stats: { strings: strings.length, results: findings.length },
      };
    },
  };

  const stringBytes: Command = {
    name: "str_bytes",
    description: "Encode text as payload bytes and report bad-character hits.",
    usage: "dx @$osed().str.bytes(text, encoding?, terminator?, exclude?)",
    examples: [
      "dx @$osed().str.bytes(\"cmd.exe\")",
      "dx @$osed().str.bytes(\"W00T\", \"ascii\", true, \"00 0A 0D\")",
    ],
    schema: {
      text: { type: "string", required: true },
      encoding: { type: "string", default: "ascii" },
      terminator: { type: "boolean", default: false },
      exclude: { type: "array", elementType: "number", default: [0, 10, 13] },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const text = options.text as string;
      const encoding = normalizeEncoding(options.encoding);
      const terminator = options.terminator as boolean;
      const normalizedExclude = normalizeByteArray((options.exclude as number[] | undefined) ?? [0, 10, 13]);
      const exclude = new Set(normalizedExclude.values);
      const bytes = encodeText(text, encoding, terminator);
      const badchars = bytes
        .map((byte, offset) => ({ byte, offset }))
        .filter((entry) => exclude.has(entry.byte));
      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];

      out.section("String Bytes");
      out.info(`Encoding:   ${encoding}`);
      out.info(`Terminator: ${terminator ? "yes" : "no"}`);
      out.info(`Length:     ${bytes.length} bytes`);
      out.print(bytesToHex(bytes));
      out.print(bytesToPython(bytes));
      if (badchars.length > 0) {
        out.warn(`Bad characters: ${badchars.map((entry) => `${out.formatHexByte(entry.byte)}@${entry.offset}`).join(", ")}`);
      }

      return {
        command: "str_bytes",
        args: options,
        success: true,
        findings: [{ text, encoding, terminator, bytes, python: bytesToPython(bytes), badchars }],
        warnings,
        errors: [],
      };
    },
  };

  return [readString, findString, refsString, stringBytes];
}
