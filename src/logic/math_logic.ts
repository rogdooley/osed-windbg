export type MathBits = 8 | 16 | 32 | 64;

export interface MathEvidence {
  input: string;
  bits: MathBits;
  hex: string;
  unsigned: string;
  signed: string;
  littleEndianBytes: string;
  twosComplement: string;
}

const VALID_BITS = new Set<number>([8, 16, 32, 64]);

export function normalizeMathBits(value: unknown): MathBits {
  const bits = value === undefined ? 32 : value;
  if (typeof bits !== "number" || !Number.isInteger(bits) || !VALID_BITS.has(bits)) {
    throw new Error("bits must be one of: 8, 16, 32, 64.");
  }
  return bits as MathBits;
}

export function parseMathValue(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      throw new Error("value must be an integer.");
    }
    return BigInt(value);
  }
  if (typeof value !== "string") {
    throw new Error("value must be an integer, bigint, decimal string, or hex string.");
  }

  const text = value.trim().replace(/`/g, "");
  if (/^-?0x[0-9a-f]+$/i.test(text)) {
    const negative = text.startsWith("-");
    const hex = negative ? text.slice(3) : text.slice(2);
    const parsed = BigInt(`0x${hex}`);
    return negative ? -parsed : parsed;
  }
  if (/^-?[0-9]+$/.test(text)) {
    return BigInt(text);
  }
  if (/^[0-9a-f]+$/i.test(text) && /[a-f]/i.test(text)) {
    return BigInt(`0x${text}`);
  }
  throw new Error("value strings must be decimal or hex, e.g. -42, 0xFFFFFFD6, or FFD6.");
}

export function analyzeMathValue(rawValue: unknown, rawBits?: unknown): MathEvidence {
  const bits = normalizeMathBits(rawBits);
  const value = parseMathValue(rawValue);
  const modulus = BigInt(1) << BigInt(bits);
  const mask = modulus - BigInt(1);
  const unsigned = value & mask;
  const signBit = BigInt(1) << BigInt(bits - 1);
  const signed = (unsigned & signBit) !== BigInt(0) ? unsigned - modulus : unsigned;
  const width = bits / 4;
  const byteCount = bits / 8;
  const hex = `0x${unsigned.toString(16).toUpperCase().padStart(width, "0")}`;
  const littleEndianBytes: string[] = [];

  for (let i = 0; i < byteCount; i += 1) {
    const byte = Number((unsigned >> BigInt(i * 8)) & BigInt(0xff));
    littleEndianBytes.push(byte.toString(16).toUpperCase().padStart(2, "0"));
  }

  return {
    input: typeof rawValue === "string" ? rawValue : value.toString(),
    bits,
    hex,
    unsigned: unsigned.toString(),
    signed: signed.toString(),
    littleEndianBytes: littleEndianBytes.join(" "),
    twosComplement: hex,
  };
}
