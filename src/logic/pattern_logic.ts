const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";

export const MSF_MAX_LENGTH = 20280;

export function generateMsfPattern(length: number): string {
  const chunks: string[] = [];
  for (const a of UPPER) {
    for (const b of LOWER) {
      for (const c of DIGITS) {
        chunks.push(`${a}${b}${c}`);
      }
    }
  }

  return chunks.join("").slice(0, length);
}

function deBruijn(alphabet: string, order: number): string {
  const k = alphabet.length;
  const a = new Array(k * order).fill(0);
  const result: number[] = [];

  function db(t: number, p: number): void {
    if (t > order) {
      if (order % p === 0) {
        for (let i = 1; i <= p; i += 1) {
          result.push(a[i]);
        }
      }
      return;
    }

    a[t] = a[t - p];
    db(t + 1, p);

    for (let j = a[t - p] + 1; j < k; j += 1) {
      a[t] = j;
      db(t + 1, t);
    }
  }

  db(1, 1);
  return result.map((index) => alphabet[index]).join("");
}

export function generateCyclicPattern(length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const sequence = deBruijn(alphabet, 3);
  if (length > sequence.length) {
    throw new Error(
      `Cyclic pattern length ${length} exceeds the maximum unique-window length ${sequence.length}. Use a smaller length or the "msf" pattern type.`,
    );
  }

  return sequence.slice(0, length);
}

export function decodeOffsetNeedle(value: number | string): string {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new Error("Numeric pattern_offset value must be a 32-bit unsigned integer.");
    }

    const bytes = [
      value & 0xff,
      (value >>> 8) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 24) & 0xff,
    ];
    return String.fromCharCode(...bytes);
  }

  if (!/^(0x)?[0-9a-fA-F]+$/.test(value)) {
    throw new Error("String pattern_offset value must be raw hex only.");
  }

  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string length must be even.");
  }

  const chars: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    chars.push(parseInt(hex.slice(i, i + 2), 16));
  }

  return String.fromCharCode(...chars.reverse());
}
