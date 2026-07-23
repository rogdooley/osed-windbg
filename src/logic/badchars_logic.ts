export type BadcharMismatch = {
  offset: number;
  expected: number;
  observed: number;
};

export type BadcharComparison = {
  mismatches: BadcharMismatch[];
  breakOffset?: number;
  nextExpected?: number;
};

export type ByteArrayFormat = "python" | "c" | "hex";

export type ArrayLocation = {
  offset: number;
  matchedRun: number;
};

export function expectedBytes(exclude: number[]): number[] {
  const excluded = new Set(exclude.map((value) => value & 0xff));
  const result: number[] = [];
  for (let i = 0; i <= 0xff; i += 1) {
    if (!excluded.has(i)) {
      result.push(i);
    }
  }
  return result;
}

function hexByte(value: number): string {
  return (value & 0xff).toString(16).padStart(2, "0");
}

// Render a test byte array in a paste-ready form for the sending harness.
export function formatByteArray(bytes: number[], format: ByteArrayFormat): string {
  switch (format) {
    case "python":
      return `b"${bytes.map((value) => `\\x${hexByte(value)}`).join("")}"`;
    case "c":
      return `"${bytes.map((value) => `\\x${hexByte(value)}`).join("")}"`;
    case "hex":
    default:
      return bytes.map(hexByte).join(" ");
  }
}

// Locate where a known expected byte array begins inside a memory window, by
// finding the start offset whose contiguous forward match against `expected` is
// longest. Tolerant of trailing corruption (the run simply ends at the first bad
// byte); returns undefined if no start reaches `minRun` matching bytes.
export function locateExpectedArray(window: Uint8Array, expected: number[], minRun = 8): ArrayLocation | undefined {
  let best: ArrayLocation = { offset: -1, matchedRun: 0 };
  for (let start = 0; start < window.length; start += 1) {
    let run = 0;
    for (let i = 0; start + i < window.length && i < expected.length; i += 1) {
      if (window[start + i] !== expected[i]) {
        break;
      }
      run += 1;
    }
    if (run > best.matchedRun) {
      best = { offset: start, matchedRun: run };
    }
  }
  return best.matchedRun >= minRun ? best : undefined;
}

export function compareBadchars(observed: Uint8Array, expected: number[]): BadcharComparison {
  const mismatches: BadcharMismatch[] = [];
  let breakOffset: number | undefined;

  for (let i = 0; i < expected.length && i < observed.length; i += 1) {
    if (observed[i] !== expected[i]) {
      mismatches.push({
        offset: i,
        expected: expected[i],
        observed: observed[i],
      });
      if (breakOffset === undefined) {
        breakOffset = i;
      }
    }
  }

  return {
    mismatches,
    breakOffset,
    nextExpected: breakOffset === undefined ? undefined : expected[breakOffset],
  };
}
