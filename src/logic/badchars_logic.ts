export type BadcharMismatch = {
  offset: number;
  expected: number;
  observed: number;
};

export type BadcharComparison = {
  badChars: number[];
  mismatches: BadcharMismatch[];
  survivorCount: number;
  expectedConsumed: number;
};

export type ByteArrayFormat = "python" | "c" | "hex";

export type ArrayLocation = {
  offset: number;
  expectedStart: number;
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

export function locateExpectedArray(window: Uint8Array, expected: number[], minRun = 8): ArrayLocation | undefined {
  const expectedIndex = new Map<number, number>();
  for (let i = 0; i < expected.length; i += 1) {
    expectedIndex.set(expected[i], i);
  }

  for (let start = 0; start < window.length; start += 1) {
    const ei = expectedIndex.get(window[start]);
    if (ei === undefined) continue;

    let run = 0;
    for (let i = 0; start + i < window.length && ei + i < expected.length; i += 1) {
      if (window[start + i] !== expected[ei + i]) break;
      run += 1;
    }
    if (run >= minRun) {
      return { offset: start, expectedStart: ei, matchedRun: run };
    }
  }

  for (let start = 0; start < window.length; start += 1) {
    const ei = expectedIndex.get(window[start]);
    if (ei === undefined) continue;

    let e = ei;
    let o = start;
    let matched = 0;
    while (e < expected.length && o < window.length) {
      if (window[o] === expected[e]) {
        matched += 1;
        e += 1;
        o += 1;
      } else if (expected[e] < window[o]) {
        e += 1;
      } else {
        break;
      }
    }
    if (matched >= minRun) {
      return { offset: start, expectedStart: ei, matchedRun: matched };
    }
  }

  return undefined;
}

export function compareBadchars(observed: Uint8Array, expected: number[]): BadcharComparison {
  const badChars: number[] = [];
  const mismatches: BadcharMismatch[] = [];
  let e = 0;
  let o = 0;

  while (e < expected.length && o < observed.length) {
    if (observed[o] === expected[e]) {
      e += 1;
      o += 1;
    } else if (expected[e] < observed[o]) {
      badChars.push(expected[e]);
      mismatches.push({ offset: e, expected: expected[e], observed: -1 });
      e += 1;
    } else {
      break;
    }
  }

  return {
    badChars,
    mismatches,
    survivorCount: o,
    expectedConsumed: e,
  };
}
