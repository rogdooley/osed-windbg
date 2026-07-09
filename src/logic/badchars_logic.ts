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

export function expectedBytes(exclude: number[]): number[] {
  const excluded = new Set(exclude);
  const result: number[] = [];
  for (let i = 0; i <= 0xff; i += 1) {
    if (!excluded.has(i)) {
      result.push(i);
    }
  }
  return result;
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
