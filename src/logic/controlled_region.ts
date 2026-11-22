export type ByteRun = {
  start: number;
  end: number;
  byte: number;
};

/** Finds maximal contiguous runs of one byte without reading past the supplied buffer. */
export function findByteRuns(buffer: Uint8Array, byte: number, maxRuns: number): ByteRun[] {
  const runs: ByteRun[] = [];
  for (let start = 0; start < buffer.length;) {
    if (buffer[start] !== byte) {
      start += 1;
      continue;
    }
    let end = start + 1;
    while (end < buffer.length && buffer[end] === byte) end += 1;
    runs.push({ start, end, byte });
    if (runs.length >= maxRuns) break;
    start = end;
  }
  return runs;
}

/** Returns the initial repeated-byte region only when it is long enough to be useful evidence. */
export function repeatedByteRunAtStart(buffer: Uint8Array, minimumLength = 16): ByteRun | undefined {
  if (buffer.length === 0) return undefined;
  const [run] = findByteRuns(buffer, buffer[0], 1);
  return run && run.start === 0 && run.end >= minimumLength ? run : undefined;
}
