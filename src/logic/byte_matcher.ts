export function findAllByteMatches(buffer: Uint8Array, pattern: Uint8Array): number[] {
  if (pattern.length === 0 || pattern.length > buffer.length) {
    return [];
  }

  const offsets: number[] = [];
  const last = buffer.length - pattern.length;

  for (let i = 0; i <= last; i += 1) {
    let match = true;
    for (let j = 0; j < pattern.length; j += 1) {
      if (buffer[i + j] !== pattern[j]) {
        match = false;
        break;
      }
    }

    if (match) {
      offsets.push(i);
    }
  }

  return offsets;
}
