import { formatAddress } from "./output";

export function readMemory(address: bigint, length: number): Uint8Array {
  const attempts: (number | bigint)[] = [address];

  if (address >= BigInt(0) && address <= BigInt(Number.MAX_SAFE_INTEGER)) {
    attempts.push(Number(address));
  }

  let lastError: unknown;
  for (const attempt of attempts) {
    try {
      const values = host.memory.readMemoryValues(attempt, length, 1, false);
      return Uint8Array.from(values.map((value) => value & 0xff));
    } catch (error) {
      lastError = error;
    }
  }

  const suffix = lastError instanceof Error && lastError.message ? ` (${lastError.message})` : "";
  throw new Error(`Memory read failed at ${formatAddress(address, 8)}${suffix}.`);
}

export function tryReadMemory(address: bigint, length: number): Uint8Array | undefined {
  try {
    return readMemory(address, length);
  } catch (_error) {
    return undefined;
  }
}

export function readUint16LE(address: bigint): number {
  const bytes = readMemory(address, 2);
  return bytes[0] | (bytes[1] << 8);
}

export function readUint32LE(address: bigint): number {
  const bytes = readMemory(address, 4);
  return (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
}

export function readUint64LE(address: bigint): bigint {
  const bytes = readMemory(address, 8);
  let result = BigInt(0);
  for (let i = 0; i < 8; i += 1) {
    result |= BigInt(bytes[i]) << BigInt(i * 8);
  }
  return result;
}

export function readPointer(address: bigint, pointerSize: 4 | 8): bigint {
  return pointerSize === 8 ? readUint64LE(address) : BigInt(readUint32LE(address));
}

export function getPointerSize(): 4 | 8 {
  const process = host.currentProcess as unknown as { Is64Bit?: boolean; Machine?: string };
  const machine = (process?.Machine ?? "").toLowerCase();
  if (process?.Is64Bit || machine.includes("x64") || machine.includes("amd64")) {
    return 8;
  }
  return 4;
}
