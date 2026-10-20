import type { ProofDebuggerAdapter } from "./adapter";
import { resolveProofExpression } from "./comparator";
import type {
  CheckpointObservation,
  DynamicDispatchResult,
  ObjectiveObservation,
  PostconditionRequest,
  ProofCheckpoint,
  ProofRegisterSnapshot,
  RuntimeApiFrame,
} from "./types";

const SUPPORTED_ARGUMENT_COUNTS: Record<string, number> = {
  VirtualProtect: 4,
  VirtualAlloc: 4,
};
const DWORD_LIMIT = BigInt(0x1_0000_0000);

function uint32le(bytes: Uint8Array, offset = 0): bigint {
  return BigInt(bytes[offset])
    | (BigInt(bytes[offset + 1]) << BigInt(8))
    | (BigInt(bytes[offset + 2]) << BigInt(16))
    | (BigInt(bytes[offset + 3]) << BigInt(24));
}

function register(snapshot: ProofRegisterSnapshot, name: string): bigint | undefined {
  const normalized = name.toLowerCase();
  if (normalized === "eip") return snapshot.eip;
  if (normalized === "esp") return snapshot.esp;
  return snapshot.registers[normalized];
}

export function resolveDynamicDispatch(
  checkpoint: ProofCheckpoint,
  observation: CheckpointObservation,
  adapter: ProofDebuggerAdapter,
): DynamicDispatchResult {
  if (checkpoint.target.kind !== "memory-dword") {
    return { status: "UNVERIFIED", reason: "dispatch target is not a memory dereference" };
  }
  const slot = resolveProofExpression(
    checkpoint.target.address,
    observation.registers,
    observation.registers,
    adapter,
  );
  if (!slot.ok) return { status: "UNVERIFIED", reason: slot.reason };
  const bytes = adapter.readMemory(slot.value, 4);
  if (!bytes.ok || bytes.value.length !== 4) {
    return {
      status: "UNVERIFIED",
      slotAddress: slot.value,
      reason: bytes.ok ? `IAT slot read returned ${bytes.value.length} bytes` : bytes.error.message,
    };
  }
  const espAssertion = checkpoint.assertions.find((assertion) => assertion.subject.toUpperCase() === "ESP");
  const expectedEsp = espAssertion?.confidence === "EXACT"
    ? resolveProofExpression(espAssertion.expected, observation.registers, observation.registers, adapter)
    : { ok: false as const, reason: "API-entry ESP is not exact" };
  return {
    status: expectedEsp.ok ? "VERIFIED" : "UNVERIFIED",
    slotAddress: slot.value,
    target: uint32le(bytes.value),
    expectedEsp: expectedEsp.ok ? expectedEsp.value : undefined,
    rawBytes: bytes.value,
    reason: expectedEsp.ok
      ? "IAT target and API-entry ESP resolved from the observed stop"
      : expectedEsp.reason,
  };
}

export function captureStdcallFrame(
  api: string,
  esp: bigint,
  adapter: ProofDebuggerAdapter,
): RuntimeApiFrame {
  const argumentCount = SUPPORTED_ARGUMENT_COUNTS[api];
  if (argumentCount === undefined) {
    return { status: "UNVERIFIED", api, esp, arguments: [], rawBytes: new Uint8Array(), reason: `unsupported API ${api}` };
  }
  const length = (argumentCount + 1) * 4;
  const read = adapter.readMemory(esp, length);
  if (!read.ok || read.value.length !== length) {
    return {
      status: "UNVERIFIED",
      api,
      esp,
      arguments: [],
      rawBytes: read.ok ? read.value : new Uint8Array(),
      reason: read.ok ? `runtime frame read returned ${read.value.length} of ${length} bytes` : read.error.message,
    };
  }
  const values: bigint[] = [];
  for (let offset = 0; offset < length; offset += 4) values.push(uint32le(read.value, offset));
  return {
    status: "VERIFIED",
    api,
    esp,
    returnAddress: values[0],
    arguments: values.slice(1),
    rawBytes: read.value,
    reason: "runtime stdcall frame captured",
  };
}

export function evaluatePostcondition(
  request: PostconditionRequest,
  frame: RuntimeApiFrame,
  returnObservation: ProofRegisterSnapshot,
  adapter: ProofDebuggerAdapter,
): ObjectiveObservation {
  const baseResult: ObjectiveObservation = {
    status: "UNVERIFIED",
    api: request.api,
    returnAddress: frame.returnAddress,
    protections: [],
    reason: "postcondition could not be evaluated",
  };
  if (frame.status !== "VERIFIED" || frame.api !== request.api || frame.returnAddress === undefined) {
    return { ...baseResult, reason: frame.reason };
  }
  if (returnObservation.eip !== frame.returnAddress) {
    return { ...baseResult, status: "FAILED", reason: "execution stopped somewhere other than the captured API return address" };
  }
  if (request.api !== "VirtualProtect" && request.api !== "VirtualAlloc") {
    return { ...baseResult, reason: `unsupported API ${request.api}` };
  }
  if (frame.arguments.length < 4) return { ...baseResult, reason: "runtime frame is incomplete" };

  const returnValue = register(returnObservation, "eax");
  if (returnValue === undefined) return { ...baseResult, reason: "EAX return value is unavailable" };
  if (returnValue === BigInt(0)) {
    return { ...baseResult, status: "FAILED", returnValue, reason: `${request.api} returned failure` };
  }

  const rangeBase = request.api === "VirtualAlloc" ? returnValue : frame.arguments[0];
  const rangeSize = frame.arguments[1];
  if (rangeSize === BigInt(0)) {
    return { ...baseResult, status: "FAILED", returnValue, rangeBase, rangeSize, reason: "protected range has zero size" };
  }
  const rangeEnd = rangeBase + rangeSize;
  if (rangeBase >= DWORD_LIMIT || rangeEnd > DWORD_LIMIT || rangeEnd <= rangeBase) {
    return { ...baseResult, status: "FAILED", returnValue, rangeBase, rangeSize, reason: "protected range overflows x86 address space" };
  }

  const protections: ObjectiveObservation["protections"] = [];
  let cursor = rangeBase;
  while (cursor < rangeEnd) {
    const queried = adapter.queryProtection(cursor);
    if (!queried.ok) {
      return { ...baseResult, returnValue, rangeBase, rangeSize, protections, reason: queried.error.message };
    }
    const region = queried.value;
    const regionEnd = region.base + region.size;
    if (region.size <= BigInt(0) || region.base > cursor || regionEnd <= cursor) {
      return { ...baseResult, returnValue, rangeBase, rangeSize, protections, reason: "protection query did not advance range coverage" };
    }
    protections.push({ address: cursor, region });
    if (!region.executable) {
      return { ...baseResult, status: "FAILED", returnValue, rangeBase, rangeSize, protections, reason: "runtime range is not fully executable" };
    }
    cursor = regionEnd < rangeEnd ? regionEnd : rangeEnd;
  }

  return {
    status: "VERIFIED",
    api: request.api,
    returnAddress: frame.returnAddress,
    returnValue,
    rangeBase,
    rangeSize,
    protections,
    reason: `${request.api} succeeded and the runtime range is executable`,
  };
}
