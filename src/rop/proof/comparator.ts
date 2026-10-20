import type { ProofDebuggerAdapter } from "./adapter";
import { uint32Add } from "./predictor";
import type {
  CheckpointObservation,
  ProofAssertionObservation,
  ProofCheckpoint,
  ProofRegisterSnapshot,
  ProofValueExpression,
} from "./types";

export interface CompareCheckpointInput {
  checkpoint: ProofCheckpoint;
  previous: ProofRegisterSnapshot;
  resolvedTarget?: bigint;
}

type EvaluatedValue =
  | { ok: true; value: bigint }
  | { ok: false; reason: string };

interface EvaluationContext {
  before: ProofRegisterSnapshot;
  after: ProofRegisterSnapshot;
  adapter: ProofDebuggerAdapter;
}

export function resolveProofExpression(
  expression: ProofValueExpression,
  before: ProofRegisterSnapshot,
  after: ProofRegisterSnapshot,
  adapter: ProofDebuggerAdapter,
): EvaluatedValue {
  return evaluate(expression, { before, after, adapter });
}

function registerValue(snapshot: ProofRegisterSnapshot, register: string): bigint | undefined {
  const normalized = register.toLowerCase();
  if (normalized === "eip") return snapshot.eip;
  if (normalized === "esp") return snapshot.esp;
  return snapshot.registers[normalized];
}

function dwordLittleEndian(bytes: Uint8Array): bigint {
  return BigInt(bytes[0])
    | (BigInt(bytes[1]) << BigInt(8))
    | (BigInt(bytes[2]) << BigInt(16))
    | (BigInt(bytes[3]) << BigInt(24));
}

function evaluate(expression: ProofValueExpression, context: EvaluationContext): EvaluatedValue {
  switch (expression.kind) {
    case "constant":
      return { ok: true, value: BigInt.asUintN(32, expression.value) };
    case "register": {
      const snapshot = expression.checkpoint === "before" ? context.before : context.after;
      const value = registerValue(snapshot, expression.register);
      return value === undefined
        ? { ok: false, reason: `register ${expression.register} is unavailable` }
        : { ok: true, value: BigInt.asUintN(32, value) };
    }
    case "register-offset": {
      const value = registerValue(context.before, expression.register);
      return value === undefined
        ? { ok: false, reason: `register ${expression.register} is unavailable` }
        : { ok: true, value: uint32Add(value, expression.offset) };
    }
    case "memory-dword": {
      const address = evaluate(expression.address, context);
      if (!address.ok) return address;
      const bytes = context.adapter.readMemory(address.value, 4);
      if (!bytes.ok) return { ok: false, reason: bytes.error.message };
      if (bytes.value.length !== 4) {
        return { ok: false, reason: `expected 4 memory bytes, observed ${bytes.value.length}` };
      }
      return { ok: true, value: dwordLittleEndian(bytes.value) };
    }
    case "sum": {
      let value = BigInt(0);
      for (const term of expression.terms) {
        const evaluated = evaluate(term, context);
        if (!evaluated.ok) return evaluated;
        value = BigInt.asUintN(32, value + evaluated.value);
      }
      return { ok: true, value };
    }
    case "deferred":
    case "unknown":
      return { ok: false, reason: expression.reason };
  }
}

function formatExpression(expression: ProofValueExpression): string {
  switch (expression.kind) {
    case "constant": return `0x${BigInt.asUintN(32, expression.value).toString(16).padStart(8, "0")}`;
    case "register": return `${expression.register.toUpperCase()}@${expression.checkpoint}`;
    case "register-offset": return `${expression.register.toUpperCase()}@before${expression.offset >= 0 ? "+" : ""}${expression.offset}`;
    case "memory-dword": return `DWORD[${formatExpression(expression.address)}]`;
    case "sum": return expression.terms.map(formatExpression).join(" + ");
    case "deferred": return `deferred: ${expression.reason}`;
    case "unknown": return `unknown: ${expression.reason}`;
  }
}

function observedExpression(subject: string): ProofValueExpression {
  return { kind: "register", register: subject.toLowerCase(), checkpoint: "after" };
}

function signedDifference(observed: bigint, expected: bigint): number {
  return Number(BigInt.asIntN(32, observed - expected));
}

export function compareCheckpoint(
  input: CompareCheckpointInput,
  adapter: ProofDebuggerAdapter,
): CheckpointObservation {
  const current = adapter.readRegisters();
  const context: EvaluationContext = { before: input.previous, after: current, adapter };
  const assertions: ProofAssertionObservation[] = [];
  const target = input.resolvedTarget === undefined
    ? evaluate(input.checkpoint.target, context)
    : { ok: true as const, value: BigInt.asUintN(32, input.resolvedTarget) };

  if (!target.ok) {
    assertions.push({
      subject: "EIP",
      expectedExpression: formatExpression(input.checkpoint.target),
      observedValue: current.eip,
      status: "UNVERIFIED",
      confidence: "UNKNOWN",
      evidence: [],
      reason: target.reason,
    });
    return {
      checkpointId: input.checkpoint.id,
      timestamp: new Date().toISOString(),
      outcome: "UNVERIFIED",
      registers: current,
      assertions,
      reason: `Checkpoint target could not be resolved: ${target.reason}`,
    };
  }

  const expectedEip = BigInt.asUintN(32, target.value);
  const observedEip = BigInt.asUintN(32, current.eip);
  if (expectedEip !== observedEip) {
    assertions.push({
      subject: "EIP",
      expectedExpression: formatExpression(input.checkpoint.target),
      expectedValue: expectedEip,
      observedValue: observedEip,
      status: "FAILED",
      confidence: "EXACT",
      evidence: input.checkpoint.provenance.flatMap((entry) => entry.instructions),
      reason: "execution stopped at an unexpected address",
    });
    return {
      checkpointId: input.checkpoint.id,
      timestamp: new Date().toISOString(),
      outcome: "UNEXPECTED_STOP",
      registers: current,
      assertions,
      reason: `Expected EIP 0x${expectedEip.toString(16)}, observed 0x${observedEip.toString(16)}; checkpoint not advanced.`,
    };
  }

  assertions.push({
    subject: "EIP",
    expectedExpression: formatExpression(input.checkpoint.target),
    expectedValue: expectedEip,
    observedValue: observedEip,
    status: "VERIFIED",
    confidence: "EXACT",
    evidence: input.checkpoint.provenance.flatMap((entry) => entry.instructions),
    reason: "stop address matched the checkpoint target",
  });

  let unverified = false;
  for (const template of input.checkpoint.assertions) {
    const expected = evaluate(template.expected, context);
    const observed = evaluate(template.observed ?? observedExpression(template.subject), context);
    const cannotVerify = template.confidence !== "EXACT" || !expected.ok || !observed.ok;
    if (cannotVerify) {
      const reason = template.confidence !== "EXACT"
        ? `assertion confidence is ${template.confidence}`
        : !expected.ok ? expected.reason : !observed.ok ? observed.reason : "assertion is not exact";
      assertions.push({
        subject: template.subject,
        expectedExpression: formatExpression(template.expected),
        expectedValue: expected.ok ? expected.value : undefined,
        observedValue: observed.ok ? observed.value : undefined,
        status: "UNVERIFIED",
        confidence: template.confidence,
        evidence: [...template.evidence],
        reason,
      });
      unverified = true;
      continue;
    }

    if (expected.value !== observed.value) {
      const differenceBytes = template.subject.toUpperCase() === "ESP"
        ? signedDifference(observed.value, expected.value)
        : undefined;
      assertions.push({
        subject: template.subject,
        expectedExpression: formatExpression(template.expected),
        expectedValue: expected.value,
        observedValue: observed.value,
        status: "FAILED",
        confidence: template.confidence,
        evidence: [...template.evidence],
        reason: differenceBytes === undefined
          ? "observed value differs from prediction"
          : `ESP differs by ${differenceBytes >= 0 ? "+" : ""}${differenceBytes} bytes`,
        differenceBytes,
      });
      return {
        checkpointId: input.checkpoint.id,
        timestamp: new Date().toISOString(),
        outcome: "FAILED",
        registers: current,
        assertions,
        reason: assertions[assertions.length - 1].reason,
      };
    }

    assertions.push({
      subject: template.subject,
      expectedExpression: formatExpression(template.expected),
      expectedValue: expected.value,
      observedValue: observed.value,
      status: "VERIFIED",
      confidence: template.confidence,
      evidence: [...template.evidence],
      reason: "observed value matched the prediction",
    });
  }

  return {
    checkpointId: input.checkpoint.id,
    timestamp: new Date().toISOString(),
    outcome: unverified ? "UNVERIFIED" : "VERIFIED",
    registers: current,
    assertions,
    reason: unverified
      ? "Checkpoint reached, but one or more assertions could not be verified."
      : "Checkpoint and all exact assertions matched.",
  };
}
