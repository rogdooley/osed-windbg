import { deriveCapabilities, type CapabilityIndex } from "../capabilities";
import type { ChainStep } from "../chain";
import { parseManualChain } from "../chain_verifier";
import type { RopCapability, RopGadget } from "../types";
import { composeSemanticSequence } from "../../semantics/compose";
import { sequenceFromLiveHit } from "../../semantics/live-provider";
import type { RegisterExpr, SemanticSequence } from "../../semantics/types";
import type { ProofDebuggerAdapter } from "./adapter";
import type {
  ProofAssertionTemplate,
  ProofCheckpoint,
  ProofPlan,
  ProofPlanInput,
  ProofValueExpression,
} from "./types";

interface GadgetDescriptor {
  address: bigint;
  semantic: SemanticSequence;
  capabilities: RopCapability[];
  module?: string;
  instructions: string[];
}

interface NormalizedChain {
  steps: ChainStep[];
  live: Map<string, GadgetDescriptor>;
  incompleteReasons: string[];
}

const DWORD_MODULUS = BigInt(0x1_0000_0000);

export function uint32Add(value: bigint, delta: number): bigint {
  const sum = (value + BigInt(delta)) % DWORD_MODULUS;
  return sum >= BigInt(0) ? sum : sum + DWORD_MODULUS;
}

function addressKey(address: bigint): string {
  return address.toString(16);
}

function gadgetsAt(corpus: CapabilityIndex | undefined, address: bigint): RopGadget[] {
  if (!corpus) return [];
  return corpus.gadgets.filter((gadget) => gadget.locations.some((location) =>
    location.virtualAddress !== undefined && BigInt(location.virtualAddress) === address));
}

function descriptorFromGadget(gadget: RopGadget, address: bigint): GadgetDescriptor {
  const location = gadget.locations.find((entry) =>
    entry.virtualAddress !== undefined && BigInt(entry.virtualAddress) === address);
  return {
    address,
    semantic: gadget.semanticSummary,
    capabilities: gadget.capabilities,
    module: location?.module,
    instructions: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText),
  };
}

function descriptorFromLive(address: bigint, instructions: string[]): GadgetDescriptor {
  const sequence = sequenceFromLiveHit({ address, mnemonic: instructions.join(" ; ") });
  const semantic = composeSemanticSequence(sequence);
  return {
    address,
    semantic,
    capabilities: deriveCapabilities(semantic, []),
    instructions: sequence.instructions.map((instruction) => instruction.normalizedText || instruction.originalText),
  };
}

function hasExactFlow(semantic: SemanticSequence): boolean {
  const flow = semantic.summary.flowEffects.values;
  return !flow.unknown && flow.conservative.size === 0 && flow.exact.size > 0;
}

function normalizeChain(input: ProofPlanInput, adapter: ProofDebuggerAdapter): NormalizedChain {
  if (Array.isArray(input.chain)) {
    return { steps: input.chain.map((step) => ({ ...step })), live: new Map(), incompleteReasons: [] };
  }

  const parsed = parseManualChain(input.chain);
  const live = new Map<string, GadgetDescriptor>();
  const incompleteReasons: string[] = [];
  const steps = parsed.map((step, index): ChainStep => {
    if (step.value === undefined) return step;
    const address = BigInt(step.value >>> 0);
    const matches = gadgetsAt(input.corpus, address);
    if (matches.length === 1) {
      return { kind: "gadget", address, comment: `manual gadget ${index}` };
    }
    if (matches.length > 1) {
      incompleteReasons.push(`manual DWORD ${index} at 0x${address.toString(16)} is ambiguous in the corpus`);
      return step;
    }

    const disassembly = adapter.disassemble(address, 16);
    if (disassembly.ok && disassembly.value.instructions.length > 0) {
      const descriptor = descriptorFromLive(address, disassembly.value.instructions);
      if (hasExactFlow(descriptor.semantic)) {
        live.set(addressKey(address), descriptor);
        return { kind: "gadget", address, comment: `manual live gadget ${index}` };
      }
    }
    return step;
  });

  return { steps, live, incompleteReasons };
}

function descriptorFor(
  step: ChainStep,
  corpus: CapabilityIndex | undefined,
  live: Map<string, GadgetDescriptor>,
): GadgetDescriptor | undefined {
  if (step.kind !== "gadget" || step.address === undefined) return undefined;
  const matches = gadgetsAt(corpus, step.address);
  if (matches.length === 1) return descriptorFromGadget(matches[0], step.address);
  return live.get(addressKey(step.address));
}

function proofExpression(expr: RegisterExpr, targetRegister: string): ProofValueExpression {
  if (expr.kind === "unknown") return { kind: "unknown", reason: `unknown ${targetRegister} transform` };
  if (expr.kind === "constant") return { kind: "constant", value: BigInt(expr.value >>> 0) };
  if (expr.kind === "memory") {
    return { kind: "memory-dword", address: proofExpression(expr.address, targetRegister) };
  }

  if (expr.offset.kind !== "constant") {
    return { kind: "unknown", reason: `${targetRegister} has a register-dependent offset` };
  }
  if (expr.base === "none") {
    return { kind: "constant", value: uint32Add(BigInt(0), expr.offset.value) };
  }
  const register = expr.base === "self" ? targetRegister : expr.base;
  return expr.offset.value === 0
    ? { kind: "register", register, checkpoint: "before" }
    : { kind: "register-offset", register, checkpoint: "before", offset: expr.offset.value };
}

function isIdentityExpression(expression: ProofValueExpression, register: string): boolean {
  return expression.kind === "register"
    && expression.register === register
    && expression.checkpoint === "before";
}

function transitionAssertions(semantic: SemanticSequence): ProofAssertionTemplate[] {
  const assertions: ProofAssertionTemplate[] = [];
  for (const [register, transform] of Object.entries(semantic.summary.registerTransforms)) {
    const expected = proofExpression(transform, register);
    if (isIdentityExpression(expected, register)) continue;
    const exact = expected.kind !== "unknown";
    assertions.push({
      subject: register.toUpperCase(),
      expected,
      confidence: exact ? "EXACT" : "UNKNOWN",
      evidence: semantic.instructionSemantics.flatMap((entry) => entry.evidence),
      required: register === "esp" || exact,
    });
  }
  return assertions.sort((left, right) => {
    if (left.subject === "ESP") return -1;
    if (right.subject === "ESP") return 1;
    return left.subject.localeCompare(right.subject);
  });
}

function provenance(...descriptors: GadgetDescriptor[]): ProofCheckpoint["provenance"] {
  return descriptors.map((descriptor) => ({
    address: descriptor.address,
    module: descriptor.module,
    instructions: descriptor.instructions,
  }));
}

function capability(descriptor: GadgetDescriptor, kind: RopCapability["kind"]): RopCapability | undefined {
  return descriptor.capabilities.find((entry) => entry.kind === kind);
}

function combineSemantics(first: GadgetDescriptor, second: GadgetDescriptor): SemanticSequence {
  const sequence = {
    ...first.semantic.instructionSequence,
    id: `${first.semantic.instructionSequence.id}+${second.semantic.instructionSequence.id}`,
    originalText: `${first.semantic.instructionSequence.originalText} ; ${second.semantic.instructionSequence.originalText}`,
    instructions: [
      ...first.semantic.instructionSequence.instructions,
      ...second.semantic.instructionSequence.instructions,
    ],
  };
  return composeSemanticSequence(sequence);
}

function memoryReadTarget(descriptor: GadgetDescriptor, register: string): ProofValueExpression | undefined {
  const transform = descriptor.semantic.summary.registerTransforms[register as keyof typeof descriptor.semantic.summary.registerTransforms];
  if (!transform || transform.kind !== "memory") return undefined;
  const address = proofExpression(transform.address, register);
  return address.kind === "unknown" ? undefined : { kind: "memory-dword", address };
}

function pivotTarget(descriptor: GadgetDescriptor): { target: ProofValueExpression; assertions: ProofAssertionTemplate[] } | undefined {
  const flow = descriptor.semantic.summary.flowEffects.values;
  if (flow.unknown || !flow.exact.has("RETURN")) return undefined;
  const espTransform = descriptor.semantic.summary.registerTransforms.esp;
  const finalEsp = proofExpression(espTransform, "esp");
  if (finalEsp.kind !== "register" && finalEsp.kind !== "register-offset") return undefined;
  if (finalEsp.register === "esp") return undefined;

  const last = descriptor.semantic.instructionSemantics[descriptor.semantic.instructionSemantics.length - 1];
  if (!last || last.stackDelta.values.unknown || last.stackDelta.values.exact.size !== 1) return undefined;
  const returnDelta = [...last.stackDelta.values.exact][0];
  const targetAddress: ProofValueExpression = finalEsp.kind === "register"
    ? { kind: "register-offset", register: finalEsp.register, checkpoint: "before", offset: -returnDelta }
    : finalEsp.offset === returnDelta
      ? { kind: "register", register: finalEsp.register, checkpoint: "before" }
      : { kind: "register-offset", register: finalEsp.register, checkpoint: "before", offset: finalEsp.offset - returnDelta };
  return {
    target: { kind: "memory-dword", address: targetAddress },
    assertions: transitionAssertions(descriptor.semantic),
  };
}

function semanticIncomplete(descriptor: GadgetDescriptor): boolean {
  return descriptor.semantic.summary.flowEffects.values.unknown
    || descriptor.semantic.summary.stackDelta.values.unknown
    || descriptor.semantic.instructionSemantics.some((entry) => !entry.supported);
}

export function buildProofPlan(input: ProofPlanInput, adapter: ProofDebuggerAdapter): ProofPlan {
  const normalized = normalizeChain(input, adapter);
  const incompleteReasons = [...normalized.incompleteReasons];
  const descriptors = normalized.steps
    .map((step, stepIndex) => ({ stepIndex, descriptor: descriptorFor(step, input.corpus, normalized.live) }))
    .filter((entry): entry is { stepIndex: number; descriptor: GadgetDescriptor } => entry.descriptor !== undefined);
  const checkpoints: ProofCheckpoint[] = [];
  let incoming: ProofAssertionTemplate[] = [];
  let targetOverride: ProofValueExpression | undefined;

  for (let position = 0; position < descriptors.length; position += 1) {
    const current = descriptors[position];
    const descriptor = current.descriptor;
    checkpoints.push({
      id: checkpoints.length,
      stepIndex: current.stepIndex,
      label: normalized.steps[current.stepIndex].comment,
      target: targetOverride ?? { kind: "constant", value: descriptor.address },
      assertions: incoming,
      provenance: provenance(descriptor),
      dynamic: targetOverride !== undefined,
    });
    targetOverride = undefined;
    incoming = [];

    if (semanticIncomplete(descriptor)) {
      incompleteReasons.push(`gadget at 0x${descriptor.address.toString(16)} has unknown semantics`);
    }

    const next = descriptors[position + 1];
    const memoryRead = capability(descriptor, "MEMORY_READ") ?? capability(descriptor, "LOAD_MEMORY");
    const dispatch = next
      ? capability(next.descriptor, "DISPATCH_JMP_REGISTER")
      : undefined;
    if (next && memoryRead?.register && dispatch?.register === memoryRead.register) {
      const target = memoryReadTarget(descriptor, memoryRead.register);
      if (!target) {
        incompleteReasons.push(`IAT dispatch at 0x${descriptor.address.toString(16)} has an unresolved memory target`);
        break;
      }
      const combined = combineSemantics(descriptor, next.descriptor);
      checkpoints.push({
        id: checkpoints.length,
        stepIndex: next.stepIndex,
        label: `${input.api ?? "resolved"} API entry`,
        target,
        assertions: transitionAssertions(combined),
        provenance: provenance(descriptor, next.descriptor),
        dynamic: true,
      });
      position += 1;
      continue;
    }

    const pivot = pivotTarget(descriptor);
    if (pivot) {
      if (next) {
        targetOverride = pivot.target;
        incoming = pivot.assertions;
      } else {
        checkpoints.push({
          id: checkpoints.length,
          stepIndex: current.stepIndex,
          label: "pivot target",
          target: pivot.target,
          assertions: pivot.assertions,
          provenance: provenance(descriptor),
          dynamic: true,
        });
      }
      continue;
    }

    incoming = transitionAssertions(descriptor.semantic);
  }

  return {
    steps: normalized.steps,
    checkpoints,
    api: input.api,
    incompleteReasons,
  };
}
