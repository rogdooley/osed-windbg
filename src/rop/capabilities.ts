import { SemanticSequence } from "../semantics/types";
import { AnalysisReason, CapabilityKind, RopCapability, RopGadget, RopIndex, RopCategory, RopQuery } from "./types";
import { queryRopGadgets, summarizeCapabilities } from "./query";

export interface CapabilityIndex {
  gadgets: RopGadget[];
  loadRegister(register: string): RopGadget[];
  zeroRegister(register: string): RopGadget[];
  moveIntoRegister(register: string): RopGadget[];
  exchangeWithRegister(register: string): RopGadget[];
  stackPivotCandidates(): RopGadget[];
  memoryReadCandidates(): RopGadget[];
  memoryWriteCandidates(): RopGadget[];
  query(query: RopQuery): RopGadget[];
  capabilityMap: Map<string, RopGadget[]>;
}

function key(kind: CapabilityKind, register?: string, targetRegister?: string): string {
  return [kind, register ?? "", targetRegister ?? ""].join(":");
}

function push(map: Map<string, RopGadget[]>, capability: RopCapability, gadget: RopGadget): void {
  const k = key(capability.kind, capability.register, capability.targetRegister);
  const existing = map.get(k) ?? [];
  existing.push(gadget);
  map.set(k, existing);
}

export function buildCapabilities(gadgets: RopGadget[]): CapabilityIndex {
  const capabilityMap = new Map<string, RopGadget[]>();
  for (const gadget of gadgets) {
    for (const capability of gadget.capabilities) {
      push(capabilityMap, capability, gadget);
      if (capability.kind === "MOVE_REGISTER" && capability.targetRegister) {
        push(capabilityMap, { ...capability, register: undefined }, gadget);
      }
      if (capability.kind === "EXCHANGE_REGISTER" && capability.register) {
        push(capabilityMap, { ...capability, targetRegister: undefined }, gadget);
        if (capability.targetRegister) {
          push(capabilityMap, {
            kind: capability.kind,
            register: capability.targetRegister,
            targetRegister: capability.register,
            evidence: capability.evidence,
          }, gadget);
        }
      }
    }
  }

  return {
    gadgets,
    capabilityMap,
    loadRegister(register: string): RopGadget[] {
      return capabilityMap.get(key("LOAD_REGISTER", register)) ?? [];
    },
    zeroRegister(register: string): RopGadget[] {
      return capabilityMap.get(key("ZERO_REGISTER", register)) ?? [];
    },
    moveIntoRegister(register: string): RopGadget[] {
      return capabilityMap.get(key("MOVE_REGISTER", undefined, register)) ?? [];
    },
    exchangeWithRegister(register: string): RopGadget[] {
      return capabilityMap.get(key("EXCHANGE_REGISTER", register)) ?? [];
    },
    stackPivotCandidates(): RopGadget[] {
      return capabilityMap.get(key("STACK_PIVOT")) ?? [];
    },
    memoryReadCandidates(): RopGadget[] {
      return capabilityMap.get(key("MEMORY_READ")) ?? [];
    },
    memoryWriteCandidates(): RopGadget[] {
      return capabilityMap.get(key("MEMORY_WRITE")) ?? [];
    },
    query(query: RopQuery): RopGadget[] {
      return queryRopGadgets(gadgets, query);
    },
  };
}

export function deriveCapabilities(semantic: SemanticSequence, categories: RopCategory[]): RopCapability[] {
  const capabilities: RopCapability[] = [];
  const add = (capability: RopCapability): void => {
    const duplicate = capabilities.some((existing) =>
      existing.kind === capability.kind
      && existing.register === capability.register
      && existing.targetRegister === capability.targetRegister);
    if (!duplicate) {
      capabilities.push(capability);
    }
  };
  for (const step of semantic.instructionSemantics) {
    const text = step.instruction.normalizedText;
    const operands = step.instruction.operands.map((operand) => operand.trim().toLowerCase());
    if (step.instruction.mnemonic === "pop" && step.instruction.operands.length === 1) {
      add({ kind: "LOAD_REGISTER", register: operands[0], evidence: [text] });
      add({ kind: "LOAD_CONSTANT", register: operands[0], evidence: [text] });
      add({ kind: "STACK_READ", register: operands[0], evidence: [text] });
    }
    if (step.instruction.mnemonic === "push" && operands.length === 1) {
      add({ kind: "STACK_WRITE", register: operands[0], evidence: [text] });
    }
    if (step.instruction.mnemonic === "pushad") {
      add({ kind: "DISPATCH_PUSHAD", evidence: [text] });
      add({ kind: "STACK_WRITE", evidence: [text] });
    }
    if (step.instruction.mnemonic === "ret") {
      add({ kind: "DISPATCH_RET", evidence: [text] });
    }
    if (step.instruction.mnemonic === "xor" && operands.length === 2) {
      add({ kind: "REGISTER_XOR", register: operands[0], targetRegister: operands[1], evidence: [text] });
      if (operands[0] === operands[1]) {
        add({ kind: "ZERO_REGISTER", register: operands[0], evidence: [text] });
        add({ kind: "REGISTER_ZERO", register: operands[0], evidence: [text] });
      }
    }
    if (step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2) {
      const [left, right] = operands;
      if (/^[a-z]{3}$/.test(left) && /^[a-z]{3}$/.test(right) && left !== right) {
        add({ kind: "MOVE_REGISTER", register: left, targetRegister: right, evidence: [text] });
        add({ kind: "REGISTER_TRANSFER", register: left, targetRegister: right, evidence: [text] });
        if (left === "esp" || right === "esp") {
          add({ kind: "STACK_COPY", register: left, targetRegister: right, evidence: [text] });
        }
      }
      if (left.includes("[") && !right.includes("[")) {
        add({ kind: "MEMORY_WRITE", register: right, evidence: [text] });
        add({ kind: "STORE_MEMORY", register: right, evidence: [text] });
      }
      if (!left.includes("[") && right.includes("[")) {
        add({ kind: "MEMORY_READ", register: left, evidence: [text] });
        add({ kind: "LOAD_MEMORY", register: left, evidence: [text] });
      }
    }
    if (step.instruction.mnemonic === "xchg" && step.instruction.operands.length === 2) {
      const [left, right] = operands;
      if (left === "esp" || right === "esp") {
        add({ kind: "STACK_PIVOT", evidence: [text] });
      }
      add({ kind: "EXCHANGE_REGISTER", register: left, targetRegister: right, evidence: [text] });
      add({ kind: "REGISTER_SWAP", register: left, targetRegister: right, evidence: [text] });
    }
    const unaryKind = {
      neg: "REGISTER_NEGATE",
      inc: "REGISTER_INCREMENT",
      dec: "REGISTER_DECREMENT",
      not: "REGISTER_NOT",
    } as const;
    const unary = unaryKind[step.instruction.mnemonic as keyof typeof unaryKind];
    if (unary && operands.length === 1) {
      add({ kind: unary, register: operands[0], evidence: [text] });
    }
    const binaryKind = {
      add: "REGISTER_ADD",
      sub: "REGISTER_SUB",
      adc: "REGISTER_ADC",
      sbb: "REGISTER_SBB",
      or: "REGISTER_OR",
      and: "REGISTER_AND",
    } as const;
    const binary = binaryKind[step.instruction.mnemonic as keyof typeof binaryKind];
    if (binary && operands.length === 2) {
      add({ kind: binary, register: operands[0], targetRegister: operands[1], evidence: [text] });
      if (operands[0] === "esp") {
        add({ kind: "STACK_ADJUST", evidence: [text] });
      }
    }
    if (step.instruction.mnemonic === "call" && operands.length === 1) {
      add({
        kind: operands[0].includes("[") ? "DISPATCH_CALL_MEMORY" : "DISPATCH_CALL_REGISTER",
        register: operands[0].includes("[") ? undefined : operands[0],
        evidence: [text],
      });
    }
    if (step.instruction.mnemonic === "jmp" && operands.length === 1 && !operands[0].includes("[")) {
      add({ kind: "DISPATCH_JMP_REGISTER", register: operands[0], evidence: [text] });
    }
  }

  if (categories.includes("STACK_PIVOT")) {
    add({ kind: "STACK_PIVOT", evidence: ["category:STACK_PIVOT"] });
  }
  if (categories.includes("STACK_ADJUST")) {
    add({ kind: "STACK_ADJUST", evidence: ["category:STACK_ADJUST"] });
  }
  return capabilities;
}

export { summarizeCapabilities };
