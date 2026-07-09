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
  for (const step of semantic.instructionSemantics) {
    const text = step.instruction.normalizedText;
    if (step.instruction.mnemonic === "pop" && step.instruction.operands.length === 1) {
      capabilities.push({ kind: "LOAD_REGISTER", register: step.instruction.operands[0].trim().toLowerCase(), evidence: [text] });
    }
    if (step.instruction.mnemonic === "xor" && step.instruction.operands.length === 2 && step.instruction.operands[0].trim().toLowerCase() === step.instruction.operands[1].trim().toLowerCase()) {
      capabilities.push({ kind: "ZERO_REGISTER", register: step.instruction.operands[0].trim().toLowerCase(), evidence: [text] });
    }
    if (step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2) {
      const left = step.instruction.operands[0].trim().toLowerCase();
      const right = step.instruction.operands[1].trim().toLowerCase();
      if (/^[a-z]{3}$/.test(left) && /^[a-z]{3}$/.test(right) && left !== right) {
        capabilities.push({ kind: "MOVE_REGISTER", register: left, targetRegister: right, evidence: [text] });
      }
      if (left.includes("[") && !right.includes("[")) {
        capabilities.push({ kind: "MEMORY_WRITE", evidence: [text] });
      }
      if (!left.includes("[") && right.includes("[")) {
        capabilities.push({ kind: "MEMORY_READ", evidence: [text] });
      }
    }
    if (step.instruction.mnemonic === "xchg" && step.instruction.operands.length === 2) {
      const left = step.instruction.operands[0].trim().toLowerCase();
      const right = step.instruction.operands[1].trim().toLowerCase();
      if (left === "esp" || right === "esp") {
        capabilities.push({ kind: "STACK_PIVOT", evidence: [text] });
      }
      capabilities.push({ kind: "EXCHANGE_REGISTER", register: left, targetRegister: right, evidence: [text] });
    }
  }

  if (categories.includes("STACK_PIVOT")) {
    capabilities.push({ kind: "STACK_PIVOT", evidence: ["category:STACK_PIVOT"] });
  }
  return capabilities;
}

export { summarizeCapabilities };
