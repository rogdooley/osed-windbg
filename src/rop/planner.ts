import { CapabilityIndex } from "./capabilities";
import { CapabilityKind } from "./types";

export type ExploitStrategy =
  | "VirtualProtect"
  | "VirtualAlloc"
  | "WriteProcessMemory"
  | "Stack Pivot";

export type ApiResolutionMode = "direct" | "iat";

export type ChainShape =
  | "SYNTHETIC_STDCALL_FRAME"
  | "STACK_PIVOT_FRAME"
  | "RET_DISPATCH"
  | "PUSHAD_DISPATCH"
  | "CALL_REGISTER"
  | "JMP_REGISTER";

export type PlanComplexity = "LOW" | "MEDIUM" | "HIGH";

export interface PlanningRequest {
  strategy: ExploitStrategy;
  apiResolution?: ApiResolutionMode;
}

export interface StrategyPlan {
  id: number;
  shape: ChainShape;
  possible: boolean;
  recommended: boolean;
  complexity: PlanComplexity;
  required: CapabilityKind[];
  satisfied: CapabilityKind[];
  missing: CapabilityKind[];
  assumptions: string[];
  reason: string;
}

export interface RopStrategyPlan {
  id: number;
  strategy: ExploitStrategy;
  apiResolution: ApiResolutionMode;
  corpusCapabilities: CapabilityKind[];
  strategies: StrategyPlan[];
}

interface ShapeDefinition {
  shape: ChainShape;
  complexity: PlanComplexity;
  required: CapabilityKind[];
  assumptions: string[];
}

const STRATEGY_NAMES = new Map<string, ExploitStrategy>([
  ["virtualprotect", "VirtualProtect"],
  ["virtualalloc", "VirtualAlloc"],
  ["writeprocessmemory", "WriteProcessMemory"],
  ["stackpivot", "Stack Pivot"],
  ["stack pivot", "Stack Pivot"],
]);

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function definitionsFor(strategy: ExploitStrategy): ShapeDefinition[] {
  if (strategy === "Stack Pivot") {
    return [
      {
        shape: "STACK_PIVOT_FRAME",
        complexity: "LOW",
        required: ["STACK_PIVOT", "DISPATCH_RET"],
        assumptions: ["A controlled stack region can hold the continuation frame."],
      },
    ];
  }

  return [
    {
      shape: "SYNTHETIC_STDCALL_FRAME",
      complexity: "LOW",
      required: ["DISPATCH_RET"],
      assumptions: ["The stack is writable and sufficiently controlled to place a flat stdcall frame."],
    },
    {
      shape: "STACK_PIVOT_FRAME",
      complexity: "LOW",
      required: ["STACK_PIVOT", "DISPATCH_RET"],
      assumptions: ["A writable controlled region can hold the synthetic frame."],
    },
    {
      shape: "RET_DISPATCH",
      complexity: "MEDIUM",
      required: ["LOAD_CONSTANT", "REGISTER_TRANSFER", "DISPATCH_RET"],
      assumptions: ["Required API arguments can be represented or synthesized without forbidden bytes."],
    },
    {
      shape: "PUSHAD_DISPATCH",
      complexity: "MEDIUM",
      required: ["LOAD_CONSTANT", "DISPATCH_PUSHAD"],
      assumptions: ["The target ABI and register layout are compatible with PUSHAD dispatch."],
    },
    {
      shape: "CALL_REGISTER",
      complexity: "HIGH",
      required: ["LOAD_CONSTANT", "DISPATCH_CALL_REGISTER"],
      assumptions: ["A usable return continuation exists after the call."],
    },
    {
      shape: "JMP_REGISTER",
      complexity: "HIGH",
      required: ["LOAD_CONSTANT", "DISPATCH_JMP_REGISTER"],
      assumptions: ["The selected API or dispatcher does not need an implicit return continuation."],
    },
  ];
}

export function normalizeExploitStrategy(value: string): ExploitStrategy | undefined {
  return STRATEGY_NAMES.get(value.trim().toLowerCase());
}

export function availableCapabilityKinds(index: CapabilityIndex): CapabilityKind[] {
  return unique(index.gadgets.flatMap((gadget) => gadget.capabilities.map((capability) => capability.kind))).sort();
}

export function planExploitStrategy(
  index: CapabilityIndex,
  request: PlanningRequest,
  planId = 1,
): RopStrategyPlan {
  const apiResolution = request.apiResolution ?? "direct";
  const available = availableCapabilityKinds(index);
  const availableSet = new Set<CapabilityKind>(available);
  const definitions = definitionsFor(request.strategy);

  const strategies = definitions.map((definition, offset): StrategyPlan => {
    const required = unique([
      ...definition.required,
      ...(apiResolution === "iat" && definition.shape !== "SYNTHETIC_STDCALL_FRAME"
        ? ["LOAD_MEMORY" as CapabilityKind]
        : []),
    ]);
    const satisfied = required.filter((capability) => availableSet.has(capability));
    const missing = required.filter((capability) => !availableSet.has(capability));
    return {
      id: offset + 1,
      shape: definition.shape,
      possible: missing.length === 0,
      recommended: false,
      complexity: definition.complexity,
      required,
      satisfied,
      missing,
      assumptions: definition.assumptions,
      reason: missing.length === 0
        ? "All required semantic capabilities exist in the corpus."
        : `Missing semantic capabilities: ${missing.join(", ")}.`,
    };
  });

  const recommendation = strategies.find((strategy) => strategy.possible);
  if (recommendation) {
    recommendation.recommended = true;
  }

  return {
    id: planId,
    strategy: request.strategy,
    apiResolution,
    corpusCapabilities: available,
    strategies,
  };
}

export function strategyPlanRows(plan: RopStrategyPlan): Array<Record<string, string>> {
  return plan.strategies.map((strategy) => ({
    Plan: plan.id.toString(),
    Strategy: plan.strategy,
    Shape: strategy.shape,
    Possible: strategy.possible ? "yes" : "no",
    Recommended: strategy.recommended ? "yes" : "",
    Complexity: strategy.complexity,
    Required: strategy.required.join(", "),
    Satisfied: strategy.satisfied.join(", "),
    Missing: strategy.missing.join(", "),
    Assumptions: strategy.assumptions.join(" "),
    Reason: strategy.reason,
  }));
}
