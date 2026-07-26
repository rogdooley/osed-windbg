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
export type FeasibilityLevel = "capability-feasible" | "exploit-state-dependent";

export interface PlanningRequest {
  strategy: ExploitStrategy;
  apiResolution?: ApiResolutionMode;
}

export interface StrategyPlan {
  id: number;
  shape: ChainShape;
  possible: boolean;
  feasibility: FeasibilityLevel;
  recommended: boolean;
  complexity: PlanComplexity;
  required: CapabilityKind[];
  satisfied: CapabilityKind[];
  missing: CapabilityKind[];
  assumptions: string[];
  preconditions: string[];
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
  preconditions: string[];
  iatExempt?: boolean;
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
  const apiName = strategy === "Stack Pivot" ? "continuation" : strategy;

  if (strategy === "Stack Pivot") {
    return [
      {
        shape: "STACK_PIVOT_FRAME",
        complexity: "LOW",
        required: ["STACK_PIVOT", "DISPATCH_RET"],
        assumptions: [],
        preconditions: [
          "A controlled, writable memory region can hold the continuation frame.",
          "The pivot source register or memory contains a valid pointer to the controlled region.",
        ],
        iatExempt: true,
      },
    ];
  }

  return [
    {
      shape: "SYNTHETIC_STDCALL_FRAME",
      complexity: "LOW",
      required: ["DISPATCH_RET"],
      assumptions: [],
      preconditions: [
        "EIP is controlled (e.g. via SEH overwrite or saved return address).",
        `ESP points to or can reach a region with ${strategy === "WriteProcessMemory" ? "28" : "24"}+ contiguous controlled bytes.`,
        `${apiName} address is known or resolvable at exploit time.`,
        "All frame values are encodable under the current charset.",
      ],
      iatExempt: true,
    },
    {
      shape: "STACK_PIVOT_FRAME",
      complexity: "LOW",
      required: ["STACK_PIVOT", "DISPATCH_RET"],
      assumptions: [],
      preconditions: [
        "A controlled, writable memory region can hold the synthetic frame.",
        "The pivot source register or memory contains a valid pointer to the controlled region.",
        `${apiName} address is known or resolvable at exploit time.`,
      ],
      iatExempt: true,
    },
    {
      shape: "RET_DISPATCH",
      complexity: "LOW",
      required: ["DISPATCH_RET"],
      assumptions: [],
      preconditions: [
        "ESP points to a controlled region large enough for the stdcall frame.",
        `${apiName} address is encodable and placed at ESP when ret executes.`,
        "Stdcall arguments follow the API address on the stack.",
      ],
      iatExempt: true,
    },
    {
      shape: "PUSHAD_DISPATCH",
      complexity: "MEDIUM",
      required: ["LOAD_CONSTANT", "DISPATCH_PUSHAD"],
      assumptions: [],
      preconditions: [
        "Registers can be loaded with the required API arguments via pop gadgets.",
        `The PUSHAD stack layout matches the ${apiName} stdcall ABI.`,
        "ESP at pushad time points into the shellcode or NOP sled (used as lpAddress).",
      ],
    },
    {
      shape: "CALL_REGISTER",
      complexity: "HIGH",
      required: ["LOAD_CONSTANT", "DISPATCH_CALL_REGISTER"],
      assumptions: [],
      preconditions: [
        `The API address must be loaded into the dispatch register before call.`,
        `A valid stdcall frame for ${apiName} must exist at [ESP] when call executes (return addr is pushed by call).`,
        "The call target must not clobber registers or stack state needed by the API.",
      ],
    },
    {
      shape: "JMP_REGISTER",
      complexity: "HIGH",
      required: ["LOAD_CONSTANT", "DISPATCH_JMP_REGISTER"],
      assumptions: [],
      preconditions: [
        `The API address must be loaded into the dispatch register before jmp.`,
        `ESP must point to: [RETURN_ADDR][arg1][arg2]... since jmp does not push a return address.`,
        `The full ${apiName} stdcall frame must already be on the stack.`,
      ],
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
      ...(apiResolution === "iat" && !definition.iatExempt
        ? ["LOAD_MEMORY" as CapabilityKind]
        : []),
    ]);
    const satisfied = required.filter((capability) => availableSet.has(capability));
    const missing = required.filter((capability) => !availableSet.has(capability));
    const hasPreconditions = definition.preconditions.length > 0;
    return {
      id: offset + 1,
      shape: definition.shape,
      possible: missing.length === 0,
      feasibility: missing.length === 0 && hasPreconditions
        ? "exploit-state-dependent"
        : missing.length === 0
          ? "capability-feasible"
          : "exploit-state-dependent",
      recommended: false,
      complexity: definition.complexity,
      required,
      satisfied,
      missing,
      assumptions: definition.assumptions,
      preconditions: definition.preconditions,
      reason: missing.length === 0
        ? "All required capabilities present. Exploit-state preconditions must be verified."
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
    Feasibility: strategy.possible ? strategy.feasibility : "",
    Recommended: strategy.recommended ? "yes" : "",
    Complexity: strategy.complexity,
    Required: strategy.required.join(", "),
    Satisfied: strategy.satisfied.join(", "),
    Missing: strategy.missing.join(", "),
    Preconditions: strategy.preconditions.join(" | "),
    Reason: strategy.reason,
  }));
}
