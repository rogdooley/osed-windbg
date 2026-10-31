export type ArchId = "x86" | "x64";

export interface ArchConfig {
  id: ArchId;
  pointerSize: 4 | 8;
  stackEntrySize: number;
  stackPointer: string;
  instructionPointer: string;
  basePointer: string;
  generalPurposeRegisters: readonly string[];
  allRegisters: readonly string[];
  volatileRegisters: readonly string[];
  nonvolatileRegisters: readonly string[];
  callingConventionArgRegisters: readonly string[];
  shadowSpaceBytes: number;
  stackAlignmentBytes: number;
  addressWidth: number;
  subregisterParent: Record<string, string>;
}

const X86_SUBREGISTER_PARENT: Record<string, string> = {
  ax: "eax", al: "eax", ah: "eax",
  bx: "ebx", bl: "ebx", bh: "ebx",
  cx: "ecx", cl: "ecx", ch: "ecx",
  dx: "edx", dl: "edx", dh: "edx",
  si: "esi", di: "edi", bp: "ebp", sp: "esp",
};

const X64_SUBREGISTER_PARENT: Record<string, string> = {
  rax: "rax", eax: "rax", ax: "rax", al: "rax", ah: "rax",
  rbx: "rbx", ebx: "rbx", bx: "rbx", bl: "rbx", bh: "rbx",
  rcx: "rcx", ecx: "rcx", cx: "rcx", cl: "rcx", ch: "rcx",
  rdx: "rdx", edx: "rdx", dx: "rdx", dl: "rdx", dh: "rdx",
  rsi: "rsi", esi: "rsi", si: "rsi", sil: "rsi",
  rdi: "rdi", edi: "rdi", di: "rdi", dil: "rdi",
  rbp: "rbp", ebp: "rbp", bp: "rbp", bpl: "rbp",
  rsp: "rsp", esp: "rsp", sp: "rsp", spl: "rsp",
  r8: "r8", r8d: "r8", r8w: "r8", r8b: "r8",
  r9: "r9", r9d: "r9", r9w: "r9", r9b: "r9",
  r10: "r10", r10d: "r10", r10w: "r10", r10b: "r10",
  r11: "r11", r11d: "r11", r11w: "r11", r11b: "r11",
  r12: "r12", r12d: "r12", r12w: "r12", r12b: "r12",
  r13: "r13", r13d: "r13", r13w: "r13", r13b: "r13",
  r14: "r14", r14d: "r14", r14w: "r14", r14b: "r14",
  r15: "r15", r15d: "r15", r15w: "r15", r15b: "r15",
};

const X86_GP_REGISTERS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"] as const;
const X64_GP_REGISTERS = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
] as const;

const X86_CONFIG: ArchConfig = {
  id: "x86",
  pointerSize: 4,
  stackEntrySize: 4,
  stackPointer: "esp",
  instructionPointer: "eip",
  basePointer: "ebp",
  generalPurposeRegisters: X86_GP_REGISTERS,
  allRegisters: [...X86_GP_REGISTERS, "eip", "eflags"],
  volatileRegisters: ["eax", "ecx", "edx"],
  nonvolatileRegisters: ["ebx", "esi", "edi", "ebp"],
  callingConventionArgRegisters: [],
  shadowSpaceBytes: 0,
  stackAlignmentBytes: 4,
  addressWidth: 8,
  subregisterParent: X86_SUBREGISTER_PARENT,
};

const X64_CONFIG: ArchConfig = {
  id: "x64",
  pointerSize: 8,
  stackEntrySize: 8,
  stackPointer: "rsp",
  instructionPointer: "rip",
  basePointer: "rbp",
  generalPurposeRegisters: X64_GP_REGISTERS,
  allRegisters: [...X64_GP_REGISTERS, "rip", "rflags"],
  volatileRegisters: ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"],
  nonvolatileRegisters: ["rbx", "rsi", "rdi", "rbp", "r12", "r13", "r14", "r15"],
  callingConventionArgRegisters: ["rcx", "rdx", "r8", "r9"],
  shadowSpaceBytes: 32,
  stackAlignmentBytes: 16,
  addressWidth: 16,
  subregisterParent: X64_SUBREGISTER_PARENT,
};

function tryGetPointerSize(): 4 | 8 {
  try {
    const process = (typeof host !== "undefined" ? host : undefined) as unknown as
      { currentProcess?: { Is64Bit?: boolean; Machine?: string } } | undefined;
    const proc = process?.currentProcess;
    const machine = (proc?.Machine ?? "").toLowerCase();
    if (proc?.Is64Bit || machine.includes("x64") || machine.includes("amd64")) {
      return 8;
    }
  } catch { /* not in WinDbg */ }
  return 4;
}

export function getArchConfig(pointerSize?: 4 | 8): ArchConfig {
  const size = pointerSize ?? tryGetPointerSize();
  return size === 8 ? X64_CONFIG : X86_CONFIG;
}

export function detectArch(): ArchId {
  return tryGetPointerSize() === 8 ? "x64" : "x86";
}

export function isStackPointer(reg: string, arch?: ArchConfig): boolean {
  const config = arch ?? getArchConfig();
  const normalized = reg.toLowerCase();
  return normalized === config.stackPointer
    || (config.id === "x64" && normalized === "esp")
    || (config.id === "x86" && normalized === "esp");
}

export function isBasePointer(reg: string, arch?: ArchConfig): boolean {
  const config = arch ?? getArchConfig();
  const normalized = reg.toLowerCase();
  return normalized === config.basePointer
    || (config.id === "x64" && normalized === "ebp");
}

export function normalizeRegisterForArch(reg: string, arch?: ArchConfig): string {
  const config = arch ?? getArchConfig();
  const normalized = reg.toLowerCase();
  return config.subregisterParent[normalized] ?? normalized;
}

export function isGPRegister(reg: string, arch?: ArchConfig): boolean {
  const config = arch ?? getArchConfig();
  const normalized = normalizeRegisterForArch(reg, config);
  return (config.generalPurposeRegisters as readonly string[]).includes(normalized);
}

export function isVolatile(reg: string, arch?: ArchConfig): boolean {
  const config = arch ?? getArchConfig();
  const normalized = normalizeRegisterForArch(reg, config);
  return config.volatileRegisters.includes(normalized);
}

export function isNonvolatile(reg: string, arch?: ArchConfig): boolean {
  const config = arch ?? getArchConfig();
  const normalized = normalizeRegisterForArch(reg, config);
  return config.nonvolatileRegisters.includes(normalized);
}

export function formatHexForArch(value: number | bigint, arch?: ArchConfig): string {
  const config = arch ?? getArchConfig();
  if (typeof value === "bigint") {
    return `0x${value.toString(16).toUpperCase().padStart(config.addressWidth, "0")}`;
  }
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(config.pointerSize * 2, "0")}`;
}

export function x64ArgCount(strategy: string): number {
  const counts: Record<string, number> = {
    VirtualProtect: 4,
    VirtualAlloc: 4,
    WriteProcessMemory: 5,
    VirtualProtectEx: 5,
    VirtualAllocEx: 5,
    WinExec: 2,
    LoadLibraryA: 1,
    GetProcAddress: 2,
  };
  return counts[strategy] ?? 0;
}
