import { ValidationFlags } from "../core/registry";

export type GadgetPattern = {
  name: string;
  bytes: number[];
  mnemonic: string;
};

export type InstructionValidationResult = {
  flags: ValidationFlags;
  mnemonic?: string;
};

const KNOWN_PATTERNS: GadgetPattern[] = [
  // plain ret — useful as a RET-slide dispatcher in PUSHAD DEP-bypass chains
  { name: "ret", bytes: [0xc3], mnemonic: "ret" },
  // pop-register ; ret — all 8 general-purpose registers
  { name: "pop_eax_ret", bytes: [0x58, 0xc3], mnemonic: "pop eax ; ret" },
  { name: "pop_ecx_ret", bytes: [0x59, 0xc3], mnemonic: "pop ecx ; ret" },
  { name: "pop_edx_ret", bytes: [0x5a, 0xc3], mnemonic: "pop edx ; ret" },
  { name: "pop_ebx_ret", bytes: [0x5b, 0xc3], mnemonic: "pop ebx ; ret" },
  { name: "pop_esp_ret", bytes: [0x5c, 0xc3], mnemonic: "pop esp ; ret" },
  { name: "pop_ebp_ret", bytes: [0x5d, 0xc3], mnemonic: "pop ebp ; ret" },
  { name: "pop_esi_ret", bytes: [0x5e, 0xc3], mnemonic: "pop esi ; ret" },
  { name: "pop_edi_ret", bytes: [0x5f, 0xc3], mnemonic: "pop edi ; ret" },
  // Stack pivots
  { name: "push_esp_ret", bytes: [0x54, 0xc3], mnemonic: "push esp ; ret" },
  { name: "leave_ret", bytes: [0xc9, 0xc3], mnemonic: "leave ; ret" },
  { name: "xchg_eax_esp_ret", bytes: [0x94, 0xc3], mnemonic: "xchg eax, esp ; ret" },
  { name: "xchg_ecx_esp_ret", bytes: [0x87, 0xcc, 0xc3], mnemonic: "xchg ecx, esp ; ret" },
  { name: "xchg_edx_esp_ret", bytes: [0x87, 0xd4, 0xc3], mnemonic: "xchg edx, esp ; ret" },
  { name: "xchg_ebx_esp_ret", bytes: [0x87, 0xdc, 0xc3], mnemonic: "xchg ebx, esp ; ret" },
  { name: "xchg_esi_esp_ret", bytes: [0x87, 0xf4, 0xc3], mnemonic: "xchg esi, esp ; ret" },
  { name: "xchg_edi_esp_ret", bytes: [0x87, 0xfc, 0xc3], mnemonic: "xchg edi, esp ; ret" },
  { name: "xchg_ebp_esp_ret", bytes: [0x87, 0xec, 0xc3], mnemonic: "xchg ebp, esp ; ret" },
  { name: "mov_esp_ebp_ret", bytes: [0x8b, 0xe5, 0xc3], mnemonic: "mov esp, ebp ; ret" },
  { name: "mov_esp_eax_ret", bytes: [0x89, 0xc4, 0xc3], mnemonic: "mov esp, eax ; ret" },
  // Direct register jumps — primary shellcode dispatch gadgets
  { name: "jmp_esp",  bytes: [0xff, 0xe4], mnemonic: "jmp esp" },
  { name: "call_esp", bytes: [0xff, 0xd4], mnemonic: "call esp" },
  { name: "jmp_eax",  bytes: [0xff, 0xe0], mnemonic: "jmp eax" },
  { name: "call_eax", bytes: [0xff, 0xd0], mnemonic: "call eax" },
  // inc reg ; ret — one-byte x86 encodings (0x40–0x47)
  { name: "inc_eax_ret", bytes: [0x40, 0xc3], mnemonic: "inc eax ; ret" },
  { name: "inc_ecx_ret", bytes: [0x41, 0xc3], mnemonic: "inc ecx ; ret" },
  { name: "inc_edx_ret", bytes: [0x42, 0xc3], mnemonic: "inc edx ; ret" },
  { name: "inc_ebx_ret", bytes: [0x43, 0xc3], mnemonic: "inc ebx ; ret" },
  { name: "inc_esp_ret", bytes: [0x44, 0xc3], mnemonic: "inc esp ; ret" },
  { name: "inc_ebp_ret", bytes: [0x45, 0xc3], mnemonic: "inc ebp ; ret" },
  { name: "inc_esi_ret", bytes: [0x46, 0xc3], mnemonic: "inc esi ; ret" },
  { name: "inc_edi_ret", bytes: [0x47, 0xc3], mnemonic: "inc edi ; ret" },
  // dec reg ; ret — one-byte x86 encodings (0x48–0x4F)
  { name: "dec_eax_ret", bytes: [0x48, 0xc3], mnemonic: "dec eax ; ret" },
  { name: "dec_ecx_ret", bytes: [0x49, 0xc3], mnemonic: "dec ecx ; ret" },
  { name: "dec_edx_ret", bytes: [0x4a, 0xc3], mnemonic: "dec edx ; ret" },
  { name: "dec_ebx_ret", bytes: [0x4b, 0xc3], mnemonic: "dec ebx ; ret" },
  { name: "dec_esp_ret", bytes: [0x4c, 0xc3], mnemonic: "dec esp ; ret" },
  { name: "dec_ebp_ret", bytes: [0x4d, 0xc3], mnemonic: "dec ebp ; ret" },
  { name: "dec_esi_ret", bytes: [0x4e, 0xc3], mnemonic: "dec esi ; ret" },
  { name: "dec_edi_ret", bytes: [0x4f, 0xc3], mnemonic: "dec edi ; ret" },
  // neg reg ; ret — opcode F7 /3 (ModRM D8–DF)
  { name: "neg_eax_ret", bytes: [0xf7, 0xd8, 0xc3], mnemonic: "neg eax ; ret" },
  { name: "neg_ecx_ret", bytes: [0xf7, 0xd9, 0xc3], mnemonic: "neg ecx ; ret" },
  { name: "neg_edx_ret", bytes: [0xf7, 0xda, 0xc3], mnemonic: "neg edx ; ret" },
  { name: "neg_ebx_ret", bytes: [0xf7, 0xdb, 0xc3], mnemonic: "neg ebx ; ret" },
  { name: "neg_esp_ret", bytes: [0xf7, 0xdc, 0xc3], mnemonic: "neg esp ; ret" },
  { name: "neg_ebp_ret", bytes: [0xf7, 0xdd, 0xc3], mnemonic: "neg ebp ; ret" },
  { name: "neg_esi_ret", bytes: [0xf7, 0xde, 0xc3], mnemonic: "neg esi ; ret" },
  { name: "neg_edi_ret", bytes: [0xf7, 0xdf, 0xc3], mnemonic: "neg edi ; ret" },
  // pushad ; ret — push all 8 GP regs (PUSHAD VirtualProtect DEP bypass technique)
  { name: "pushad_ret", bytes: [0x60, 0xc3], mnemonic: "pushad ; ret" },
];

const X64_PATTERNS: GadgetPattern[] = [
  { name: "ret", bytes: [0xc3], mnemonic: "ret" },
  { name: "pop_rax_ret", bytes: [0x58, 0xc3], mnemonic: "pop rax ; ret" },
  { name: "pop_rcx_ret", bytes: [0x59, 0xc3], mnemonic: "pop rcx ; ret" },
  { name: "pop_rdx_ret", bytes: [0x5a, 0xc3], mnemonic: "pop rdx ; ret" },
  { name: "pop_rbx_ret", bytes: [0x5b, 0xc3], mnemonic: "pop rbx ; ret" },
  { name: "pop_rsp_ret", bytes: [0x5c, 0xc3], mnemonic: "pop rsp ; ret" },
  { name: "pop_rbp_ret", bytes: [0x5d, 0xc3], mnemonic: "pop rbp ; ret" },
  { name: "pop_rsi_ret", bytes: [0x5e, 0xc3], mnemonic: "pop rsi ; ret" },
  { name: "pop_rdi_ret", bytes: [0x5f, 0xc3], mnemonic: "pop rdi ; ret" },
  { name: "pop_r8_ret", bytes: [0x41, 0x58, 0xc3], mnemonic: "pop r8 ; ret" },
  { name: "pop_r9_ret", bytes: [0x41, 0x59, 0xc3], mnemonic: "pop r9 ; ret" },
  { name: "pop_r10_ret", bytes: [0x41, 0x5a, 0xc3], mnemonic: "pop r10 ; ret" },
  { name: "pop_r11_ret", bytes: [0x41, 0x5b, 0xc3], mnemonic: "pop r11 ; ret" },
  { name: "pop_r12_ret", bytes: [0x41, 0x5c, 0xc3], mnemonic: "pop r12 ; ret" },
  { name: "pop_r13_ret", bytes: [0x41, 0x5d, 0xc3], mnemonic: "pop r13 ; ret" },
  { name: "pop_r14_ret", bytes: [0x41, 0x5e, 0xc3], mnemonic: "pop r14 ; ret" },
  { name: "pop_r15_ret", bytes: [0x41, 0x5f, 0xc3], mnemonic: "pop r15 ; ret" },
  { name: "jmp_rsp", bytes: [0xff, 0xe4], mnemonic: "jmp rsp" },
  { name: "call_rsp", bytes: [0xff, 0xd4], mnemonic: "call rsp" },
  { name: "jmp_rax", bytes: [0xff, 0xe0], mnemonic: "jmp rax" },
  { name: "call_rax", bytes: [0xff, 0xd0], mnemonic: "call rax" },
  { name: "push_rsp_ret", bytes: [0x54, 0xc3], mnemonic: "push rsp ; ret" },
  { name: "leave_ret", bytes: [0xc9, 0xc3], mnemonic: "leave ; ret" },
  { name: "xchg_rax_rsp_ret", bytes: [0x48, 0x94, 0xc3], mnemonic: "xchg rax, rsp ; ret" },
  { name: "xchg_rcx_rsp_ret", bytes: [0x48, 0x87, 0xcc, 0xc3], mnemonic: "xchg rcx, rsp ; ret" },
  { name: "xchg_rdx_rsp_ret", bytes: [0x48, 0x87, 0xd4, 0xc3], mnemonic: "xchg rdx, rsp ; ret" },
  { name: "xchg_rbx_rsp_ret", bytes: [0x48, 0x87, 0xdc, 0xc3], mnemonic: "xchg rbx, rsp ; ret" },
  { name: "xchg_rbp_rsp_ret", bytes: [0x48, 0x87, 0xec, 0xc3], mnemonic: "xchg rbp, rsp ; ret" },
  { name: "xchg_rsi_rsp_ret", bytes: [0x48, 0x87, 0xf4, 0xc3], mnemonic: "xchg rsi, rsp ; ret" },
  { name: "xchg_rdi_rsp_ret", bytes: [0x48, 0x87, 0xfc, 0xc3], mnemonic: "xchg rdi, rsp ; ret" },
  { name: "mov_rsp_rbp_ret", bytes: [0x48, 0x89, 0xec, 0xc3], mnemonic: "mov rsp, rbp ; ret" },
  { name: "mov_rsp_rax_ret", bytes: [0x48, 0x89, 0xc4, 0xc3], mnemonic: "mov rsp, rax ; ret" },
];

const POP_REGS: Array<{ code: number; name: string }> = [
  { code: 0x58, name: "eax" },
  { code: 0x59, name: "ecx" },
  { code: 0x5a, name: "edx" },
  { code: 0x5b, name: "ebx" },
  { code: 0x5c, name: "esp" },
  { code: 0x5d, name: "ebp" },
  { code: 0x5e, name: "esi" },
  { code: 0x5f, name: "edi" },
];

function buildPprPatterns(): GadgetPattern[] {
  const patterns: GadgetPattern[] = [];
  for (const first of POP_REGS) {
    for (const second of POP_REGS) {
      patterns.push({
        name: `pop_${first.name}_pop_${second.name}_ret`,
        bytes: [first.code, second.code, 0xc3],
        mnemonic: `pop ${first.name} ; pop ${second.name} ; ret`,
      });
    }
  }
  return patterns;
}

// mov [dst], src ; ret — opcode 89 /r, mod=00 (register-to-memory, no displacement)
// Encodeable destinations with mod=00: EAX(0),ECX(1),EDX(2),EBX(3),ESI(6),EDI(7)
// ESP(4) requires SIB; EBP(5) with mod=00 means disp32 — both excluded.
function buildWritePatterns(): GadgetPattern[] {
  const dsts = [
    { rm: 0, name: "eax" }, { rm: 1, name: "ecx" }, { rm: 2, name: "edx" },
    { rm: 3, name: "ebx" }, { rm: 6, name: "esi" }, { rm: 7, name: "edi" },
  ];
  const srcs = [
    { code: 0, name: "eax" }, { code: 1, name: "ecx" }, { code: 2, name: "edx" },
    { code: 3, name: "ebx" }, { code: 4, name: "esp" }, { code: 5, name: "ebp" },
    { code: 6, name: "esi" }, { code: 7, name: "edi" },
  ];
  const patterns: GadgetPattern[] = [];
  for (const dst of dsts) {
    for (const src of srcs) {
      const modRM = (src.code << 3) | dst.rm; // mod=00 implicit
      patterns.push({
        name: `mov_mem_${dst.name}_${src.name}_ret`,
        bytes: [0x89, modRM, 0xc3],
        mnemonic: `mov [${dst.name}], ${src.name} ; ret`,
      });
    }
  }
  return patterns;
}

const ALL_PATTERNS: GadgetPattern[] = [...KNOWN_PATTERNS, ...buildPprPatterns(), ...buildWritePatterns()];

function sameBytes(left: Uint8Array, right: number[]): boolean {
  if (left.length !== right.length) {
    return false;
  }

  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) {
      return false;
    }
  }

  return true;
}

export function knownPatterns(): GadgetPattern[] {
  return ALL_PATTERNS;
}

export function knownPatternsForPointerSize(pointerSize: 4 | 8): GadgetPattern[] {
  return pointerSize === 8 ? X64_PATTERNS : ALL_PATTERNS;
}

export function validateInstructionCandidate(
  candidateBytes: Uint8Array,
  executable: boolean,
  moduleBacked: boolean,
): InstructionValidationResult {
  const matched = ALL_PATTERNS.find((pattern) => sameBytes(candidateBytes, pattern.bytes));

  return {
    flags: {
      executable,
      moduleBacked,
      decoded: matched !== undefined,
      mnemonicMatch: matched !== undefined,
      badcharSafe: true,
    },
    mnemonic: matched?.mnemonic,
  };
}

export function validateInstructionCandidateForPointerSize(
  candidateBytes: Uint8Array,
  executable: boolean,
  moduleBacked: boolean,
  pointerSize: 4 | 8,
): InstructionValidationResult {
  const patterns = knownPatternsForPointerSize(pointerSize);
  const matched = patterns.find((pattern) => sameBytes(candidateBytes, pattern.bytes));

  return {
    flags: {
      executable,
      moduleBacked,
      decoded: matched !== undefined,
      mnemonicMatch: matched !== undefined,
      badcharSafe: true,
    },
    mnemonic: matched?.mnemonic,
  };
}
