#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(_M_IX86)
#error Build this validation target with MSVC -A Win32.
#endif

__declspec(dllexport) __declspec(naked) void proof_pop_eax_ret(void) {
    __asm {
        pop eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void proof_ret_8(void) {
    __asm {
        ret 8
    }
}

__declspec(dllexport) __declspec(naked) void proof_pivot_eax(void) {
    __asm {
        xchg eax, esp
        ret
    }
}

__declspec(dllexport) __declspec(naked) void proof_deref_eax(void) {
    __asm {
        mov eax, dword ptr [eax]
        ret
    }
}

__declspec(dllexport) __declspec(naked) void proof_jmp_eax(void) {
    __asm {
        jmp eax
    }
}

__declspec(dllexport) FARPROC proof_virtual_protect_import(void) {
    return GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect");
}

int main(void) {
    DWORD old_protect = 0;
    unsigned char *page = (unsigned char *)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }
    page[0] = 0xC3;
    printf("pid=%lu page=%p VirtualProtect=%p\n", GetCurrentProcessId(), (void *)page, (void *)proof_virtual_protect_import());
    printf("Attach WinDbg, set up the documented proof chain, then press Enter.\n");
    (void)getchar();
    if (!VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &old_protect)) {
        fprintf(stderr, "VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(page, 0, MEM_RELEASE);
        return 2;
    }
    printf("page=%p is now PAGE_EXECUTE_READ; press Enter to exit.\n", (void *)page);
    (void)getchar();
    VirtualFree(page, 0, MEM_RELEASE);
    return 0;
}
