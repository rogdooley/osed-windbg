import { describe, expect, test, it } from "vitest";
import { tryDecodeInsn } from "../src/core/backward_scanner";

describe("backward scanner instruction decoder", () => {
  function decode(bytes: number[]): string | undefined {
    return tryDecodeInsn(Uint8Array.from(bytes), 0)?.mnemonic;
  }
  function decodeLen(bytes: number[]): number | undefined {
    return tryDecodeInsn(Uint8Array.from(bytes), 0)?.length;
  }

  describe("single-byte instructions", () => {
    it("decodes inc reg", () => {
      expect(decode([0x40])).toBe("inc eax");
      expect(decode([0x41])).toBe("inc ecx");
      expect(decode([0x42])).toBe("inc edx");
      expect(decode([0x43])).toBe("inc ebx");
      expect(decode([0x47])).toBe("inc edi");
    });

    it("decodes dec reg", () => {
      expect(decode([0x48])).toBe("dec eax");
      expect(decode([0x4f])).toBe("dec edi");
    });

    it("decodes push/pop reg", () => {
      expect(decode([0x50])).toBe("push eax");
      expect(decode([0x5b])).toBe("pop ebx");
      expect(decode([0x5d])).toBe("pop ebp");
    });

    it("decodes pushad, nop, leave", () => {
      expect(decode([0x60])).toBe("pushad");
      expect(decode([0x90])).toBe("nop");
      expect(decode([0xc9])).toBe("leave");
    });

    it("decodes xchg eax, reg", () => {
      expect(decode([0x91])).toBe("xchg eax, ecx");
      expect(decode([0x93])).toBe("xchg eax, ebx");
      expect(decode([0x96])).toBe("xchg eax, esi");
    });

    it("all single-byte have length 1", () => {
      expect(decodeLen([0x40])).toBe(1);
      expect(decodeLen([0x60])).toBe(1);
      expect(decodeLen([0x90])).toBe(1);
      expect(decodeLen([0xc9])).toBe(1);
    });
  });

  describe("register-register arithmetic (ModRM mod=11)", () => {
    it("decodes add edx, ebx", () => {
      // add r/m32, r32: opcode 01, ModRM = C0 | (ebx=3 << 3) | edx=2 = 0xDA
      expect(decode([0x01, 0xda])).toBe("add edx, ebx");
      expect(decodeLen([0x01, 0xda])).toBe(2);
    });

    it("decodes sub eax, ecx", () => {
      // sub r/m32, r32: opcode 29, ModRM = C0 | (ecx=1 << 3) | eax=0 = 0xC8
      expect(decode([0x29, 0xc8])).toBe("sub eax, ecx");
    });

    it("decodes or esi, edi", () => {
      // or r/m32, r32: opcode 09, ModRM = C0 | (edi=7 << 3) | esi=6 = 0xFE
      expect(decode([0x09, 0xfe])).toBe("or esi, edi");
    });

    it("decodes and edx, eax", () => {
      // and r/m32, r32: opcode 21, ModRM = C0 | (eax=0 << 3) | edx=2 = 0xC2
      expect(decode([0x21, 0xc2])).toBe("and edx, eax");
    });

    it("decodes adc edx, esi", () => {
      // adc r/m32, r32: opcode 11, ModRM = C0 | (esi=6 << 3) | edx=2 = 0xF2
      expect(decode([0x11, 0xf2])).toBe("adc edx, esi");
    });

    it("decodes sbb eax, eax", () => {
      // sbb r/m32, r32: opcode 19, ModRM = C0 | (eax=0 << 3) | eax=0 = 0xC0
      expect(decode([0x19, 0xc0])).toBe("sbb eax, eax");
    });

    it("decodes xor ecx, ecx", () => {
      expect(decode([0x31, 0xc9])).toBe("xor ecx, ecx");
    });

    it("decodes mov edx, eax (opcode 89)", () => {
      // mov r/m32, r32: opcode 89, ModRM = C0 | (eax=0 << 3) | edx=2 = 0xC2
      expect(decode([0x89, 0xc2])).toBe("mov edx, eax");
    });

    it("decodes mov eax, ecx (opcode 8B)", () => {
      // mov r32, r/m32: opcode 8B, ModRM = C0 | (eax=0 << 3) | ecx=1 = 0xC1
      expect(decode([0x8b, 0xc1])).toBe("mov eax, ecx");
    });

    it("decodes xchg ebx, esi (opcode 87)", () => {
      // xchg r/m32, r32: opcode 87, ModRM = C0 | (ebx=3 << 3) | esi=6 = 0xDE
      expect(decode([0x87, 0xde])).toBe("xchg esi, ebx");
    });

    it("decodes test eax, eax", () => {
      expect(decode([0x85, 0xc0])).toBe("test eax, eax");
    });

    it("rejects mod != 11 (memory operand)", () => {
      // ModRM = 0x02 → mod=00, memory operand — should reject
      expect(decode([0x01, 0x02])).toBeUndefined();
      expect(decode([0x89, 0x45])).toBeUndefined();
    });
  });

  describe("neg and not (F7)", () => {
    it("decodes neg eax", () => {
      // F7 /3: ModRM = C0 | (3 << 3) | eax=0 = 0xD8
      expect(decode([0xf7, 0xd8])).toBe("neg eax");
    });

    it("decodes not ecx", () => {
      // F7 /2: ModRM = C0 | (2 << 3) | ecx=1 = 0xD1
      expect(decode([0xf7, 0xd1])).toBe("not ecx");
    });

    it("rejects mul/div", () => {
      // F7 /4 (mul): ModRM = C0 | (4 << 3) | eax=0 = 0xE0
      expect(decode([0xf7, 0xe0])).toBeUndefined();
    });
  });

  describe("group 1 with imm8 (opcode 83)", () => {
    it("decodes add esp, 0x10", () => {
      // 83 /0: ModRM = C0 | (0 << 3) | esp=4 = 0xC4, imm8 = 0x10
      expect(decode([0x83, 0xc4, 0x10])).toBe("add esp, 0x10");
      expect(decodeLen([0x83, 0xc4, 0x10])).toBe(3);
    });

    it("decodes and eax, 0x8", () => {
      // 83 /4: ModRM = C0 | (4 << 3) | eax=0 = 0xE0, imm8 = 8
      expect(decode([0x83, 0xe0, 0x08])).toBe("and eax, 0x8");
    });

    it("decodes sub ebp, 0x4", () => {
      // 83 /5: ModRM = C0 | (5 << 3) | ebp=5 = 0xED, imm8 = 4
      expect(decode([0x83, 0xed, 0x04])).toBe("sub ebp, 0x4");
    });

    it("decodes xor esi, 0xff as sign-extended hex", () => {
      // 83 /6: ModRM = C0 | (6 << 3) | esi=6 = 0xF6, imm8 = 0xFF (-1 signed)
      const result = decode([0x83, 0xf6, 0xff]);
      expect(result).toBe("xor esi, 0xffffffff");
    });

    it("rejects mod != 11", () => {
      expect(decode([0x83, 0x44, 0x10])).toBeUndefined();
    });
  });

  describe("ALU eax, imm32 short forms", () => {
    it("decodes add eax, 0x20", () => {
      expect(decode([0x05, 0x20, 0x00, 0x00, 0x00])).toBe("add eax, 0x20");
      expect(decodeLen([0x05, 0x20, 0x00, 0x00, 0x00])).toBe(5);
    });

    it("decodes sub eax, 0xdeadbeef", () => {
      // 0xDEADBEEF in LE: EF BE AD DE
      expect(decode([0x2d, 0xef, 0xbe, 0xad, 0xde])).toBe("sub eax, 0xdeadbeef");
    });

    it("decodes xor eax, imm32", () => {
      expect(decode([0x35, 0x01, 0x00, 0x00, 0x00])).toBe("xor eax, 0x1");
    });
  });

  describe("call/jmp register (FF)", () => {
    it("decodes call eax", () => {
      // FF /2: ModRM = C0 | (2 << 3) | eax=0 = 0xD0
      expect(decode([0xff, 0xd0])).toBe("call eax");
    });

    it("decodes jmp esp", () => {
      // FF /4: ModRM = C0 | (4 << 3) | esp=4 = 0xE4
      expect(decode([0xff, 0xe4])).toBe("jmp esp");
    });

    it("rejects push (FF /6)", () => {
      expect(decode([0xff, 0xf0])).toBeUndefined();
    });
  });

  describe("FPU instructions (D9)", () => {
    it("decodes fpatan", () => {
      expect(decode([0xd9, 0xf3])).toBe("fpatan");
      expect(decodeLen([0xd9, 0xf3])).toBe(2);
    });

    it("decodes fsin", () => {
      expect(decode([0xd9, 0xfe])).toBe("fsin");
    });

    it("rejects unknown D9 forms", () => {
      expect(decode([0xd9, 0x00])).toBeUndefined();
    });
  });

  describe("multi-instruction sequences", () => {
    it("decodes add edx, ebx ; pop ebx ; ret 0x10 as gadget mnemonic", () => {
      // 01 DA  5B  C2 10 00
      const bytes = Uint8Array.from([0x01, 0xda, 0x5b, 0xc2, 0x10, 0x00]);
      const i1 = tryDecodeInsn(bytes, 0);
      expect(i1?.mnemonic).toBe("add edx, ebx");
      expect(i1?.length).toBe(2);
      const i2 = tryDecodeInsn(bytes, 2);
      expect(i2?.mnemonic).toBe("pop ebx");
      expect(i2?.length).toBe(1);
    });

    it("decodes inc ecx ; and eax, 0x8 ; ret", () => {
      // 41  83 E0 08  C3
      const bytes = Uint8Array.from([0x41, 0x83, 0xe0, 0x08, 0xc3]);
      const i1 = tryDecodeInsn(bytes, 0);
      expect(i1?.mnemonic).toBe("inc ecx");
      const i2 = tryDecodeInsn(bytes, 1);
      expect(i2?.mnemonic).toBe("and eax, 0x8");
    });

    it("decodes inc ebx ; fpatan ; ret", () => {
      // 43  D9 F3  C3
      const bytes = Uint8Array.from([0x43, 0xd9, 0xf3, 0xc3]);
      const i1 = tryDecodeInsn(bytes, 0);
      expect(i1?.mnemonic).toBe("inc ebx");
      const i2 = tryDecodeInsn(bytes, 1);
      expect(i2?.mnemonic).toBe("fpatan");
    });
  });

  describe("offset decoding", () => {
    it("decodes at non-zero offset", () => {
      const bytes = Uint8Array.from([0x90, 0x90, 0x01, 0xda]);
      const result = tryDecodeInsn(bytes, 2);
      expect(result?.mnemonic).toBe("add edx, ebx");
    });

    it("returns undefined past end of buffer", () => {
      const bytes = Uint8Array.from([0x01]);
      expect(tryDecodeInsn(bytes, 0)).toBeUndefined();
      expect(tryDecodeInsn(bytes, 5)).toBeUndefined();
    });
  });
});
