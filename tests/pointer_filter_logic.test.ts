import { describe, expect, test } from "vitest";
import {
  addressHasBadchar,
  addressToBytes,
  applyFilters,
  badcharAddressFilter,
  encodeInstructionSearch,
  encodeJumpToRegister,
} from "../src/logic/pointer_filter_logic";

describe("pointer filter logic", () => {
  test("encodeJumpToRegister covers jmp/call/pushret for base registers", () => {
    expect(encodeJumpToRegister("jmp", "esp")).toEqual([0xff, 0xe4]);
    expect(encodeJumpToRegister("jmp", "eax")).toEqual([0xff, 0xe0]);
    expect(encodeJumpToRegister("call", "esp")).toEqual([0xff, 0xd4]);
    expect(encodeJumpToRegister("pushret", "esp")).toEqual([0x54, 0xc3]);
    expect(encodeJumpToRegister("jmp", "rsp")).toEqual([0xff, 0xe4]);
    expect(encodeJumpToRegister("jmp", "r8")).toBeUndefined();
  });

  test("encodeInstructionSearch parses textual searches", () => {
    expect(encodeInstructionSearch("jmp esp")).toEqual([0xff, 0xe4]);
    expect(encodeInstructionSearch("CALL EAX")).toEqual([0xff, 0xd0]);
    expect(encodeInstructionSearch("push+ret esp")).toEqual([0x54, 0xc3]);
    expect(encodeInstructionSearch("jmp")).toBeUndefined();
    expect(encodeInstructionSearch("nop esp")).toBeUndefined();
  });

  test("addressToBytes emits little-endian pointer bytes", () => {
    expect(addressToBytes(BigInt(0x11223344), 4)).toEqual([0x44, 0x33, 0x22, 0x11]);
    expect(addressToBytes(BigInt(0x0000000100402010), 8)).toEqual([0x10, 0x20, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00]);
  });

  test("addressHasBadchar inspects the pointer bytes", () => {
    expect(addressHasBadchar(BigInt(0x004010a0), 4, [0x00])).toBe(true); // high byte is 0x00
    expect(addressHasBadchar(BigInt(0x10203040), 4, [0x00])).toBe(false);
    expect(addressHasBadchar(BigInt(0x100a2030), 4, [0x0a])).toBe(true);
    expect(addressHasBadchar(BigInt(0x10203040), 4, [])).toBe(false);
  });

  test("applyFilters partitions kept and rejected with a reason", () => {
    const filter = badcharAddressFilter([0x00], 4);
    const addresses = [BigInt(0x10203040), BigInt(0x00401000), BigInt(0x625a4d41)];
    const outcome = applyFilters(addresses, [filter]);
    expect(outcome.kept).toEqual([BigInt(0x10203040), BigInt(0x625a4d41)]);
    expect(outcome.rejected).toEqual([{ address: BigInt(0x00401000), failed: "badchar-free-address" }]);
  });
});
