import { describe, expect, test } from "vitest";
import {
  captureProofFingerprint,
  compareProofFingerprint,
  Sha256,
  sha256,
  type FingerprintGadget,
  type TargetFingerprint,
} from "../src/rop/proof";
import fixture from "./fixtures/proof/linear-good.json";
import { ReplayProofAdapter, type ReplayFixture } from "./helpers/replay_proof_adapter";

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function gadget(overrides: Partial<FingerprintGadget> = {}): FingerprintGadget {
  return {
    address: 0x10001000n,
    module: "target.exe",
    rva: 0x1000n,
    bytes: Uint8Array.from([0x58, 0xc3]),
    instructions: ["pop eax", "ret"],
    ...overrides,
  };
}

function fingerprint(overrides: Partial<TargetFingerprint> = {}): TargetFingerprint {
  return {
    processId: 0x1234n,
    threadId: 0x55n,
    architecture: "x86",
    pointerSize: 4,
    targetPath: "C:\\labs\\target.exe",
    targetSha256: "a".repeat(64),
    complete: true,
    incompleteReasons: [],
    modules: [{
      name: "target.exe",
      path: "C:\\labs\\target.exe",
      base: 0x10000000n,
      preferredBase: 0x10000000n,
      size: 0x10000n,
    }],
    gadgets: [gadget()],
    protections: [],
    ...overrides,
  };
}

describe("proof fingerprinting", () => {
  test("matches standard SHA-256 vectors and supports streaming", () => {
    expect(sha256(bytes(""))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256(bytes("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const stream = new Sha256();
    stream.update(bytes("a"));
    stream.update(bytes("bc"));
    expect(stream.digestHex()).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  test("preserves incomplete identity instead of claiming a match", () => {
    const adapter = new ReplayProofAdapter(fixture as ReplayFixture);
    const captured = captureProofFingerprint({ moduleNames: [], gadgetAddresses: [], protectionAddresses: [] }, adapter);
    expect(captured.complete).toBe(true);

    const comparison = compareProofFingerprint(fingerprint(), fingerprint({
      complete: false,
      targetSha256: undefined,
      incompleteReasons: ["target file could not be read"],
    }));
    expect(comparison.status).toBe("INCOMPLETE");
    expect(comparison.reasons.join(" ")).toContain("target file could not be read");
  });

  test.each([
    ["module base", fingerprint({ modules: [{ ...fingerprint().modules[0], base: 0x20000000n }] })],
    ["gadget bytes", fingerprint({ gadgets: [gadget({ bytes: Uint8Array.from([0x59, 0xc3]) })] })],
    ["target hash", fingerprint({ targetSha256: "b".repeat(64) })],
  ])("detects stale target after %s changes", (_name, current) => {
    expect(compareProofFingerprint(fingerprint(), current).status).toBe("STALE_TARGET");
  });

  test("ignores modules outside the captured scope", () => {
    const current = fingerprint({
      modules: [...fingerprint().modules, {
        name: "irrelevant.dll",
        path: "C:\\Windows\\irrelevant.dll",
        base: 0x70000000n,
        preferredBase: 0x70000000n,
        size: 0x1000n,
      }],
    });
    expect(compareProofFingerprint(fingerprint(), current).status).toBe("CURRENT");
  });

  test("allows only the owned software-breakpoint byte substitution", () => {
    const current = fingerprint({ gadgets: [gadget({ bytes: Uint8Array.from([0xcc, 0xc3]) })] });
    expect(compareProofFingerprint(fingerprint(), current).status).toBe("STALE_TARGET");
    expect(compareProofFingerprint(fingerprint(), current, {
      ownedBreakpoint: { id: 7, address: 0x10001000n, enabled: true, oneShot: true, marker: "osed-proof:v1:s:n:1" },
    }).status).toBe("CURRENT");

    const unrelated = fingerprint({ gadgets: [gadget({ bytes: Uint8Array.from([0xcc, 0x90]) })] });
    expect(compareProofFingerprint(fingerprint(), unrelated, {
      ownedBreakpoint: { id: 7, address: 0x10001000n, enabled: true, oneShot: true, marker: "osed-proof:v1:s:n:1" },
    }).status).toBe("STALE_TARGET");
  });
});
