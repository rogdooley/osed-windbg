import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize } from "../core/memory";
import { readRegisters } from "./triage";
import { mapStack, StackMapResult } from "../analysis/stackmap";

export function createStackmapCommand(): Command {
  return {
    name: "stackmap",
    description: "Maps the call stack at crash time, classifying each slot as pattern bytes, live return address, saved frame pointer, or data.",
    usage: "dx @$osed().stackmap(depth?, patternLength?)",
    examples: [
      "dx @$osed().stackmap()",
      "dx @$osed().stackmap(128)",
      "dx @$osed().stackmap(64, 20000)",
    ],
    schema: {
      depth: { type: "number", min: 8, max: 512, default: 64 },
      patternLength: { type: "number", min: 256, max: 100000, default: 10000 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const regs = readRegisters(pointerSize);
      const depth = options.depth as number;
      const patternLength = options.patternLength as number;

      if (regs.sp === undefined) {
        out.error("Stack pointer is unavailable.");
        return {
          command: "stackmap",
          args: options,
          success: false,
          findings: [],
          warnings: [],
          errors: ["Stack pointer is unavailable."],
        };
      }

      const result = mapStack(
        regs.sp,
        regs.spName ?? (pointerSize === 8 ? "RSP" : "ESP"),
        regs.ip,
        regs.ipName ?? (pointerSize === 8 ? "RIP" : "EIP"),
        depth,
        patternLength,
      );

      renderStackMap(result);

      return {
        command: "stackmap",
        args: options,
        success: true,
        findings: [serializeResult(result)],
        warnings: [],
        errors: [],
      };
    },
  };
}

function renderStackMap(result: StackMapResult): void {
  const { pointerSize, slots, spName } = result;
  const ipLabel = result.ipName ?? (pointerSize === 8 ? "RIP" : "EIP");
  const spLabel = spName.toUpperCase();

  out.section("CALL STACK MAP");
  out.info(
    `${ipLabel}: ${result.ip !== undefined ? out.formatAddress(result.ip, pointerSize) : "n/a"} · ${spLabel}: ${out.formatAddress(result.sp, pointerSize)} · ${slots.length} slots mapped`,
  );

  const collapseThreshold = 4;
  let i = 0;
  const rows: Array<Record<string, string>> = [];

  while (i < slots.length) {
    const slot = slots[i];

    if (slot.classification === "PATTERN") {
      let runEnd = i + 1;
      while (runEnd < slots.length && slots[runEnd].classification === "PATTERN") {
        runEnd++;
      }
      const runLength = runEnd - i;

      if (runLength <= collapseThreshold) {
        for (let j = i; j < runEnd; j++) {
          rows.push(formatSlotRow(slots[j], spLabel, pointerSize));
        }
      } else {
        rows.push(formatSlotRow(slots[i], spLabel, pointerSize));
        rows.push(formatSlotRow(slots[i + 1], spLabel, pointerSize));
        const firstOffset = slots[i].patternOffset ?? 0;
        const lastOffset = slots[runEnd - 1].patternOffset ?? 0;
        const kind = slots[i].patternKind ?? "pattern";
        rows.push({
          Offset: "···",
          Address: "",
          Value: "",
          Class: `PATTERN ×${runLength - 3}`,
          Detail: `contiguous, ${kind} ${firstOffset}–${lastOffset}`,
        });
        rows.push(formatSlotRow(slots[runEnd - 1], spLabel, pointerSize));
      }
      i = runEnd;
    } else {
      rows.push(formatSlotRow(slot, spLabel, pointerSize));
      i++;
    }
  }

  out.table(
    [
      { key: "Offset", header: "Offset", width: 12 },
      { key: "Address", header: "Address", width: pointerSize === 8 ? 18 : 10 },
      { key: "Value", header: "Value", width: pointerSize === 8 ? 18 : 10 },
      { key: "Class", header: "Class", width: 12 },
      { key: "Detail", header: "Detail" },
    ],
    rows,
  );

  out.section("SUMMARY");
  out.info(`Controlled slots: ${result.controlledCount}`);
  out.info(`Live frames (CALL verified): ${result.liveFrameCount}`);
  out.info(
    `ROP room: ${result.ropRoom} bytes${result.firstLiveRetOffset !== undefined ? ` (before first live RET at ${spLabel}+0x${result.firstLiveRetOffset.toString(16).toUpperCase()})` : " (no live RET found in scan range)"}`,
  );
  if (result.overwrittenFrames.length > 0) {
    out.info(`Overwritten frames: ${result.overwrittenFrames.join(" → ")}`);
  }

  out.section("CHAIN ENTRY");
  const firstControlled = slots.find((s) => s.classification === "PATTERN");
  const firstLiveRet = slots.find(
    (s) => s.classification === "RET" && s.callSiteVerified,
  );
  if (firstControlled) {
    out.info(
      `First controlled: ${spLabel}+0x${firstControlled.offset.toString(16).toUpperCase()} (${firstControlled.patternKind} offset ${firstControlled.patternOffset})`,
    );
  } else {
    out.info("No pattern bytes found on the stack.");
  }
  if (firstLiveRet) {
    out.info(
      `First intact frame: ${spLabel}+0x${firstLiveRet.offset.toString(16).toUpperCase()} (${firstLiveRet.module}+0x${firstLiveRet.moduleOffset!.toString(16).toUpperCase()})`,
    );
  }
  if (firstControlled && result.ropRoom > 0) {
    out.info(
      `Recommendation: ${result.ropRoom} bytes available at ${spLabel} for inline chain or stage-one pivot`,
    );
  }
}

function formatSlotRow(
  slot: StackMapResult["slots"][number],
  spLabel: string,
  pointerSize: 4 | 8,
): Record<string, string> {
  return {
    Offset: `${spLabel}+0x${slot.offset.toString(16).toUpperCase().padStart(2, "0")}`,
    Address: out.formatAddress(slot.address, pointerSize),
    Value: out.formatAddress(slot.value, pointerSize),
    Class: slot.classification + (slot.callSiteVerified ? " ✓" : ""),
    Detail: slot.detail,
  };
}

function serializeResult(result: StackMapResult): Record<string, unknown> {
  const ps = result.pointerSize;
  return {
    sp: out.formatAddress(result.sp, ps),
    spName: result.spName,
    ip: result.ip !== undefined ? out.formatAddress(result.ip, ps) : undefined,
    ipName: result.ipName,
    pointerSize: ps,
    slotCount: result.slots.length,
    controlledCount: result.controlledCount,
    liveFrameCount: result.liveFrameCount,
    firstLiveRetOffset: result.firstLiveRetOffset,
    ropRoom: result.ropRoom,
    overwrittenFrames: result.overwrittenFrames,
    slots: result.slots.map((slot) => ({
      offset: slot.offset,
      address: out.formatAddress(slot.address, ps),
      value: out.formatAddress(slot.value, ps),
      classification: slot.classification,
      detail: slot.detail,
      patternKind: slot.patternKind,
      patternOffset: slot.patternOffset,
      module: slot.module,
      moduleOffset: slot.moduleOffset !== undefined
        ? `0x${slot.moduleOffset.toString(16).toUpperCase()}`
        : undefined,
      callSiteVerified: slot.callSiteVerified,
    })),
  };
}
