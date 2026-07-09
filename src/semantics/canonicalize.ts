import { Instruction, InstructionSequence } from "./types";

function normalizeHexImmediate(value: string): string {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) {
    return trimmed;
  }

  if (/^0x[0-9a-f]+$/.test(trimmed)) {
    return `0x${trimmed.slice(2).replace(/^0+/, "") || "0"}`;
  }

  if (/^-?\d+$/.test(trimmed)) {
    const num = Number.parseInt(trimmed, 10);
    if (Number.isFinite(num)) {
      const normalized = (num >>> 0).toString(16);
      return `0x${normalized}`;
    }
  }

  return trimmed;
}

function normalizeOperand(text: string): string {
  let value = text.trim().toLowerCase();
  value = value.replace(/\s+/g, " ");
  value = value.replace(/\[\s+/g, "[");
  value = value.replace(/\s+\]/g, "]");
  value = value.replace(/\s*,\s*/g, ", ");
  value = value.replace(/\s*\+\s*/g, "+");
  value = value.replace(/\s*-\s*/g, "-");
  return value;
}

function parseInstructionText(text: string): { mnemonic: string; operands: string[] } {
  const cleaned = text.trim().replace(/;+\s*$/, "").trim();
  if (!cleaned) {
    return { mnemonic: "", operands: [] };
  }

  const firstSpace = cleaned.indexOf(" ");
  const rawMnemonic = (firstSpace >= 0 ? cleaned.slice(0, firstSpace) : cleaned).trim().toLowerCase();
  const remainder = firstSpace >= 0 ? cleaned.slice(firstSpace + 1).trim() : "";

  if (!remainder) {
    return { mnemonic: rawMnemonic, operands: [] };
  }

  const operands = remainder
    .split(",")
    .map((operand) => normalizeOperand(operand))
    .filter((operand) => operand.length > 0)
    .map((operand) => operand.replace(/\b(?:byte|word|dword|qword)\s+ptr\b/g, (match) => match.toLowerCase()));

  return { mnemonic: rawMnemonic, operands };
}

export function normalizeInstructionText(text: string): string {
  const { mnemonic, operands } = parseInstructionText(text);
  if (!mnemonic) {
    return "";
  }

  const normalizedMnemonic = mnemonic === "retn" ? "ret" : mnemonic;
  const normalizedOperands = operands.map((operand) => {
    if (normalizedMnemonic === "ret" && operand.length > 0) {
      return normalizeHexImmediate(operand);
    }
    return normalizeHexImmediate(operand);
  });

  return normalizedOperands.length > 0
    ? `${normalizedMnemonic} ${normalizedOperands.join(", ")}`
    : normalizedMnemonic;
}

export function parseInstruction(text: string): Instruction {
  const normalizedText = normalizeInstructionText(text);
  const { mnemonic, operands } = parseInstructionText(text);
  const normalizedMnemonic = mnemonic === "retn" ? "ret" : mnemonic;
  return {
    originalText: text.trim(),
    normalizedText,
    mnemonic: normalizedMnemonic,
    operands: operands.map((operand) => normalizeHexImmediate(operand)),
  };
}

export function canonicalizeInstruction(instruction: Instruction): string {
  const operands = instruction.operands
    .map((operand) => normalizeHexImmediate(operand))
    .join(", ");
  return operands.length > 0
    ? `${instruction.mnemonic.toLowerCase()} ${operands}`
    : instruction.mnemonic.toLowerCase();
}

export function canonicalizeInstructionSequence(sequence: InstructionSequence): string {
  return sequence.instructions.map((instruction) => canonicalizeInstruction(instruction)).join(" | ");
}

export function canonicalizeTextSequence(text: string): string {
  return text
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => normalizeInstructionText(part))
    .join(" | ");
}

