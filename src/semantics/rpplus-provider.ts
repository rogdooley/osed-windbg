import { canonicalizeTextSequence, parseInstruction } from "./canonicalize";
import { InstructionSequenceProvider } from "./provider";
import { InstructionSequence, InstructionSequenceSource, Provenance, SEMANTIC_SCHEMA_VERSION } from "./types";

export interface RPPlusProviderOptions {
  source?: Partial<InstructionSequenceSource>;
  provenance?: Partial<Provenance>;
  preserveEmptyLines?: boolean;
}

function defaultSource(): InstructionSequenceSource {
  return {
    kind: "source-adapter",
    name: "rp++",
    format: "rp++",
    version: "v1",
  };
}

function defaultProvenance(): Provenance {
  return {
    executable: "UNKNOWN",
    writable: "UNKNOWN",
    aslr: "UNKNOWN",
    rebaseable: "UNKNOWN",
  };
}

function parseAddress(line: string): number | undefined {
  const match = line.match(/^\s*0x([0-9a-fA-F]+)\s*:/);
  if (!match) {
    return undefined;
  }

  const value = Number.parseInt(match[1], 16);
  return Number.isFinite(value) ? value >>> 0 : undefined;
}

function splitInstructionParts(line: string): string[] {
  const colon = line.indexOf(":");
  if (colon < 0) {
    return [];
  }

  const body = line.slice(colon + 1).trim();
  return body
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .filter((part) => !/^\(\d+\s+found\)$/i.test(part));
}

function isBannerLine(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed) {
    return true;
  }

  if (!/^0x[0-9a-fA-F]+\s*:/.test(trimmed)) {
    return true;
  }

  return false;
}

export function parseRpPlusSequences(text: string, options: RPPlusProviderOptions = {}): InstructionSequence[] {
  const lines = text.split(/\r?\n/);
  const source = { ...defaultSource(), ...options.source };
  const provenance = { ...defaultProvenance(), ...options.provenance };

  const sequences: InstructionSequence[] = [];
  for (const line of lines) {
    if (isBannerLine(line)) {
      if (options.preserveEmptyLines && line.trim().length === 0) {
        continue;
      }
      if (!/^0x[0-9a-fA-F]+\s*:/.test(line.trim())) {
        continue;
      }
    }

    const address = parseAddress(line);
    if (address === undefined) {
      continue;
    }

    const parts = splitInstructionParts(line);
    if (parts.length === 0) {
      continue;
    }

    const instructions = parts.map((part) => parseInstruction(part));
    const canonical = canonicalizeTextSequence(parts.join(" ; "));
    sequences.push({
      schemaVersion: SEMANTIC_SCHEMA_VERSION,
      id: `rp++:${address.toString(16).padStart(8, "0")}:${canonical}`,
      source,
      originalText: line.trim(),
      instructions,
      provenance: {
        ...provenance,
        virtualAddress: address,
      },
    });
  }

  return sequences;
}

export class RPPlusProvider implements InstructionSequenceProvider {
  private readonly text: string;
  private readonly options: RPPlusProviderOptions;

  constructor(text: string, options: RPPlusProviderOptions = {}) {
    this.text = text;
    this.options = options;
  }

  async *load(): AsyncIterable<InstructionSequence> {
    for (const sequence of parseRpPlusSequences(this.text, this.options)) {
      yield sequence;
    }
  }
}
