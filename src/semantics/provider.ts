import { InstructionSequence } from "./types";

export interface InstructionSequenceProvider {
  load(): AsyncIterable<InstructionSequence>;
}

