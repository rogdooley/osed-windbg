declare const host: {
  diagnostics: {
    debugLog(message: string): void;
  };
  memory: {
    readMemoryValues(address: number | bigint, count: number, elementSize: number, isSigned?: boolean): number[];
  };
  currentProcess: unknown;
  currentThread: unknown;
};
