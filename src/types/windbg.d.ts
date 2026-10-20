declare const host: {
  diagnostics: {
    debugLog(message: string): void;
  };
  memory: {
    readMemoryValues(address: number | bigint, count: number, elementSize: number, isSigned?: boolean): number[];
  };
  currentProcess: unknown;
  currentThread: unknown;
  namespace?: {
    Debugger?: {
      Utility?: {
        Control?: { ExecuteCommand?(command: string): unknown };
        FileSystem?: {
          OpenFile?(path: string): unknown;
          CreateFile?(path: string, disposition: string): unknown;
        };
      };
    };
  };
};
