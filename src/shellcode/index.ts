import { getPointerSize, readMemory, readUint16LE, readUint32LE, readPointer } from "../core/memory";
import { formatAddress } from "../core/output";

type ModuleInfo = {
  name: string;
  path: string;
  base: bigint;
  end: bigint;
  size: bigint;
};

type LookupResult =
  | { kind: "ok"; module: ModuleInfo }
  | { kind: "ambiguous"; candidates: ModuleInfo[] }
  | { kind: "not_found"; name: string };

type PeHeaders = {
  dosHeader: bigint;
  eLfanew: number;
  ntHeader: bigint;
  machine: number;
  machineName: string;
  entryPointRva: number;
  entryPointVa: bigint;
  imageBase: bigint;
  sizeOfImage: number;
  optionalHeaderMagic: number;
  exportDirectoryRva: number;
  exportDirectoryVa: bigint;
  exportDirectorySize: number;
};

type ExportEntry = {
  ordinal: number;
  rva: number;
  va: bigint;
  name: string;
};

type ExportDirectoryInfo = {
  exportDirectoryRva: number;
  exportDirectoryVa: bigint;
  exportDirectorySize: number;
  numberOfFunctions: number;
  numberOfNames: number;
  addressOfFunctionsRva: number;
  addressOfNamesRva: number;
  addressOfNameOrdinalsRva: number;
  ordinalBase: number;
};

type IatEntry = {
  ownerModule: string;
  importDll: string;
  symbol: string;
  ordinal?: number;
  slot: bigint;
  target: bigint;
  expectedModule?: ModuleInfo;
  actualModule?: ModuleInfo;
  nearest?: { name: string; offset: bigint };
  status: string;
};

interface HashProvider {
  readonly algorithm: string;
  readonly aliases?: string[];
  readonly description: string;
  hash(text: string): number;
}

class MetasploitRor13Provider implements HashProvider {
  public readonly algorithm = "metasploit_ror13";
  public readonly aliases = ["ror13", "msf_ror13"];
  public readonly description = "Classic Metasploit-style API hash: ROR 13 then add byte.";

  private ror32(value: number, bits: number): number {
    const shift = bits & 31;
    return ((value >>> shift) | (value << (32 - shift))) >>> 0;
  }

  public hash(text: string): number {
    let hash = 0;
    for (const byte of asciiBytes(text)) {
      hash = this.ror32(hash, 13);
      hash = (hash + byte) >>> 0;
    }
    return hash >>> 0;
  }
}

class HashResolver {
  private readonly providers: Map<string, HashProvider>;
  private readonly canonicalProviders: HashProvider[];
  private readonly defaultAlias = "ror13";

  public constructor(providers?: HashProvider[]) {
    const configured: HashProvider[] = providers ?? [
      new MetasploitRor13Provider(),
      new Crc32Provider(),
      new Rol7AddProvider(),
    ];
    this.canonicalProviders = configured;
    this.providers = new Map<string, HashProvider>();
    for (const provider of configured) {
      this.providers.set(provider.algorithm.toLowerCase(), provider);
      for (const alias of provider.aliases ?? []) {
        this.providers.set(alias.toLowerCase(), provider);
      }
    }
  }

  public compute(exportsList: ExportEntry[], algorithm?: string): Array<Record<string, string>> {
    const provider = this.resolveProvider(algorithm);
    if (!provider) {
      throw new Error(`Unknown hash algorithm "${algorithm}". Supported: ${this.supportedAlgorithms().join(", ")}.`);
    }

    const label = this.displayName(provider);
    return exportsList
      .filter((entry) => entry.name.length > 0)
      .map((entry) => ({
        Algorithm: label,
        Hash: `0x${provider.hash(entry.name).toString(16).toUpperCase().padStart(8, "0")}`,
        Name: entry.name,
        Address: toDmlAddress(entry.va, "u"),
      }))
      .sort((a, b) => a.Name.localeCompare(b.Name));
  }

  public hashValue(text: string, algorithm?: string): Record<string, string> {
    const provider = this.resolveProvider(algorithm);
    if (!provider) {
      throw new Error(`Unknown hash algorithm "${algorithm}". Supported: ${this.supportedAlgorithms().join(", ")}.`);
    }
    return {
      Input: text,
      Algorithm: this.displayName(provider),
      Hash: `0x${provider.hash(text).toString(16).toUpperCase().padStart(8, "0")}`,
    };
  }

  public listAlgorithms(): Array<Record<string, string>> {
    const defaultProvider = this.resolveProvider(this.defaultAlias);
    return this.canonicalProviders
      .map((provider) => ({
        Algorithm: provider.algorithm,
        Aliases: (provider.aliases ?? []).join(", "),
        Description: provider.description,
        Default: provider === defaultProvider ? "yes" : "no",
      }))
      .sort((a, b) => a.Algorithm.localeCompare(b.Algorithm));
  }

  public supportedAlgorithms(): string[] {
    return Array.from(this.providers.keys()).sort();
  }

  private resolveProvider(algorithm?: string): HashProvider | undefined {
    const selected = (algorithm ?? this.defaultAlias).trim().toLowerCase();
    return this.providers.get(selected);
  }

  private displayName(provider: HashProvider): string {
    return provider.aliases && provider.aliases.length > 0 ? provider.aliases[0].toUpperCase() : provider.algorithm;
  }
}

class Crc32Provider implements HashProvider {
  public readonly algorithm = "crc32";
  public readonly description = "CRC32 (IEEE polynomial 0xEDB88320) over ASCII bytes.";
  private readonly table: number[];

  public constructor() {
    this.table = this.buildTable();
  }

  public hash(text: string): number {
    let crc = 0xffffffff;
    for (const byte of asciiBytes(text)) {
      const index = (crc ^ byte) & 0xff;
      crc = (crc >>> 8) ^ this.table[index];
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  private buildTable(): number[] {
    const table: number[] = [];
    for (let i = 0; i < 256; i += 1) {
      let value = i;
      for (let bit = 0; bit < 8; bit += 1) {
        if ((value & 1) === 1) {
          value = (value >>> 1) ^ 0xedb88320;
        } else {
          value >>>= 1;
        }
      }
      table.push(value >>> 0);
    }
    return table;
  }
}

class Rol7AddProvider implements HashProvider {
  public readonly algorithm = "rol7_add";
  public readonly aliases = ["rol7"];
  public readonly description = "Rotate-left by 7 then add byte (32-bit accumulator).";

  private rol32(value: number, bits: number): number {
    const shift = bits & 31;
    return ((value << shift) | (value >>> (32 - shift))) >>> 0;
  }

  public hash(text: string): number {
    let hash = 0;
    for (const byte of asciiBytes(text)) {
      hash = this.rol32(hash, 7);
      hash = (hash + byte) >>> 0;
    }
    return hash >>> 0;
  }
}

function asciiBytes(text: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code > 0x7f) {
      throw new Error("Hash input must be ASCII for shellforge parity.");
    }
    bytes.push(code & 0xff);
  }
  return bytes;
}

class PEParser {
  private readonly pointerSize: 4 | 8;

  public constructor(pointerSize: 4 | 8) {
    this.pointerSize = pointerSize;
  }

  public parseHeaders(module: ModuleInfo): PeHeaders {
    const base = module.base;
    const mz = readUint16LE(base);
    if (mz !== 0x5a4d) {
      throw new Error(`Invalid DOS header for ${module.name}.`);
    }

    const eLfanew = readUint32LE(base + BigInt(0x3c));
    const ntHeader = base + BigInt(eLfanew);
    const signature = readUint32LE(ntHeader);
    if (signature !== 0x4550) {
      throw new Error(`Invalid NT header signature for ${module.name}.`);
    }

    const machine = readUint16LE(ntHeader + BigInt(0x4));
    const optionalHeader = ntHeader + BigInt(0x18);
    const optionalHeaderMagic = readUint16LE(optionalHeader);
    const isPe32Plus = optionalHeaderMagic === 0x20b;
    if (!isPe32Plus && optionalHeaderMagic !== 0x10b) {
      throw new Error(`Unsupported optional header magic 0x${optionalHeaderMagic.toString(16)}.`);
    }

    const entryPointRva = readUint32LE(optionalHeader + BigInt(0x10));
    const imageBase = isPe32Plus
      ? readPointer(optionalHeader + BigInt(0x18), 8)
      : BigInt(readUint32LE(optionalHeader + BigInt(0x1c)));
    const sizeOfImage = readUint32LE(optionalHeader + BigInt(0x38));

    const dataDirectoryOffset = optionalHeader + BigInt(isPe32Plus ? 0x70 : 0x60);
    const exportDirectoryRva = readUint32LE(dataDirectoryOffset);
    const exportDirectorySize = readUint32LE(dataDirectoryOffset + BigInt(0x4));

    return {
      dosHeader: base,
      eLfanew,
      ntHeader,
      machine,
      machineName: machineToString(machine),
      entryPointRva,
      entryPointVa: base + BigInt(entryPointRva),
      imageBase,
      sizeOfImage,
      optionalHeaderMagic,
      exportDirectoryRva,
      exportDirectoryVa: base + BigInt(exportDirectoryRva),
      exportDirectorySize,
    };
  }

  public parseExports(module: ModuleInfo): ExportEntry[] {
    const exportInfo = this.parseExportDirectory(module);
    if (!exportInfo) {
      return [];
    }
    if (exportInfo.numberOfFunctions === 0 || exportInfo.addressOfFunctionsRva === 0) {
      return [];
    }

    const functionsVa = module.base + BigInt(exportInfo.addressOfFunctionsRva);
    const namesVa = module.base + BigInt(exportInfo.addressOfNamesRva);
    const ordinalsVa = module.base + BigInt(exportInfo.addressOfNameOrdinalsRva);

    const namesByIndex = new Map<number, string>();

    for (let i = 0; i < exportInfo.numberOfNames; i += 1) {
      const nameRva = readUint32LE(namesVa + BigInt(i * 4));
      const ordinalIndex = readUint16LE(ordinalsVa + BigInt(i * 2));
      const nameAddress = module.base + BigInt(nameRva);
      namesByIndex.set(ordinalIndex, readAsciiString(nameAddress, 512));
    }

    const entries: ExportEntry[] = [];
    for (let index = 0; index < exportInfo.numberOfFunctions; index += 1) {
      const rva = readUint32LE(functionsVa + BigInt(index * 4));
      const va = module.base + BigInt(rva);
      const ordinal = exportInfo.ordinalBase + index;
      entries.push({
        ordinal,
        rva,
        va,
        name: namesByIndex.get(index) ?? "",
      });
    }

    return entries;
  }

  public formatHeaderRows(module: ModuleInfo): Array<Record<string, string>> {
    const headers = this.parseHeaders(module);
    return [
      { Field: "Base", Value: toDmlAddress(module.base, "db") },
      { Field: "DOS Header", Value: toDmlAddress(headers.dosHeader, "db") },
      { Field: "e_lfanew", Value: `0x${headers.eLfanew.toString(16).toUpperCase()}` },
      { Field: "NT Header", Value: toDmlAddress(headers.ntHeader, "db") },
      { Field: "Machine", Value: `${headers.machineName} (0x${headers.machine.toString(16).toUpperCase()})` },
      { Field: "EntryPoint", Value: `${toDmlAddress(headers.entryPointVa, "u")} (RVA 0x${headers.entryPointRva.toString(16).toUpperCase()})` },
      { Field: "ImageBase", Value: formatAddress(headers.imageBase, this.pointerSize) },
      { Field: "SizeOfImage", Value: `0x${headers.sizeOfImage.toString(16).toUpperCase()}` },
      { Field: "ExportDir RVA", Value: `0x${headers.exportDirectoryRva.toString(16).toUpperCase()}` },
      { Field: "ExportDir VA", Value: toDmlAddress(headers.exportDirectoryVa, "db") },
    ];
  }

  public parseExportDirectory(module: ModuleInfo): ExportDirectoryInfo | undefined {
    const headers = this.parseHeaders(module);
    if (headers.exportDirectoryRva === 0 || headers.exportDirectorySize === 0) {
      return undefined;
    }
    const exportDir = module.base + BigInt(headers.exportDirectoryRva);
    return {
      exportDirectoryRva: headers.exportDirectoryRva,
      exportDirectoryVa: headers.exportDirectoryVa,
      exportDirectorySize: headers.exportDirectorySize,
      ordinalBase: readUint32LE(exportDir + BigInt(0x10)),
      numberOfFunctions: readUint32LE(exportDir + BigInt(0x14)),
      numberOfNames: readUint32LE(exportDir + BigInt(0x18)),
      addressOfFunctionsRva: readUint32LE(exportDir + BigInt(0x1c)),
      addressOfNamesRva: readUint32LE(exportDir + BigInt(0x20)),
      addressOfNameOrdinalsRva: readUint32LE(exportDir + BigInt(0x24)),
    };
  }
}

class ExportResolver {
  private readonly parser: PEParser;

  public constructor(parser: PEParser) {
    this.parser = parser;
  }

  public enumerate(module: ModuleInfo, filter?: string): Array<Record<string, string>> {
    const entries = this.parser.parseExports(module);
    const needle = normalizeNeedle(filter);
    return entries
      .filter((entry) => {
        if (!needle) {
          return true;
        }
        return entry.name.toLowerCase().includes(needle);
      })
      .sort((a, b) => {
        const left = a.name || `~${a.ordinal.toString(16)}`;
        const right = b.name || `~${b.ordinal.toString(16)}`;
        return left.localeCompare(right);
      })
      .map((entry) => ({
        Ordinal: entry.ordinal.toString(),
        RVA: `0x${entry.rva.toString(16).toUpperCase().padStart(8, "0")}`,
        VA: toDmlAddress(entry.va, "u"),
        Name: entry.name || "<unnamed>",
      }));
  }

  public resolve(module: ModuleInfo, symbol: string): ExportEntry | undefined {
    const needle = symbol.trim().toLowerCase();
    if (!needle) {
      return undefined;
    }
    return this.parser.parseExports(module).find((entry) => entry.name.toLowerCase() === needle);
  }

  public getExports(module: ModuleInfo): ExportEntry[] {
    return this.parser.parseExports(module);
  }

  public getExportDirectory(module: ModuleInfo): ExportDirectoryInfo | undefined {
    return this.parser.parseExportDirectory(module);
  }

  public findByOrdinalIndex(module: ModuleInfo, ordinalIndex: number): ExportEntry | undefined {
    if (ordinalIndex < 0) {
      return undefined;
    }
    const exportDir = this.parser.parseExportDirectory(module);
    if (!exportDir) {
      return undefined;
    }
    const targetOrdinal = exportDir.ordinalBase + ordinalIndex;
    return this.parser.parseExports(module).find((entry) => entry.ordinal === targetOrdinal);
  }

  public isForwarded(module: ModuleInfo, entry: ExportEntry): { forwarded: boolean; target: string } {
    const exportDir = this.parser.parseExportDirectory(module);
    if (!exportDir) {
      return { forwarded: false, target: "" };
    }
    const start = exportDir.exportDirectoryRva;
    const end = start + exportDir.exportDirectorySize;
    if (entry.rva >= start && entry.rva < end) {
      return {
        forwarded: true,
        target: readAsciiString(module.base + BigInt(entry.rva), 512),
      };
    }
    return { forwarded: false, target: "" };
  }

  public nearestSymbol(module: ModuleInfo, address: bigint): { name: string; offset: bigint } | undefined {
    const exportsList = this.parser
      .parseExports(module)
      .filter((entry) => entry.name.length > 0)
      .sort((a, b) => (a.va < b.va ? -1 : 1));

    let nearest: ExportEntry | undefined;
    for (const entry of exportsList) {
      if (entry.va > address) {
        break;
      }
      nearest = entry;
    }
    if (!nearest) {
      return undefined;
    }
    return { name: nearest.name, offset: address - nearest.va };
  }
}

class IATResolver {
  private readonly pointerSize: 4 | 8;
  private readonly parser: PEParser;
  private readonly exportResolver: ExportResolver;
  private readonly modulesProvider: () => ModuleInfo[];

  public constructor(
    pointerSize: 4 | 8,
    parser: PEParser,
    exportResolver: ExportResolver,
    modulesProvider: () => ModuleInfo[],
  ) {
    this.pointerSize = pointerSize;
    this.parser = parser;
    this.exportResolver = exportResolver;
    this.modulesProvider = modulesProvider;
  }

  public enumerateIat(owner: ModuleInfo): IatEntry[] {
    const headers = this.parser.parseHeaders(owner);
    const importDirRva = this.readImportDirectoryRva(owner, headers.optionalHeaderMagic, headers.ntHeader);
    if (importDirRva === 0) {
      return [];
    }

    const modules = this.modulesProvider();
    const rows: IatEntry[] = [];
    let descriptorAddress = owner.base + BigInt(importDirRva);
    const maxDescriptors = 4096;

    for (let index = 0; index < maxDescriptors; index += 1) {
      const originalFirstThunk = readUint32LE(descriptorAddress);
      const _timeDateStamp = readUint32LE(descriptorAddress + BigInt(0x4));
      const _forwarderChain = readUint32LE(descriptorAddress + BigInt(0x8));
      const nameRva = readUint32LE(descriptorAddress + BigInt(0xc));
      const firstThunk = readUint32LE(descriptorAddress + BigInt(0x10));

      if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) {
        break;
      }

      const dllName = nameRva === 0 ? "<unknown>" : readAsciiString(owner.base + BigInt(nameRva), 260);
      const expectedModule = this.findByDllName(modules, dllName);
      const intBaseRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;

      let intPtr = owner.base + BigInt(intBaseRva);
      let iatPtr = owner.base + BigInt(firstThunk);
      const maxThunks = 16384;

      for (let thunkIndex = 0; thunkIndex < maxThunks; thunkIndex += 1) {
        const intValue = this.readThunk(intPtr);
        const iatValue = this.readThunk(iatPtr);
        if (intValue === BigInt(0) && iatValue === BigInt(0)) {
          break;
        }

        const imported = this.parseImportedName(owner, intValue);
        const target = iatValue;
        const actualModule = this.findContainingModule(modules, target);
        const trampoline = this.resolveTrampoline(target);
        const nearest = actualModule ? this.exportResolver.nearestSymbol(actualModule, trampoline.target) : undefined;

        rows.push({
          ownerModule: owner.name,
          importDll: dllName,
          symbol: imported.name,
          ordinal: imported.ordinal,
          slot: iatPtr,
          target: trampoline.target,
          expectedModule,
          actualModule,
          nearest,
          status: this.classifyStatus(target, trampoline.target, expectedModule, actualModule),
        });

        intPtr += BigInt(this.pointerSize);
        iatPtr += BigInt(this.pointerSize);
      }

      descriptorAddress += BigInt(0x14);
    }

    return rows;
  }

  private classifyStatus(target: bigint, resolvedTarget: bigint, expected?: ModuleInfo, actual?: ModuleInfo): string {
    if (target === BigInt(0)) {
      return "unresolved";
    }
    if (!this.isMapped(resolvedTarget)) {
      return "unmapped";
    }
    if (!actual) {
      return "unknown-module";
    }
    if (!this.isExecutable(actual, resolvedTarget)) {
      return "non-exec";
    }
    if (expected && expected.name.toLowerCase() !== actual.name.toLowerCase()) {
      return "outside-module";
    }
    return "ok";
  }

  private isMapped(address: bigint): boolean {
    if (address === BigInt(0)) {
      return false;
    }
    try {
      readMemory(address, 1);
      return true;
    } catch (_error) {
      return false;
    }
  }

  private isExecutable(module: ModuleInfo, address: bigint): boolean {
    try {
      const headers = this.parser.parseHeaders(module);
      const numberOfSections = readUint16LE(headers.ntHeader + BigInt(0x6));
      const sizeOfOptionalHeader = readUint16LE(headers.ntHeader + BigInt(0x14));
      let sectionHeader = headers.ntHeader + BigInt(0x18 + sizeOfOptionalHeader);
      const rva = address - module.base;
      const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

      for (let i = 0; i < numberOfSections; i += 1) {
        const virtualSize = readUint32LE(sectionHeader + BigInt(0x8));
        const virtualAddress = readUint32LE(sectionHeader + BigInt(0xc));
        const characteristics = readUint32LE(sectionHeader + BigInt(0x24));
        const start = BigInt(virtualAddress);
        const end = start + BigInt(Math.max(virtualSize, 1));
        if (rva >= start && rva < end) {
          return (characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0;
        }
        sectionHeader += BigInt(0x28);
      }
    } catch (_error) {
      return false;
    }
    return false;
  }

  private resolveTrampoline(address: bigint): { target: bigint; note: string } {
    if (address === BigInt(0)) {
      return { target: address, note: "" };
    }
    try {
      const first = readMemory(address, 6);
      const op = first[0];
      if (op === 0xe9 && first.length >= 5) {
        const imm = this.readInt32LE(address + BigInt(1));
        const dest = address + BigInt(5) + BigInt(imm);
        return { target: dest, note: "jmp-rel32" };
      }
      if (op === 0xeb && first.length >= 2) {
        const rel8 = first[1] >= 0x80 ? first[1] - 0x100 : first[1];
        const dest = address + BigInt(2) + BigInt(rel8);
        return { target: dest, note: "jmp-rel8" };
      }
      if (this.pointerSize === 4 && op === 0xff && first[1] === 0x25) {
        const memPtr = BigInt(readUint32LE(address + BigInt(2)));
        const dest = readPointer(memPtr, this.pointerSize);
        return { target: dest, note: "jmp-[imm]" };
      }
    } catch (_error) {
      return { target: address, note: "" };
    }
    return { target: address, note: "" };
  }

  private readInt32LE(address: bigint): number {
    const value = readUint32LE(address);
    return value > 0x7fffffff ? value - 0x100000000 : value;
  }

  private readImportDirectoryRva(owner: ModuleInfo, optionalMagic: number, ntHeader: bigint): number {
    const optionalHeader = ntHeader + BigInt(0x18);
    const dataDirectoryOffset = optionalHeader + BigInt(optionalMagic === 0x20b ? 0x70 : 0x60);
    try {
      return readUint32LE(dataDirectoryOffset + BigInt(8));
    } catch (_error) {
      return 0;
    }
  }

  private findContainingModule(modules: ModuleInfo[], address: bigint): ModuleInfo | undefined {
    return modules.find((module) => address >= module.base && address < module.end);
  }

  private findByDllName(modules: ModuleInfo[], name: string): ModuleInfo | undefined {
    const needle = name.trim().toLowerCase();
    if (!needle) {
      return undefined;
    }
    const noExt = needle.endsWith(".dll") ? needle.slice(0, -4) : needle;
    return modules.find((module) => {
      const lower = module.name.toLowerCase();
      const lowerNoExt = lower.endsWith(".dll") ? lower.slice(0, -4) : lower;
      return lower === needle || lowerNoExt === noExt;
    });
  }

  private parseImportedName(owner: ModuleInfo, intValue: bigint): { name: string; ordinal?: number } {
    if (intValue === BigInt(0)) {
      return { name: "<null>" };
    }
    const ordinalFlag = this.pointerSize === 8 ? BigInt("0x8000000000000000") : BigInt("0x80000000");
    if ((intValue & ordinalFlag) !== BigInt(0)) {
      return { name: "<ordinal>", ordinal: Number(intValue & BigInt(0xffff)) };
    }
    const byName = owner.base + intValue + BigInt(2);
    return { name: readAsciiString(byName, 512) };
  }

  private readThunk(address: bigint): bigint {
    return this.pointerSize === 8 ? readPointer(address, 8) : BigInt(readUint32LE(address));
  }
}

class ShellcodeHelper {
  private readonly pointerSize: 4 | 8;
  private readonly parser: PEParser;
  private readonly exportResolver: ExportResolver;
  private readonly hashResolver: HashResolver;
  private readonly iatResolver: IATResolver;

  public constructor() {
    this.pointerSize = getPointerSize();
    this.parser = new PEParser(this.pointerSize);
    this.exportResolver = new ExportResolver(this.parser);
    this.hashResolver = new HashResolver();
    this.iatResolver = new IATResolver(this.pointerSize, this.parser, this.exportResolver, () => this.readModules());
  }

  public peb(): Array<Record<string, string>> {
    const pebAddress = this.getPebAddress();
    if (!pebAddress) {
      return this.errorRows("Unable to resolve PEB in current context.");
    }

    try {
      const ldrOffset = this.pointerSize === 8 ? 0x18 : 0x0c;
      const processParametersOffset = this.pointerSize === 8 ? 0x20 : 0x10;
      const imageBaseOffset = this.pointerSize === 8 ? 0x10 : 0x08;

      const ldr = readPointer(pebAddress + BigInt(ldrOffset), this.pointerSize);
      const processParameters = readPointer(pebAddress + BigInt(processParametersOffset), this.pointerSize);
      const imageBase = readPointer(pebAddress + BigInt(imageBaseOffset), this.pointerSize);
      const beingDebugged = readMemory(pebAddress + BigInt(0x2), 1)[0] !== 0;

      return [
        { Field: "PEB", Value: toDmlAddress(pebAddress, "db") },
        { Field: "Ldr", Value: toDmlAddress(ldr, "db") },
        { Field: "ProcessParameters", Value: toDmlAddress(processParameters, "db") },
        { Field: "BeingDebugged", Value: beingDebugged ? "true" : "false" },
        { Field: "ImageBase", Value: toDmlAddress(imageBase, "db") },
      ];
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public modules(): Array<Record<string, string>> {
    return this.readModules().map((module) => ({
      Base: toDmlAddress(module.base, "db"),
      End: toDmlAddress(module.end, "db"),
      Size: `0x${module.size.toString(16).toUpperCase()}`,
      Name: module.name,
      Path: module.path,
    }));
  }

  public modulePages(moduleName: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    const pageSize = BigInt(0x1000);
    const pages = lookup.module.size === BigInt(0)
      ? BigInt(0)
      : (lookup.module.size + pageSize - BigInt(1)) / pageSize;

    return [
      {
        Module: lookup.module.name,
        Base: toDmlAddress(lookup.module.base, "db"),
        End: toDmlAddress(lookup.module.end, "db"),
        Size: `0x${lookup.module.size.toString(16).toUpperCase()}`,
        PageSize: `0x${pageSize.toString(16).toUpperCase()}`,
        Pages: pages.toString(),
      },
    ];
  }

  public pageSummary(moduleName: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    const summary = this.collectPageProtections(lookup.module);
    const pageSize = BigInt(0x1000);
    const totalPages = Array.from(summary.values()).reduce((sum, count) => sum + count, 0);
    const executablePages = Array.from(summary.entries()).reduce((sum, [protect, count]) => {
      return sum + (this.isExecutableProtect(protect) ? count : 0);
    }, 0);

    const rows: Array<Record<string, string>> = [
      {
        Module: lookup.module.name,
        Base: toDmlAddress(lookup.module.base, "db"),
        End: toDmlAddress(lookup.module.end, "db"),
        Size: `0x${lookup.module.size.toString(16).toUpperCase()}`,
        PageSize: `0x${pageSize.toString(16).toUpperCase()}`,
        TotalPages: totalPages.toString(),
        ExecutablePages: executablePages.toString(),
      },
      {
        Protect: "TOTAL",
        Name: "TOTAL",
        Pages: totalPages.toString(),
        ExecutablePages: executablePages.toString(),
      },
      ...[...summary.entries()].sort((left, right) => left[0] - right[0]).map(([protect, count]) => {
        const decoded = decodeProtectValue(protect);
        return {
          Protect: `0x${protect.toString(16).toUpperCase().padStart(2, "0")}`,
          Name: decoded.name,
          Pages: count.toString(),
          Executable: decoded.executable ? "yes" : "no",
          Writable: decoded.writable ? "yes" : "no",
        };
      }),
    ];

    return rows;
  }

  public base(name: string): Array<Record<string, string>> {
    const lookup = this.findModule(name);
    if (lookup.kind === "ok") {
      return [{ Module: lookup.module.name, Base: toDmlAddress(lookup.module.base, "db") }];
    }
    if (lookup.kind === "ambiguous") {
      return this.moduleCandidatesRows(lookup.candidates);
    }
    return this.errorRows(`No module matches "${name}".`);
  }

  public pe(name: string): Array<Record<string, string>> {
    const lookup = this.findModule(name);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    try {
      return this.parser.formatHeaderRows(lookup.module);
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public exports(name: string, filter?: string): Array<Record<string, string>> {
    const lookup = this.findModule(name);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    try {
      const rows = this.exportResolver.enumerate(lookup.module, filter);
      if (rows.length === 0) {
        return this.errorRows("No exports matched the requested filter.");
      }
      return rows;
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public resolve(moduleName: string, symbol: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    const entry = this.exportResolver.resolve(lookup.module, symbol);
    if (!entry) {
      return this.errorRows(`Symbol "${symbol}" was not found in ${lookup.module.name}.`);
    }

    return [
      {
        Module: lookup.module.name,
        Symbol: `${entry.name} (${lookup.module.name}!${entry.name})`,
        Address: toDmlAddress(entry.va, "u"),
      },
    ];
  }

  public hashes(moduleName: string, algorithm?: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    try {
      const exportsList = this.exportResolver.getExports(lookup.module);
      const rows = this.hashResolver.compute(exportsList, algorithm);
      if (rows.length === 0) {
        return this.errorRows("No named exports were found to hash.");
      }
      return rows;
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public hashresolve(moduleName: string, hashValue: string | number | bigint, algorithm = "ROR13"): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }
    const parsed = parseHashValue(hashValue);
    if (parsed === undefined) {
      return this.errorRows(`Invalid hash value "${String(hashValue)}".`);
    }
    try {
      for (const entry of this.exportResolver.getExports(lookup.module)) {
        if (!entry.name) {
          continue;
        }
        const hashHex = this.hashResolver.hashValue(entry.name, algorithm).Hash;
        const computed = parseInt(hashHex.replace(/^0x/i, ""), 16) >>> 0;
        if (computed === parsed) {
          const forward = this.exportResolver.isForwarded(lookup.module, entry);
          return [
            {
              Module: lookup.module.name,
              Algorithm: String(this.hashResolver.hashValue(entry.name, algorithm).Algorithm),
              Hash: `0x${parsed.toString(16).toUpperCase().padStart(8, "0")}`,
              Symbol: entry.name,
              Address: toDmlAddress(entry.va, "u"),
              Forwarded: forward.forwarded ? "true" : "false",
              ForwardTo: forward.target || "",
            },
          ];
        }
      }
      return this.errorRows(`No symbol matched hash 0x${parsed.toString(16).toUpperCase().padStart(8, "0")}.`);
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public exportdir(moduleName: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }
    try {
      const info = this.exportResolver.getExportDirectory(lookup.module);
      if (!info) {
        return this.errorRows(`Module ${lookup.module.name} has no export directory.`);
      }
      return [
        { Field: "Module", Value: lookup.module.name },
        { Field: "Base", Value: toDmlAddress(lookup.module.base, "db") },
        { Field: "Export RVA", Value: `0x${info.exportDirectoryRva.toString(16).toUpperCase()}` },
        { Field: "Export VA", Value: toDmlAddress(info.exportDirectoryVa, "db") },
        { Field: "AddressOfNames", Value: `0x${info.addressOfNamesRva.toString(16).toUpperCase()}` },
        { Field: "NumberOfFunctions", Value: info.numberOfFunctions.toString() },
        { Field: "NumberOfNames", Value: info.numberOfNames.toString() },
        { Field: "AddressOfFunctions", Value: `0x${info.addressOfFunctionsRva.toString(16).toUpperCase()}` },
        { Field: "AddressOfNameOrdinals", Value: `0x${info.addressOfNameOrdinalsRva.toString(16).toUpperCase()}` },
      ];
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public export(moduleName: string, symbol: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }
    try {
      const entry = this.exportResolver.resolve(lookup.module, symbol);
      if (!entry) {
        return this.errorRows(`Symbol "${symbol}" was not found in ${lookup.module.name}.`);
      }
      const exportDir = this.exportResolver.getExportDirectory(lookup.module);
      if (!exportDir) {
        return this.errorRows(`Module ${lookup.module.name} has no export directory.`);
      }
      const namesVa = lookup.module.base + BigInt(exportDir.addressOfNamesRva);
      const ordinalsVa = lookup.module.base + BigInt(exportDir.addressOfNameOrdinalsRva);
      let nameRva = 0;
      let ordinalIndex = entry.ordinal - exportDir.ordinalBase;
      for (let i = 0; i < exportDir.numberOfNames; i += 1) {
        const candidateNameRva = readUint32LE(namesVa + BigInt(i * 4));
        const candidateOrdinal = readUint16LE(ordinalsVa + BigInt(i * 2));
        const candidate = readAsciiString(lookup.module.base + BigInt(candidateNameRva), 512);
        if (candidate.toLowerCase() === entry.name.toLowerCase()) {
          nameRva = candidateNameRva;
          ordinalIndex = candidateOrdinal;
          break;
        }
      }
      const forward = this.exportResolver.isForwarded(lookup.module, entry);
      return [
        { Property: "Name", Value: entry.name || "<unnamed>" },
        { Property: "Name RVA", Value: `0x${nameRva.toString(16).toUpperCase()}` },
        { Property: "Name VA", Value: toDmlAddress(lookup.module.base + BigInt(nameRva), "db") },
        { Property: "Ordinal Index", Value: ordinalIndex.toString() },
        { Property: "Ordinal", Value: entry.ordinal.toString() },
        { Property: "Function RVA", Value: `0x${entry.rva.toString(16).toUpperCase()}` },
        { Property: "Function VA", Value: toDmlAddress(entry.va, "u") },
        { Property: "Forwarded", Value: forward.forwarded ? "true" : "false" },
        { Property: "ForwardTo", Value: forward.target || "" },
      ];
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public exportat(moduleName: string, ordinalIndex: number): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }
    try {
      const entry = this.exportResolver.findByOrdinalIndex(lookup.module, ordinalIndex);
      if (!entry) {
        return this.errorRows(`Ordinal index ${ordinalIndex} not found in ${lookup.module.name}.`);
      }
      const forward = this.exportResolver.isForwarded(lookup.module, entry);
      return [
        {
          Module: lookup.module.name,
          OrdinalIndex: ordinalIndex.toString(),
          Ordinal: entry.ordinal.toString(),
          Name: entry.name || "<unnamed>",
          RVA: `0x${entry.rva.toString(16).toUpperCase()}`,
          VA: toDmlAddress(entry.va, "u"),
          Forwarded: forward.forwarded ? "true" : "false",
          ForwardTo: forward.target || "",
        },
      ];
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public exportwalk(moduleName: string, symbol = "GetProcAddress", verbose = false): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }
    try {
      const headers = this.parser.parseHeaders(lookup.module);
      const exportDir = this.exportResolver.getExportDirectory(lookup.module);
      if (!exportDir) {
        return this.errorRows(`Module ${lookup.module.name} has no export directory.`);
      }
      const namesVa = lookup.module.base + BigInt(exportDir.addressOfNamesRva);
      const ordinalsVa = lookup.module.base + BigInt(exportDir.addressOfNameOrdinalsRva);
      const functionsVa = lookup.module.base + BigInt(exportDir.addressOfFunctionsRva);
      const rows: Array<Record<string, string>> = [];

      let matchIndex = -1;
      let matchName = "";
      let ordinalIndex = -1;
      let functionRva = 0;
      for (let i = 0; i < exportDir.numberOfNames; i += 1) {
        const nameRva = readUint32LE(namesVa + BigInt(i * 4));
        const name = readAsciiString(lookup.module.base + BigInt(nameRva), 512);
        if (verbose) {
          rows.push({ Step: "Walk", Value: `${i}: ${name}` });
        }
        if (name.toLowerCase() === symbol.trim().toLowerCase()) {
          matchIndex = i;
          matchName = name;
          ordinalIndex = readUint16LE(ordinalsVa + BigInt(i * 2));
          functionRva = readUint32LE(functionsVa + BigInt(ordinalIndex * 4));
          break;
        }
      }

      const summary: Array<Record<string, string>> = [
        { Step: "Resolving", Value: symbol },
        { Step: "[1] Module base", Value: toDmlAddress(lookup.module.base, "db") },
        { Step: "[2] DOS header", Value: toDmlAddress(headers.dosHeader, "db") },
        { Step: "[3] DOS.e_lfanew", Value: `0x${headers.eLfanew.toString(16).toUpperCase()}` },
        { Step: "[4] NT header", Value: toDmlAddress(headers.ntHeader, "db") },
        { Step: "[5] Export directory", Value: toDmlAddress(exportDir.exportDirectoryVa, "db") },
        { Step: "[6] AddressOfNames", Value: toDmlAddress(namesVa, "db") },
        { Step: "[7] AddressOfNameOrdinals", Value: toDmlAddress(ordinalsVa, "db") },
        { Step: "[8] AddressOfFunctions", Value: toDmlAddress(functionsVa, "db") },
      ];
      if (matchIndex < 0) {
        summary.push({ Step: "[9] Match", Value: "not found" });
        return summary.concat(verbose ? rows : []);
      }
      const finalVa = lookup.module.base + BigInt(functionRva);
      const matchedEntry = this.exportResolver.resolve(lookup.module, matchName);
      const forward = matchedEntry ? this.exportResolver.isForwarded(lookup.module, matchedEntry) : { forwarded: false, target: "" };
      summary.push(
        { Step: "[9] Match index", Value: `${matchIndex}: ${matchName}` },
        { Step: "[10] Ordinal index", Value: ordinalIndex.toString() },
        { Step: "[11] Function RVA", Value: `0x${functionRva.toString(16).toUpperCase()}` },
        { Step: "[12] Final VA", Value: toDmlAddress(finalVa, "u") },
        { Step: "[13] Forwarded", Value: forward.forwarded ? `true (${forward.target})` : "false" },
      );
      return summary.concat(verbose ? rows : []);
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public hash(name: string, algorithm = "ROR13"): Array<Record<string, string>> {
    const input = name.trim();
    if (!input) {
      return this.errorRows("Input string is required.");
    }
    try {
      return [this.hashResolver.hashValue(input, algorithm)];
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public algorithms(): Array<Record<string, string>> {
    return this.hashResolver.listAlgorithms();
  }

  public iat(moduleName?: string, filter?: string): Array<Record<string, string>> {
    const lookup = moduleName ? this.findModule(moduleName) : this.findMainModule();
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    try {
      const needle = filter?.trim().toLowerCase();
      const rows = this.iatResolver.enumerateIat(lookup.module)
        .filter((entry) => {
          if (!needle) return true;
          return entry.symbol.toLowerCase().includes(needle) || entry.importDll.toLowerCase().includes(needle);
        })
        .map((entry) => ({
          Owner: entry.ownerModule,
          DLL: entry.importDll,
          Symbol: entry.symbol,
          Ordinal: entry.ordinal ? entry.ordinal.toString() : "",
          Slot: toDmlAddress(entry.slot, "dps"),
          Target: toDmlAddress(entry.target, "u"),
          Module: entry.actualModule?.name ?? "unknown",
          "Symbol+Offset": entry.nearest ? `${entry.nearest.name}+0x${entry.nearest.offset.toString(16).toUpperCase()}` : "",
          Status: entry.status,
        }));
      if (rows.length === 0) {
        return this.errorRows(filter ? `No IAT entries in ${lookup.module.name} matched "${filter}".` : `No IAT entries found for ${lookup.module.name}.`);
      }
      return rows;
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public iat_find(symbol: string): Array<Record<string, string>> {
    const needle = symbol.trim().toLowerCase();
    if (!needle) {
      return this.errorRows("Symbol substring is required.");
    }

    const rows: Array<Record<string, string>> = [];
    for (const module of this.readModules()) {
      try {
        const entries = this.iatResolver.enumerateIat(module);
        for (const entry of entries) {
          if (entry.symbol.toLowerCase().includes(needle)) {
            rows.push({
              Owner: entry.ownerModule,
              DLL: entry.importDll,
              Symbol: entry.symbol,
              Slot: toDmlAddress(entry.slot, "dps"),
              Target: toDmlAddress(entry.target, "u"),
              Module: entry.actualModule?.name ?? "unknown",
              Status: entry.status,
            });
          }
        }
      } catch (_error) {
        // Continue scanning other modules.
      }
    }

    if (rows.length === 0) {
      return this.errorRows(`No IAT entries matched "${symbol}".`);
    }
    return rows;
  }

  public iat_ptr(moduleName: string, symbol: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }
    const needle = symbol.trim().toLowerCase();
    if (!needle) {
      return this.errorRows("Symbol is required.");
    }

    try {
      const match = this.iatResolver
        .enumerateIat(lookup.module)
        .find((entry) => entry.symbol.toLowerCase() === needle || entry.symbol.toLowerCase().includes(needle));
      if (!match) {
        return this.errorRows(`No IAT slot found for "${symbol}" in ${lookup.module.name}.`);
      }
      return [
        {
          slot: formatAddress(match.slot, this.pointerSize),
          target: formatAddress(match.target, this.pointerSize),
          module: match.actualModule?.name ?? "unknown",
          symbol: match.symbol,
          status: match.status,
        },
      ];
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  private findModule(name: string): LookupResult {
    const needle = normalizeNeedle(name);
    if (!needle) {
      return { kind: "not_found", name };
    }

    const modules = this.readModules();
    const scored = modules
      .map((module) => {
        const basename = module.name.toLowerCase();
        const basenameNoExt = basename.endsWith(".dll") ? basename.slice(0, -4) : basename;
        const fullPath = module.path.toLowerCase();

        if (basename === needle || basenameNoExt === needle) {
          return { module, score: 0 };
        }
        if (basename.startsWith(needle) || basenameNoExt.startsWith(needle)) {
          return { module, score: 1 };
        }
        if (basename.includes(needle) || basenameNoExt.includes(needle)) {
          return { module, score: 2 };
        }
        if (fullPath.includes(needle)) {
          return { module, score: 3 };
        }
        return undefined;
      })
      .filter((entry): entry is { module: ModuleInfo; score: number } => entry !== undefined);

    if (scored.length === 0) {
      return { kind: "not_found", name };
    }

    const bestScore = Math.min(...scored.map((entry) => entry.score));
    const candidates = scored
      .filter((entry) => entry.score === bestScore)
      .map((entry) => entry.module)
      .sort((a, b) => (a.base < b.base ? -1 : 1));

    if (candidates.length === 1) {
      return { kind: "ok", module: candidates[0] };
    }
    return { kind: "ambiguous", candidates };
  }

  private findMainModule(): LookupResult {
    const modules = this.readModules();
    if (modules.length === 0) {
      return { kind: "not_found", name: "<main-executable>" };
    }

    const process = host as unknown as {
      currentProcess?: {
        ExecutablePath?: string;
        Path?: string;
        Name?: string;
      };
    };
    const executablePath = (process.currentProcess?.ExecutablePath ?? process.currentProcess?.Path ?? "").toLowerCase();
    const processName = (process.currentProcess?.Name ?? "").toLowerCase();

    if (executablePath) {
      const byPath = modules.find((module) => module.path.toLowerCase() === executablePath);
      if (byPath) {
        return { kind: "ok", module: byPath };
      }
    }

    if (processName) {
      const normalized = processName.endsWith(".exe") ? processName : `${processName}.exe`;
      const byName = modules.find((module) => module.name.toLowerCase() === normalized);
      if (byName) {
        return { kind: "ok", module: byName };
      }
    }

    // Fallback: first module by load address is typically the main image.
    return { kind: "ok", module: modules[0] };
  }

  private getPebAddress(): bigint | undefined {
    const hostAny = host as unknown as {
      namespace?: {
        Debugger?: {
          State?: {
            PseudoRegisters?: {
              General?: {
                peb?: unknown;
              };
            };
          };
        };
      };
      currentProcess?: {
        Environment?: {
          EnvironmentBlock?: unknown;
        };
      };
    };

    const fromPseudo = tryToBigInt(hostAny.namespace?.Debugger?.State?.PseudoRegisters?.General?.peb);
    if (fromPseudo && fromPseudo !== BigInt(0)) {
      return fromPseudo;
    }

    const fromProcess = tryToBigInt(hostAny.currentProcess?.Environment?.EnvironmentBlock);
    if (fromProcess && fromProcess !== BigInt(0)) {
      return fromProcess;
    }

    return undefined;
  }

  private readModules(): ModuleInfo[] {
    const hostAny = host as unknown as {
      currentProcess?: {
        Modules?: unknown;
      };
    };
    const source = hostAny.currentProcess?.Modules;
    const items = toArray(source);
    return items
      .map((entry) => {
        const moduleAny = entry as {
          Name?: string;
          Path?: string;
          BaseAddress?: unknown;
          Base?: unknown;
          Address?: unknown;
          EndAddress?: unknown;
          Size?: unknown;
          Length?: unknown;
        };
        const name = moduleAny.Name ?? "<unknown>";
        const path = moduleAny.Path ?? name;
        const base = tryToBigInt(moduleAny.BaseAddress ?? moduleAny.Base ?? moduleAny.Address) ?? BigInt(0);
        let end = tryToBigInt(moduleAny.EndAddress);
        const sizeFromModule = tryToBigInt(moduleAny.Size ?? moduleAny.Length);
        if (!end && sizeFromModule && sizeFromModule > BigInt(0)) {
          end = base + sizeFromModule;
        }
        if (!end) {
          end = base;
        }
        const size = end > base ? end - base : BigInt(0);

        return {
          name,
          path,
          base,
          end,
          size,
        };
      })
      .filter((module) => module.base !== BigInt(0))
      .sort((a, b) => (a.base < b.base ? -1 : 1));
  }

  private collectPageProtections(module: ModuleInfo): Map<number, number> {
    const counts = new Map<number, number>();
    const pageSize = BigInt(0x1000);
    for (let page = module.base; page < module.end; page += pageSize) {
      const protect = this.readPageProtection(page);
      counts.set(protect, (counts.get(protect) ?? 0) + 1);
    }
    return counts;
  }

  private readPageProtection(address: bigint): number {
    const output = executeDebuggerCommand(`!vprot ${formatAddress(address, this.pointerSize)}`);
    const parsed = parseProtectFromVprot(output);
    if (parsed !== undefined) {
      return parsed;
    }
    throw new Error(`Unable to parse !vprot output for ${formatAddress(address, this.pointerSize)}.`);
  }

  private isExecutableProtect(protect: number): boolean {
    return (protect & 0xff) === 0x10 || (protect & 0xff) === 0x20 || (protect & 0xff) === 0x40 || (protect & 0xff) === 0x80;
  }

  private moduleCandidatesRows(candidates: ModuleInfo[]): Array<Record<string, string>> {
    return candidates.map((module) => ({
      Base: toDmlAddress(module.base, "db"),
      End: toDmlAddress(module.end, "db"),
      Name: module.name,
      Path: module.path,
    }));
  }

  private lookupFailureRows(lookup: LookupResult): Array<Record<string, string>> {
    if (lookup.kind === "ambiguous") {
      return this.moduleCandidatesRows(lookup.candidates);
    }
    if (lookup.kind === "not_found") {
      return this.errorRows(`No module matches "${lookup.name}".`);
    }
    return this.errorRows(`Unexpected successful module lookup for "${lookup.module.name}".`);
  }

  private errorRows(message: string): Array<Record<string, string>> {
    return [{ Error: message }];
  }
}

function toArray(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (value && typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function") {
    try {
      return Array.from(value as Iterable<unknown>);
    } catch (_error) {
      return [];
    }
  }
  return [];
}

function executeDebuggerCommand(command: string): string[] {
  const hostAny = host as unknown as {
    namespace?: {
      Debugger?: {
        Utility?: {
          Control?: {
            ExecuteCommand?: (input: string) => unknown;
          };
        };
      };
    };
  };

  const exec = hostAny.namespace?.Debugger?.Utility?.Control?.ExecuteCommand;
  if (typeof exec !== "function") {
    throw new Error("WinDbg command execution is unavailable in this host.");
  }

  const control = hostAny.namespace?.Debugger?.Utility?.Control;
  const result = exec.call(control, command);
  return toArray(result).map((line) => String(line));
}

function parseProtectFromVprot(lines: string[]): number | undefined {
  for (const line of lines) {
    const match = line.match(/^\s*Protect:\s+([0-9a-f`]+)\s+/i);
    if (match) {
      return Number(BigInt(`0x${match[1].replace(/`/g, "")}`) & BigInt(0xffffffff));
    }
  }
  return undefined;
}

function decodeProtectValue(value: number): { name: string; executable: boolean; writable: boolean } {
  const protect = value & 0xff;
  switch (protect) {
    case 0x01:
      return { name: "PAGE_NOACCESS", executable: false, writable: false };
    case 0x02:
      return { name: "PAGE_READONLY", executable: false, writable: false };
    case 0x04:
      return { name: "PAGE_READWRITE", executable: false, writable: true };
    case 0x08:
      return { name: "PAGE_WRITECOPY", executable: false, writable: true };
    case 0x10:
      return { name: "PAGE_EXECUTE", executable: true, writable: false };
    case 0x20:
      return { name: "PAGE_EXECUTE_READ", executable: true, writable: false };
    case 0x40:
      return { name: "PAGE_EXECUTE_READWRITE", executable: true, writable: true };
    case 0x80:
      return { name: "PAGE_EXECUTE_WRITECOPY", executable: true, writable: true };
    default:
      return { name: `0x${protect.toString(16).toUpperCase().padStart(2, "0")}`, executable: false, writable: false };
  }
}

function tryToBigInt(value: unknown): bigint | undefined {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return BigInt(Math.max(0, Math.trunc(value)));
  }
  if (typeof value === "string") {
    const text = value.trim();
    if (/^0x[0-9a-f]+$/i.test(text)) {
      return BigInt(text);
    }
    if (/^[0-9a-f]+$/i.test(text)) {
      return BigInt(`0x${text}`);
    }
    if (/^[0-9]+$/.test(text)) {
      return BigInt(text);
    }
    return undefined;
  }
  if (!value || typeof value !== "object") {
    return undefined;
  }

  const addressed = value as { address?: unknown; Address?: unknown };
  const fromAddress = tryToBigInt(addressed.address ?? addressed.Address);
  if (fromAddress !== undefined) {
    return fromAddress;
  }

  const valueOf = (value as { valueOf?: () => unknown }).valueOf;
  if (typeof valueOf === "function") {
    const unwrapped = valueOf.call(value);
    if (unwrapped !== value) {
      const parsed = tryToBigInt(unwrapped);
      if (parsed !== undefined) {
        return parsed;
      }
    }
  }

  const asString = (value as { toString?: () => string }).toString;
  if (typeof asString === "function") {
    return tryToBigInt(asString.call(value));
  }

  return undefined;
}

function readAsciiString(address: bigint, maxLength: number): string {
  const bytes = readMemory(address, maxLength);
  const chars: string[] = [];
  for (let i = 0; i < bytes.length; i += 1) {
    const ch = bytes[i];
    if (ch === 0) {
      break;
    }
    chars.push(String.fromCharCode(ch));
  }
  return chars.join("");
}

function toDmlAddress(address: bigint, command: string): string {
  const hex = `0x${address.toString(16).toUpperCase()}`;
  return `<link cmd="${command} ${hex}">${hex}</link>`;
}

function machineToString(machine: number): string {
  switch (machine) {
    case 0x014c:
      return "x86";
    case 0x8664:
      return "x64";
    default:
      return "unknown";
  }
}

function normalizeNeedle(value?: string): string {
  if (!value) {
    return "";
  }
  return value.trim().toLowerCase();
}

function formatError(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return String(error);
}

function parseHashValue(value: string | number | bigint): number | undefined {
  if (typeof value === "number") {
    return Number.isFinite(value) ? (value >>> 0) : undefined;
  }
  if (typeof value === "bigint") {
    return Number(value & BigInt(0xffffffff));
  }
  const text = value.trim().toLowerCase();
  if (!text) {
    return undefined;
  }
  const parsed = text.startsWith("0x") ? parseInt(text, 16) : parseInt(text, 10);
  if (Number.isNaN(parsed)) {
    return undefined;
  }
  return parsed >>> 0;
}

export function createShellcodeNamespace(): {
  peb: () => unknown[];
  modules: () => unknown[];
  module_pages: (name: string) => unknown[];
  page_summary: (name: string) => unknown[];
  base: (name: string) => unknown[];
  pe: (name: string) => unknown[];
  exports: (name: string, filter?: string) => unknown[];
  resolve: (module: string, symbol: string) => unknown[];
  hashes: (module: string, algorithm?: string) => unknown[];
  hash: (name: string, algorithm?: string) => unknown[];
  hashresolve: (module: string, hashValue: string | number | bigint, algorithm?: string) => unknown[];
  algorithms: () => unknown[];
  exportdir: (module: string) => unknown[];
  export: (module: string, symbol: string) => unknown[];
  exportat: (module: string, ordinalIndex: number) => unknown[];
  exportwalk: (module: string, symbol?: string, verbose?: boolean) => unknown[];
  iat: (module?: string, filter?: string) => unknown[];
  iat_find: (symbol: string) => unknown[];
  iat_ptr: (module: string, symbol: string) => unknown[];
} {
  const helper = new ShellcodeHelper();
  return {
    peb: () => toDxRows(helper.peb()),
    modules: () => toDxRows(helper.modules()),
    module_pages: (name: string) => toDxRows(helper.modulePages(name)),
    page_summary: (name: string) => toDxRows(helper.pageSummary(name)),
    base: (name: string) => toDxRows(helper.base(name)),
    pe: (name: string) => toDxRows(helper.pe(name)),
    exports: (name: string, filter?: string) => toDxRows(helper.exports(name, filter)),
    resolve: (module: string, symbol: string) => toDxRows(helper.resolve(module, symbol)),
    hashes: (module: string, algorithm?: string) => toDxRows(helper.hashes(module, algorithm)),
    hash: (name: string, algorithm?: string) => toDxRows(helper.hash(name, algorithm)),
    hashresolve: (module: string, hashValue: string | number | bigint, algorithm?: string) =>
      toDxRows(helper.hashresolve(module, hashValue, algorithm)),
    algorithms: () => toDxRows(helper.algorithms()),
    exportdir: (module: string) => toDxRows(helper.exportdir(module)),
    export: (module: string, symbol: string) => toDxRows(helper.export(module, symbol)),
    exportat: (module: string, ordinalIndex: number) => toDxRows(helper.exportat(module, ordinalIndex)),
    exportwalk: (module: string, symbol?: string, verbose?: boolean) => toDxRows(helper.exportwalk(module, symbol, verbose)),
    iat: (module?: string, filter?: string) => toDxRows(helper.iat(module, filter)),
    iat_find: (symbol: string) => toDxRows(helper.iat_find(symbol)),
    iat_ptr: (module: string, symbol: string) => toDxRows(helper.iat_ptr(module, symbol)),
  };
}

class DxRow {
  public constructor(values: Record<string, string>) {
    for (const [key, value] of Object.entries(values)) {
      (this as unknown as Record<string, string>)[key] = value;
    }
  }

  public toString(): string {
    const pairs = Object.entries(this as unknown as Record<string, string>).filter(([, v]) => typeof v === "string");
    return pairs.map(([k, v]) => `${k}: ${v}`).join(" | ");
  }
}

function toDxRows(rows: Array<Record<string, string>>): unknown[] {
  return rows.map((row) => new DxRow(row));
}
