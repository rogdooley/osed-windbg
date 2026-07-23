"use strict";
var osed_bundle = (() => {
  var __defProp = Object.defineProperty;
  var __defProps = Object.defineProperties;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropDescs = Object.getOwnPropertyDescriptors;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getOwnPropSymbols = Object.getOwnPropertySymbols;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __propIsEnum = Object.prototype.propertyIsEnumerable;
  var __defNormalProp = (obj, key2, value) => key2 in obj ? __defProp(obj, key2, { enumerable: true, configurable: true, writable: true, value }) : obj[key2] = value;
  var __spreadValues = (a, b) => {
    for (var prop in b || (b = {}))
      if (__hasOwnProp.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    if (__getOwnPropSymbols)
      for (var prop of __getOwnPropSymbols(b)) {
        if (__propIsEnum.call(b, prop))
          __defNormalProp(a, prop, b[prop]);
      }
    return a;
  };
  var __spreadProps = (a, b) => __defProps(a, __getOwnPropDescs(b));
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key2 of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key2) && key2 !== except)
          __defProp(to, key2, { get: () => from[key2], enumerable: !(desc = __getOwnPropDesc(from, key2)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // src/index.ts
  var index_exports = {};
  __export(index_exports, {
    initializeScript: () => initializeScript
  });

  // src/core/output.ts
  function write(line = "") {
    host.diagnostics.debugLog(`${line}
`);
  }
  function pad(value, width) {
    return value.length >= width ? value : `${value}${" ".repeat(width - value.length)}`;
  }
  function stripDml(value) {
    return value.replace(/<link\b[^>]*>(.*?)<\/link>/gi, "$1");
  }
  function visibleLength(value) {
    return stripDml(value).length;
  }
  function print(message) {
    write(message);
  }
  function section(title) {
    write();
    write(`=== ${title} ===`);
  }
  function info(message) {
    write(`[+] ${message}`);
  }
  function warn(message) {
    write(`[!] ${message}`);
  }
  function error(message) {
    write(`[-] ${message}`);
  }
  function whyItMatters(line) {
    write(`Why this matters for exploitation: ${line}`);
  }
  function formatAddress(address, pointerSize) {
    const width = pointerSize === 8 ? 16 : 8;
    return `0x${address.toString(16).toUpperCase().padStart(width, "0")}`;
  }
  function formatHexByte(byte) {
    return `0x${(byte & 255).toString(16).toUpperCase().padStart(2, "0")}`;
  }
  function table(columns, rows) {
    const hasVisibleValues = rows.some(
      (row) => columns.some((column) => {
        const value = row[column.key];
        return value !== void 0 && value !== "";
      })
    );
    if (rows.length === 0 || !hasVisibleValues) {
      write("(no rows)");
      return;
    }
    const widths = columns.map((column) => {
      var _a;
      const maxValueWidth = rows.reduce((max, row) => {
        var _a2;
        const value = (_a2 = row[column.key]) != null ? _a2 : "";
        return Math.max(max, visibleLength(value));
      }, 0);
      return Math.max((_a = column.width) != null ? _a : 0, column.header.length, maxValueWidth);
    });
    const render = (values) => values.map((value, i) => pad(stripDml(value), widths[i])).join("  ");
    write(render(columns.map((column) => column.header)));
    write(render(widths.map((width) => "-".repeat(width))));
    for (const row of rows) {
      write(render(columns.map((column) => {
        var _a;
        return (_a = row[column.key]) != null ? _a : "";
      })));
    }
  }

  // src/core/validation.ts
  function kindOf(value) {
    if (Array.isArray(value)) {
      return "array";
    }
    if (value === null) {
      return "object";
    }
    return typeof value;
  }
  function validateOptions(options, schema) {
    const errors = [];
    const warnings = [];
    if (typeof options !== "object" || options === null || Array.isArray(options)) {
      return {
        success: false,
        errors: [{ path: "$", message: "Options must be an object." }],
        warnings
      };
    }
    const input = options;
    const normalized = {};
    for (const key2 of Object.keys(input)) {
      if (!(key2 in schema)) {
        errors.push({ path: key2, message: "Unknown option key." });
      }
    }
    for (const [key2, rules] of Object.entries(schema)) {
      const value = input[key2];
      if (value === void 0) {
        if (rules.default !== void 0) {
          normalized[key2] = rules.default;
        } else if (rules.required) {
          errors.push({ path: key2, message: "Missing required option." });
        }
        continue;
      }
      const expectedTypes = Array.isArray(rules.type) ? rules.type : [rules.type];
      const actual = kindOf(value);
      if (!expectedTypes.includes(actual)) {
        errors.push({ path: key2, message: `Expected ${expectedTypes.join(" | ")}.` });
        continue;
      }
      if (rules.enum && typeof value === "string" && !rules.enum.includes(value)) {
        errors.push({ path: key2, message: `Expected one of: ${rules.enum.join(", ")}.` });
        continue;
      }
      if (typeof value === "number") {
        if (!Number.isFinite(value) || !Number.isInteger(value)) {
          errors.push({ path: key2, message: "Expected finite integer." });
          continue;
        }
        if (rules.min !== void 0 && value < rules.min) {
          errors.push({ path: key2, message: `Must be >= ${rules.min}.` });
          continue;
        }
        if (rules.max !== void 0 && value > rules.max) {
          normalized[key2] = rules.max;
          warnings.push(`${key2} clamped to ${rules.max}.`);
          continue;
        }
      }
      if (Array.isArray(value) && rules.elementType) {
        const invalid = value.find((entry) => typeof entry !== rules.elementType);
        if (invalid !== void 0) {
          errors.push({ path: key2, message: `Array entries must be ${rules.elementType}.` });
          continue;
        }
      }
      normalized[key2] = value;
    }
    if (errors.length > 0) {
      return { success: false, errors, warnings };
    }
    return {
      success: true,
      value: normalized,
      errors: [],
      warnings
    };
  }
  function normalizeAddress(value) {
    if (typeof value === "number") {
      if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
        throw new Error("Address number must be a non-negative integer.");
      }
      return BigInt(value);
    }
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!/^0x[0-9a-fA-F]+$/.test(trimmed) && !/^[0-9a-fA-F]+$/.test(trimmed)) {
        throw new Error("Address strings must be hex only (e.g. 0x625011AF).");
      }
      if (/^[0-9]+$/.test(trimmed)) {
        throw new Error("Decimal address strings are not allowed.");
      }
      const hex = trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
      return BigInt(hex);
    }
    throw new Error("Address must be a number or hex string.");
  }
  function normalizeByteArray(values) {
    const invalid = values.find((value) => !Number.isInteger(value) || value < 0 || value > 255);
    if (invalid !== void 0) {
      throw new Error("Byte arrays must contain integers in range 0x00..0xFF.");
    }
    const sorted = [...values].sort((a, b) => a - b);
    const unique = [];
    for (const value of sorted) {
      if (unique.length === 0 || unique[unique.length - 1] !== value) {
        unique.push(value);
      }
    }
    if (unique.length !== values.length) {
      return {
        values: unique,
        warning: "Duplicate exclude bytes were removed during normalization."
      };
    }
    return { values: unique };
  }

  // src/core/registry.ts
  var CommandRegistry = class {
    constructor() {
      this.commands = /* @__PURE__ */ new Map();
    }
    register(command) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(command.name)) {
        throw new Error(`Invalid command name '${command.name}'.`);
      }
      this.commands.set(command.name, command);
    }
    getAll() {
      return [...this.commands.values()].sort((a, b) => a.name.localeCompare(b.name));
    }
    get(name) {
      return this.commands.get(name);
    }
    clear() {
      this.commands.clear();
    }
    setReloader(reloader) {
      this.reloader = reloader;
    }
    reload() {
      if (!this.reloader) {
        return this.failure("reload", {}, "Reload hook is not configured.");
      }
      this.clear();
      this.reloader();
      return {
        command: "reload",
        args: {},
        success: true,
        findings: [{ commandCount: this.getAll().length }],
        warnings: [],
        errors: []
      };
    }
    execute(name, options) {
      const command = this.commands.get(name);
      if (!command) {
        return this.failure(name, {}, `Unknown command '${name}'.`);
      }
      const checked = validateOptions(options != null ? options : {}, command.schema);
      if (!checked.success || !checked.value) {
        const errors = checked.errors.map((issue) => `${issue.path}: ${issue.message}`);
        return {
          command: name,
          args: {},
          success: false,
          findings: [],
          warnings: checked.warnings,
          errors,
          schema: command.schema
        };
      }
      try {
        const result3 = command.execute(checked.value);
        result3.warnings = [...checked.warnings, ...result3.warnings];
        return result3;
      } catch (caught) {
        const message = caught instanceof Error ? caught.message : String(caught);
        error(`Command failed: ${message}`);
        return this.failure(name, checked.value, message);
      }
    }
    failure(name, args, message) {
      return {
        command: name,
        args,
        success: false,
        findings: [],
        warnings: [],
        errors: [message]
      };
    }
  };

  // src/logic/pattern_logic.ts
  var UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var LOWER = "abcdefghijklmnopqrstuvwxyz";
  var DIGITS = "0123456789";
  var MSF_MAX_LENGTH = 20280;
  function generateMsfPattern(length) {
    const chunks = [];
    for (const a of UPPER) {
      for (const b of LOWER) {
        for (const c of DIGITS) {
          chunks.push(`${a}${b}${c}`);
        }
      }
    }
    return chunks.join("").slice(0, length);
  }
  function deBruijn(alphabet, order) {
    const k = alphabet.length;
    const a = new Array(k * order).fill(0);
    const result3 = [];
    function db(t, p) {
      if (t > order) {
        if (order % p === 0) {
          for (let i = 1; i <= p; i += 1) {
            result3.push(a[i]);
          }
        }
        return;
      }
      a[t] = a[t - p];
      db(t + 1, p);
      for (let j = a[t - p] + 1; j < k; j += 1) {
        a[t] = j;
        db(t + 1, t);
      }
    }
    db(1, 1);
    return result3.map((index) => alphabet[index]).join("");
  }
  function generateCyclicPattern(length) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const sequence = deBruijn(alphabet, 3);
    if (length > sequence.length) {
      throw new Error(
        `Cyclic pattern length ${length} exceeds the maximum unique-window length ${sequence.length}. Use a smaller length or the "msf" pattern type.`
      );
    }
    return sequence.slice(0, length);
  }
  function decodeOffsetNeedle(value) {
    if (typeof value === "number") {
      if (!Number.isInteger(value) || value < 0 || value > 4294967295) {
        throw new Error("Numeric pattern_offset value must be a 32-bit unsigned integer.");
      }
      const bytes = [
        value & 255,
        value >>> 8 & 255,
        value >>> 16 & 255,
        value >>> 24 & 255
      ];
      return String.fromCharCode(...bytes);
    }
    if (!/^(0x)?[0-9a-fA-F]+$/.test(value)) {
      throw new Error("String pattern_offset value must be raw hex only.");
    }
    const hex = value.startsWith("0x") ? value.slice(2) : value;
    if (hex.length % 2 !== 0) {
      throw new Error("Hex string length must be even.");
    }
    const chars = [];
    for (let i = 0; i < hex.length; i += 2) {
      chars.push(parseInt(hex.slice(i, i + 2), 16));
    }
    return String.fromCharCode(...chars.reverse());
  }

  // src/commands/pattern.ts
  function success(command, args, findings) {
    return { command, args, success: true, findings, warnings: [], errors: [] };
  }
  function createPatternCommands() {
    const patternCreate = {
      name: "pattern_create",
      description: "Generate cyclic pattern strings.",
      usage: "dx @$osed().pattern_create({ length: 300, type: 'msf' })",
      examples: [
        "dx @$osed().pattern_create({ length: 300, type: 'msf' })",
        "dx @$osed().pattern_create({ length: 800, type: 'cyclic' })"
      ],
      schema: {
        length: { type: "number", required: true, min: 1, max: 1e5 },
        type: { type: "string", enum: ["msf", "cyclic"], default: "msf" }
      },
      execute(options) {
        const length = options.length;
        const type = options.type;
        if (type === "msf" && length > MSF_MAX_LENGTH) {
          throw new Error(`MSF pattern max length is ${MSF_MAX_LENGTH}.`);
        }
        const pattern = type === "msf" ? generateMsfPattern(length) : generateCyclicPattern(length);
        section("Pattern Create");
        info(`Format: ${type}`);
        info(`Length: ${length}`);
        print(pattern);
        whyItMatters("Reliable offset discovery is the foundation of controlled EIP/RIP overwrite.");
        return success("pattern_create", options, [{ type, length, pattern }]);
      }
    };
    const patternOffset = {
      name: "pattern_offset",
      description: "Locate value offset inside a generated pattern.",
      usage: "dx @$osed().pattern_offset({ value: 0x39654138, type: 'msf' })",
      examples: [
        "dx @$osed().pattern_offset({ value: 0x39654138, type: 'msf' })",
        "dx @$osed().pattern_offset({ value: '41326341', type: 'cyclic' })"
      ],
      schema: {
        value: { type: ["number", "string"], required: true },
        type: { type: "string", enum: ["msf", "cyclic"], default: "msf" }
      },
      execute(options) {
        const raw = options.value;
        if (typeof raw !== "number" && typeof raw !== "string") {
          throw new Error("pattern_offset.value must be number or hex string.");
        }
        const needle = decodeOffsetNeedle(raw);
        const type = options.type;
        const pattern = type === "msf" ? generateMsfPattern(MSF_MAX_LENGTH) : generateCyclicPattern(1e5);
        const offset = pattern.indexOf(needle);
        section("Pattern Offset");
        info(`Format: ${type}`);
        info(`Needle: ${needle}`);
        if (offset < 0) {
          error("Needle not found in selected pattern.");
        } else {
          info(`Offset: ${offset}`);
        }
        whyItMatters("Exact offset maps crash control to payload layout and exploit reliability.");
        return success("pattern_offset", options, [{ needle, offset }]);
      }
    };
    return [patternCreate, patternOffset];
  }

  // src/core/memory.ts
  function readMemory(address, length) {
    const attempts = [address];
    if (address >= BigInt(0) && address <= BigInt(Number.MAX_SAFE_INTEGER)) {
      attempts.push(Number(address));
    }
    let lastError;
    for (const attempt of attempts) {
      try {
        const values = host.memory.readMemoryValues(attempt, length, 1, false);
        return Uint8Array.from(values.map((value) => value & 255));
      } catch (error2) {
        lastError = error2;
      }
    }
    const suffix = lastError instanceof Error && lastError.message ? ` (${lastError.message})` : "";
    throw new Error(`Memory read failed at ${formatAddress(address, 8)}${suffix}.`);
  }
  function tryReadMemory(address, length) {
    try {
      return readMemory(address, length);
    } catch (_error) {
      return void 0;
    }
  }
  function readUint16LE(address) {
    const bytes = readMemory(address, 2);
    return bytes[0] | bytes[1] << 8;
  }
  function readUint32LE(address) {
    const bytes = readMemory(address, 4);
    return (bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24) >>> 0;
  }
  function readUint64LE(address) {
    const bytes = readMemory(address, 8);
    let result3 = BigInt(0);
    for (let i = 0; i < 8; i += 1) {
      result3 |= BigInt(bytes[i]) << BigInt(i * 8);
    }
    return result3;
  }
  function readPointer(address, pointerSize) {
    return pointerSize === 8 ? readUint64LE(address) : BigInt(readUint32LE(address));
  }
  function getPointerSize() {
    var _a;
    const process = host.currentProcess;
    const machine = ((_a = process == null ? void 0 : process.Machine) != null ? _a : "").toLowerCase();
    if ((process == null ? void 0 : process.Is64Bit) || machine.includes("x64") || machine.includes("amd64")) {
      return 8;
    }
    return 4;
  }

  // src/logic/badchars_logic.ts
  function expectedBytes(exclude) {
    const excluded = new Set(exclude.map((value) => value & 255));
    const result3 = [];
    for (let i = 0; i <= 255; i += 1) {
      if (!excluded.has(i)) {
        result3.push(i);
      }
    }
    return result3;
  }
  function hexByte(value) {
    return (value & 255).toString(16).padStart(2, "0");
  }
  function formatByteArray(bytes, format) {
    switch (format) {
      case "python":
        return `b"${bytes.map((value) => `\\x${hexByte(value)}`).join("")}"`;
      case "c":
        return `"${bytes.map((value) => `\\x${hexByte(value)}`).join("")}"`;
      case "hex":
      default:
        return bytes.map(hexByte).join(" ");
    }
  }
  function locateExpectedArray(window, expected, minRun = 8) {
    let best = { offset: -1, matchedRun: 0 };
    for (let start = 0; start < window.length; start += 1) {
      let run = 0;
      for (let i = 0; start + i < window.length && i < expected.length; i += 1) {
        if (window[start + i] !== expected[i]) {
          break;
        }
        run += 1;
      }
      if (run > best.matchedRun) {
        best = { offset: start, matchedRun: run };
      }
    }
    return best.matchedRun >= minRun ? best : void 0;
  }
  function compareBadchars(observed, expected) {
    const mismatches = [];
    let breakOffset;
    for (let i = 0; i < expected.length && i < observed.length; i += 1) {
      if (observed[i] !== expected[i]) {
        mismatches.push({
          offset: i,
          expected: expected[i],
          observed: observed[i]
        });
        if (breakOffset === void 0) {
          breakOffset = i;
        }
      }
    }
    return {
      mismatches,
      breakOffset,
      nextExpected: breakOffset === void 0 ? void 0 : expected[breakOffset]
    };
  }

  // src/core/scan_engine.ts
  var IMAGE_SCN_MEM_EXECUTE = 536870912;
  function decodeAscii(bytes) {
    let result3 = "";
    for (const byte of bytes) {
      if (byte === 0) {
        break;
      }
      result3 += String.fromCharCode(byte);
    }
    return result3;
  }
  function parseBigIntString(value) {
    const text = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(text)) {
      return BigInt(text);
    }
    if (/^[0-9a-fA-F]+$/.test(text)) {
      return BigInt(`0x${text}`);
    }
    if (/^[0-9]+$/.test(text)) {
      return BigInt(text);
    }
    return BigInt(0);
  }
  function toBigInt(value) {
    if (typeof value === "bigint") {
      return value;
    }
    if (typeof value === "number") {
      return BigInt(Math.max(0, Math.trunc(value)));
    }
    if (typeof value === "string") {
      return parseBigIntString(value);
    }
    if (value && typeof value === "object") {
      const valueOf = value.valueOf;
      if (typeof valueOf === "function") {
        const resolved = valueOf.call(value);
        if (resolved !== value) {
          const parsed = toBigInt(resolved);
          if (parsed !== BigInt(0)) {
            return parsed;
          }
        }
      }
      const asString = value.toString;
      if (typeof asString === "function") {
        return parseBigIntString(asString.call(value));
      }
    }
    return BigInt(0);
  }
  function asArray(value) {
    if (Array.isArray(value)) {
      return value;
    }
    if (value && typeof value[Symbol.iterator] === "function") {
      try {
        return Array.from(value);
      } catch (_error) {
        return [];
      }
    }
    return [];
  }
  function getModules() {
    const process = host.currentProcess;
    const modules = asArray(process == null ? void 0 : process.Modules);
    return modules.map((entry) => {
      var _a, _b, _c, _d, _e, _f;
      const module = entry;
      const base = toBigInt((_b = (_a = module.BaseAddress) != null ? _a : module.Base) != null ? _b : module.Address);
      let size = toBigInt((_c = module.Size) != null ? _c : module.Length);
      const end = toBigInt(module.EndAddress);
      if (size === BigInt(0) && end > base) {
        size = end - base;
      }
      return {
        name: (_d = module.Name) != null ? _d : "<unknown>",
        path: (_f = (_e = module.Path) != null ? _e : module.Name) != null ? _f : "<unknown>",
        base,
        size
      };
    }).filter((module) => module.size > BigInt(0)).sort((a, b) => a.base < b.base ? -1 : 1);
  }
  function parseSections(module) {
    var _a;
    const sections = [];
    try {
      const mz = readUint16LE(module.base);
      if (mz !== 23117) {
        return sections;
      }
      const peOffset = readUint32LE(module.base + BigInt(60));
      const pe = module.base + BigInt(peOffset);
      const sig = readUint32LE(pe);
      if (sig !== 17744) {
        return sections;
      }
      const sectionCount = readUint16LE(pe + BigInt(6));
      const optionalHeaderSize = readUint16LE(pe + BigInt(20));
      const sectionTable = pe + BigInt(24) + BigInt(optionalHeaderSize);
      for (let i = 0; i < sectionCount; i += 1) {
        const entry = sectionTable + BigInt(i * 40);
        const nameBytes = (_a = tryReadMemory(entry, 8)) != null ? _a : new Uint8Array();
        const name = decodeAscii(nameBytes).replace(/\0+$/, "") || `.sec${i}`;
        const virtualSize = readUint32LE(entry + BigInt(8));
        const virtualAddress = readUint32LE(entry + BigInt(12));
        const characteristics = readUint32LE(entry + BigInt(36));
        const executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0;
        if (virtualSize > 0) {
          sections.push({
            module,
            name,
            start: module.base + BigInt(virtualAddress),
            size: virtualSize,
            executable
          });
        }
      }
    } catch (_error) {
      return [];
    }
    return sections;
  }
  function matchesModuleFilter(module, filter) {
    if (!filter) {
      return true;
    }
    const needle = filter.toLowerCase();
    return module.name.toLowerCase().includes(needle) || module.path.toLowerCase().includes(needle);
  }
  function forEachSection(options) {
    const warnings = [];
    const sections = [];
    for (const module of getModules().filter((item) => matchesModuleFilter(item, options.module))) {
      const parsed = parseSections(module);
      if (parsed.length === 0) {
        warnings.push(`Could not parse PE sections for module ${module.name}.`);
        continue;
      }
      for (const section2 of parsed) {
        if (!options.executableOnly || section2.executable) {
          sections.push(section2);
        }
      }
    }
    sections.sort((a, b) => a.start < b.start ? -1 : 1);
    return { sections, warnings };
  }
  function scanPattern(options, pattern) {
    const hits = [];
    const warnings = [];
    const normalizedChunk = Math.max(4096, Math.min(16384, options.chunkSize));
    const normalizedMax = Math.min(options.maxResults, 200);
    const scope = forEachSection(__spreadProps(__spreadValues({}, options), {
      chunkSize: normalizedChunk,
      maxResults: normalizedMax
    }));
    for (const warning of scope.warnings) {
      warnings.push({ region: "module", message: warning });
    }
    let chunksRead = 0;
    let chunksSkipped = 0;
    for (const section2 of scope.sections) {
      for (let offset = 0; offset < section2.size; offset += normalizedChunk) {
        const chunkStart = section2.start + BigInt(offset);
        const remaining = section2.size - offset;
        const size = Math.max(0, Math.min(remaining, normalizedChunk + pattern.length - 1));
        if (size < pattern.length) {
          continue;
        }
        const bytes = tryReadMemory(chunkStart, size);
        if (!bytes) {
          chunksSkipped += 1;
          warnings.push({
            region: `${section2.module.name}:${section2.name}`,
            message: `Unreadable memory at chunk offset 0x${offset.toString(16).toUpperCase()}.`
          });
          continue;
        }
        chunksRead += 1;
        const last = bytes.length - pattern.length;
        for (let i = 0; i <= last; i += 1) {
          let matched = true;
          for (let j = 0; j < pattern.length; j += 1) {
            if (bytes[i + j] !== pattern[j]) {
              matched = false;
              break;
            }
          }
          if (matched) {
            hits.push(chunkStart + BigInt(i));
            if (hits.length >= normalizedMax) {
              return {
                hits: hits.sort((a, b) => a < b ? -1 : 1),
                warnings,
                stats: {
                  sectionsScanned: scope.sections.length,
                  chunksRead,
                  chunksSkipped,
                  results: hits.length,
                  stoppedEarly: 1
                }
              };
            }
          }
        }
      }
    }
    return {
      hits: hits.sort((a, b) => a < b ? -1 : 1),
      warnings,
      stats: {
        sectionsScanned: scope.sections.length,
        chunksRead,
        chunksSkipped,
        results: hits.length,
        stoppedEarly: 0
      }
    };
  }

  // src/analysis/memory.ts
  var PAGE_NOACCESS = 1;
  var PAGE_READONLY = 2;
  var PAGE_READWRITE = 4;
  var PAGE_WRITECOPY = 8;
  var PAGE_EXECUTE = 16;
  var PAGE_EXECUTE_READ = 32;
  var PAGE_EXECUTE_READWRITE = 64;
  var PAGE_EXECUTE_WRITECOPY = 128;
  var PAGE_GUARD = 256;
  var MEM_COMMIT = 4096;
  var MEM_PRIVATE = 131072;
  var MEM_MAPPED = 262144;
  var MEM_IMAGE = 16777216;
  function protectionBase(protection) {
    return protection & 255;
  }
  function formatAddressValue(value) {
    return `0x${value.toString(16).toUpperCase().padStart(16, "0")}`;
  }
  function serializeMemoryRegionEvidence(evidence) {
    return {
      address: formatAddressValue(evidence.address),
      baseAddress: evidence.baseAddress === void 0 ? void 0 : formatAddressValue(evidence.baseAddress),
      allocationBase: evidence.allocationBase === void 0 ? void 0 : formatAddressValue(evidence.allocationBase),
      regionSize: evidence.regionSize === void 0 ? void 0 : `0x${evidence.regionSize.toString(16).toUpperCase()}`,
      readable: evidence.readable,
      writable: evidence.writable,
      executable: evidence.executable,
      guarded: evidence.guarded,
      noAccess: evidence.noAccess,
      committed: evidence.committed,
      regionType: evidence.regionType,
      raw: __spreadValues({}, evidence.raw),
      source: evidence.source,
      warnings: [...evidence.warnings]
    };
  }
  function normalizeMemoryRegion(address, raw, source = "vprot") {
    const protection = raw.protection;
    const base = protection === void 0 ? void 0 : protectionBase(protection);
    const knownProtection = base !== void 0 && [
      PAGE_NOACCESS,
      PAGE_READONLY,
      PAGE_READWRITE,
      PAGE_WRITECOPY,
      PAGE_EXECUTE,
      PAGE_EXECUTE_READ,
      PAGE_EXECUTE_READWRITE,
      PAGE_EXECUTE_WRITECOPY
    ].includes(base);
    const readable = !knownProtection ? null : [PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].includes(base);
    const writable = !knownProtection ? null : [PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].includes(base);
    const executable = !knownProtection ? null : [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].includes(base);
    let regionType = "unknown";
    if (raw.type === MEM_IMAGE) regionType = "image";
    else if (raw.type === MEM_MAPPED) regionType = "mapped";
    else if (raw.type === MEM_PRIVATE) regionType = "private";
    return {
      address,
      baseAddress: raw.baseAddress,
      allocationBase: raw.allocationBase,
      regionSize: raw.regionSize,
      readable,
      writable,
      executable,
      guarded: protection === void 0 ? null : (protection & PAGE_GUARD) !== 0,
      noAccess: !knownProtection ? null : base === PAGE_NOACCESS,
      committed: raw.state === void 0 ? null : raw.state === MEM_COMMIT,
      regionType,
      raw: {
        state: raw.state,
        protection: raw.protection,
        allocationProtection: raw.allocationProtection,
        type: raw.type
      },
      source,
      warnings: []
    };
  }
  function toArray(value) {
    if (Array.isArray(value)) return value;
    if (value && typeof value[Symbol.iterator] === "function") {
      try {
        return Array.from(value);
      } catch (_error) {
        return [];
      }
    }
    return [];
  }
  function parseHexValue(value) {
    const cleaned = value.replace(/`/g, "");
    return /^[0-9a-f]+$/i.test(cleaned) ? BigInt(`0x${cleaned}`) : void 0;
  }
  function parseVprot(lines) {
    const fields = /* @__PURE__ */ new Map();
    for (const line of lines) {
      const match = line.match(/^\s*(BaseAddress|AllocationBase|RegionSize|State|Protect|AllocationProtect|Type):\s+([0-9a-f`]+)/i);
      if (!match) continue;
      const value = parseHexValue(match[2]);
      if (value !== void 0) fields.set(match[1].toLowerCase(), value);
    }
    const asNumber = (key2) => {
      const value = fields.get(key2);
      return value === void 0 ? void 0 : Number(value & BigInt(4294967295));
    };
    return {
      baseAddress: fields.get("baseaddress"),
      allocationBase: fields.get("allocationbase"),
      regionSize: fields.get("regionsize"),
      state: asNumber("state"),
      protection: asNumber("protect"),
      allocationProtection: asNumber("allocationprotect"),
      type: asNumber("type")
    };
  }
  function memoryRegion(address) {
    var _a, _b, _c;
    try {
      const hostAny = host;
      const control = (_c = (_b = (_a = hostAny.namespace) == null ? void 0 : _a.Debugger) == null ? void 0 : _b.Utility) == null ? void 0 : _c.Control;
      const execute = control == null ? void 0 : control.ExecuteCommand;
      if (typeof execute !== "function") throw new Error("WinDbg command execution is unavailable.");
      const result3 = execute.call(control, `!vprot 0x${address.toString(16)}`);
      const raw = parseVprot(toArray(result3).map(String));
      if (raw.protection === void 0 && raw.state === void 0 && raw.type === void 0) {
        throw new Error("WinDbg returned no recognizable memory metadata.");
      }
      return normalizeMemoryRegion(address, raw);
    } catch (error2) {
      const evidence = normalizeMemoryRegion(address, {}, "unavailable");
      evidence.warnings.push(error2 instanceof Error ? error2.message : String(error2));
      return evidence;
    }
  }

  // src/analysis/landing.ts
  var POSITIVE_OBSERVATION_KINDS = /* @__PURE__ */ new Set([
    "nop_sled_detected",
    "repeated_marker_bytes",
    "cyclic_pattern_match",
    "payload_like_bytes",
    "known_payload_prefix",
    "executable_region",
    "disassembly_succeeded"
  ]);
  function formatAddressValue2(value) {
    return `0x${value.toString(16).toUpperCase().padStart(16, "0")}`;
  }
  function serializeUnknown(value) {
    if (typeof value === "bigint") return formatAddressValue2(value);
    if (Array.isArray(value)) return value.map(serializeUnknown);
    if (value && typeof value === "object") {
      const out = {};
      for (const [key2, entry] of Object.entries(value)) {
        out[key2] = serializeUnknown(entry);
      }
      return out;
    }
    return value;
  }
  function serializeLandingEvidence(evidence) {
    return {
      address: evidence.address === void 0 ? void 0 : formatAddressValue2(evidence.address),
      memory: evidence.memory === void 0 ? void 0 : serializeMemoryRegionEvidence(evidence.memory),
      bytes: [...evidence.bytes],
      requestedBytes: evidence.requestedBytes,
      observations: evidence.observations.map((item) => ({
        kind: item.kind,
        confidence: item.confidence,
        address: item.address === void 0 ? void 0 : formatAddressValue2(item.address),
        length: item.length,
        details: serializeUnknown(item.details)
      })),
      confidence: evidence.confidence,
      recommendation: evidence.recommendation
    };
  }
  function calculateLandingConfidence(observations) {
    const contributions = observations.filter((item) => POSITIVE_OBSERVATION_KINDS.has(item.kind)).map((item) => Math.max(0, Math.min(1, Number.isFinite(item.confidence) ? item.confidence : 0))).sort((left, right) => left - right);
    if (contributions.length === 0) return 0;
    return Math.max(0, Math.min(1, contributions.reduce((sum, value) => sum + value, 0) / 2));
  }
  function observation(kind, confidence, address, offset, length, details = {}) {
    return { kind, confidence, address: address + BigInt(offset), length, details: __spreadValues({ offset }, details) };
  }
  function repeatedRuns(bytes, minimum = 4) {
    const runs = [];
    for (let start = 0; start < bytes.length; ) {
      let end = start + 1;
      while (end < bytes.length && bytes[end] === bytes[start]) end += 1;
      if (end - start >= minimum) runs.push({ byte: bytes[start], offset: start, length: end - start });
      start = end;
    }
    return runs;
  }
  function findPattern(bytes) {
    if (bytes.length < 8) return void 0;
    const text = String.fromCharCode(...bytes);
    const candidates2 = [
      { kind: "msf", value: generateMsfPattern(20280) },
      { kind: "cyclic", value: generateCyclicPattern(2e4) }
    ];
    for (const candidate of candidates2) {
      const length = Math.min(text.length, 32);
      for (let window = length; window >= 8; window -= 1) {
        for (let offset = 0; offset <= text.length - window; offset += 1) {
          if (candidate.value.includes(text.slice(offset, offset + window))) return { kind: candidate.kind, offset, length: window };
        }
      }
    }
    return void 0;
  }
  function analyzeLandingBytes(address, bytes, memory, requestedBytes = bytes.length, disassemblySucceeded = null) {
    const observations = [];
    const runs = repeatedRuns(bytes);
    for (const run of runs) {
      if (run.byte === 144 && run.length >= 8) {
        observations.push(observation("nop_sled_detected", 0.95, address, run.offset, run.length, { byte: run.byte }));
      } else if ([65, 66, 67, 68].includes(run.byte)) {
        observations.push(observation("repeated_marker_bytes", 0.8, address, run.offset, run.length, { byte: run.byte }));
      } else {
        observations.push(observation("repeated_byte_run", 0.45, address, run.offset, run.length, { byte: run.byte }));
      }
    }
    const pattern = findPattern(bytes);
    if (pattern) observations.push(observation("cyclic_pattern_match", 0.9, address, pattern.offset, pattern.length, { pattern: pattern.kind }));
    for (let offset = 0; offset <= bytes.length - 32; offset += 4) {
      const window = bytes.slice(offset, offset + 32);
      let zeroes = 0;
      let printable = 0;
      for (const byte of window) {
        if (byte === 0) zeroes += 1;
        if (byte >= 32 && byte <= 126) printable += 1;
      }
      if (zeroes <= 1 && printable <= 8) {
        observations.push(observation("payload_like_bytes", 0.4, address, offset, window.length, { zeroes, printable }));
      }
    }
    const prefixes = [
      { name: "x86_cld_call", bytes: [252, 232] },
      { name: "x86_getpc_fnstenv", bytes: [217, 238, 217, 116, 36, 244] }
    ];
    for (const prefix of prefixes) {
      if (prefix.bytes.every((value, index) => bytes[index] === value)) {
        observations.push(observation("known_payload_prefix", 0.65, address, 0, prefix.bytes.length, { prefix: prefix.name }));
      }
    }
    if (memory.readable !== null) observations.push(observation(memory.readable ? "readable_region" : "unreadable_region", 1, address, 0, bytes.length));
    if (memory.executable !== null) observations.push(observation(memory.executable ? "executable_region" : "non_executable_region", 1, address, 0, bytes.length));
    if (disassemblySucceeded !== null) observations.push(observation(disassemblySucceeded ? "disassembly_succeeded" : "disassembly_failed", 0.8, address, 0, Math.min(bytes.length, 16)));
    if (bytes.length < requestedBytes) observations.push(observation(bytes.length === 0 ? "bytes_inaccessible" : "bytes_truncated", 1, address, bytes.length, requestedBytes - bytes.length, { requestedBytes, actualBytes: bytes.length }));
    const positive = observations.filter((item) => POSITIVE_OBSERVATION_KINDS.has(item.kind));
    const confidence = calculateLandingConfidence(observations);
    const recommendation = memory.executable === false ? "Execution from this page will fault; redirect to executable memory or change the staging strategy." : bytes.length === 0 ? "The landing bytes are inaccessible; verify the address and debugger context." : positive.length > 0 ? "The address has payload-like evidence; validate control flow and the complete byte sequence." : "No strong landing signal was found in the sampled bytes.";
    return { address, memory, bytes: Array.from(bytes), requestedBytes, observations, confidence, recommendation };
  }
  function stackPointer() {
    var _a, _b, _c;
    const thread = host.currentThread;
    const registers = (_b = (_a = thread == null ? void 0 : thread.Registers) == null ? void 0 : _a.User) != null ? _b : thread == null ? void 0 : thread.Registers;
    const names = getPointerSize() === 8 ? ["rsp", "esp"] : ["esp", "rsp"];
    for (const name of names) {
      const value = (_c = registers == null ? void 0 : registers[name]) != null ? _c : registers == null ? void 0 : registers[name.toUpperCase()];
      if (typeof value === "bigint") return value;
      if (typeof value === "number" && Number.isFinite(value)) return BigInt(Math.trunc(value));
      if (typeof value === "string" && /^(0x)?[0-9a-f`]+$/i.test(value)) return BigInt(`0x${value.replace(/^0x/i, "").replace(/`/g, "")}`);
      if (value && typeof value === "object") {
        try {
          const rendered = String(value);
          if (/^(0x)?[0-9a-f`]+$/i.test(rendered)) return BigInt(`0x${rendered.replace(/^0x/i, "").replace(/`/g, "")}`);
        } catch (_error) {
        }
      }
    }
    return void 0;
  }
  function readAvailablePrefix(address, requestedBytes) {
    const complete = tryReadMemory(address, requestedBytes);
    if (complete) return complete;
    let low = 0;
    let high = requestedBytes - 1;
    let available = new Uint8Array();
    while (low <= high) {
      const length = Math.floor((low + high) / 2);
      if (length === 0) {
        low = 1;
        continue;
      }
      const bytes = tryReadMemory(address, length);
      if (bytes) {
        available = bytes;
        low = length + 1;
      } else {
        high = length - 1;
      }
    }
    return available;
  }
  function canDisassemble(address) {
    var _a, _b, _c;
    try {
      const hostAny = host;
      const control = (_c = (_b = (_a = hostAny.namespace) == null ? void 0 : _a.Debugger) == null ? void 0 : _b.Utility) == null ? void 0 : _c.Control;
      if (typeof (control == null ? void 0 : control.ExecuteCommand) !== "function") return null;
      const lines = Array.from(control.ExecuteCommand.call(control, `u 0x${address.toString(16)} L1`)).map(String);
      return lines.some((line) => /\b[0-9a-f`]+\s+[0-9a-f]{2}/i.test(line)) && !lines.some((line) => /memory access error|could not be read|unable to/i.test(line));
    } catch (_error) {
      return null;
    }
  }
  function landing(address, requestedBytes = 64) {
    const target = address != null ? address : stackPointer();
    if (target === void 0) {
      return { bytes: [], requestedBytes, observations: [], confidence: 0, recommendation: "Stack pointer is unavailable; provide an explicit address." };
    }
    const memory = memoryRegion(target);
    const bytes = readAvailablePrefix(target, requestedBytes);
    return analyzeLandingBytes(target, bytes, memory, requestedBytes, canDisassemble(target));
  }

  // src/analysis/seh.ts
  function safeGet(value, key2) {
    if (!value || typeof value !== "object") return void 0;
    try {
      return value[key2];
    } catch (_error) {
      return void 0;
    }
  }
  function safeKeys(value) {
    if (!value || typeof value !== "object") return [];
    try {
      return Object.keys(value);
    } catch (_error) {
      return [];
    }
  }
  function toAddress(value) {
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && Number.isFinite(value)) return BigInt(Math.max(0, Math.trunc(value)));
    if (typeof value === "string") {
      const text = value.trim();
      const embeddedHex = text.match(/0x[0-9a-fA-F]+/);
      if (embeddedHex) return BigInt(embeddedHex[0]);
      if (/^[0-9a-fA-F]+$/.test(text)) return BigInt(`0x${text}`);
    }
    if (value && typeof value === "object") {
      for (const key2 of ["targetLocation", "address", "Address", "Value", "value"]) {
        const parsed = toAddress(safeGet(value, key2));
        if (parsed !== BigInt(0)) return parsed;
      }
      try {
        const valueOf = safeGet(value, "valueOf");
        if (typeof valueOf === "function") {
          const resolved = valueOf.call(value);
          if (resolved !== value) {
            const parsed = toAddress(resolved);
            if (parsed !== BigInt(0)) return parsed;
          }
        }
      } catch (_error) {
      }
      try {
        const toString = safeGet(value, "toString");
        if (typeof toString === "function") return toAddress(toString.call(value));
      } catch (_error) {
      }
    }
    return BigInt(0);
  }
  function signedInteger(value) {
    if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
    if (typeof value === "bigint") return Number(value);
    const text = typeof value === "string" ? value : String(value != null ? value : "");
    const match = text.match(/-?[0-9]+/);
    return match ? parseInt(match[0], 10) : 0;
  }
  function environmentTeb(thread) {
    for (const environment of [safeGet(thread, "Environment"), safeGet(thread, "NativeEnvironment")]) {
      const block = safeGet(environment, "EnvironmentBlock");
      if (!block || typeof block !== "object") continue;
      const direct = toAddress(safeGet(block, "Self"));
      if (direct !== BigInt(0)) return direct;
      const ntTib = safeGet(block, "NtTib");
      const nativeSelf = toAddress(safeGet(ntTib, "Self"));
      const wowOffset = signedInteger(safeGet(block, "WowTebOffset"));
      if (nativeSelf !== BigInt(0) && wowOffset !== 0) return nativeSelf + BigInt(wowOffset);
      if (nativeSelf !== BigInt(0)) return nativeSelf;
    }
    return BigInt(0);
  }
  function candidates(value, depth = 0) {
    if (depth > 2 || value === null || value === void 0) return [];
    const found = /* @__PURE__ */ new Set();
    const direct = toAddress(value);
    if (direct !== BigInt(0)) found.add(direct);
    if (typeof value === "object") {
      for (const key2 of safeKeys(value)) {
        for (const item of candidates(safeGet(value, key2), depth + 1)) found.add(item);
      }
    }
    return [...found];
  }
  function looksLikeTeb32(address, reader) {
    try {
      if (address < BigInt(4096) || reader(address + BigInt(24), 4) !== address) return false;
      const head = reader(address, 4);
      return head !== BigInt(0) && head !== BigInt(4294967295);
    } catch (_error) {
      return false;
    }
  }
  function resolveTeb32Address(thread, reader = readPointer) {
    const fromEnvironment = environmentTeb(thread);
    if (fromEnvironment !== BigInt(0)) return fromEnvironment;
    for (const key2 of ["Teb", "Teb32", "TebAddress", "Wow64Teb", "Wow64Teb32"]) {
      const parsed = toAddress(safeGet(thread, key2));
      if (parsed !== BigInt(0)) return parsed;
    }
    for (const key2 of safeKeys(thread)) {
      if (/teb/i.test(key2)) {
        const parsed = toAddress(safeGet(thread, key2));
        if (parsed !== BigInt(0)) return parsed;
      }
    }
    return candidates(thread).find((candidate) => looksLikeTeb32(candidate, reader));
  }
  function readSehRecords(teb, maxRecords = 64, reader = readPointer) {
    const records = [];
    let node = reader(teb, 4);
    while (node !== BigInt(4294967295) && records.length < maxRecords) {
      const next = reader(node, 4);
      records.push({ node, next, handler: reader(node + BigInt(4), 4) });
      node = next;
    }
    return records;
  }

  // src/commands/modules.ts
  var IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 64;
  var IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 256;
  function parseBigIntString2(value) {
    const text = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(text)) {
      return BigInt(text);
    }
    if (/^[0-9a-fA-F]+$/.test(text)) {
      return BigInt(`0x${text}`);
    }
    if (/^[0-9]+$/.test(text)) {
      return BigInt(text);
    }
    return BigInt(0);
  }
  function toBigInt2(value) {
    if (typeof value === "bigint") {
      return value;
    }
    if (typeof value === "number") {
      return BigInt(Math.max(0, Math.trunc(value)));
    }
    if (typeof value === "string") {
      return parseBigIntString2(value);
    }
    if (value && typeof value === "object") {
      const valueOf = value.valueOf;
      if (typeof valueOf === "function") {
        const resolved = valueOf.call(value);
        if (resolved !== value) {
          const parsed = toBigInt2(resolved);
          if (parsed !== BigInt(0)) {
            return parsed;
          }
        }
      }
      const asString = value.toString;
      if (typeof asString === "function") {
        return parseBigIntString2(asString.call(value));
      }
    }
    return BigInt(0);
  }
  function asArray2(value) {
    if (Array.isArray(value)) {
      return value;
    }
    if (value && typeof value[Symbol.iterator] === "function") {
      try {
        return Array.from(value);
      } catch (_error) {
        return [];
      }
    }
    return [];
  }
  function parseSafeSeh(base, pe, optionalHeaderMagic) {
    if (optionalHeaderMagic !== 267) {
      return "unknown";
    }
    try {
      const optionalHeaderOffset = pe + BigInt(24);
      const dataDirectoryOffset = optionalHeaderOffset + BigInt(96);
      const loadConfigRva = readUint32LE(dataDirectoryOffset + BigInt(8 * 10));
      const loadConfigSize = readUint32LE(dataDirectoryOffset + BigInt(8 * 10 + 4));
      if (loadConfigRva === 0 || loadConfigSize === 0) {
        return "disabled";
      }
      const loadConfig = base + BigInt(loadConfigRva);
      const sehTable = readUint32LE(loadConfig + BigInt(64));
      const sehCount = readUint32LE(loadConfig + BigInt(68));
      if (sehTable !== 0 && sehCount > 0) {
        return "enabled";
      }
      return "disabled";
    } catch (_error) {
      return "unknown";
    }
  }
  function listModulesWithMitigations(filter) {
    const process = host.currentProcess;
    const modules = asArray2(process == null ? void 0 : process.Modules);
    const listed = modules.map((entry) => {
      var _a, _b, _c, _d, _e;
      const module = entry;
      const name = (_a = module.Name) != null ? _a : "<unknown>";
      const path = (_b = module.Path) != null ? _b : name;
      const base = toBigInt2((_d = (_c = module.BaseAddress) != null ? _c : module.Base) != null ? _d : module.Address);
      let size = toBigInt2((_e = module.Size) != null ? _e : module.Length);
      const end = toBigInt2(module.EndAddress);
      if (size === BigInt(0) && end > base) {
        size = end - base;
      }
      let characteristics = 0;
      let dllCharacteristics = 0;
      let aslr = "unknown";
      let dep = "unknown";
      let safeseh = "unknown";
      try {
        const mz = readUint16LE(base);
        if (mz === 23117) {
          const peOffset = readUint32LE(base + BigInt(60));
          const pe = base + BigInt(peOffset);
          const sig = readUint32LE(pe);
          if (sig === 17744) {
            characteristics = readUint16LE(pe + BigInt(22));
            const optionalHeaderMagic = readUint16LE(pe + BigInt(24));
            dllCharacteristics = readUint16LE(pe + BigInt(94));
            aslr = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) !== 0 ? "enabled" : "disabled";
            dep = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) !== 0 ? "enabled" : "disabled";
            safeseh = parseSafeSeh(base, pe, optionalHeaderMagic);
          }
        }
      } catch (_error) {
      }
      const system = path.toLowerCase().includes("\\windows\\system32");
      return {
        name,
        path,
        base,
        size,
        characteristics,
        dllCharacteristics,
        aslr,
        dep,
        safeseh,
        system
      };
    }).filter((item) => {
      if (!filter) {
        return true;
      }
      const needle = filter.toLowerCase();
      return item.name.toLowerCase().includes(needle) || item.path.toLowerCase().includes(needle);
    }).sort((a, b) => a.base < b.base ? -1 : 1);
    return listed;
  }
  function findModuleByAddress(address) {
    return listModulesWithMitigations().find((module) => {
      const start = module.base;
      const end = module.base + module.size;
      return address >= start && address < end;
    });
  }
  function createModulesCommand() {
    return {
      name: "modules",
      description: "Enumerate modules and mitigation states.",
      usage: "dx @$osed().modules({ filter: 'essfunc' })",
      examples: ["dx @$osed().modules({})", "dx @$osed().modules({ filter: 'kernel32' })"],
      schema: {
        filter: { type: "string" }
      },
      execute(options) {
        const modules = listModulesWithMitigations(options.filter);
        const pointerSize = getPointerSize();
        section("Modules");
        table(
          [
            { key: "name", header: "Module", width: 20 },
            { key: "base", header: "Base", width: 18 },
            { key: "size", header: "Size", width: 10 },
            { key: "aslr", header: "ASLR", width: 8 },
            { key: "dep", header: "DEP", width: 8 },
            { key: "safeseh", header: "SafeSEH", width: 8 },
            { key: "system", header: "System", width: 8 }
          ],
          modules.map((module) => ({
            name: module.name,
            base: formatAddress(module.base, pointerSize),
            size: `0x${module.size.toString(16).toUpperCase()}`,
            aslr: module.aslr,
            dep: module.dep,
            safeseh: module.safeseh,
            system: module.system ? "yes" : "no"
          }))
        );
        whyItMatters("Mitigation triage identifies practical modules for reliable exploitation paths.");
        return {
          command: "modules",
          args: options,
          success: true,
          findings: modules,
          warnings: [],
          errors: []
        };
      }
    };
  }

  // src/commands/triage.ts
  function safeGet2(value, key2) {
    if (!value || typeof value !== "object") {
      return void 0;
    }
    try {
      return value[key2];
    } catch (_error) {
      return void 0;
    }
  }
  function safeKeys2(value) {
    if (!value || typeof value !== "object") {
      return [];
    }
    try {
      return Object.keys(value);
    } catch (_error) {
      return [];
    }
  }
  function toBigInt3(value) {
    if (typeof value === "bigint") {
      return value;
    }
    if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
      return BigInt(Math.trunc(value));
    }
    if (typeof value === "string") {
      const text = value.trim();
      if (/^0x[0-9a-fA-F]+$/.test(text)) {
        return BigInt(text);
      }
      if (/^[0-9a-fA-F]+$/.test(text)) {
        return BigInt(`0x${text}`);
      }
      if (/^[0-9]+$/.test(text)) {
        return BigInt(text);
      }
    }
    if (value && typeof value === "object") {
      const nested = ["value", "Value", "address", "Address", "targetLocation"];
      for (const key2 of nested) {
        const parsed = toBigInt3(safeGet2(value, key2));
        if (parsed !== void 0) {
          return parsed;
        }
      }
      try {
        const valueOf = safeGet2(value, "valueOf");
        if (typeof valueOf === "function") {
          const resolved = valueOf.call(value);
          if (resolved !== value) {
            const parsed = toBigInt3(resolved);
            if (parsed !== void 0) {
              return parsed;
            }
          }
        }
      } catch (_error) {
      }
      try {
        const asString = safeGet2(value, "toString");
        if (typeof asString === "function") {
          const str = asString.call(value);
          if (typeof str === "string" && str !== "[object Object]") {
            return toBigInt3(str);
          }
        }
      } catch (_error) {
      }
    }
    return void 0;
  }
  function readRegisters(pointerSize) {
    var _a;
    const thread = host.currentThread;
    const regsRoot = safeGet2(thread, "Registers");
    const userRegs = (_a = safeGet2(regsRoot, "User")) != null ? _a : regsRoot;
    const all = [];
    for (const key2 of safeKeys2(userRegs)) {
      const parsed = toBigInt3(safeGet2(userRegs, key2));
      if (parsed !== void 0) {
        all.push({ name: key2, value: parsed });
      }
    }
    const pick = (...names) => {
      for (const candidate of names) {
        const found = all.find((entry) => entry.name.toLowerCase() === candidate.toLowerCase());
        if (found) {
          return found;
        }
      }
      return void 0;
    };
    const ip = pointerSize === 8 ? pick("rip", "eip") : pick("eip", "rip");
    const sp = pointerSize === 8 ? pick("rsp", "esp") : pick("esp", "rsp");
    const ex = pick("exceptioncode", "exception", "lastExceptionCode");
    return {
      ip: ip == null ? void 0 : ip.value,
      ipName: ip == null ? void 0 : ip.name,
      sp: sp == null ? void 0 : sp.value,
      spName: sp == null ? void 0 : sp.name,
      exceptionCode: ex == null ? void 0 : ex.value,
      all
    };
  }
  function findOffset(raw, maxLen) {
    if (raw === void 0) {
      return void 0;
    }
    const low = Number(raw & BigInt(4294967295));
    const candidates2 = [
      { kind: "msf", haystack: generateMsfPattern(Math.min(maxLen, 20280)) },
      { kind: "cyclic", haystack: generateCyclicPattern(Math.max(maxLen, 2e4)) }
    ];
    for (const candidate of candidates2) {
      const needle = decodeOffsetNeedle(low);
      const offset = candidate.haystack.indexOf(needle);
      if (offset >= 0) {
        return { kind: candidate.kind, offset };
      }
    }
    return void 0;
  }
  function isInstructionPointerControlled(evidence) {
    if (evidence.patternMatched) {
      return true;
    }
    if (evidence.ip === void 0) {
      return false;
    }
    if (evidence.exceptionCode === BigInt(3221225477)) {
      return true;
    }
    return evidence.ipBackedByModule === false;
  }
  function landingCandidateAddresses(evidence) {
    const candidateKinds = /* @__PURE__ */ new Set(["nop_sled_detected", "payload_like_bytes"]);
    const addresses = evidence.observations.filter((item) => candidateKinds.has(item.kind) && item.address !== void 0).map((item) => item.address);
    return [...new Set(addresses.map(String))].map(BigInt).sort((a, b) => a < b ? -1 : a > b ? 1 : 0).slice(0, 5);
  }
  function scoreModule(module) {
    let score = 0;
    if (!module.system) score += 25;
    if (module.aslr === "disabled") score += 35;
    if (module.dep === "disabled") score += 10;
    if (module.safeseh === "disabled") score += 30;
    return score;
  }
  function scanGadgets(pointerSize, moduleFilter) {
    const fmt = (address) => {
      const mod = findModuleByAddress(address);
      if (!mod) {
        return formatAddress(address, getPointerSize());
      }
      const delta = address - mod.base;
      return `${mod.name}+0x${delta.toString(16).toUpperCase()}`;
    };
    const jmpHits = scanPattern({ module: moduleFilter, executableOnly: true, maxResults: 12, chunkSize: 16384 }, Uint8Array.from([255, 228])).hits;
    const callHits = scanPattern({ module: moduleFilter, executableOnly: true, maxResults: 12, chunkSize: 16384 }, Uint8Array.from([255, 212])).hits;
    const pprHits = [];
    if (pointerSize === 4) {
      for (let a = 88; a <= 95 && pprHits.length < 12; a += 1) {
        for (let b = 88; b <= 95 && pprHits.length < 12; b += 1) {
          const hits = scanPattern(
            { module: moduleFilter, executableOnly: true, maxResults: Math.max(0, 12 - pprHits.length), chunkSize: 16384 },
            Uint8Array.from([a, b, 195])
          ).hits;
          pprHits.push(...hits);
        }
      }
    }
    const pivotPatterns = pointerSize === 8 ? [
      Uint8Array.from([72, 148, 195]),
      Uint8Array.from([84, 195]),
      Uint8Array.from([72, 137, 236, 195]),
      Uint8Array.from([72, 137, 196, 195])
    ] : [Uint8Array.from([148, 195]), Uint8Array.from([84, 195]), Uint8Array.from([139, 229, 195])];
    const pivotHits = [];
    for (const pattern of pivotPatterns) {
      const hits = scanPattern(
        { module: moduleFilter, executableOnly: true, maxResults: Math.max(0, 12 - pivotHits.length), chunkSize: 16384 },
        pattern
      ).hits;
      pivotHits.push(...hits);
      if (pivotHits.length >= 12) {
        break;
      }
    }
    const uniq = (values) => [...new Set(values.map((v) => v.toString()))].map((v) => BigInt(v));
    return {
      jmp: uniq(jmpHits).slice(0, 5).map(fmt),
      call: uniq(callHits).slice(0, 5).map(fmt),
      ppr: uniq(pprHits).slice(0, 5).map(fmt),
      pivots: uniq(pivotHits).slice(0, 5).map(fmt)
    };
  }
  function readSehPreview(pointerSize) {
    if (pointerSize !== 4) {
      return { overwritten: "unknown", warning: "SEH overwrite analysis is x86-only." };
    }
    const tebCandidate = resolveTeb32Address(host.currentThread);
    if (!tebCandidate) {
      return { overwritten: "unknown", warning: "TEB unavailable for SEH walk." };
    }
    try {
      const first = readSehRecords(tebCandidate, 1)[0];
      if (!first) {
        return { overwritten: "no", warning: "SEH chain is empty." };
      }
      const { next, handler } = first;
      const mod = findModuleByAddress(handler);
      const overwritten = mod ? "no" : "yes";
      return { overwritten, next, handler };
    } catch (error2) {
      const msg = error2 instanceof Error ? error2.message : String(error2);
      return { overwritten: "unknown", warning: `SEH read failed: ${msg}` };
    }
  }
  function quickBadcharScan(bytes, badchars) {
    if (!bytes) {
      return [];
    }
    return badchars.map((byte) => {
      let count = 0;
      let first;
      for (let i = 0; i < bytes.length; i += 1) {
        if (bytes[i] === byte) {
          count += 1;
          if (first === void 0) {
            first = i;
          }
        }
      }
      return { byte, count, first };
    });
  }
  function createTriageCommand() {
    return {
      name: "triage",
      description: "Fast crash triage for exploit-development workflows.",
      usage: "dx @$osed().triage({ patternLength: 10000, badchars: [0,10,13], module: 'essfunc' })",
      examples: ["dx @$osed().triage()", "dx @$osed().triage({ module: 'vuln' })"],
      schema: {
        patternLength: { type: "number", min: 256, max: 1e5, default: 1e4 },
        badchars: { type: "array", elementType: "number", default: [0, 10, 13] },
        module: { type: "string" },
        stackBytes: { type: "number", min: 128, max: 4096, default: 1024 }
      },
      execute(options) {
        var _a, _b, _c, _d, _e;
        const pointerSize = getPointerSize();
        const regs = readRegisters(pointerSize);
        const patternLength = options.patternLength;
        const stackBytesToRead = options.stackBytes;
        const badchars = ((_a = options.badchars) != null ? _a : [0, 10, 13]).map((v) => v & 255);
        const moduleFilter = options.module;
        const patternOffset = findOffset(regs.ip, patternLength);
        const seh = readSehPreview(pointerSize);
        const landingEvidence = landing(regs.sp, stackBytesToRead);
        const stackBytes = landingEvidence.bytes.length > 0 ? Uint8Array.from(landingEvidence.bytes) : void 0;
        const shellcode = landingCandidateAddresses(landingEvidence);
        const badcharStats = quickBadcharScan(stackBytes, badchars);
        const modules = listModulesWithMitigations(moduleFilter).map((module) => ({
          module: module.name,
          score: scoreModule(module),
          aslr: module.aslr,
          dep: module.dep,
          safeseh: module.safeseh,
          system: module.system
        })).sort((a, b) => b.score - a.score).slice(0, 6);
        const gadgets = scanGadgets(pointerSize, moduleFilter);
        const ipBackedByModule = regs.ip !== void 0 ? findModuleByAddress(regs.ip) !== void 0 : void 0;
        const eipControlled = isInstructionPointerControlled({
          patternMatched: patternOffset !== void 0,
          ip: regs.ip,
          ipBackedByModule,
          exceptionCode: regs.exceptionCode
        }) ? "yes" : "no";
        const badSp = stackBytes ? "no" : "yes";
        section("CONTROL");
        print(`${pointerSize === 8 ? "RIP" : "EIP"} controlled: ${eipControlled}`);
        print(`Offset: ${patternOffset ? patternOffset.offset : "n/a"}`);
        print(`Pattern: ${patternOffset ? patternOffset.kind : "n/a"}`);
        section("SEH");
        if (pointerSize === 8) {
          print("Not applicable: classic SEH overwrite workflow is x86-only.");
        } else {
          print(`Overwritten: ${seh.overwritten}`);
          print(`Next SEH: ${seh.next !== void 0 ? formatAddress(seh.next, 4) : "n/a"}`);
          print(`Handler: ${seh.handler !== void 0 ? formatAddress(seh.handler, 4) : "n/a"}`);
          if (seh.warning) print(`Status: ${seh.warning}`);
        }
        section("STACK");
        print(`${(_b = regs.spName) != null ? _b : "SP"}: ${regs.sp !== void 0 ? formatAddress(regs.sp, pointerSize) : "n/a"}`);
        print(`Bad stack pointer: ${badSp}`);
        print(`SP points into cyclic pattern: ${stackBytes && regs.sp ? findOffset(regs.sp, patternLength) ? "yes" : "no" : "unknown"}`);
        if (shellcode.length > 0) {
          print("Shellcode candidates:");
          for (const candidate of shellcode) {
            print(`  ${formatAddress(candidate, pointerSize)}`);
          }
        } else {
          print("Shellcode candidates: none");
        }
        section("GADGETS");
        print(pointerSize === 8 ? "JMP RSP:" : "JMP ESP:");
        for (const line of gadgets.jmp) print(`  ${line}`);
        print(pointerSize === 8 ? "CALL RSP:" : "CALL ESP:");
        for (const line of gadgets.call) print(`  ${line}`);
        if (pointerSize === 4) {
          print("POP POP RET:");
          for (const line of gadgets.ppr) print(`  ${line}`);
        }
        print("Stack pivots:");
        for (const line of gadgets.pivots) print(`  ${line}`);
        section("CONTEXT");
        print(`Exception code: ${regs.exceptionCode !== void 0 ? formatAddress(regs.exceptionCode, 4) : "n/a"}`);
        print(`${(_c = regs.ipName) != null ? _c : "IP"}: ${regs.ip !== void 0 ? formatAddress(regs.ip, pointerSize) : "n/a"}`);
        section("MODULE SCORE");
        table(
          [
            { key: "module", header: "Module", width: 20 },
            { key: "score", header: "Score", width: 6 },
            { key: "aslr", header: "ASLR", width: 8 },
            { key: "dep", header: "DEP", width: 8 },
            { key: "safeseh", header: "SafeSEH", width: 8 },
            { key: "system", header: "System", width: 8 }
          ],
          modules.map((item) => ({
            module: item.module,
            score: `${item.score}`,
            aslr: item.aslr,
            dep: item.dep,
            safeseh: item.safeseh,
            system: item.system ? "yes" : "no"
          }))
        );
        section("BADCHAR QUICK SCAN");
        table(
          [
            { key: "byte", header: "Byte", width: 8 },
            { key: "count", header: "Count", width: 6 },
            { key: "first", header: "FirstOff", width: 8 }
          ],
          badcharStats.map((entry) => ({
            byte: formatHexByte(entry.byte),
            count: `${entry.count}`,
            first: entry.first !== void 0 ? `${entry.first}` : "n/a"
          }))
        );
        const warnings = [];
        warnings.push(...(_e = (_d = landingEvidence.memory) == null ? void 0 : _d.warnings) != null ? _e : []);
        if (landingEvidence.address === void 0) warnings.push(landingEvidence.recommendation);
        else if (landingEvidence.observations.some((item) => item.kind === "bytes_inaccessible")) warnings.push("Stack read failed: landing bytes are inaccessible.");
        else if (landingEvidence.observations.some((item) => item.kind === "bytes_truncated")) warnings.push("Stack read was truncated before the requested length.");
        if (seh.warning) warnings.push(seh.warning);
        const findings = [
          {
            control: {
              ipControlled: eipControlled === "yes",
              offset: patternOffset == null ? void 0 : patternOffset.offset,
              pattern: patternOffset == null ? void 0 : patternOffset.kind,
              ip: regs.ip,
              ipName: regs.ipName
            },
            seh,
            stack: {
              sp: regs.sp,
              spName: regs.spName,
              badPointer: badSp === "yes",
              shellcodeCandidates: shellcode,
              landing: landingEvidence
            },
            gadgets,
            modules,
            badchars: badcharStats,
            exception: regs.exceptionCode
          }
        ];
        return {
          command: "triage",
          args: options,
          success: true,
          findings,
          warnings,
          errors: []
        };
      }
    };
  }

  // src/commands/badchars.ts
  function result(command, args, findings, warnings = []) {
    return { command, args, success: true, findings, warnings, errors: [] };
  }
  function createBadcharsCommand() {
    return {
      name: "badchars",
      description: "Identify bad characters from a memory byte sequence.",
      usage: "dx @$osed().badchars({ address: 0x41414141, exclude: [0, 10, 13] })",
      examples: [
        "dx @$osed().badchars({ address: 0x00B8F900 })",
        "dx @$osed().badchars({ address: '00B8F900', exclude: [0, 10, 13, 0] })"
      ],
      schema: {
        address: { type: ["number", "string"], required: true },
        exclude: { type: "array", elementType: "number", default: [] }
      },
      execute(options) {
        var _a;
        const address = normalizeAddress(options.address);
        const normalizedExclude = normalizeByteArray((_a = options.exclude) != null ? _a : []);
        const expected = expectedBytes(normalizedExclude.values);
        const observed = readMemory(address, expected.length);
        const compared = compareBadchars(observed, expected);
        const pointerSize = getPointerSize();
        section("Bad Character Analysis");
        info(`Start address: ${formatAddress(address, pointerSize)}`);
        info(`Exclude count: ${normalizedExclude.values.length}`);
        if (compared.breakOffset !== void 0 && compared.nextExpected !== void 0) {
          warn(`Sequence breaks at offset 0x${compared.breakOffset.toString(16).toUpperCase()}.`);
          warn(`Next expected byte: ${formatHexByte(compared.nextExpected)}`);
        } else {
          info("No sequence break detected in sampled byte range.");
        }
        table(
          [
            { key: "offset", header: "Offset", width: 8 },
            { key: "expected", header: "Expected", width: 10 },
            { key: "observed", header: "Observed", width: 10 }
          ],
          compared.mismatches.slice(0, 32).map((mismatch) => ({
            offset: `0x${mismatch.offset.toString(16).toUpperCase()}`,
            expected: formatHexByte(mismatch.expected),
            observed: formatHexByte(mismatch.observed)
          }))
        );
        const excludeList = normalizedExclude.values.map((value) => value.toString(16).toUpperCase().padStart(2, "0")).join(" ");
        info(`Copy-ready exclude list: ${excludeList}`);
        whyItMatters("Accurate badchar profiling prevents payload corruption before shellcode staging.");
        const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
        return result(
          "badchars",
          __spreadProps(__spreadValues({}, options), {
            exclude: normalizedExclude.values
          }),
          [
            {
              breakOffset: compared.breakOffset,
              nextExpected: compared.nextExpected,
              mismatches: compared.mismatches,
              exclude: normalizedExclude.values
            }
          ],
          warnings
        );
      }
    };
  }
  function createBadcharArrayCommand() {
    return {
      name: "badchar_array",
      description: "Generate a bad-character test byte array (0x00-0xFF minus excludes) in paste-ready forms.",
      usage: "dx @$osed().badchar_array({ exclude: [0, 10, 13] })",
      examples: ["dx @$osed().badchar_array()", "dx @$osed().badchar_array({ exclude: [0, 10, 13] })"],
      schema: {
        exclude: { type: "array", elementType: "number", default: [] }
      },
      execute(options) {
        var _a;
        const normalizedExclude = normalizeByteArray((_a = options.exclude) != null ? _a : []);
        const expected = expectedBytes(normalizedExclude.values);
        const python = formatByteArray(expected, "python");
        const c = formatByteArray(expected, "c");
        const hex = formatByteArray(expected, "hex");
        section("Bad Character Test Array");
        info(`Bytes: ${expected.length} (excluded ${normalizedExclude.values.length})`);
        print(`Python: ${python}`);
        print(`C:      ${c}`);
        print(`Hex:    ${hex}`);
        whyItMatters("Send this array to the target, then use badchar_find to locate it in memory and see which bytes were mangled.");
        const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
        return result(
          "badchar_array",
          __spreadProps(__spreadValues({}, options), { exclude: normalizedExclude.values }),
          [{ count: expected.length, exclude: normalizedExclude.values, bytes: expected, formats: { python, c, hex } }],
          warnings
        );
      }
    };
  }
  function createBadcharFindCommand() {
    return {
      name: "badchar_find",
      description: "Locate a sent bad-character array in memory (near an address or the stack pointer) and report the first corrupted byte.",
      usage: "dx @$osed().badchar_find({ address: 0x0012F800, exclude: [0, 10, 13] })",
      examples: ["dx @$osed().badchar_find()", "dx @$osed().badchar_find({ address: '0012F800', exclude: [0, 10, 13] })"],
      schema: {
        address: { type: ["number", "string"] },
        exclude: { type: "array", elementType: "number", default: [] },
        windowBytes: { type: "number", min: 256, max: 16384, default: 2048 },
        minRun: { type: "number", min: 4, max: 64, default: 8 }
      },
      execute(options) {
        var _a, _b;
        const pointerSize = getPointerSize();
        const normalizedExclude = normalizeByteArray((_a = options.exclude) != null ? _a : []);
        const expected = expectedBytes(normalizedExclude.values);
        const windowBytes = options.windowBytes;
        const minRun = options.minRun;
        let anchor;
        let anchorLabel = "n/a";
        if (options.address !== void 0) {
          anchor = normalizeAddress(options.address);
          anchorLabel = formatAddress(anchor, pointerSize);
        } else {
          const regs = readRegisters(pointerSize);
          anchor = regs.sp;
          anchorLabel = regs.sp !== void 0 ? `${(_b = regs.spName) != null ? _b : "sp"} ${formatAddress(regs.sp, pointerSize)}` : "n/a";
        }
        section("Bad Character Locate");
        if (anchor === void 0) {
          warn("No anchor address available (stack pointer unreadable). Provide an explicit address.");
          return result("badchar_find", options, [{ located: false }], ["No anchor address available."]);
        }
        info(`Anchor: ${anchorLabel}`);
        info(`Window: ${windowBytes} bytes, expecting a ${expected.length}-byte array.`);
        const window = tryReadMemory(anchor, windowBytes);
        if (!window) {
          warn("Anchor memory was not readable.");
          return result("badchar_find", options, [{ located: false }], ["Anchor memory was not readable."]);
        }
        const located = locateExpectedArray(window, expected, minRun);
        if (!located) {
          warn(`Test array not found within ${windowBytes} bytes of the anchor (min run ${minRun}).`);
          return result("badchar_find", options, [{ located: false }], ["Test array not found near anchor."]);
        }
        const landing2 = anchor + BigInt(located.offset);
        const observed = window.slice(located.offset);
        const compared = compareBadchars(observed, expected);
        info(`Located at ${formatAddress(landing2, pointerSize)} (anchor + 0x${located.offset.toString(16).toUpperCase()}).`);
        info(`Clean run before first break: ${located.matchedRun} bytes.`);
        if (compared.breakOffset !== void 0 && compared.nextExpected !== void 0) {
          warn(`First corruption at array offset 0x${compared.breakOffset.toString(16).toUpperCase()}: expected ${formatHexByte(compared.nextExpected)}, observed ${formatHexByte(observed[compared.breakOffset])}.`);
          info("The first break is the high-confidence bad byte; later mismatches may be shift artifacts.");
        } else {
          info("No corruption detected across the located array \u2014 no bad characters in this exclude set.");
        }
        table(
          [
            { key: "offset", header: "Offset", width: 8 },
            { key: "expected", header: "Expected", width: 10 },
            { key: "observed", header: "Observed", width: 10 }
          ],
          compared.mismatches.slice(0, 32).map((mismatch) => ({
            offset: `0x${mismatch.offset.toString(16).toUpperCase()}`,
            expected: formatHexByte(mismatch.expected),
            observed: formatHexByte(mismatch.observed)
          }))
        );
        const suggestedExclude = compared.nextExpected !== void 0 ? [.../* @__PURE__ */ new Set([...normalizedExclude.values, compared.nextExpected])].sort((a, b) => a - b) : normalizedExclude.values;
        info(`Suggested next exclude: ${suggestedExclude.map((value) => value.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "(none)"}`);
        const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
        return result(
          "badchar_find",
          __spreadProps(__spreadValues({}, options), { exclude: normalizedExclude.values }),
          [
            {
              located: true,
              landingAddress: landing2,
              anchorOffset: located.offset,
              cleanRun: located.matchedRun,
              breakOffset: compared.breakOffset,
              nextExpected: compared.nextExpected,
              mismatches: compared.mismatches,
              suggestedExclude,
              exclude: normalizedExclude.values
            }
          ],
          warnings
        );
      }
    };
  }

  // src/commands/egghunter.ts
  var EGGHUNTERS = {
    ntaccess_x86: [102, 129, 202, 255, 15, 66, 82, 106, 2, 88, 205, 46, 60, 5, 90, 116, 239, 184, 87, 48, 48, 84, 139, 250, 175, 117, 234, 175, 117, 231, 255, 231],
    ntaccess_wow64: [102, 129, 202, 255, 15, 65, 106, 2, 88, 205, 46, 60, 5, 90, 116, 239, 184, 87, 48, 48, 84, 139, 250, 175, 117, 234, 175, 117, 231, 255, 231]
  };
  function bytesToHex(bytes) {
    return bytes.map((value) => value.toString(16).toUpperCase().padStart(2, "0")).join("");
  }
  function bytesToPython(bytes) {
    return `b"${bytes.map((value) => `\\x${value.toString(16).padStart(2, "0")}`).join("")}"`;
  }
  function build(options) {
    if (options.mode === "seh") {
      throw new Error(
        'The SEH egghunter mode is not implemented. Use mode: "ntaccess" instead, which probes memory via the NtAccessCheckAndAuditAlarm syscall (INT 0x2E).'
      );
    }
    const key2 = `${options.mode}_${options.wow64 ? "wow64" : "x86"}`;
    const bytes = EGGHUNTERS[key2];
    if (!bytes) {
      throw new Error(`Unsupported egghunter mode: ${key2}`);
    }
    const hunter = [...bytes];
    const tagBytes = options.tag.padEnd(4, "X").slice(0, 4).split("").map((char) => char.charCodeAt(0));
    hunter.splice(18, 4, ...tagBytes);
    return hunter;
  }
  function createEgghunterCommand() {
    return {
      name: "egghunter",
      description: "Generate NtAccess/SEH egghunter stubs.",
      usage: "dx @$osed().egghunter({ tag: 'W00T', mode: 'ntaccess', wow64: false })",
      examples: [
        "dx @$osed().egghunter({ tag: 'W00T', mode: 'ntaccess', wow64: false })",
        "dx @$osed().egghunter({ tag: 'B33F', mode: 'seh', wow64: true })"
      ],
      schema: {
        tag: { type: "string", default: "W00T" },
        mode: { type: "string", enum: ["ntaccess", "seh"], default: "ntaccess" },
        wow64: { type: "boolean", default: false }
      },
      execute(options) {
        const hunter = build(options);
        section("Egghunter");
        info(`Tag: ${options.tag}`);
        info(`Mode: ${options.mode}`);
        info(`WoW64: ${options.wow64 ? "yes" : "no"}`);
        info(`Size: ${hunter.length} bytes`);
        print(bytesToHex(hunter));
        print(bytesToPython(hunter));
        whyItMatters("Egghunters shrink staged exploits and locate payloads in constrained buffers.");
        return {
          command: "egghunter",
          args: options,
          success: true,
          findings: [{ bytes: hunter, size: hunter.length }],
          warnings: [],
          errors: []
        };
      }
    };
  }

  // src/commands/seh.ts
  function createSehCommand() {
    return {
      name: "seh",
      description: "Walk current thread SEH chain.",
      usage: "dx @$osed().seh({})",
      examples: ["dx @$osed().seh({})", "dx @$osed().seh({})"],
      schema: {},
      execute(options) {
        var _a;
        const pointerSize = getPointerSize();
        if (pointerSize !== 4) {
          return {
            command: "seh",
            args: options,
            success: false,
            findings: [],
            warnings: ["SEH chain walking is x86-focused in v1."],
            errors: ["Current pointer size is not x86."]
          };
        }
        const teb = resolveTeb32Address(host.currentThread);
        if (teb === void 0) {
          throw new Error("Current thread TEB is unavailable.");
        }
        const rows = [];
        const findings = [];
        const records = readSehRecords(teb);
        for (const { node, next, handler } of records) {
          const module = findModuleByAddress(handler);
          const safeSehRisk = module && module.safeseh !== "enabled" ? "risk" : "ok";
          const outsideModule = module === void 0;
          rows.push({
            node: formatAddress(node, 4),
            handler: formatAddress(handler, 4),
            target: module ? `${module.name}+0x${(handler - module.base).toString(16).toUpperCase()}` : "<outside module>",
            safeseh: module ? module.safeseh : "unknown",
            status: outsideModule || safeSehRisk === "risk" ? "flag" : "ok"
          });
          findings.push({
            node,
            next,
            handler,
            module: module == null ? void 0 : module.name,
            outsideModule,
            safeSeh: (_a = module == null ? void 0 : module.safeseh) != null ? _a : "unknown"
          });
        }
        section("SEH Chain");
        table(
          [
            { key: "node", header: "Node", width: 10 },
            { key: "handler", header: "Handler", width: 10 },
            { key: "target", header: "Module+Offset", width: 24 },
            { key: "safeseh", header: "SafeSEH", width: 8 },
            { key: "status", header: "Status", width: 6 }
          ],
          rows
        );
        whyItMatters("SEH handler control is a classic exploit path when stack overwrite is constrained.");
        return {
          command: "seh",
          args: options,
          success: true,
          findings,
          warnings: records.length >= 64 ? ["SEH walk stopped at guard limit (64 entries)."] : [],
          errors: []
        };
      }
    };
  }

  // src/logic/instruction_validation.ts
  var KNOWN_PATTERNS = [
    // pop-register ; ret — all 8 general-purpose registers
    { name: "pop_eax_ret", bytes: [88, 195], mnemonic: "pop eax ; ret" },
    { name: "pop_ecx_ret", bytes: [89, 195], mnemonic: "pop ecx ; ret" },
    { name: "pop_edx_ret", bytes: [90, 195], mnemonic: "pop edx ; ret" },
    { name: "pop_ebx_ret", bytes: [91, 195], mnemonic: "pop ebx ; ret" },
    { name: "pop_esp_ret", bytes: [92, 195], mnemonic: "pop esp ; ret" },
    { name: "pop_ebp_ret", bytes: [93, 195], mnemonic: "pop ebp ; ret" },
    { name: "pop_esi_ret", bytes: [94, 195], mnemonic: "pop esi ; ret" },
    { name: "pop_edi_ret", bytes: [95, 195], mnemonic: "pop edi ; ret" },
    // Stack pivots
    { name: "push_esp_ret", bytes: [84, 195], mnemonic: "push esp ; ret" },
    { name: "leave_ret", bytes: [201, 195], mnemonic: "leave ; ret" },
    { name: "xchg_eax_esp_ret", bytes: [148, 195], mnemonic: "xchg eax, esp ; ret" },
    { name: "xchg_ecx_esp_ret", bytes: [135, 204, 195], mnemonic: "xchg ecx, esp ; ret" },
    { name: "xchg_edx_esp_ret", bytes: [135, 212, 195], mnemonic: "xchg edx, esp ; ret" },
    { name: "xchg_ebx_esp_ret", bytes: [135, 220, 195], mnemonic: "xchg ebx, esp ; ret" },
    { name: "xchg_esi_esp_ret", bytes: [135, 244, 195], mnemonic: "xchg esi, esp ; ret" },
    { name: "xchg_edi_esp_ret", bytes: [135, 252, 195], mnemonic: "xchg edi, esp ; ret" },
    { name: "xchg_ebp_esp_ret", bytes: [135, 236, 195], mnemonic: "xchg ebp, esp ; ret" },
    { name: "mov_esp_ebp_ret", bytes: [139, 229, 195], mnemonic: "mov esp, ebp ; ret" },
    { name: "mov_esp_eax_ret", bytes: [137, 196, 195], mnemonic: "mov esp, eax ; ret" },
    // Direct register jumps — primary shellcode dispatch gadgets
    { name: "jmp_esp", bytes: [255, 228], mnemonic: "jmp esp" },
    { name: "call_esp", bytes: [255, 212], mnemonic: "call esp" },
    { name: "jmp_eax", bytes: [255, 224], mnemonic: "jmp eax" },
    { name: "call_eax", bytes: [255, 208], mnemonic: "call eax" },
    // inc reg ; ret — one-byte x86 encodings (0x40–0x47)
    { name: "inc_eax_ret", bytes: [64, 195], mnemonic: "inc eax ; ret" },
    { name: "inc_ecx_ret", bytes: [65, 195], mnemonic: "inc ecx ; ret" },
    { name: "inc_edx_ret", bytes: [66, 195], mnemonic: "inc edx ; ret" },
    { name: "inc_ebx_ret", bytes: [67, 195], mnemonic: "inc ebx ; ret" },
    { name: "inc_esp_ret", bytes: [68, 195], mnemonic: "inc esp ; ret" },
    { name: "inc_ebp_ret", bytes: [69, 195], mnemonic: "inc ebp ; ret" },
    { name: "inc_esi_ret", bytes: [70, 195], mnemonic: "inc esi ; ret" },
    { name: "inc_edi_ret", bytes: [71, 195], mnemonic: "inc edi ; ret" },
    // dec reg ; ret — one-byte x86 encodings (0x48–0x4F)
    { name: "dec_eax_ret", bytes: [72, 195], mnemonic: "dec eax ; ret" },
    { name: "dec_ecx_ret", bytes: [73, 195], mnemonic: "dec ecx ; ret" },
    { name: "dec_edx_ret", bytes: [74, 195], mnemonic: "dec edx ; ret" },
    { name: "dec_ebx_ret", bytes: [75, 195], mnemonic: "dec ebx ; ret" },
    { name: "dec_esp_ret", bytes: [76, 195], mnemonic: "dec esp ; ret" },
    { name: "dec_ebp_ret", bytes: [77, 195], mnemonic: "dec ebp ; ret" },
    { name: "dec_esi_ret", bytes: [78, 195], mnemonic: "dec esi ; ret" },
    { name: "dec_edi_ret", bytes: [79, 195], mnemonic: "dec edi ; ret" },
    // neg reg ; ret — opcode F7 /3 (ModRM D8–DF)
    { name: "neg_eax_ret", bytes: [247, 216, 195], mnemonic: "neg eax ; ret" },
    { name: "neg_ecx_ret", bytes: [247, 217, 195], mnemonic: "neg ecx ; ret" },
    { name: "neg_edx_ret", bytes: [247, 218, 195], mnemonic: "neg edx ; ret" },
    { name: "neg_ebx_ret", bytes: [247, 219, 195], mnemonic: "neg ebx ; ret" },
    { name: "neg_esp_ret", bytes: [247, 220, 195], mnemonic: "neg esp ; ret" },
    { name: "neg_ebp_ret", bytes: [247, 221, 195], mnemonic: "neg ebp ; ret" },
    { name: "neg_esi_ret", bytes: [247, 222, 195], mnemonic: "neg esi ; ret" },
    { name: "neg_edi_ret", bytes: [247, 223, 195], mnemonic: "neg edi ; ret" },
    // pushad ; ret — push all 8 GP regs (PUSHAD VirtualProtect DEP bypass technique)
    { name: "pushad_ret", bytes: [96, 195], mnemonic: "pushad ; ret" }
  ];
  var X64_PATTERNS = [
    { name: "pop_rax_ret", bytes: [88, 195], mnemonic: "pop rax ; ret" },
    { name: "pop_rcx_ret", bytes: [89, 195], mnemonic: "pop rcx ; ret" },
    { name: "pop_rdx_ret", bytes: [90, 195], mnemonic: "pop rdx ; ret" },
    { name: "pop_rbx_ret", bytes: [91, 195], mnemonic: "pop rbx ; ret" },
    { name: "pop_rsp_ret", bytes: [92, 195], mnemonic: "pop rsp ; ret" },
    { name: "pop_rbp_ret", bytes: [93, 195], mnemonic: "pop rbp ; ret" },
    { name: "pop_rsi_ret", bytes: [94, 195], mnemonic: "pop rsi ; ret" },
    { name: "pop_rdi_ret", bytes: [95, 195], mnemonic: "pop rdi ; ret" },
    { name: "pop_r8_ret", bytes: [65, 88, 195], mnemonic: "pop r8 ; ret" },
    { name: "pop_r9_ret", bytes: [65, 89, 195], mnemonic: "pop r9 ; ret" },
    { name: "pop_r10_ret", bytes: [65, 90, 195], mnemonic: "pop r10 ; ret" },
    { name: "pop_r11_ret", bytes: [65, 91, 195], mnemonic: "pop r11 ; ret" },
    { name: "pop_r12_ret", bytes: [65, 92, 195], mnemonic: "pop r12 ; ret" },
    { name: "pop_r13_ret", bytes: [65, 93, 195], mnemonic: "pop r13 ; ret" },
    { name: "pop_r14_ret", bytes: [65, 94, 195], mnemonic: "pop r14 ; ret" },
    { name: "pop_r15_ret", bytes: [65, 95, 195], mnemonic: "pop r15 ; ret" },
    { name: "jmp_rsp", bytes: [255, 228], mnemonic: "jmp rsp" },
    { name: "call_rsp", bytes: [255, 212], mnemonic: "call rsp" },
    { name: "jmp_rax", bytes: [255, 224], mnemonic: "jmp rax" },
    { name: "call_rax", bytes: [255, 208], mnemonic: "call rax" },
    { name: "push_rsp_ret", bytes: [84, 195], mnemonic: "push rsp ; ret" },
    { name: "leave_ret", bytes: [201, 195], mnemonic: "leave ; ret" },
    { name: "xchg_rax_rsp_ret", bytes: [72, 148, 195], mnemonic: "xchg rax, rsp ; ret" },
    { name: "xchg_rcx_rsp_ret", bytes: [72, 135, 204, 195], mnemonic: "xchg rcx, rsp ; ret" },
    { name: "xchg_rdx_rsp_ret", bytes: [72, 135, 212, 195], mnemonic: "xchg rdx, rsp ; ret" },
    { name: "xchg_rbx_rsp_ret", bytes: [72, 135, 220, 195], mnemonic: "xchg rbx, rsp ; ret" },
    { name: "xchg_rbp_rsp_ret", bytes: [72, 135, 236, 195], mnemonic: "xchg rbp, rsp ; ret" },
    { name: "xchg_rsi_rsp_ret", bytes: [72, 135, 244, 195], mnemonic: "xchg rsi, rsp ; ret" },
    { name: "xchg_rdi_rsp_ret", bytes: [72, 135, 252, 195], mnemonic: "xchg rdi, rsp ; ret" },
    { name: "mov_rsp_rbp_ret", bytes: [72, 137, 236, 195], mnemonic: "mov rsp, rbp ; ret" },
    { name: "mov_rsp_rax_ret", bytes: [72, 137, 196, 195], mnemonic: "mov rsp, rax ; ret" }
  ];
  var POP_REGS = [
    { code: 88, name: "eax" },
    { code: 89, name: "ecx" },
    { code: 90, name: "edx" },
    { code: 91, name: "ebx" },
    { code: 92, name: "esp" },
    { code: 93, name: "ebp" },
    { code: 94, name: "esi" },
    { code: 95, name: "edi" }
  ];
  function buildPprPatterns() {
    const patterns = [];
    for (const first of POP_REGS) {
      for (const second of POP_REGS) {
        patterns.push({
          name: `pop_${first.name}_pop_${second.name}_ret`,
          bytes: [first.code, second.code, 195],
          mnemonic: `pop ${first.name} ; pop ${second.name} ; ret`
        });
      }
    }
    return patterns;
  }
  function buildWritePatterns() {
    const dsts = [
      { rm: 0, name: "eax" },
      { rm: 1, name: "ecx" },
      { rm: 2, name: "edx" },
      { rm: 3, name: "ebx" },
      { rm: 6, name: "esi" },
      { rm: 7, name: "edi" }
    ];
    const srcs = [
      { code: 0, name: "eax" },
      { code: 1, name: "ecx" },
      { code: 2, name: "edx" },
      { code: 3, name: "ebx" },
      { code: 4, name: "esp" },
      { code: 5, name: "ebp" },
      { code: 6, name: "esi" },
      { code: 7, name: "edi" }
    ];
    const patterns = [];
    for (const dst of dsts) {
      for (const src of srcs) {
        const modRM = src.code << 3 | dst.rm;
        patterns.push({
          name: `mov_mem_${dst.name}_${src.name}_ret`,
          bytes: [137, modRM, 195],
          mnemonic: `mov [${dst.name}], ${src.name} ; ret`
        });
      }
    }
    return patterns;
  }
  var ALL_PATTERNS = [...KNOWN_PATTERNS, ...buildPprPatterns(), ...buildWritePatterns()];
  function sameBytes(left, right) {
    if (left.length !== right.length) {
      return false;
    }
    for (let i = 0; i < left.length; i += 1) {
      if (left[i] !== right[i]) {
        return false;
      }
    }
    return true;
  }
  function knownPatterns() {
    return ALL_PATTERNS;
  }
  function knownPatternsForPointerSize(pointerSize) {
    return pointerSize === 8 ? X64_PATTERNS : ALL_PATTERNS;
  }
  function validateInstructionCandidate(candidateBytes, executable, moduleBacked) {
    const matched = ALL_PATTERNS.find((pattern) => sameBytes(candidateBytes, pattern.bytes));
    return {
      flags: {
        executable,
        moduleBacked,
        decoded: matched !== void 0,
        mnemonicMatch: matched !== void 0,
        badcharSafe: true
      },
      mnemonic: matched == null ? void 0 : matched.mnemonic
    };
  }
  function validateInstructionCandidateForPointerSize(candidateBytes, executable, moduleBacked, pointerSize) {
    const patterns = knownPatternsForPointerSize(pointerSize);
    const matched = patterns.find((pattern) => sameBytes(candidateBytes, pattern.bytes));
    return {
      flags: {
        executable,
        moduleBacked,
        decoded: matched !== void 0,
        mnemonicMatch: matched !== void 0,
        badcharSafe: true
      },
      mnemonic: matched == null ? void 0 : matched.mnemonic
    };
  }

  // src/rop/types.ts
  var ROP_SCHEMA_VERSION = "v1";

  // src/semantics/canonicalize.ts
  function normalizeHexImmediate(value) {
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
  function normalizeOperand(text) {
    let value = text.trim().toLowerCase();
    value = value.replace(/\s+/g, " ");
    value = value.replace(/\[\s+/g, "[");
    value = value.replace(/\s+\]/g, "]");
    value = value.replace(/\s*,\s*/g, ", ");
    value = value.replace(/\s*\+\s*/g, "+");
    value = value.replace(/\s*-\s*/g, "-");
    return value;
  }
  function parseInstructionText(text) {
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
    const operands = remainder.split(",").map((operand) => normalizeOperand(operand)).filter((operand) => operand.length > 0).map((operand) => operand.replace(/\b(?:byte|word|dword|qword)\s+ptr\b/g, (match) => match.toLowerCase()));
    return { mnemonic: rawMnemonic, operands };
  }
  function normalizeInstructionText(text) {
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
    return normalizedOperands.length > 0 ? `${normalizedMnemonic} ${normalizedOperands.join(", ")}` : normalizedMnemonic;
  }
  function parseInstruction(text) {
    const normalizedText = normalizeInstructionText(text);
    const { mnemonic, operands } = parseInstructionText(text);
    const normalizedMnemonic = mnemonic === "retn" ? "ret" : mnemonic;
    return {
      originalText: text.trim(),
      normalizedText,
      mnemonic: normalizedMnemonic,
      operands: operands.map((operand) => normalizeHexImmediate(operand))
    };
  }
  function canonicalizeInstruction(instruction) {
    const operands = instruction.operands.map((operand) => normalizeHexImmediate(operand)).join(", ");
    return operands.length > 0 ? `${instruction.mnemonic.toLowerCase()} ${operands}` : instruction.mnemonic.toLowerCase();
  }
  function canonicalizeInstructionSequence(sequence) {
    return sequence.instructions.map((instruction) => canonicalizeInstruction(instruction)).join(" | ");
  }
  function canonicalizeTextSequence(text) {
    return text.split(";").map((part) => part.trim()).filter((part) => part.length > 0).map((part) => normalizeInstructionText(part)).join(" | ");
  }

  // src/rop/classifier.ts
  function hasExactFlow(semantic, kind) {
    return semantic.summary.flowEffects.values.exact.has(kind);
  }
  var ARITHMETIC_MNEMONICS = /* @__PURE__ */ new Set(["add", "sub", "inc", "dec", "neg"]);
  function zeroedRegisters(semantic) {
    const zeroed = [];
    for (const [register, expr] of Object.entries(semantic.summary.registerTransforms)) {
      if (expr.kind === "constant" && expr.value === 0) {
        zeroed.push(register);
      }
    }
    return zeroed;
  }
  function pivotsStack(semantic) {
    const esp = semantic.summary.registerTransforms.esp;
    return esp.kind === "affine" && esp.base !== "esp" && esp.base !== "none";
  }
  function isLoadRegister(step) {
    if (!step.supported) {
      return void 0;
    }
    if (step.instruction.mnemonic === "pop" && step.instruction.operands.length === 1) {
      const register = step.instruction.operands[0].trim().toLowerCase();
      return register === "esp" ? void 0 : register;
    }
    if (step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2) {
      const left = step.instruction.operands[0].trim().toLowerCase();
      const right = step.instruction.operands[1].trim().toLowerCase();
      if (/^[a-z]{3}$/.test(left) && /^[a-z]{3}$/.test(right) && left !== right && left !== "esp") {
        return left;
      }
    }
    return void 0;
  }
  function adjustsStackExplicitly(step) {
    var _a;
    const ins = step.instruction;
    const destination = (_a = ins.operands[0]) == null ? void 0 : _a.trim().toLowerCase();
    if ((ins.mnemonic === "add" || ins.mnemonic === "sub") && destination === "esp") {
      return true;
    }
    return ins.mnemonic === "ret" && ins.operands.length >= 1;
  }
  function addCategory(categories, reasonList, category, rule, message, evidence) {
    categories.add(category);
    reasonList.push({ rule, message, evidence });
  }
  function buildEvidenceFromSemantic(semantic) {
    return semantic.instructionSemantics.flatMap((step) => step.evidence.length > 0 ? step.evidence : [step.instruction.normalizedText]);
  }
  function classifySemanticSequence(semantic) {
    const categories = /* @__PURE__ */ new Set();
    const reasons = [];
    const evidence = buildEvidenceFromSemantic(semantic);
    if (hasExactFlow(semantic, "RETURN")) {
      addCategory(categories, reasons, "RETURN", "return-flow", "gadget returns control to the stack", evidence);
    }
    if (hasExactFlow(semantic, "CALL") || hasExactFlow(semantic, "JUMP")) {
      addCategory(categories, reasons, "FLOW_TRANSFER", "flow-transfer", "gadget transfers control flow", evidence);
    }
    for (const zeroReg of zeroedRegisters(semantic)) {
      addCategory(categories, reasons, "ZERO_REGISTER", "zero-register", `net-zeroes ${zeroReg}`, evidence);
    }
    for (const step of semantic.instructionSemantics) {
      const text = canonicalizeInstruction(step.instruction);
      const loadRegister = isLoadRegister(step);
      if (loadRegister) {
        if (semantic.instructionSemantics.length === 1 || semantic.instructionSemantics.every((item) => item.supported)) {
          addCategory(categories, reasons, "LOAD_REGISTER", "load-register", `loads ${loadRegister}`, [text]);
        }
      }
      if (adjustsStackExplicitly(step)) {
        addCategory(categories, reasons, "STACK_ADJUST", "stack-adjust", "adjusts the stack pointer by a fixed amount", [text]);
      }
      if (ARITHMETIC_MNEMONICS.has(step.instruction.mnemonic)) {
        addCategory(categories, reasons, "ARITHMETIC", "arithmetic", "performs arithmetic transformation", [text]);
      }
      if (step.instruction.mnemonic === "pop" && step.instruction.operands.length > 1) {
        addCategory(categories, reasons, "MULTI_REGISTER_LOAD", "multi-load", "loads multiple registers", [text]);
      }
      if (step.instruction.mnemonic === "call" || step.instruction.mnemonic === "jmp") {
        addCategory(categories, reasons, "FLOW_TRANSFER", "explicit-flow", "explicit control-flow transfer", [text]);
      }
    }
    if (pivotsStack(semantic)) {
      addCategory(categories, reasons, "STACK_PIVOT", "stack-pivot", "esp becomes based on another register", evidence);
    }
    if (semantic.instructionSemantics.some((step) => step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2 && step.instruction.operands[0].includes("[") && !step.instruction.operands[1].includes("["))) {
      addCategory(categories, reasons, "MEMORY_WRITE", "memory-write", "contains a memory write", evidence);
    }
    if (semantic.instructionSemantics.some((step) => step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2 && !step.instruction.operands[0].includes("[") && step.instruction.operands[1].includes("["))) {
      addCategory(categories, reasons, "MEMORY_READ", "memory-read", "contains a memory read", evidence);
    }
    return { categories: [...categories], reasons };
  }
  function canonicalizeRopGadgetId(semantic) {
    return canonicalizeInstructionSequence(semantic.instructionSequence);
  }
  function buildRopGadget(semantic) {
    const classification = classifySemanticSequence(semantic);
    return {
      schemaVersion: ROP_SCHEMA_VERSION,
      canonicalId: canonicalizeRopGadgetId(semantic),
      categories: classification.categories,
      classificationReasons: classification.reasons
    };
  }

  // src/rop/scoring.ts
  function addReason(reasons, rule, message, evidence, delta) {
    reasons.push({ rule, message: `${message} (${delta >= 0 ? "+" : ""}${delta})`, evidence });
  }
  function hasCategory(categories, category) {
    return categories.includes(category);
  }
  function scoreSemanticSequence(semantic, categories) {
    let score = 100;
    const reasons = [];
    const evidence = semantic.instructionSemantics.flatMap((step) => step.evidence.length > 0 ? step.evidence : [step.instruction.normalizedText]);
    const instructionCount = semantic.instructionSemantics.length;
    const unsupportedCount = semantic.instructionSemantics.filter((step) => !step.supported).length;
    const memoryWrites = semantic.summary.memoryWrites.values.exact.size + semantic.summary.memoryWrites.values.conservative.size;
    const memoryReads = semantic.summary.memoryReads.values.exact.size + semantic.summary.memoryReads.values.conservative.size;
    const flowTransfers = semantic.summary.flowEffects.values.exact.size;
    const stackWrites = semantic.summary.writes.values.exact.has("esp") || semantic.summary.writes.values.conservative.has("esp");
    const exactFields = [
      semantic.summary.reads.confidence,
      semantic.summary.writes.confidence,
      semantic.summary.stackDelta.confidence,
      semantic.summary.flags.confidence,
      semantic.summary.memoryReads.confidence,
      semantic.summary.memoryWrites.confidence,
      semantic.summary.flowEffects.confidence
    ].filter((confidence) => confidence === "EXACT").length;
    score += exactFields * 5;
    if (exactFields > 0) {
      addReason(reasons, "exact-semantics", "exact semantic facts available", evidence, exactFields * 5);
    }
    if (instructionCount <= 2) {
      score += 20;
      addReason(reasons, "short-gadget", "short gadget", evidence, 20);
    } else {
      const penalty = (instructionCount - 2) * 10;
      score -= penalty;
      addReason(reasons, "long-gadget", "longer gadget", evidence, -penalty);
    }
    if (unsupportedCount > 0) {
      const penalty = unsupportedCount * 30;
      score -= penalty;
      addReason(reasons, "unknown-semantics", "unsupported instructions reduce confidence", evidence, -penalty);
    }
    if (memoryWrites > 0) {
      const penalty = memoryWrites * 35;
      score -= penalty;
      addReason(reasons, "memory-write", "memory writes are expensive and risky", evidence, -penalty);
    }
    if (memoryReads > 0) {
      const penalty = memoryReads * 10;
      score -= penalty;
      addReason(reasons, "memory-read", "memory reads add side effects", evidence, -penalty);
    }
    if (flowTransfers > 0 || hasCategory(categories, "FLOW_TRANSFER")) {
      const penalty = 55;
      score -= penalty;
      addReason(reasons, "flow-transfer", "explicit control-flow transfer", evidence, -penalty);
    }
    if (hasCategory(categories, "STACK_PIVOT")) {
      const penalty = 25;
      score -= penalty;
      addReason(reasons, "stack-pivot", "stack pivot candidates are deprioritized by default", evidence, -penalty);
    }
    if (stackWrites && !hasCategory(categories, "STACK_PIVOT")) {
      const penalty = 15;
      score -= penalty;
      addReason(reasons, "stack-write", "writes to ESP without a pivot classification", evidence, -penalty);
    }
    if (semantic.summary.writes.values.exact.size === 1 && semantic.summary.writes.values.exact.has("eax")) {
      score += 5;
      addReason(reasons, "simple-register-load", "simple single-register write", evidence, 5);
    }
    if (categories.includes("LOAD_REGISTER") || categories.includes("ZERO_REGISTER") || categories.includes("MOVE_REGISTER")) {
      score += 10;
      addReason(reasons, "register-primitive", "simple register primitive", evidence, 10);
    }
    if (semantic.summary.memoryWrites.values.unknown || semantic.summary.memoryReads.values.unknown) {
      score -= 10;
      addReason(reasons, "unknown-memory", "unknown memory effects reduce confidence", evidence, -10);
    }
    return {
      score,
      scoreReasons: reasons
    };
  }

  // src/rop/query.ts
  function normalizeRegisters(registers) {
    return (registers != null ? registers : []).map((register) => register.trim().toLowerCase()).filter((register) => register.length > 0);
  }
  function normalizeKinds(values) {
    if (values === void 0) {
      return [];
    }
    return Array.isArray(values) ? values : [values];
  }
  function fieldSupportsAll(field, expected) {
    if (expected.length === 0) {
      return true;
    }
    if (!field || field.values.unknown) {
      return false;
    }
    for (const value of expected) {
      if (!field.values.exact.has(value) && !field.values.conservative.has(value)) {
        return false;
      }
    }
    return true;
  }
  function fieldExcludesAll(field, forbidden) {
    if (forbidden.length === 0) {
      return true;
    }
    if (!field || field.values.unknown) {
      return false;
    }
    for (const value of forbidden) {
      if (field.values.exact.has(value) || field.values.conservative.has(value)) {
        return false;
      }
    }
    return true;
  }
  function fieldMatchesAny(field, expected) {
    if (expected.length === 0) {
      return true;
    }
    if (!field || field.values.unknown) {
      return false;
    }
    for (const value of expected) {
      if (field.values.exact.has(value) || field.values.conservative.has(value)) {
        return true;
      }
    }
    return false;
  }
  function hasKnownValues(field) {
    return !!field && !field.values.unknown && (field.values.exact.size > 0 || field.values.conservative.size > 0);
  }
  function isDefinitelyEmpty(field) {
    return !!field && !field.values.unknown && field.values.exact.size === 0 && field.values.conservative.size === 0;
  }
  function matchesStackDelta(field, expected) {
    return fieldMatchesAny(field, expected);
  }
  function matchesCapability(gadget, expected) {
    if (expected.length === 0) {
      return true;
    }
    const expectedSet = new Set(expected.map((item) => item.trim().toUpperCase()));
    return gadget.capabilities.some((capability) => expectedSet.has(capability.kind));
  }
  function matchesTerminator(gadget, expected) {
    if (expected.length === 0) {
      return true;
    }
    return fieldMatchesAny(gadget.semanticSummary.summary.flowEffects, expected);
  }
  function matchesExecutableOnly(gadget) {
    return gadget.locations.some((location) => location.executable !== "UNKNOWN");
  }
  function isIdentityTransform(register, expr) {
    return !!expr && expr.kind === "affine" && expr.base === register && expr.offset.kind === "constant" && expr.offset.value === 0;
  }
  function matchesPreserves(gadget, registers) {
    if (registers.length === 0) {
      return true;
    }
    const transforms = gadget.semanticSummary.summary.registerTransforms;
    return registers.every((register) => isIdentityTransform(register, transforms[register]));
  }
  function normalizeTransformQuery(query) {
    var _a, _b;
    return {
      register: query.register.trim().toLowerCase(),
      base: (_a = query.base) == null ? void 0 : _a.trim().toLowerCase(),
      offset: query.offset,
      offsetRegister: (_b = query.offsetRegister) == null ? void 0 : _b.trim().toLowerCase(),
      constant: query.constant,
      fromMemory: query.fromMemory
    };
  }
  function matchesTransform(expr, query) {
    if (!expr) {
      return false;
    }
    if (query.constant !== void 0) {
      if (expr.kind !== "constant" || expr.value !== query.constant) {
        return false;
      }
    }
    if (query.fromMemory !== void 0 && expr.kind === "memory" !== query.fromMemory) {
      return false;
    }
    const wantsAffine = query.base !== void 0 || query.offset !== void 0 || query.offsetRegister !== void 0;
    if (wantsAffine) {
      if (expr.kind !== "affine") {
        return false;
      }
      if (query.base !== void 0 && expr.base !== query.base) {
        return false;
      }
      if (query.offset !== void 0 && (expr.offset.kind !== "constant" || expr.offset.value !== query.offset)) {
        return false;
      }
      if (query.offsetRegister !== void 0 && (expr.offset.kind !== "register" || expr.offset.register !== query.offsetRegister)) {
        return false;
      }
    }
    return true;
  }
  function matchesTransforms(gadget, queries) {
    if (queries.length === 0) {
      return true;
    }
    const transforms = gadget.semanticSummary.summary.registerTransforms;
    return queries.every((query) => matchesTransform(transforms[query.register], query));
  }
  function queryRopGadgets(gadgets, query) {
    var _a, _b, _c;
    const reads = normalizeRegisters(query.reads);
    const writes = normalizeRegisters(query.writes);
    const preserves = normalizeRegisters(query.preserves);
    const preservesThroughout = normalizeRegisters(query.preservesThroughout);
    const transforms = ((_a = query.transforms) != null ? _a : []).map(normalizeTransformQuery);
    const stackDelta = normalizeKinds(query.stackDelta);
    const capabilities = normalizeKinds(query.capability);
    const terminators = normalizeKinds(query.terminator);
    const memoryReads = (_b = query.memoryReads) != null ? _b : query.memoryRead;
    const memoryWrites = (_c = query.memoryWrites) != null ? _c : query.memoryWrite;
    return gadgets.filter((gadget) => {
      if (query.executableOnly && !matchesExecutableOnly(gadget)) {
        return false;
      }
      if (!fieldSupportsAll(gadget.semanticSummary.summary.reads, reads)) {
        return false;
      }
      if (!fieldSupportsAll(gadget.semanticSummary.summary.writes, writes)) {
        return false;
      }
      if (!matchesPreserves(gadget, preserves)) {
        return false;
      }
      if (!fieldExcludesAll(gadget.semanticSummary.summary.writes, preservesThroughout)) {
        return false;
      }
      if (!matchesTransforms(gadget, transforms)) {
        return false;
      }
      if (!matchesStackDelta(gadget.semanticSummary.summary.stackDelta, stackDelta)) {
        return false;
      }
      if (!matchesCapability(gadget, capabilities)) {
        return false;
      }
      if (!matchesTerminator(gadget, terminators)) {
        return false;
      }
      if (memoryReads !== void 0) {
        const field = gadget.semanticSummary.summary.memoryReads;
        if (memoryReads ? !hasKnownValues(field) : !isDefinitelyEmpty(field)) {
          return false;
        }
      }
      if (memoryWrites !== void 0) {
        const field = gadget.semanticSummary.summary.memoryWrites;
        if (memoryWrites ? !hasKnownValues(field) : !isDefinitelyEmpty(field)) {
          return false;
        }
      }
      return true;
    });
  }
  function summarizeCapabilities(index) {
    var _a, _b, _c, _d, _e;
    const counts = /* @__PURE__ */ new Map();
    for (const gadget of index.gadgets) {
      for (const capability of gadget.capabilities) {
        const key2 = [capability.kind, (_a = capability.register) != null ? _a : "", (_b = capability.targetRegister) != null ? _b : ""].join(":");
        const existing = (_e = counts.get(key2)) != null ? _e : {
          kind: capability.kind,
          register: (_c = capability.register) != null ? _c : "",
          targetRegister: (_d = capability.targetRegister) != null ? _d : "",
          count: 0
        };
        existing.count += 1;
        counts.set(key2, existing);
      }
    }
    return [...counts.values()].sort((left, right) => {
      if (left.kind !== right.kind) {
        return left.kind.localeCompare(right.kind);
      }
      if (left.register !== right.register) {
        return left.register.localeCompare(right.register);
      }
      return left.targetRegister.localeCompare(right.targetRegister);
    }).map((entry) => ({
      Kind: entry.kind,
      Register: entry.register || "",
      Target: entry.targetRegister || "",
      Count: entry.count.toString()
    }));
  }

  // src/rop/capabilities.ts
  function key(kind, register, targetRegister) {
    return [kind, register != null ? register : "", targetRegister != null ? targetRegister : ""].join(":");
  }
  function push(map, capability, gadget) {
    var _a;
    const k = key(capability.kind, capability.register, capability.targetRegister);
    const existing = (_a = map.get(k)) != null ? _a : [];
    existing.push(gadget);
    map.set(k, existing);
  }
  function buildCapabilities(gadgets) {
    const capabilityMap = /* @__PURE__ */ new Map();
    for (const gadget of gadgets) {
      for (const capability of gadget.capabilities) {
        push(capabilityMap, capability, gadget);
        if (capability.kind === "MOVE_REGISTER" && capability.targetRegister) {
          push(capabilityMap, __spreadProps(__spreadValues({}, capability), { register: void 0 }), gadget);
        }
        if (capability.kind === "EXCHANGE_REGISTER" && capability.register) {
          push(capabilityMap, __spreadProps(__spreadValues({}, capability), { targetRegister: void 0 }), gadget);
          if (capability.targetRegister) {
            push(capabilityMap, {
              kind: capability.kind,
              register: capability.targetRegister,
              targetRegister: capability.register,
              evidence: capability.evidence
            }, gadget);
          }
        }
      }
    }
    return {
      gadgets,
      capabilityMap,
      loadRegister(register) {
        var _a;
        return (_a = capabilityMap.get(key("LOAD_REGISTER", register))) != null ? _a : [];
      },
      zeroRegister(register) {
        var _a;
        return (_a = capabilityMap.get(key("ZERO_REGISTER", register))) != null ? _a : [];
      },
      moveIntoRegister(register) {
        var _a;
        return (_a = capabilityMap.get(key("MOVE_REGISTER", void 0, register))) != null ? _a : [];
      },
      exchangeWithRegister(register) {
        var _a;
        return (_a = capabilityMap.get(key("EXCHANGE_REGISTER", register))) != null ? _a : [];
      },
      stackPivotCandidates() {
        var _a;
        return (_a = capabilityMap.get(key("STACK_PIVOT"))) != null ? _a : [];
      },
      memoryReadCandidates() {
        var _a;
        return (_a = capabilityMap.get(key("MEMORY_READ"))) != null ? _a : [];
      },
      memoryWriteCandidates() {
        var _a;
        return (_a = capabilityMap.get(key("MEMORY_WRITE"))) != null ? _a : [];
      },
      query(query) {
        return queryRopGadgets(gadgets, query);
      }
    };
  }
  function deriveCapabilities(semantic, categories) {
    const capabilities = [];
    for (const step of semantic.instructionSemantics) {
      const text = step.instruction.normalizedText;
      if (step.instruction.mnemonic === "pop" && step.instruction.operands.length === 1) {
        capabilities.push({ kind: "LOAD_REGISTER", register: step.instruction.operands[0].trim().toLowerCase(), evidence: [text] });
      }
      if (step.instruction.mnemonic === "xor" && step.instruction.operands.length === 2 && step.instruction.operands[0].trim().toLowerCase() === step.instruction.operands[1].trim().toLowerCase()) {
        capabilities.push({ kind: "ZERO_REGISTER", register: step.instruction.operands[0].trim().toLowerCase(), evidence: [text] });
      }
      if (step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2) {
        const left = step.instruction.operands[0].trim().toLowerCase();
        const right = step.instruction.operands[1].trim().toLowerCase();
        if (/^[a-z]{3}$/.test(left) && /^[a-z]{3}$/.test(right) && left !== right) {
          capabilities.push({ kind: "MOVE_REGISTER", register: left, targetRegister: right, evidence: [text] });
        }
        if (left.includes("[") && !right.includes("[")) {
          capabilities.push({ kind: "MEMORY_WRITE", evidence: [text] });
        }
        if (!left.includes("[") && right.includes("[")) {
          capabilities.push({ kind: "MEMORY_READ", evidence: [text] });
        }
      }
      if (step.instruction.mnemonic === "xchg" && step.instruction.operands.length === 2) {
        const left = step.instruction.operands[0].trim().toLowerCase();
        const right = step.instruction.operands[1].trim().toLowerCase();
        if (left === "esp" || right === "esp") {
          capabilities.push({ kind: "STACK_PIVOT", evidence: [text] });
        }
        capabilities.push({ kind: "EXCHANGE_REGISTER", register: left, targetRegister: right, evidence: [text] });
      }
    }
    if (categories.includes("STACK_PIVOT")) {
      capabilities.push({ kind: "STACK_PIVOT", evidence: ["category:STACK_PIVOT"] });
    }
    return capabilities;
  }

  // src/rop/chain.ts
  function firstKnownAddress(gadget) {
    const location = gadget.locations.find((entry) => entry.virtualAddress !== void 0);
    return (location == null ? void 0 : location.virtualAddress) !== void 0 ? BigInt(location.virtualAddress) : void 0;
  }
  function isSinglePopRet(gadget, register) {
    if (gadget.instructions.length !== 2) {
      return false;
    }
    const [pop, ret] = gadget.instructions;
    return pop.mnemonic === "pop" && pop.operands.length === 1 && pop.operands[0].trim().toLowerCase() === register && ret.mnemonic === "ret" && ret.operands.length === 0;
  }
  function selectPopGadget(index, register) {
    return index.loadRegister(register).filter((gadget) => isSinglePopRet(gadget, register) && firstKnownAddress(gadget) !== void 0).sort((a, b) => b.score - a.score)[0];
  }
  function isZeroRet(gadget, register) {
    if (gadget.instructions.length !== 2) {
      return false;
    }
    const [xor, ret] = gadget.instructions;
    return xor.mnemonic === "xor" && xor.operands.length === 2 && xor.operands[0].trim().toLowerCase() === register && xor.operands[1].trim().toLowerCase() === register && ret.mnemonic === "ret" && ret.operands.length === 0;
  }
  function selectZeroGadget(index, register) {
    return index.zeroRegister(register).filter((gadget) => isZeroRet(gadget, register) && firstKnownAddress(gadget) !== void 0).sort((a, b) => b.score - a.score)[0];
  }
  function popSequenceRegisters(gadget) {
    const instructions = gadget.instructions;
    if (instructions.length < 2) {
      return void 0;
    }
    const ret = instructions[instructions.length - 1];
    if (ret.mnemonic !== "ret" || ret.operands.length !== 0) {
      return void 0;
    }
    const registers = [];
    for (let index = 0; index < instructions.length - 1; index += 1) {
      const step = instructions[index];
      if (step.mnemonic !== "pop" || step.operands.length !== 1) {
        return void 0;
      }
      registers.push(step.operands[0].trim().toLowerCase());
    }
    return registers;
  }
  function valueComment(register, value) {
    return `${register} = 0x${(value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
  }
  function planRegisterSetup(index, targets) {
    const steps = [];
    const satisfied = [];
    const unsatisfied = [];
    const remaining = /* @__PURE__ */ new Map();
    const order = [];
    for (const target of targets) {
      const register = target.register.trim().toLowerCase();
      if (!remaining.has(register)) {
        order.push(register);
      }
      remaining.set(register, target.value >>> 0);
    }
    for (const register of order) {
      if (remaining.get(register) !== 0) {
        continue;
      }
      const gadget = selectZeroGadget(index, register);
      if (gadget) {
        steps.push({ kind: "gadget", address: firstKnownAddress(gadget), comment: `xor ${register}, ${register} ; ret (${register} = 0)` });
        satisfied.push(register);
        remaining.delete(register);
      }
    }
    const popSequences = index.gadgets.map((gadget) => ({ gadget, registers: popSequenceRegisters(gadget) })).filter((entry) => entry.registers !== void 0 && entry.registers.length >= 2 && firstKnownAddress(entry.gadget) !== void 0);
    let progressed = true;
    while (progressed) {
      progressed = false;
      let best;
      for (const candidate of popSequences) {
        const { registers } = candidate;
        const distinct = new Set(registers).size === registers.length;
        if (!distinct || !registers.every((register) => remaining.has(register))) {
          continue;
        }
        if (!best || registers.length > best.registers.length || registers.length === best.registers.length && candidate.gadget.score > best.gadget.score) {
          best = candidate;
        }
      }
      if (best) {
        steps.push({ kind: "gadget", address: firstKnownAddress(best.gadget), comment: `${best.registers.map((register) => `pop ${register}`).join(" ; ")} ; ret` });
        for (const register of best.registers) {
          const value = remaining.get(register) >>> 0;
          steps.push({ kind: "value", value, comment: valueComment(register, value) });
          satisfied.push(register);
          remaining.delete(register);
        }
        progressed = true;
      }
    }
    for (const register of order) {
      if (!remaining.has(register)) {
        continue;
      }
      const gadget = selectPopGadget(index, register);
      if (!gadget) {
        const reason = index.loadRegister(register).length > 0 ? "only multi-pop or address-less load gadgets available" : "no pop gadget found for register";
        unsatisfied.push({ register, reason });
        remaining.delete(register);
        continue;
      }
      const value = remaining.get(register) >>> 0;
      steps.push({ kind: "gadget", address: firstKnownAddress(gadget), comment: `pop ${register} ; ret` });
      steps.push({ kind: "value", value, comment: valueComment(register, value) });
      satisfied.push(register);
      remaining.delete(register);
    }
    return { steps, satisfied, unsatisfied, stackBytes: steps.length * 4 };
  }
  function hex32(value) {
    const asBig = typeof value === "bigint" ? value : BigInt(value >>> 0);
    return `0x${asBig.toString(16).toUpperCase().padStart(8, "0")}`;
  }
  function formatChainPython(plan) {
    const lines = ["from struct import pack", 'rop = b""'];
    for (const step of plan.steps) {
      const word = step.kind === "gadget" ? step.address : step.value;
      lines.push(`rop += pack("<I", ${hex32(word)})  # ${step.comment}`);
    }
    return lines;
  }

  // src/semantics/types.ts
  var SEMANTIC_SCHEMA_VERSION = "v1";

  // src/semantics/instruction-semantics.ts
  var REGISTERS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
  function makeSet(exact = [], conservative = [], unknown = false) {
    return {
      exact: new Set(exact),
      conservative: new Set(conservative),
      unknown
    };
  }
  function confidenceForSet(set) {
    if (set.unknown) {
      return "UNKNOWN";
    }
    if (set.conservative.size > 0) {
      return "CONSERVATIVE";
    }
    return "EXACT";
  }
  function makeField(exact = [], conservative = [], unknown = false, evidence = []) {
    const values = makeSet(exact, conservative, unknown);
    return {
      values,
      confidence: confidenceForSet(values),
      evidence
    };
  }
  function parseOperand(text) {
    const normalized = text.trim().toLowerCase();
    if (!normalized) {
      return { kind: "unknown", text: normalized };
    }
    if (REGISTERS.includes(normalized)) {
      return { kind: "register", text: normalized, register: normalized };
    }
    if (/^-?(?:0x[0-9a-f]+|\d+)$/.test(normalized)) {
      return { kind: "immediate", text: normalized };
    }
    if (normalized.includes("[") || normalized.includes("]")) {
      return { kind: "memory", text: normalized };
    }
    return { kind: "unknown", text: normalized };
  }
  function memoryBaseRegister(text) {
    const match = text.toLowerCase().match(/\[([a-z]{3})\]/);
    if (!match) {
      return void 0;
    }
    const register = match[1];
    return REGISTERS.includes(register) ? register : void 0;
  }
  function isRegisterOperand(operand) {
    return operand.kind === "register" && operand.register !== void 0;
  }
  function sameRegisterOperands(instruction) {
    if (instruction.operands.length !== 2) {
      return void 0;
    }
    const left = parseOperand(instruction.operands[0]);
    const right = parseOperand(instruction.operands[1]);
    if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
      return void 0;
    }
    if (left.register !== right.register) {
      return void 0;
    }
    return left.register;
  }
  function immediateOperand(instruction) {
    if (instruction.operands.length === 0) {
      return void 0;
    }
    const operand = parseOperand(instruction.operands[instruction.operands.length - 1]);
    if (operand.kind !== "immediate") {
      return void 0;
    }
    const raw = operand.text;
    if (raw.startsWith("0x")) {
      return Number.parseInt(raw.slice(2), 16) >>> 0;
    }
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) ? parsed >>> 0 : void 0;
  }
  function parseImmediateValue(text) {
    const raw = text.trim().toLowerCase();
    if (/^-?0x[0-9a-f]+$/.test(raw)) {
      const negative = raw.startsWith("-");
      const hex = negative ? raw.slice(3) : raw.slice(2);
      const parsed = Number.parseInt(hex, 16);
      if (!Number.isFinite(parsed)) {
        return void 0;
      }
      const value = negative ? -parsed : parsed;
      return value | 0;
    }
    if (/^-?\d+$/.test(raw)) {
      const parsed = Number.parseInt(raw, 10);
      return Number.isFinite(parsed) ? parsed | 0 : void 0;
    }
    return void 0;
  }
  function constantOffset(value) {
    return { kind: "constant", value };
  }
  function selfPlus(value) {
    return { kind: "affine", base: "self", offset: constantOffset(value) };
  }
  function registerExpr(register, offset = 0) {
    return { kind: "affine", base: register, offset: constantOffset(offset) };
  }
  function constantExpr(value) {
    return { kind: "constant", value };
  }
  function unknownExpr() {
    return { kind: "unknown" };
  }
  function memoryExpr(address) {
    return { kind: "memory", address, confidence: "EXACT" };
  }
  function memoryAddressExpression(text) {
    const match = text.toLowerCase().match(/\[\s*([a-z]{3})(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?\s*\]/);
    if (!match) {
      return void 0;
    }
    const register = match[1];
    if (!REGISTERS.includes(register)) {
      return void 0;
    }
    const rawOffset = match[3] === void 0 ? 0 : parseImmediateValue(match[3]);
    if (rawOffset === void 0) {
      return void 0;
    }
    const offset = match[2] === "-" ? -rawOffset : rawOffset;
    return registerExpr(register, offset);
  }
  function stackDeltaForRegisterImmediate(register, delta) {
    return register === "esp" && delta !== void 0 ? { exact: [delta] } : void 0;
  }
  function unsupported(instruction) {
    const text = canonicalizeInstruction(instruction);
    const unknownField = () => makeField([], [], true, [text]);
    return {
      schemaVersion: SEMANTIC_SCHEMA_VERSION,
      instructionIndex: -1,
      instruction,
      reads: unknownField(),
      writes: unknownField(),
      stackDelta: unknownField(),
      flags: unknownField(),
      memoryReads: unknownField(),
      memoryWrites: unknownField(),
      flowEffects: unknownField(),
      registerEffects: {},
      registerEffectsUnknown: true,
      evidence: [`unsupported instruction: ${text}`],
      supported: false
    };
  }
  var RULES = [
    {
      name: "pop-reg",
      match: (instruction) => instruction.mnemonic === "pop" && instruction.operands.length === 1,
      evaluate: (instruction) => {
        const operand = parseOperand(instruction.operands[0]);
        if (!isRegisterOperand(operand)) {
          return {};
        }
        const popsEsp = operand.register === "esp";
        return {
          reads: ["esp"],
          writes: [operand.register],
          stackDelta: popsEsp ? { unknown: true } : { exact: [4] },
          memoryReads: ["[esp]"],
          flowEffects: [],
          registerEffects: popsEsp ? { esp: unknownExpr() } : {
            [operand.register]: memoryExpr(registerExpr("esp")),
            esp: selfPlus(4)
          },
          evidence: [`POP ${operand.register} reads stack and writes ${operand.register}`]
        };
      }
    },
    {
      name: "push-reg",
      match: (instruction) => instruction.mnemonic === "push" && instruction.operands.length === 1,
      evaluate: (instruction) => {
        const operand = parseOperand(instruction.operands[0]);
        if (!isRegisterOperand(operand)) {
          return {};
        }
        return {
          reads: [operand.register, "esp"],
          writes: ["esp"],
          stackDelta: { exact: [-4] },
          memoryWrites: ["[esp]"],
          registerEffects: { esp: selfPlus(-4) },
          evidence: [`PUSH ${operand.register} decrements stack pointer`]
        };
      }
    },
    {
      name: "ret",
      match: (instruction) => instruction.mnemonic === "ret",
      evaluate: (instruction) => {
        const imm = immediateOperand(instruction);
        const delta = imm === void 0 ? 4 : 4 + imm;
        const evidence = imm === void 0 ? ["RET pops return address"] : [`RET ${imm} adjusts stack by ${delta}`];
        return {
          reads: ["esp"],
          writes: ["esp"],
          stackDelta: { exact: [delta] },
          flowEffects: ["RETURN"],
          registerEffects: { esp: selfPlus(delta) },
          evidence
        };
      }
    },
    {
      name: "mov-reg-reg",
      match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
          return {};
        }
        return {
          reads: [right.register],
          writes: [left.register],
          registerEffects: { [left.register]: registerExpr(right.register) },
          evidence: [`MOV ${left.register}, ${right.register}`]
        };
      }
    },
    {
      name: "mov-reg-mem",
      match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (!isRegisterOperand(left) || right.kind !== "memory") {
          return {};
        }
        const baseRegister = memoryBaseRegister(right.text);
        const address = memoryAddressExpression(right.text);
        return {
          reads: baseRegister ? [baseRegister] : [],
          writes: [left.register],
          memoryReads: [right.text],
          registerEffects: { [left.register]: address ? memoryExpr(address) : unknownExpr() },
          evidence: [`MOV ${left.register}, ${right.text}`]
        };
      }
    },
    {
      name: "mov-mem-reg",
      match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (left.kind !== "memory" || !isRegisterOperand(right)) {
          return {};
        }
        const base = memoryBaseRegister(left.text);
        return {
          reads: [right.register, ...base ? [base] : []],
          writes: base === "esp" ? ["esp"] : [],
          memoryWrites: [left.text],
          evidence: [`MOV ${left.text}, ${right.register}`]
        };
      }
    },
    {
      name: "xor-reg-reg",
      match: (instruction) => instruction.mnemonic === "xor" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const reg = sameRegisterOperands(instruction);
        if (!reg) {
          return {};
        }
        return {
          reads: [reg],
          writes: [reg],
          registerEffects: { [reg]: constantExpr(0) },
          evidence: [`XOR ${reg}, ${reg} zeros register`]
        };
      }
    },
    {
      name: "add-reg-reg",
      match: (instruction) => instruction.mnemonic === "add" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
          return {};
        }
        return {
          reads: [left.register, right.register],
          writes: [left.register],
          registerEffects: { [left.register]: { kind: "affine", base: "self", offset: { kind: "register", register: right.register } } },
          evidence: [`ADD ${left.register}, ${right.register}`]
        };
      }
    },
    {
      name: "add-reg-imm",
      match: (instruction) => instruction.mnemonic === "add" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (!isRegisterOperand(left) || right.kind !== "immediate") {
          return {};
        }
        const imm = parseImmediateValue(right.text);
        return {
          reads: [left.register],
          writes: [left.register],
          stackDelta: stackDeltaForRegisterImmediate(left.register, imm),
          registerEffects: { [left.register]: imm === void 0 ? unknownExpr() : selfPlus(imm) },
          evidence: [`ADD ${left.register}, ${right.text}`]
        };
      }
    },
    {
      name: "sub-reg-reg",
      match: (instruction) => instruction.mnemonic === "sub" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
          return {};
        }
        return {
          reads: [left.register, right.register],
          writes: [left.register],
          registerEffects: { [left.register]: unknownExpr() },
          evidence: [`SUB ${left.register}, ${right.register}`]
        };
      }
    },
    {
      name: "sub-reg-imm",
      match: (instruction) => instruction.mnemonic === "sub" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (!isRegisterOperand(left) || right.kind !== "immediate") {
          return {};
        }
        const imm = parseImmediateValue(right.text);
        return {
          reads: [left.register],
          writes: [left.register],
          stackDelta: stackDeltaForRegisterImmediate(left.register, imm === void 0 ? void 0 : -imm),
          registerEffects: { [left.register]: imm === void 0 ? unknownExpr() : selfPlus(-imm) },
          evidence: [`SUB ${left.register}, ${right.text}`]
        };
      }
    },
    {
      name: "neg-reg",
      match: (instruction) => instruction.mnemonic === "neg" && instruction.operands.length === 1,
      evaluate: (instruction) => {
        const operand = parseOperand(instruction.operands[0]);
        if (!isRegisterOperand(operand)) {
          return {};
        }
        return {
          reads: [operand.register],
          writes: [operand.register],
          registerEffects: { [operand.register]: unknownExpr() },
          evidence: [`NEG ${operand.register}`]
        };
      }
    },
    {
      name: "inc-reg",
      match: (instruction) => instruction.mnemonic === "inc" && instruction.operands.length === 1,
      evaluate: (instruction) => {
        const operand = parseOperand(instruction.operands[0]);
        if (!isRegisterOperand(operand)) {
          return {};
        }
        return {
          reads: [operand.register],
          writes: [operand.register],
          registerEffects: { [operand.register]: selfPlus(1) },
          evidence: [`INC ${operand.register}`]
        };
      }
    },
    {
      name: "dec-reg",
      match: (instruction) => instruction.mnemonic === "dec" && instruction.operands.length === 1,
      evaluate: (instruction) => {
        const operand = parseOperand(instruction.operands[0]);
        if (!isRegisterOperand(operand)) {
          return {};
        }
        return {
          reads: [operand.register],
          writes: [operand.register],
          registerEffects: { [operand.register]: selfPlus(-1) },
          evidence: [`DEC ${operand.register}`]
        };
      }
    },
    {
      name: "xchg-reg-reg",
      match: (instruction) => instruction.mnemonic === "xchg" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
          return {};
        }
        return {
          reads: [left.register, right.register],
          writes: [left.register, right.register],
          registerEffects: {
            [left.register]: registerExpr(right.register),
            [right.register]: registerExpr(left.register)
          },
          evidence: [`XCHG ${left.register}, ${right.register}`]
        };
      }
    },
    {
      name: "lea-reg-mem",
      match: (instruction) => instruction.mnemonic === "lea" && instruction.operands.length === 2,
      evaluate: (instruction) => {
        const left = parseOperand(instruction.operands[0]);
        const right = parseOperand(instruction.operands[1]);
        if (!isRegisterOperand(left) || right.kind !== "memory") {
          return {};
        }
        const address = memoryAddressExpression(right.text);
        if (!address) {
          return {};
        }
        const base = memoryBaseRegister(right.text);
        return {
          reads: base ? [base] : [],
          writes: [left.register],
          registerEffects: { [left.register]: address },
          evidence: [`LEA ${left.register}, ${right.text}`]
        };
      }
    },
    {
      name: "leave",
      match: (instruction) => instruction.mnemonic === "leave",
      evaluate: () => ({
        reads: ["ebp", "esp"],
        writes: ["esp", "ebp"],
        stackDelta: { conservative: [4] },
        memoryReads: ["[ebp]"],
        registerEffects: {
          esp: registerExpr("ebp", 4),
          ebp: memoryExpr(registerExpr("ebp"))
        },
        evidence: ["LEAVE restores frame and pops saved base pointer"]
      })
    },
    {
      name: "call",
      match: (instruction) => instruction.mnemonic === "call" && instruction.operands.length >= 1,
      evaluate: (instruction) => {
        var _a;
        return {
          reads: instruction.operands.length > 0 ? [(_a = parseOperand(instruction.operands[0]).register) != null ? _a : "eax"] : ["eax"],
          writes: ["esp"],
          stackDelta: { exact: [-4] },
          flowEffects: ["CALL"],
          registerEffects: { esp: selfPlus(-4) },
          evidence: [`CALL ${instruction.operands.join(", ")}`]
        };
      }
    },
    {
      name: "jmp",
      match: (instruction) => instruction.mnemonic === "jmp" && instruction.operands.length >= 1,
      evaluate: (instruction) => {
        var _a;
        return {
          reads: instruction.operands.length > 0 ? [(_a = parseOperand(instruction.operands[0]).register) != null ? _a : "eax"] : ["eax"],
          flowEffects: ["JUMP"],
          evidence: [`JMP ${instruction.operands.join(", ")}`]
        };
      }
    },
    {
      name: "nop",
      match: (instruction) => instruction.mnemonic === "nop",
      evaluate: () => ({
        evidence: ["NOP has no semantic side effects"]
      })
    }
  ];
  function buildSemanticField(values, evidence = []) {
    var _a, _b, _c;
    return makeField((_a = values == null ? void 0 : values.exact) != null ? _a : [], (_b = values == null ? void 0 : values.conservative) != null ? _b : [], (_c = values == null ? void 0 : values.unknown) != null ? _c : false, evidence);
  }
  function fromRuleResult(instruction, index, result3, supported) {
    var _a, _b;
    return {
      schemaVersion: SEMANTIC_SCHEMA_VERSION,
      instructionIndex: index,
      instruction,
      reads: buildSemanticField({ exact: result3.reads }, result3.evidence),
      writes: buildSemanticField({ exact: result3.writes }, result3.evidence),
      stackDelta: buildSemanticField(result3.stackDelta, result3.evidence),
      flags: buildSemanticField(result3.flags, result3.evidence),
      memoryReads: buildSemanticField({ exact: result3.memoryReads }, result3.evidence),
      memoryWrites: buildSemanticField({ exact: result3.memoryWrites }, result3.evidence),
      flowEffects: buildSemanticField({ exact: result3.flowEffects }, result3.evidence),
      registerEffects: (_a = result3.registerEffects) != null ? _a : {},
      registerEffectsUnknown: false,
      evidence: (_b = result3.evidence) != null ? _b : [],
      supported
    };
  }
  function analyzeInstruction(instruction, index) {
    for (const rule of RULES) {
      if (!rule.match(instruction)) {
        continue;
      }
      const result3 = rule.evaluate(instruction);
      const supported = Object.values(result3).some((value) => Array.isArray(value) ? value.length > 0 : value !== void 0);
      if (!supported) {
        continue;
      }
      return fromRuleResult(instruction, index, result3, true);
    }
    const fallback = unsupported(instruction);
    return __spreadProps(__spreadValues({}, fallback), {
      instructionIndex: index
    });
  }

  // src/semantics/compose.ts
  var REGISTERS2 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
  function makeSet2(exact = [], conservative = [], unknown = false) {
    return {
      exact: new Set(exact),
      conservative: new Set(conservative),
      unknown
    };
  }
  function confidenceForSet2(set) {
    if (set.unknown) {
      return "UNKNOWN";
    }
    if (set.conservative.size > 0) {
      return "CONSERVATIVE";
    }
    return "EXACT";
  }
  function makeField2(exact = [], conservative = [], unknown = false, evidence = []) {
    const values = makeSet2(exact, conservative, unknown);
    return { values, confidence: confidenceForSet2(values), evidence };
  }
  function mergeSet(left, right) {
    return {
      exact: /* @__PURE__ */ new Set([...left.exact, ...right.exact]),
      conservative: /* @__PURE__ */ new Set([...left.conservative, ...right.conservative]),
      unknown: left.unknown || right.unknown
    };
  }
  function mergeField(left, right) {
    const values = mergeSet(left.values, right.values);
    return {
      values,
      confidence: confidenceForSet2(values),
      evidence: [...left.evidence, ...right.evidence]
    };
  }
  function emptyField() {
    return makeField2();
  }
  function registerIdentity(register) {
    return { kind: "affine", base: register, offset: { kind: "constant", value: 0 } };
  }
  function initialRegisterTransforms() {
    return Object.fromEntries(REGISTERS2.map((register) => [register, registerIdentity(register)]));
  }
  function unknownExpr2() {
    return { kind: "unknown" };
  }
  function isZeroOffset(offset) {
    return offset.kind === "constant" && offset.value === 0;
  }
  function addOffset(expr, offset) {
    if (offset.kind === "unknown" || expr.kind === "unknown") {
      return unknownExpr2();
    }
    if (isZeroOffset(offset)) {
      return expr;
    }
    if (expr.kind === "constant") {
      return offset.kind === "constant" ? { kind: "constant", value: expr.value + offset.value } : unknownExpr2();
    }
    if (expr.kind !== "affine") {
      return unknownExpr2();
    }
    if (expr.offset.kind !== "constant") {
      return unknownExpr2();
    }
    if (offset.kind === "constant") {
      return {
        kind: "affine",
        base: expr.base,
        offset: { kind: "constant", value: expr.offset.value + offset.value }
      };
    }
    if (expr.offset.value !== 0) {
      return unknownExpr2();
    }
    return {
      kind: "affine",
      base: expr.base,
      offset
    };
  }
  function substituteExpr(expr, state, target) {
    if (expr.kind === "constant" || expr.kind === "unknown") {
      return expr;
    }
    if (expr.kind === "memory") {
      return {
        kind: "memory",
        address: substituteExpr(expr.address, state, target),
        confidence: expr.confidence
      };
    }
    const baseExpr = expr.base === "self" ? target ? state[target] : unknownExpr2() : expr.base === "none" ? { kind: "affine", base: "none", offset: { kind: "constant", value: 0 } } : state[expr.base];
    return addOffset(baseExpr, expr.offset);
  }
  function aggregateRegisterTransforms(instructionSemantics) {
    let state = initialRegisterTransforms();
    for (const step of instructionSemantics) {
      if (step.registerEffectsUnknown) {
        state = Object.fromEntries(REGISTERS2.map((register) => [register, unknownExpr2()]));
        continue;
      }
      const nextState = __spreadValues({}, state);
      for (const [register, effect] of Object.entries(step.registerEffects)) {
        nextState[register] = substituteExpr(effect, state, register);
      }
      state = nextState;
    }
    return state;
  }
  function appendField(current, next) {
    return mergeField(current, next);
  }
  function aggregateStackDelta(instructionSemantics) {
    let exactTotal = 0;
    let conservativeTotal = 0;
    let sawExact = true;
    let sawConservative = false;
    let sawUnknown = false;
    const evidence = [];
    for (const step of instructionSemantics) {
      evidence.push(...step.stackDelta.evidence);
      if (step.stackDelta.values.unknown) {
        sawUnknown = true;
        sawExact = false;
        continue;
      }
      if (step.stackDelta.values.conservative.size > 0) {
        sawConservative = true;
        sawExact = false;
        for (const value of step.stackDelta.values.conservative) {
          conservativeTotal += value;
        }
        continue;
      }
      if (step.stackDelta.values.exact.size === 1) {
        exactTotal += [...step.stackDelta.values.exact][0];
        continue;
      }
      if (step.stackDelta.values.exact.size > 1) {
        sawExact = false;
        sawUnknown = true;
      }
    }
    if (sawUnknown) {
      return makeField2([], [], true, evidence);
    }
    if (sawConservative) {
      return makeField2([], [conservativeTotal], false, evidence);
    }
    if (sawExact) {
      return makeField2([exactTotal], [], false, evidence);
    }
    return makeField2([], [], true, evidence);
  }
  function makeSummary() {
    return {
      schemaVersion: SEMANTIC_SCHEMA_VERSION,
      reads: emptyField(),
      writes: emptyField(),
      stackDelta: emptyField(),
      flags: emptyField(),
      memoryReads: emptyField(),
      memoryWrites: emptyField(),
      flowEffects: emptyField(),
      registerTransforms: initialRegisterTransforms()
    };
  }
  function composeSemanticSequence(sequence) {
    const instructionSemantics = sequence.instructions.map((instruction, index) => analyzeInstruction(instruction, index));
    const summary = makeSummary();
    for (const semantic of instructionSemantics) {
      summary.reads = appendField(summary.reads, semantic.reads);
      summary.writes = appendField(summary.writes, semantic.writes);
      summary.stackDelta = appendField(summary.stackDelta, semantic.stackDelta);
      summary.flags = appendField(summary.flags, semantic.flags);
      summary.memoryReads = appendField(summary.memoryReads, semantic.memoryReads);
      summary.memoryWrites = appendField(summary.memoryWrites, semantic.memoryWrites);
      summary.flowEffects = appendField(summary.flowEffects, semantic.flowEffects);
    }
    summary.stackDelta = aggregateStackDelta(instructionSemantics);
    summary.registerTransforms = aggregateRegisterTransforms(instructionSemantics);
    return {
      schemaVersion: SEMANTIC_SCHEMA_VERSION,
      instructionSequenceId: sequence.id,
      instructionSequence: sequence,
      instructionSemantics,
      summary
    };
  }
  function canonicalizeSequenceForPolicy(sequence) {
    return canonicalizeInstructionSequence(sequence);
  }

  // src/semantics/rpplus-provider.ts
  function defaultSource() {
    return {
      kind: "source-adapter",
      name: "rp++",
      format: "rp++",
      version: "v1"
    };
  }
  function defaultProvenance() {
    return {
      executable: "UNKNOWN",
      writable: "UNKNOWN",
      aslr: "UNKNOWN",
      rebaseable: "UNKNOWN"
    };
  }
  function parseAddress(line) {
    const match = line.match(/^\s*0x([0-9a-fA-F]+)\s*:/);
    if (!match) {
      return void 0;
    }
    const value = Number.parseInt(match[1], 16);
    return Number.isFinite(value) ? value >>> 0 : void 0;
  }
  function splitInstructionParts(line) {
    const colon = line.indexOf(":");
    if (colon < 0) {
      return [];
    }
    const body = line.slice(colon + 1).trim();
    return body.split(";").map((part) => part.trim()).filter((part) => part.length > 0).filter((part) => !/^\(\d+\s+found\)$/i.test(part));
  }
  function isBannerLine(line) {
    const trimmed = line.trim();
    if (!trimmed) {
      return true;
    }
    if (!/^0x[0-9a-fA-F]+\s*:/.test(trimmed)) {
      return true;
    }
    return false;
  }
  function parseRpPlusSequences(text, options = {}) {
    const lines = text.split(/\r?\n/);
    const source = __spreadValues(__spreadValues({}, defaultSource()), options.source);
    const provenance = __spreadValues(__spreadValues({}, defaultProvenance()), options.provenance);
    const sequences = [];
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
      if (address === void 0) {
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
        provenance: __spreadProps(__spreadValues({}, provenance), {
          virtualAddress: address
        })
      });
    }
    return sequences;
  }

  // src/rop/index.ts
  function locationFromSequence(sequence) {
    return {
      module: sequence.provenance.module,
      section: sequence.provenance.section,
      virtualAddress: sequence.provenance.virtualAddress,
      fileOffset: sequence.provenance.fileOffset,
      executable: sequence.provenance.executable,
      writable: sequence.provenance.writable,
      aslr: sequence.provenance.aslr,
      rebaseable: sequence.provenance.rebaseable,
      source: sequence.source.name
    };
  }
  function buildRopGadgetFromSequence(sequence) {
    const semanticSummary = composeSemanticSequence(sequence);
    const classification = buildRopGadget(semanticSummary);
    const scoring = scoreSemanticSequence(semanticSummary, classification.categories);
    const capabilities = deriveCapabilities(semanticSummary, classification.categories);
    return {
      schemaVersion: ROP_SCHEMA_VERSION,
      canonicalId: canonicalizeSequenceForPolicy(sequence),
      instructions: sequence.instructions,
      locations: [locationFromSequence(sequence)],
      semanticSummary,
      categories: classification.categories,
      score: scoring.score,
      scoreReasons: scoring.scoreReasons,
      classificationReasons: classification.classificationReasons,
      capabilities
    };
  }
  function dedupeRopGadgets(gadgets) {
    const byCanonicalId = /* @__PURE__ */ new Map();
    for (const gadget of gadgets) {
      const existing = byCanonicalId.get(gadget.canonicalId);
      if (!existing) {
        byCanonicalId.set(gadget.canonicalId, gadget);
        continue;
      }
      existing.locations.push(...gadget.locations);
    }
    return [...byCanonicalId.values()];
  }
  function buildRopIndexFromSequences(sequences) {
    const gadgets = dedupeRopGadgets([...sequences].map((sequence) => buildRopGadgetFromSequence(sequence)));
    const byCanonicalId = /* @__PURE__ */ new Map();
    for (const gadget of gadgets) {
      byCanonicalId.set(gadget.canonicalId, gadget);
    }
    return { gadgets, byCanonicalId };
  }
  function buildRopIndexFromRpPlusText(text, options = {}) {
    return buildRopIndexFromSequences(parseRpPlusSequences(text, options));
  }
  function buildCapabilityIndexFromRpPlusText(text, options = {}) {
    return buildCapabilityIndex(buildRopIndexFromRpPlusText(text, options));
  }
  function buildCapabilityIndex(index) {
    return buildCapabilities(index.gadgets);
  }
  function buildCapabilityIndexFromSequences(sequences) {
    return buildCapabilities(buildRopIndexFromSequences(sequences).gadgets);
  }

  // src/commands/rop.ts
  function readCandidate(address, size) {
    try {
      return readMemory(address, size);
    } catch (_error) {
      return void 0;
    }
  }
  function normalizeScan(options) {
    var _a, _b, _c;
    return {
      module: options.module,
      executableOnly: (_a = options.executableOnly) != null ? _a : true,
      maxResults: Math.min((_b = options.maxResults) != null ? _b : 50, 200),
      mode: (_c = options.mode) != null ? _c : "fast"
    };
  }
  function normalizeRopSuggest(options) {
    var _a;
    return __spreadProps(__spreadValues({}, normalizeScan(options)), {
      engine: (_a = options.engine) != null ? _a : "legacy"
    });
  }
  function validationPass(flags) {
    return flags.decoded && Boolean(flags.mnemonicMatch) && flags.executable;
  }
  function collectValidatedPatternHits(pattern, options) {
    var _a;
    const pointerSize = getPointerSize();
    const scan = scanPattern(
      {
        module: options.module,
        executableOnly: options.executableOnly,
        maxResults: options.maxResults,
        chunkSize: options.mode === "thorough" ? 4096 : 16384
      },
      Uint8Array.from(pattern.bytes)
    );
    const hits = [];
    for (const hit of scan.hits) {
      const candidate = readCandidate(hit, pattern.bytes.length);
      if (!candidate) {
        continue;
      }
      const validated = validateInstructionCandidateForPointerSize(candidate, true, true, pointerSize);
      if (!validationPass(validated.flags)) {
        continue;
      }
      hits.push({
        address: hit,
        pattern,
        mnemonic: (_a = validated.mnemonic) != null ? _a : pattern.mnemonic,
        bytes: pattern.bytes
      });
    }
    return {
      hits,
      warnings: scan.warnings.map((warning) => `${warning.region}: ${warning.message}`),
      stats: scan.stats
    };
  }
  function scanForPattern(name, pattern, options) {
    const pointerSize = getPointerSize();
    const { hits, warnings, stats } = collectValidatedPatternHits(pattern, options);
    const findings = hits.map((hit) => ({
      address: hit.address,
      bytes: hit.bytes,
      mnemonic: hit.mnemonic,
      pattern: hit.pattern.name
    }));
    const rows = hits.map((hit) => ({
      address: formatAddress(hit.address, pointerSize),
      mnemonic: hit.mnemonic,
      bytes: hit.bytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" "),
      py: `0x${hit.address.toString(16).toUpperCase()}`
    })).sort((a, b) => a.address < b.address ? -1 : 1);
    section(name);
    table(
      [
        { key: "address", header: "Address", width: 18 },
        { key: "mnemonic", header: "Mnemonic", width: 18 },
        { key: "bytes", header: "Bytes", width: 16 },
        { key: "py", header: "Python", width: 14 }
      ],
      rows
    );
    return {
      command: name,
      args: options,
      success: true,
      findings,
      warnings,
      errors: [],
      stats
    };
  }
  function buildSequenceFromHit(hit) {
    const instructions = hit.pattern.mnemonic.split(" ; ").map((part) => parseInstruction(part));
    const moduleInfo = findModuleByAddress(hit.address);
    const provenance = {
      module: moduleInfo == null ? void 0 : moduleInfo.name,
      section: moduleInfo ? ".text" : void 0,
      virtualAddress: Number(hit.address & BigInt(4294967295)),
      fileOffset: void 0,
      executable: "EXACT",
      writable: "UNKNOWN",
      aslr: "UNKNOWN",
      rebaseable: "UNKNOWN"
    };
    const source = {
      kind: "rop-suggest",
      name: "semantic-backend",
      format: "synthetic",
      version: "v1"
    };
    return {
      schemaVersion: SEMANTIC_SCHEMA_VERSION,
      id: `rop-suggest:${hit.pattern.name}:${hit.address.toString(16)}:${instructions.map((instruction) => instruction.normalizedText).join(" | ")}`,
      source,
      originalText: hit.pattern.mnemonic,
      instructions,
      provenance
    };
  }
  function runSemanticRopSuggest(options) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j;
    const pointerSize = getPointerSize();
    const combinedWarnings = [];
    const allHits = [];
    let combinedStats = { sectionsScanned: 0, chunksRead: 0, chunksSkipped: 0, results: 0, stoppedEarly: 0 };
    for (const pattern of knownPatternsForPointerSize(pointerSize)) {
      const result3 = collectValidatedPatternHits(pattern, options);
      allHits.push(...result3.hits);
      combinedWarnings.push(...result3.warnings);
      combinedStats = {
        sectionsScanned: combinedStats.sectionsScanned + ((_b = (_a = result3.stats) == null ? void 0 : _a.sectionsScanned) != null ? _b : 0),
        chunksRead: combinedStats.chunksRead + ((_d = (_c = result3.stats) == null ? void 0 : _c.chunksRead) != null ? _d : 0),
        chunksSkipped: combinedStats.chunksSkipped + ((_f = (_e = result3.stats) == null ? void 0 : _e.chunksSkipped) != null ? _f : 0),
        results: combinedStats.results + ((_h = (_g = result3.stats) == null ? void 0 : _g.results) != null ? _h : 0),
        stoppedEarly: combinedStats.stoppedEarly + ((_j = (_i = result3.stats) == null ? void 0 : _i.stoppedEarly) != null ? _j : 0)
      };
    }
    const index = buildRopIndexFromSequences(allHits.map((hit) => buildSequenceFromHit(hit)));
    const gadgets = [...index.gadgets].sort((left, right) => {
      var _a2, _b2, _c2, _d2;
      if (left.score !== right.score) {
        return right.score - left.score;
      }
      const leftAddress = (_b2 = (_a2 = left.locations[0]) == null ? void 0 : _a2.virtualAddress) != null ? _b2 : 0;
      const rightAddress = (_d2 = (_c2 = right.locations[0]) == null ? void 0 : _c2.virtualAddress) != null ? _d2 : 0;
      return leftAddress - rightAddress;
    });
    const rows = gadgets.map((gadget, index2) => {
      var _a2, _b2;
      const firstLocation = gadget.locations[0];
      const address = BigInt((_a2 = firstLocation == null ? void 0 : firstLocation.virtualAddress) != null ? _a2 : 0);
      return {
        rank: `${index2 + 1}`,
        address: formatAddress(address, pointerSize),
        mnemonic: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; "),
        category: (_b2 = gadget.categories[0]) != null ? _b2 : "UNKNOWN",
        score: `${gadget.score}`,
        python: `0x${address.toString(16).toUpperCase()}`,
        locations: `${gadget.locations.length}`
      };
    });
    section("ROP Suggestions (semantic)");
    if (rows.length === 0) {
      print("No semantic gadget suggestions found.");
    } else {
      table(
        [
          { key: "rank", header: "Rank", width: 6 },
          { key: "address", header: "Address", width: 18 },
          { key: "mnemonic", header: "Mnemonic", width: 28 },
          { key: "category", header: "Category", width: 18 },
          { key: "score", header: "Score", width: 6 },
          { key: "locations", header: "Locs", width: 6 },
          { key: "python", header: "Python", width: 14 }
        ],
        rows
      );
    }
    info("Semantic backend selected; duplicate gadgets are merged by canonical IR.");
    whyItMatters("Semantic gadget suggestions improve ranking, deduplication, and explainability.");
    return {
      command: "rop_suggest",
      args: options,
      success: true,
      findings: gadgets,
      warnings: combinedWarnings,
      errors: [],
      stats: __spreadProps(__spreadValues({}, combinedStats), { canonicalResults: gadgets.length })
    };
  }
  function runLegacyRopSuggest(options, initialWarnings = []) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j;
    const combinedFindings = [];
    const combinedWarnings = [...initialWarnings];
    let combinedStats = { sectionsScanned: 0, chunksRead: 0, chunksSkipped: 0, results: 0, stoppedEarly: 0 };
    const pointerSize = getPointerSize();
    for (const pattern of knownPatternsForPointerSize(pointerSize)) {
      const result3 = scanForPattern(`ROP Suggest: ${pattern.name}`, pattern, options);
      combinedFindings.push(
        ...result3.findings.map((finding) => __spreadProps(__spreadValues({}, finding), { pattern: pattern.name }))
      );
      combinedWarnings.push(...result3.warnings);
      combinedStats = {
        sectionsScanned: combinedStats.sectionsScanned + ((_b = (_a = result3.stats) == null ? void 0 : _a.sectionsScanned) != null ? _b : 0),
        chunksRead: combinedStats.chunksRead + ((_d = (_c = result3.stats) == null ? void 0 : _c.chunksRead) != null ? _d : 0),
        chunksSkipped: combinedStats.chunksSkipped + ((_f = (_e = result3.stats) == null ? void 0 : _e.chunksSkipped) != null ? _f : 0),
        results: combinedStats.results + ((_h = (_g = result3.stats) == null ? void 0 : _g.results) != null ? _h : 0),
        stoppedEarly: combinedStats.stoppedEarly + ((_j = (_i = result3.stats) == null ? void 0 : _i.stoppedEarly) != null ? _j : 0)
      };
    }
    whyItMatters("Validated gadget suggestions reduce false positives during ROP chain construction.");
    return {
      command: "rop_suggest",
      args: options,
      success: true,
      findings: combinedFindings,
      warnings: combinedWarnings,
      errors: [],
      stats: combinedStats
    };
  }
  function createRopCommands() {
    const rop = {
      name: "rop",
      description: "ROP helper entrypoint and module triage.",
      usage: "dx @$osed().rop.find({ module: 'essfunc', maxResults: 50 })",
      examples: ["dx @$osed().rop.find({})", "dx @$osed().rop.find({ module: 'essfunc' })"],
      schema: {
        module: { type: "string" },
        executableOnly: { type: "boolean", default: true },
        maxResults: { type: "number", min: 1, max: 200, default: 50 },
        mode: { type: "string", enum: ["fast", "thorough"], default: "fast" }
      },
      execute(options) {
        const modules = listModulesWithMitigations(options.module);
        section("ROP Module Scope");
        table(
          [
            { key: "name", header: "Module", width: 18 },
            { key: "base", header: "Base", width: 18 },
            { key: "size", header: "Size", width: 10 }
          ],
          modules.map((module) => ({
            name: module.name,
            base: formatAddress(module.base, 8),
            size: `0x${module.size.toString(16).toUpperCase()}`
          }))
        );
        info("Use find_bytes or rop_suggest for bounded gadget discovery.");
        whyItMatters("ROP planning starts with selecting stable module memory ranges.");
        return {
          command: "rop",
          args: options,
          success: true,
          findings: modules,
          warnings: [],
          errors: []
        };
      }
    };
    const findBytes = {
      name: "find_bytes",
      description: "Find byte sequence hits in executable sections.",
      usage: "dx @$osed().find_bytes({ module: 'essfunc', bytes: [0xFF,0xE4] })",
      examples: [
        "dx @$osed().find_bytes({ module: 'essfunc', bytes: [0xFF, 0xE4] })",
        "dx @$osed().find_bytes({ module: 'essfunc', bytes: [0x58, 0xC3], maxResults: 25 })"
      ],
      schema: {
        module: { type: "string", required: true },
        bytes: { type: "array", elementType: "number", required: true },
        executableOnly: { type: "boolean", default: true },
        maxResults: { type: "number", min: 1, max: 200, default: 50 },
        mode: { type: "string", enum: ["fast", "thorough"], default: "fast" }
      },
      execute(options) {
        const bytes = options.bytes;
        if (bytes.length === 0 || bytes.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
          throw new Error("bytes must contain 0x00..0xFF integers.");
        }
        const scanOpts = normalizeScan(options);
        const scan = scanPattern(
          {
            module: options.module,
            executableOnly: scanOpts.executableOnly,
            maxResults: scanOpts.maxResults,
            chunkSize: scanOpts.mode === "thorough" ? 4096 : 16384
          },
          Uint8Array.from(bytes)
        );
        const pointerSize = getPointerSize();
        const rows = scan.hits.map((hit) => ({
          address: formatAddress(hit, pointerSize),
          python: `0x${hit.toString(16).toUpperCase()}`
        }));
        section("Find Bytes");
        table(
          [
            { key: "address", header: "Address", width: 18 },
            { key: "python", header: "Python", width: 18 }
          ],
          rows
        );
        whyItMatters("Targeted byte matches accelerate practical gadget and pivot discovery.");
        return {
          command: "find_bytes",
          args: options,
          success: true,
          findings: scan.hits,
          warnings: scan.warnings.map((warning) => `${warning.region}: ${warning.message}`),
          errors: [],
          stats: scan.stats
        };
      }
    };
    const ropSuggest = {
      name: "rop_suggest",
      description: "Suggest common exploit-friendly gadget patterns.",
      usage: "dx @$osed().rop_suggest({ module: 'essfunc', engine: 'semantic' })",
      examples: [
        "dx @$osed().rop_suggest({ module: 'essfunc' })",
        "dx @$osed().rop_suggest({ module: 'essfunc', engine: 'semantic' })",
        "dx @$osed().rop_suggest({ mode: 'thorough', engine: 'legacy' })"
      ],
      schema: {
        module: { type: "string" },
        executableOnly: { type: "boolean", default: true },
        maxResults: { type: "number", min: 1, max: 200, default: 50 },
        mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
        engine: { type: "string", enum: ["legacy", "semantic"], default: "legacy" }
      },
      execute(options) {
        const scanOptions = normalizeRopSuggest(options);
        if (scanOptions.engine === "semantic") {
          if (getPointerSize() === 8) {
            return runLegacyRopSuggest(scanOptions, ["Semantic ROP backend is currently x86-only; used x64 byte-pattern scanner instead."]);
          }
          return runSemanticRopSuggest(scanOptions);
        }
        return runLegacyRopSuggest(scanOptions);
      }
    };
    const retnGadgets = {
      name: "retn",
      description: "Scan for retn N gadgets that pop N bytes before returning.",
      usage: "dx @$osed().retn({ module: 'essfunc', maxResults: 50 })",
      examples: [
        "dx @$osed().retn({ module: 'essfunc' })",
        "dx @$osed().retn({ module: 'essfunc', maxResults: 100 })"
      ],
      schema: {
        module: { type: "string" },
        executableOnly: { type: "boolean", default: true },
        maxResults: { type: "number", min: 1, max: 200, default: 50 },
        mode: { type: "string", enum: ["fast", "thorough"], default: "fast" }
      },
      execute(options) {
        var _a, _b;
        const pointerSize = getPointerSize();
        const maxResults = Math.min((_a = options.maxResults) != null ? _a : 50, 200);
        const executableOnly = (_b = options.executableOnly) != null ? _b : true;
        const moduleFilter = options.module;
        const chunkSize = options.mode === "thorough" ? 4096 : 16384;
        const scan = scanPattern(
          { module: moduleFilter, executableOnly, maxResults: 200, chunkSize },
          Uint8Array.from([194])
        );
        const warnings = [...scan.warnings.map((w) => `${w.region}: ${w.message}`)];
        const groups = /* @__PURE__ */ new Map();
        for (const hit of scan.hits) {
          const bytes = tryReadMemory(hit, 3);
          if (!bytes || bytes.length < 3 || bytes[0] !== 194) continue;
          const n = bytes[1] | bytes[2] << 8;
          if (n === 0) continue;
          const existing = groups.get(n);
          if (existing) {
            existing.count += 1;
          } else {
            groups.set(n, { first: hit, count: 1 });
          }
        }
        const sorted = [...groups.entries()].sort(([a], [b]) => a - b).slice(0, maxResults);
        const findings = sorted.map(([n, { first, count }]) => ({ n, address: first, count }));
        const rows = findings.map(({ n, address, count }) => ({
          n: `0x${n.toString(16).toUpperCase().padStart(4, "0")}`,
          decimal: n.toString(),
          count: count.toString(),
          address: formatAddress(address, pointerSize),
          python: `0x${address.toString(16).toUpperCase()}`
        }));
        section("RETN N Gadgets");
        if (rows.length === 0) {
          print("No retn N gadgets found.");
        } else {
          table(
            [
              { key: "n", header: "N (hex)", width: 8 },
              { key: "decimal", header: "N (dec)", width: 8 },
              { key: "count", header: "Count", width: 6 },
              { key: "address", header: "Address", width: 18 },
              { key: "python", header: "Python", width: 14 }
            ],
            rows
          );
        }
        whyItMatters("retn N pops N bytes before returning \u2014 used to skip arguments in stdcall ROP chains.");
        return {
          command: "retn",
          args: options,
          success: true,
          findings,
          warnings,
          errors: [],
          stats: scan.stats
        };
      }
    };
    const addEsp = {
      name: "add_esp",
      description: "Scan for add esp, N ; ret gadgets used to skip stack slots in ROP chains.",
      usage: "dx @$osed().add_esp({ module: 'essfunc', maxResults: 50 })",
      examples: [
        "dx @$osed().add_esp({ module: 'essfunc' })",
        "dx @$osed().add_esp({ module: 'essfunc', maxResults: 100 })"
      ],
      schema: {
        module: { type: "string" },
        executableOnly: { type: "boolean", default: true },
        maxResults: { type: "number", min: 1, max: 200, default: 50 },
        mode: { type: "string", enum: ["fast", "thorough"], default: "fast" }
      },
      execute(options) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n, _o, _p, _q, _r;
        const pointerSize = getPointerSize();
        const maxResults = Math.min((_a = options.maxResults) != null ? _a : 50, 200);
        const executableOnly = (_b = options.executableOnly) != null ? _b : true;
        const moduleFilter = options.module;
        const chunkSize = options.mode === "thorough" ? 4096 : 16384;
        const warnings = [];
        const groups = /* @__PURE__ */ new Map();
        const scan8 = scanPattern({ module: moduleFilter, executableOnly, maxResults: 200, chunkSize }, Uint8Array.from([131, 196]));
        warnings.push(...scan8.warnings.map((w) => `${w.region}: ${w.message}`));
        for (const hit of scan8.hits) {
          const bytes = tryReadMemory(hit, 4);
          if (!bytes || bytes.length < 4 || bytes[0] !== 131 || bytes[1] !== 196 || bytes[3] !== 195) continue;
          const n = bytes[2];
          if (n === 0) continue;
          const existing = groups.get(n);
          if (existing) {
            existing.count += 1;
          } else {
            groups.set(n, { first: hit, count: 1, imm32: false });
          }
        }
        const scan32 = scanPattern({ module: moduleFilter, executableOnly, maxResults: 200, chunkSize }, Uint8Array.from([129, 196]));
        warnings.push(...scan32.warnings.map((w) => `${w.region}: ${w.message}`));
        for (const hit of scan32.hits) {
          const bytes = tryReadMemory(hit, 7);
          if (!bytes || bytes.length < 7 || bytes[0] !== 129 || bytes[1] !== 196 || bytes[6] !== 195) continue;
          const n = bytes[2] | bytes[3] << 8 | bytes[4] << 16 | bytes[5] << 24;
          if (n <= 0) continue;
          if (!groups.has(n)) {
            groups.set(n, { first: hit, count: 1, imm32: true });
          } else {
            groups.get(n).count += 1;
          }
        }
        const sorted = [...groups.entries()].filter(([n]) => n > 0).sort(([a], [b]) => a - b).slice(0, maxResults);
        const findings = sorted.map(([n, { first, count, imm32 }]) => ({ n, address: first, count, imm32 }));
        const rows = findings.map(({ n, address, count, imm32 }) => ({
          n: `0x${n.toString(16).toUpperCase().padStart(imm32 ? 8 : 2, "0")}`,
          decimal: n.toString(),
          enc: imm32 ? "imm32" : "imm8",
          count: count.toString(),
          address: formatAddress(address, pointerSize),
          python: `0x${address.toString(16).toUpperCase()}`
        }));
        section("ADD ESP, N ; RET Gadgets");
        if (rows.length === 0) {
          print("No add esp, N ; ret gadgets found.");
        } else {
          table(
            [
              { key: "n", header: "N (hex)", width: 10 },
              { key: "decimal", header: "N (dec)", width: 8 },
              { key: "enc", header: "Enc", width: 6 },
              { key: "count", header: "Count", width: 6 },
              { key: "address", header: "Address", width: 18 },
              { key: "python", header: "Python", width: 14 }
            ],
            rows
          );
        }
        whyItMatters("add esp, N skips N bytes of ROP chain slots \u2014 essential for aligning stdcall argument frames.");
        const stats = {
          sectionsScanned: ((_d = (_c = scan8.stats) == null ? void 0 : _c.sectionsScanned) != null ? _d : 0) + ((_f = (_e = scan32.stats) == null ? void 0 : _e.sectionsScanned) != null ? _f : 0),
          chunksRead: ((_h = (_g = scan8.stats) == null ? void 0 : _g.chunksRead) != null ? _h : 0) + ((_j = (_i = scan32.stats) == null ? void 0 : _i.chunksRead) != null ? _j : 0),
          chunksSkipped: ((_l = (_k = scan8.stats) == null ? void 0 : _k.chunksSkipped) != null ? _l : 0) + ((_n = (_m = scan32.stats) == null ? void 0 : _m.chunksSkipped) != null ? _n : 0),
          results: findings.length,
          stoppedEarly: ((_p = (_o = scan8.stats) == null ? void 0 : _o.stoppedEarly) != null ? _p : 0) + ((_r = (_q = scan32.stats) == null ? void 0 : _q.stoppedEarly) != null ? _r : 0)
        };
        return { command: "add_esp", args: options, success: true, findings, warnings, errors: [], stats };
      }
    };
    return [rop, findBytes, ropSuggest, retnGadgets, addEsp];
  }

  // src/commands/pivot.ts
  var PIVOT_PATTERNS = [
    { sequence: "xchg eax, esp ; ret", bytes: [148, 195] },
    { sequence: "xchg ecx, esp ; ret", bytes: [135, 204, 195] },
    { sequence: "xchg edx, esp ; ret", bytes: [135, 212, 195] },
    { sequence: "xchg ebx, esp ; ret", bytes: [135, 220, 195] },
    { sequence: "xchg esi, esp ; ret", bytes: [135, 244, 195] },
    { sequence: "xchg edi, esp ; ret", bytes: [135, 252, 195] },
    { sequence: "xchg ebp, esp ; ret", bytes: [135, 236, 195] },
    { sequence: "push esp ; ret", bytes: [84, 195] },
    { sequence: "mov esp, ebp ; ret", bytes: [139, 229, 195] },
    { sequence: "mov esp, eax ; ret", bytes: [137, 196, 195] },
    { sequence: "leave ; ret", bytes: [201, 195] }
  ];
  var X64_PIVOT_PATTERNS = [
    { sequence: "xchg rax, rsp ; ret", bytes: [72, 148, 195] },
    { sequence: "xchg rcx, rsp ; ret", bytes: [72, 135, 204, 195] },
    { sequence: "xchg rdx, rsp ; ret", bytes: [72, 135, 212, 195] },
    { sequence: "xchg rbx, rsp ; ret", bytes: [72, 135, 220, 195] },
    { sequence: "xchg rsi, rsp ; ret", bytes: [72, 135, 244, 195] },
    { sequence: "xchg rdi, rsp ; ret", bytes: [72, 135, 252, 195] },
    { sequence: "xchg rbp, rsp ; ret", bytes: [72, 135, 236, 195] },
    { sequence: "push rsp ; ret", bytes: [84, 195] },
    { sequence: "mov rsp, rbp ; ret", bytes: [72, 137, 236, 195] },
    { sequence: "mov rsp, rax ; ret", bytes: [72, 137, 196, 195] },
    { sequence: "leave ; ret", bytes: [201, 195] }
  ];
  function buildSequence(address, sequence) {
    const moduleInfo = findModuleByAddress(address);
    const provenance = {
      module: moduleInfo == null ? void 0 : moduleInfo.name,
      section: moduleInfo ? ".text" : void 0,
      virtualAddress: Number(address & BigInt(4294967295)),
      fileOffset: void 0,
      executable: "EXACT",
      writable: "UNKNOWN",
      aslr: "UNKNOWN",
      rebaseable: "UNKNOWN"
    };
    const source = {
      kind: "pivot-scan",
      name: "stack-pivot",
      format: "synthetic",
      version: "v1"
    };
    return {
      schemaVersion: SEMANTIC_SCHEMA_VERSION,
      id: `pivot:${sequence}:${address.toString(16)}`,
      source,
      originalText: sequence,
      instructions: sequence.split(" ; ").map((part) => parseInstruction(part)),
      provenance
    };
  }
  function createPivotCommand() {
    return {
      name: "pivots",
      description: "Scan for stack pivot candidates.",
      usage: "dx @$osed().pivots({ module: 'essfunc', maxResults: 50 })",
      examples: ["dx @$osed().pivots({ module: 'essfunc' })", "dx @$osed().pivots({ mode: 'thorough' })"],
      schema: {
        module: { type: "string" },
        executableOnly: { type: "boolean", default: true },
        maxResults: { type: "number", min: 1, max: 200, default: 50 },
        mode: { type: "string", enum: ["fast", "thorough"], default: "fast" }
      },
      execute(options) {
        var _a, _b, _c, _d;
        const pointerSize = getPointerSize();
        const patterns = pointerSize === 8 ? X64_PIVOT_PATTERNS : PIVOT_PATTERNS;
        const warnings = [];
        const sequenceHits = [];
        const detailsByAddress = /* @__PURE__ */ new Map();
        for (const pivot of patterns) {
          const scan = scanPattern(
            {
              module: options.module,
              executableOnly: (_a = options.executableOnly) != null ? _a : true,
              maxResults: (_b = options.maxResults) != null ? _b : 50,
              chunkSize: options.mode === "thorough" ? 4096 : 16384
            },
            Uint8Array.from(pivot.bytes)
          );
          warnings.push(...scan.warnings.map((warning) => `${warning.region}: ${warning.message}`));
          for (const hit of scan.hits) {
            const candidate = readMemory(hit, pivot.bytes.length);
            const validated = validateInstructionCandidateForPointerSize(candidate, true, true, pointerSize);
            if (!validated.flags.decoded || !validated.flags.mnemonicMatch || !validated.flags.executable) {
              continue;
            }
            detailsByAddress.set(hit, {
              sequence: pivot.sequence,
              flags: validated.flags
            });
            sequenceHits.push(buildSequence(hit, pivot.sequence));
          }
        }
        const findings = pointerSize === 8 ? [...detailsByAddress.entries()].map(([address, detail]) => ({
          address,
          sequence: detail.sequence,
          offset: `0x${address.toString(16).toUpperCase()}`,
          flags: detail.flags
        })).sort((left, right) => left.address < right.address ? -1 : 1).slice(0, Math.min((_c = options.maxResults) != null ? _c : 50, 200)) : buildCapabilityIndex(buildRopIndexFromSequences(sequenceHits)).query({
          capability: "STACK_PIVOT",
          executableOnly: true
        }).map((gadget) => {
          var _a2, _b2, _c2, _d2;
          const address = BigInt((_b2 = (_a2 = gadget.locations[0]) == null ? void 0 : _a2.virtualAddress) != null ? _b2 : 0);
          const detail = detailsByAddress.get(address);
          return {
            address,
            sequence: (_c2 = detail == null ? void 0 : detail.sequence) != null ? _c2 : gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; "),
            offset: `0x${address.toString(16).toUpperCase()}`,
            flags: (_d2 = detail == null ? void 0 : detail.flags) != null ? _d2 : {}
          };
        }).sort((left, right) => left.address < right.address ? -1 : 1).slice(0, Math.min((_d = options.maxResults) != null ? _d : 50, 200));
        section("Stack Pivot Candidates");
        table(
          [
            { key: "address", header: "Address", width: 18 },
            { key: "sequence", header: "Sequence", width: 22 },
            { key: "python", header: "Python", width: 18 }
          ],
          findings.map((finding) => ({
            address: formatAddress(finding.address, pointerSize),
            sequence: finding.sequence,
            python: `0x${finding.address.toString(16).toUpperCase()}`
          }))
        );
        whyItMatters("Stack pivots transition execution into attacker-controlled ROP chains.");
        return {
          command: "pivots",
          args: options,
          success: true,
          findings,
          warnings,
          errors: []
        };
      }
    };
  }

  // src/core/help_catalog.ts
  var NAMESPACE_HELP_ENTRIES = [
    {
      name: "pattern.create",
      description: "Generates cyclic pattern text.",
      usage: "dx @$osed().pattern.create(length, type?)",
      examples: ['dx @$osed().pattern.create(300, "msf")']
    },
    {
      name: "pattern.offset",
      description: "Finds an offset in the selected pattern family.",
      usage: "dx @$osed().pattern.offset(value, type?)",
      examples: ['dx @$osed().pattern.offset(0x39654138, "msf")']
    },
    {
      name: "seh.visualize",
      description: "Walks the current thread SEH chain.",
      usage: "dx @$osed().seh.visualize()",
      examples: ["dx @$osed().seh.visualize()"]
    },
    {
      name: "fmt.build",
      description: "Builds a format-string write payload.",
      usage: "dx @$osed().fmt.build(addr, value, argIndex, width?, exclude?)",
      examples: ["dx @$osed().fmt.build(0x00402118, 0x625011AF, 6)"]
    },
    {
      name: "fmt.offset",
      description: "Finds the controlled format-string parameter index.",
      usage: "dx @$osed().fmt.offset(marker?, count?, firstArg?)",
      examples: ["dx @$osed().fmt.offset(0x41414141, 40)"]
    },
    {
      name: "rop_find",
      description: "Flat alias for legacy ROP helper/module triage.",
      usage: "dx @$osed().rop_find(module?, maxResults?, executableOnly?, mode?)",
      examples: ['dx @$osed().rop_find("essfunc")']
    },
    {
      name: "rop.find",
      description: "Runs the legacy ROP helper/module triage from the ROP namespace.",
      usage: "dx @$osed().rop.find(module?, maxResults?, executableOnly?, mode?)",
      examples: ['dx @$osed().rop.find("essfunc")']
    },
    {
      name: "rop.scan",
      description: "Loads pasted RP++ output into the semantic ROP corpus.",
      usage: "dx @$osed().rop.scan(text, options?)",
      examples: ['dx @$osed().rop.scan("0x1000: pop eax ; ret ;")']
    },
    {
      name: "rop.query",
      description: "Filters the loaded semantic ROP corpus.",
      usage: "dx @$osed().rop.query(query)",
      examples: ['dx @$osed().rop.query({ transforms: [{ register: "esi", base: "esi", offset: 4 }] })']
    },
    {
      name: "rop.capabilities",
      description: "Summarizes capabilities in the loaded semantic ROP corpus.",
      usage: "dx @$osed().rop.capabilities()",
      examples: ["dx @$osed().rop.capabilities()"]
    },
    {
      name: "sc.iat",
      description: "Enumerates imported addresses for a module, optionally filtered by DLL or symbol substring.",
      usage: "dx @$osed().sc.iat(module?, filter?)",
      examples: ["dx @$osed().sc.iat()", 'dx @$osed().sc.iat("app.exe", "Virtual")']
    },
    {
      name: "sc.iat_find",
      description: "Searches all loaded modules for matching IAT entries.",
      usage: "dx @$osed().sc.iat_find(symbol)",
      examples: ['dx @$osed().sc.iat_find("VirtualAlloc")']
    },
    {
      name: "sc.iat_ptr",
      description: "Resolves one imported symbol to its IAT slot and current target pointer.",
      usage: "dx @$osed().sc.iat_ptr(module, symbol)",
      examples: ['dx @$osed().sc.iat_ptr("app.exe", "VirtualProtect")']
    },
    {
      name: "sc.exportdir",
      description: "Shows PE export directory addresses and table metadata.",
      usage: "dx @$osed().sc.exportdir(module)",
      examples: ['dx @$osed().sc.exportdir("kernel32")']
    },
    {
      name: "sc.export",
      description: "Resolves an export by name and reports ordinal, RVA, VA, and forwarder data.",
      usage: "dx @$osed().sc.export(module, symbol)",
      examples: ['dx @$osed().sc.export("kernel32", "GetProcAddress")']
    },
    {
      name: "sc.exportwalk",
      description: "Walks PE export resolution checkpoints.",
      usage: "dx @$osed().sc.exportwalk(module, symbol?, verbose?)",
      examples: ['dx @$osed().sc.exportwalk("kernel32", "GetProcAddress")']
    },
    {
      name: "sc.exportat",
      description: "Resolves an export by ordinal index.",
      usage: "dx @$osed().sc.exportat(module, ordinalIndex)",
      examples: ['dx @$osed().sc.exportat("kernel32", 842)']
    },
    {
      name: "sc.hashresolve",
      description: "Resolves an API hash against module exports.",
      usage: "dx @$osed().sc.hashresolve(module, hashValue, algorithm?)",
      examples: ['dx @$osed().sc.hashresolve("kernel32", 0x7c0dfcaa, "ROR13")']
    },
    {
      name: "sc.exports",
      description: "Enumerates exported symbols, optionally filtered by substring.",
      usage: "dx @$osed().sc.exports(module, filter?)",
      examples: ['dx @$osed().sc.exports("kernel32", "Virtual")']
    },
    {
      name: "sc.resolve",
      description: "Resolves one export to an address.",
      usage: "dx @$osed().sc.resolve(module, symbol)",
      examples: ['dx @$osed().sc.resolve("kernel32", "WinExec")']
    },
    {
      name: "sc.hashes",
      description: "Hashes named exports with the selected shellforge-compatible algorithm.",
      usage: "dx @$osed().sc.hashes(module, algorithm?)",
      examples: ['dx @$osed().sc.hashes("kernel32", "crc32")']
    },
    {
      name: "sc.hash",
      description: "Hashes one API name.",
      usage: "dx @$osed().sc.hash(name, algorithm?)",
      examples: ['dx @$osed().sc.hash("WinExec", "ROR13")']
    },
    {
      name: "sc.algorithms",
      description: "Lists supported API hash algorithms.",
      usage: "dx @$osed().sc.algorithms()",
      examples: ["dx @$osed().sc.algorithms()"]
    },
    {
      name: "sc.pe",
      description: "Prints PE header fields for a module.",
      usage: "dx @$osed().sc.pe(module)",
      examples: ['dx @$osed().sc.pe("kernel32")']
    },
    {
      name: "sc.base",
      description: "Resolves a module base address.",
      usage: "dx @$osed().sc.base(module)",
      examples: ['dx @$osed().sc.base("kernel32")']
    },
    {
      name: "sc.modules",
      description: "Lists loaded modules.",
      usage: "dx @$osed().sc.modules()",
      examples: ["dx @$osed().sc.modules()"]
    },
    {
      name: "sc.peb",
      description: "Dumps current PEB-oriented module evidence.",
      usage: "dx @$osed().sc.peb()",
      examples: ["dx @$osed().sc.peb()"]
    },
    {
      name: "sc.module_pages",
      description: "Reports module size and estimated page count.",
      usage: "dx @$osed().sc.module_pages(module)",
      examples: ['dx @$osed().sc.module_pages("kernel32")']
    },
    {
      name: "sc.page_summary",
      description: "Buckets module pages by protection value.",
      usage: "dx @$osed().sc.page_summary(module)",
      examples: ['dx @$osed().sc.page_summary("kernel32")']
    }
  ];
  function findHelpEntry(name) {
    const normalized = name.trim().toLowerCase();
    return NAMESPACE_HELP_ENTRIES.find((entry) => entry.name.toLowerCase() === normalized);
  }
  function helpRows(entry) {
    return [
      {
        Helper: entry.name,
        Usage: entry.usage,
        Description: entry.description
      },
      ...entry.examples.map((example) => ({
        Helper: "example",
        Usage: example,
        Description: ""
      }))
    ];
  }

  // src/commands/help.ts
  function createHelpCommand(registry2) {
    const firstExample = (examples) => {
      var _a;
      return (_a = examples[0]) != null ? _a : "";
    };
    return {
      name: "help",
      description: "List commands or show detailed command help.",
      usage: "dx @$osed().help(command?)",
      examples: ["dx @$osed().help()", 'dx @$osed().help("badchars")', 'dx @$osed().help("sc.iat")'],
      schema: {
        command: { type: "string" }
      },
      execute(options) {
        var _a;
        const commandName = options.command;
        if (!commandName) {
          const commands = registry2.getAll().filter((command2) => command2.name !== "rop");
          section("OSED Commands");
          table(
            [
              { key: "name", header: "Command", width: 16 },
              { key: "description", header: "Description", width: 40 },
              { key: "example", header: "Example", width: 34 }
            ],
            commands.map((command2) => ({
              name: command2.name,
              description: command2.description,
              example: firstExample(command2.examples)
            }))
          );
          const groups = /* @__PURE__ */ new Map();
          for (const entry of NAMESPACE_HELP_ENTRIES) {
            const group = entry.name.includes(".") ? entry.name.split(".")[0] : "other";
            groups.set(group, [...(_a = groups.get(group)) != null ? _a : [], entry]);
          }
          for (const [group, entries] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
            section(`${group} Namespace Helpers`);
            table(
              [
                { key: "name", header: "Helper", width: 22 },
                { key: "description", header: "Description", width: 56 },
                { key: "example", header: "Example", width: 34 }
              ],
              entries.map((entry) => ({
                name: entry.name,
                description: entry.description,
                example: firstExample(entry.examples)
              }))
            );
          }
          info('Use help("name") for details, e.g. dx @$osed().help("sc.iat").');
          info('Most helpers also accept "help" as the first argument, e.g. dx @$osed().sc.iat("help").');
          whyItMatters("Fast command discovery lowers debugger friction during exploit iteration.");
          return {
            command: "help",
            args: options,
            success: true,
            findings: [
              ...commands.map((command2) => ({
                name: command2.name,
                description: command2.description,
                usage: command2.usage,
                examples: command2.examples,
                schema: command2.schema
              })),
              ...NAMESPACE_HELP_ENTRIES
            ],
            warnings: [],
            errors: [],
            schema: {
              command: { type: "string", optional: true }
            }
          };
        }
        const command = registry2.get(commandName);
        const helper = findHelpEntry(commandName === "rop" ? "rop.find" : commandName);
        if (!command && !helper) {
          return {
            command: "help",
            args: options,
            success: false,
            findings: [],
            warnings: [],
            errors: [`Unknown command '${commandName}'.`]
          };
        }
        if (helper) {
          section(`Help: ${helper.name}`);
          info(helper.description);
          info(`Usage: ${helper.usage}`);
          for (const example of helper.examples) {
            print(`  ${example}`);
          }
          whyItMatters("Inline helper documentation keeps namespace workflows discoverable at the debugger prompt.");
          return {
            command: "help",
            args: options,
            success: true,
            findings: helpRows(helper),
            warnings: [],
            errors: []
          };
        }
        if (!command) {
          return {
            command: "help",
            args: options,
            success: false,
            findings: [],
            warnings: [],
            errors: [`Unknown command '${commandName}'.`]
          };
        }
        section(`Help: ${command.name}`);
        info(command.description);
        info(`Usage: ${command.usage}`);
        for (const example of command.examples) {
          print(`  ${example}`);
        }
        whyItMatters("Inline help prevents context switching and keeps exploit workflow focused.");
        return {
          command: "help",
          args: options,
          success: true,
          findings: [
            {
              name: command.name,
              description: command.description,
              usage: command.usage,
              examples: command.examples,
              schema: command.schema
            }
          ],
          warnings: [],
          errors: [],
          schema: command.schema
        };
      }
    };
  }

  // src/commands/reload.ts
  function createReloadCommand(registry2) {
    return {
      name: "reload",
      description: "Clear and re-register command registry.",
      usage: "dx @$osed().reload({})",
      examples: ["dx @$osed().reload({})", "dx @$osed().reload({})"],
      schema: {},
      execute(options) {
        var _a, _b;
        const result3 = registry2.reload();
        result3.args = options;
        section("Reload");
        if (result3.success) {
          info(`Re-registered ${(_b = (_a = result3.findings[0]) == null ? void 0 : _a.commandCount) != null ? _b : 0} commands.`);
        } else {
          for (const err of result3.errors) {
            error(err);
          }
        }
        whyItMatters("Fast in-session reload shortens debug-iterate-test cycles.");
        return result3;
      }
    };
  }

  // src/commands/seh_ppr.ts
  function addressBytes(address, pointerSize) {
    const bytes = [];
    for (let i = 0; i < pointerSize; i += 1) {
      bytes.push(Number(address >> BigInt(i * 8) & BigInt(255)));
    }
    return bytes;
  }
  function isBadcharSafe(address, pointerSize, exclude) {
    if (exclude.length === 0) {
      return true;
    }
    const blocked = new Set(exclude);
    return !addressBytes(address, pointerSize).some((value) => blocked.has(value));
  }
  function scoreFinding(badcharSafe, aslr, safeseh) {
    let score = 0;
    const reasons = [];
    if (badcharSafe) {
      score += 35;
      reasons.push("address bytes avoid excluded badchars");
    } else {
      score -= 40;
      reasons.push("address bytes contain excluded badchars");
    }
    if (aslr === "disabled") {
      score += 25;
      reasons.push("module has ASLR disabled");
    } else if (aslr === "unknown") {
      score += 5;
      reasons.push("module ASLR state unknown");
    } else {
      score -= 20;
      reasons.push("module has ASLR enabled");
    }
    if (safeseh === "disabled") {
      score += 30;
      reasons.push("module SafeSEH is disabled");
    } else if (safeseh === "unknown") {
      score += 10;
      reasons.push("module SafeSEH state unknown");
    } else {
      score -= 40;
      reasons.push("module SafeSEH is enabled");
    }
    return { score, reasons };
  }
  function normalizeMode(value) {
    return value === "thorough" ? "thorough" : "fast";
  }
  function createSehPprCommand() {
    return {
      name: "seh_ppr",
      description: "Find and rank pop-pop-ret candidates for SEH workflows.",
      usage: "dx @$osed().seh_ppr('libspp.dll', '00 0A 0D', 50, true, 'fast')",
      examples: ["dx @$osed().seh_ppr()", "dx @$osed().seh_ppr('libspp.dll', '00 0A 0D', 100, true, 'thorough')"],
      schema: {
        module: { type: "string" },
        exclude: { type: "array", elementType: "number", default: [] },
        maxResults: { type: "number", min: 1, max: 200, default: 50 },
        executableOnly: { type: "boolean", default: true },
        mode: { type: "string", enum: ["fast", "thorough"], default: "fast" }
      },
      execute(options) {
        var _a, _b, _c, _d, _e, _f, _g;
        const pointerSize = getPointerSize();
        const normalizedExclude = normalizeByteArray((_a = options.exclude) != null ? _a : []);
        const executableOnly = (_b = options.executableOnly) != null ? _b : true;
        const maxResults = Math.min((_c = options.maxResults) != null ? _c : 50, 200);
        const mode = normalizeMode(options.mode);
        const moduleFilter = options.module;
        const warnings = [];
        if (normalizedExclude.warning) {
          warnings.push(normalizedExclude.warning);
        }
        const findings = [];
        const seen = /* @__PURE__ */ new Set();
        const patterns = knownPatterns().filter((p) => /^pop \w+ ; pop \w+ ; ret$/.test(p.mnemonic)).map((p) => p.bytes);
        for (const pattern of patterns) {
          if (findings.length >= maxResults) {
            break;
          }
          const remaining = Math.max(1, maxResults - findings.length);
          const scan = scanPattern(
            {
              module: moduleFilter,
              executableOnly,
              maxResults: remaining,
              chunkSize: mode === "thorough" ? 4096 : 16384
            },
            Uint8Array.from(pattern)
          );
          warnings.push(...scan.warnings.map((warning) => `${warning.region}: ${warning.message}`));
          for (const hit of scan.hits) {
            const key2 = hit.toString();
            if (seen.has(key2)) {
              continue;
            }
            seen.add(key2);
            const candidate = tryReadMemory(hit, 3);
            if (!candidate) {
              continue;
            }
            const validated = validateInstructionCandidate(candidate, true, true);
            if (!validated.flags.decoded || !validated.flags.mnemonicMatch || !validated.flags.executable) {
              continue;
            }
            const moduleInfo = findModuleByAddress(hit);
            const moduleName = (_d = moduleInfo == null ? void 0 : moduleInfo.name) != null ? _d : "<outside module>";
            const moduleOffset = moduleInfo ? `0x${(hit - moduleInfo.base).toString(16).toUpperCase()}` : "n/a";
            const aslr = (_e = moduleInfo == null ? void 0 : moduleInfo.aslr) != null ? _e : "unknown";
            const safeseh = (_f = moduleInfo == null ? void 0 : moduleInfo.safeseh) != null ? _f : "unknown";
            const badcharSafe = isBadcharSafe(hit, pointerSize, normalizedExclude.values);
            const scored = scoreFinding(badcharSafe, aslr, safeseh);
            findings.push({
              address: hit,
              module: moduleName,
              module_offset: moduleOffset,
              instructions: (_g = validated.mnemonic) != null ? _g : "pop ? ; pop ? ; ret",
              badchar_safe: badcharSafe,
              aslr,
              safeseh,
              score: scored.score,
              reasons: scored.reasons
            });
            if (findings.length >= maxResults) {
              break;
            }
          }
        }
        findings.sort((a, b) => {
          if (a.score !== b.score) {
            return b.score - a.score;
          }
          return a.address < b.address ? -1 : 1;
        });
        section("SEH PPR Candidates");
        table(
          [
            { key: "rank", header: "Rank", width: 6 },
            { key: "address", header: "Address", width: 18 },
            { key: "module", header: "Module", width: 18 },
            { key: "offset", header: "Offset", width: 12 },
            { key: "instr", header: "Instructions", width: 24 },
            { key: "badchar", header: "BadChar", width: 8 },
            { key: "aslr", header: "ASLR", width: 8 },
            { key: "safeseh", header: "SafeSEH", width: 8 },
            { key: "score", header: "Score", width: 6 }
          ],
          findings.map((finding, index) => ({
            rank: `${index + 1}`,
            address: formatAddress(finding.address, pointerSize),
            module: finding.module,
            offset: finding.module_offset,
            instr: finding.instructions,
            badchar: finding.badchar_safe ? "safe" : "bad",
            aslr: finding.aslr,
            safeseh: finding.safeseh,
            score: `${finding.score}`
          }))
        );
        whyItMatters("Reliable pop-pop-ret selection is central to practical SEH overwrite exploitation.");
        return {
          command: "seh_ppr",
          args: __spreadProps(__spreadValues({}, options), {
            exclude: normalizedExclude.values,
            executableOnly,
            maxResults,
            mode
          }),
          success: true,
          findings,
          warnings,
          errors: []
        };
      }
    };
  }

  // src/commands/exploit.ts
  function result2(args, commands) {
    return {
      command: "exploit",
      args,
      success: true,
      findings: [{ commands }],
      warnings: [],
      errors: []
    };
  }
  function createExploitCommand() {
    return {
      name: "exploit",
      description: "Emit deterministic exploit-development command workflows.",
      usage: "dx @$osed().exploit({ mode: 'egghunter', tag: 'W00T', offset: 260 })",
      examples: [
        "dx @$osed().exploit({ mode: 'egghunter', tag: 'W00T', offset: 260 })",
        "dx @$osed().exploit({ mode: 'offset' })",
        "dx @$osed().exploit({ mode: 'badchars', address: 0x00B8F900 })"
      ],
      schema: {
        mode: { type: "string", enum: ["egghunter", "offset", "badchars"], required: true },
        tag: { type: "string" },
        offset: { type: "number" },
        address: { type: "number" }
      },
      execute(options) {
        const mode = options.mode;
        const tag = options.tag || "W00T";
        const offset = options.offset;
        const address = options.address;
        let commands = [];
        if (mode === "egghunter") {
          commands = [
            `dx @$osed().egghunter("${tag}")`
          ];
        } else if (mode === "offset") {
          commands = ["dx @$osed().pattern_create(300)", "dx @$osed().pattern_offset(<value>)"];
        } else if (mode === "badchars") {
          if (address === void 0) {
            throw new Error("exploit.badchars requires address.");
          }
          commands = [`dx @$osed().badchars(${address})`];
        } else {
          throw new Error(`Unsupported exploit mode: ${String(mode)}`);
        }
        for (const command of commands) {
          print(command);
        }
        return result2(options, commands);
      }
    };
  }

  // src/logic/pattern_scan_logic.ts
  var CYCLIC_MAX_LENGTH = 62 * 62 * 62;
  function buildHaystacks(length) {
    const requested = Number.isFinite(length) ? Math.trunc(length) : 0;
    return {
      msf: generateMsfPattern(Math.max(4, Math.min(requested, MSF_MAX_LENGTH))),
      cyclic: generateCyclicPattern(Math.max(4, Math.min(Math.max(requested, 2e4), CYCLIC_MAX_LENGTH)))
    };
  }
  function confidenceFor(haystack, needle, firstOffset) {
    return haystack.indexOf(needle, firstOffset + 1) === -1 ? "EXACT" : "CONSERVATIVE";
  }
  function matchRegisterValue(low322, haystacks) {
    const needle = decodeOffsetNeedle(low322 >>> 0);
    for (const kind of ["msf", "cyclic"]) {
      const offset = haystacks[kind].indexOf(needle);
      if (offset >= 0) {
        return { kind, offset, confidence: confidenceFor(haystacks[kind], needle, offset) };
      }
    }
    return void 0;
  }
  function bufferToLatin1(buffer) {
    let text = "";
    for (let index = 0; index < buffer.length; index += 1) {
      text += String.fromCharCode(buffer[index]);
    }
    return text;
  }
  function locatePatternInBuffer(buffer, haystacks, maxProbe = 64) {
    const text = bufferToLatin1(buffer);
    const cap = Math.min(text.length, maxProbe);
    for (const kind of ["msf", "cyclic"]) {
      const haystack = haystacks[kind];
      for (let length = cap; length >= 4; length -= 1) {
        const needle = text.slice(0, length);
        const offset = haystack.indexOf(needle);
        if (offset >= 0) {
          return { kind, offset, length, confidence: confidenceFor(haystack, needle, offset) };
        }
      }
    }
    return void 0;
  }
  function dwordAt(buffer, index) {
    if (index < 0 || index + 4 > buffer.length) {
      return void 0;
    }
    return (buffer[index] | buffer[index + 1] << 8 | buffer[index + 2] << 16 | buffer[index + 3] << 24) >>> 0;
  }

  // src/commands/findmsp.ts
  var MIN_POINTER = BigInt(65536);
  var MAX_STACK_MATCHES = 100;
  function low32(value) {
    return Number(value & BigInt(4294967295)) >>> 0;
  }
  function scanRegisters(regs, haystacks, probeBytes) {
    const matches = [];
    for (const register of regs.all) {
      const direct = matchRegisterValue(low32(register.value), haystacks);
      if (direct) {
        matches.push({
          source: register.name.toLowerCase(),
          type: "register",
          kind: direct.kind,
          offset: direct.offset,
          confidence: direct.confidence,
          detail: "register overwritten with pattern bytes"
        });
        continue;
      }
      if (register.value < MIN_POINTER) {
        continue;
      }
      const buffer = tryReadMemory(register.value, probeBytes);
      if (!buffer) {
        continue;
      }
      const located = locatePatternInBuffer(buffer, haystacks);
      if (located) {
        matches.push({
          source: register.name.toLowerCase(),
          type: "pointer",
          kind: located.kind,
          offset: located.offset,
          confidence: located.confidence,
          detail: `points into pattern (${located.length} contiguous bytes readable)`
        });
      }
    }
    return matches;
  }
  function scanStack(regs, haystacks, stackBytes) {
    var _a;
    if (regs.sp === void 0) {
      return { matches: [], truncated: false, readable: false };
    }
    const buffer = tryReadMemory(regs.sp, stackBytes);
    if (!buffer) {
      return { matches: [], truncated: false, readable: false };
    }
    const label = ((_a = regs.spName) != null ? _a : "sp").toLowerCase();
    const matches = [];
    let truncated = false;
    for (let index = 0; index + 4 <= buffer.length; index += 4) {
      const value = dwordAt(buffer, index);
      if (value === void 0) {
        continue;
      }
      const match = matchRegisterValue(value, haystacks);
      if (!match) {
        continue;
      }
      if (matches.length >= MAX_STACK_MATCHES) {
        truncated = true;
        break;
      }
      matches.push({
        source: `${label}+0x${index.toString(16)}`,
        type: "stack",
        kind: match.kind,
        offset: match.offset,
        confidence: match.confidence,
        detail: "stack slot holds pattern bytes"
      });
    }
    return { matches, truncated, readable: true };
  }
  function scanSeh(pointerSize, haystacks) {
    if (pointerSize !== 4) {
      return { matches: [] };
    }
    const teb = resolveTeb32Address(host.currentThread);
    if (!teb) {
      return { matches: [], warning: "TEB unavailable for SEH walk." };
    }
    try {
      const records = readSehRecords(teb, 3);
      const matches = [];
      records.forEach((record, index) => {
        const fields = [
          { name: "next", value: record.next },
          { name: "handler", value: record.handler }
        ];
        for (const field of fields) {
          const match = matchRegisterValue(low32(field.value), haystacks);
          if (match) {
            matches.push({
              source: `seh[${index}].${field.name}`,
              type: "seh",
              kind: match.kind,
              offset: match.offset,
              confidence: match.confidence,
              detail: "SEH record field holds pattern bytes"
            });
          }
        }
      });
      return { matches };
    } catch (error2) {
      const message = error2 instanceof Error ? error2.message : String(error2);
      return { matches: [], warning: `SEH read failed: ${message}` };
    }
  }
  function createFindMspCommand() {
    return {
      name: "findmsp",
      description: "Comprehensive cyclic-pattern offset scan across registers, the stack, SEH, and pointer targets.",
      usage: "dx @$osed().findmsp({ patternLength: 10000 })",
      examples: ["dx @$osed().findmsp()", "dx @$osed().findmsp({ patternLength: 20000, stackBytes: 4096 })"],
      schema: {
        patternLength: { type: "number", min: 256, max: 1e5, default: 1e4 },
        stackBytes: { type: "number", min: 128, max: 8192, default: 2048 },
        probeBytes: { type: "number", min: 8, max: 256, default: 32 }
      },
      execute(options) {
        var _a;
        const pointerSize = getPointerSize();
        const patternLength = options.patternLength;
        const stackBytes = options.stackBytes;
        const probeBytes = options.probeBytes;
        const haystacks = buildHaystacks(patternLength);
        const regs = readRegisters(pointerSize);
        const registerMatches = scanRegisters(regs, haystacks, probeBytes);
        const stack = scanStack(regs, haystacks, stackBytes);
        const seh = scanSeh(pointerSize, haystacks);
        const matches = [...registerMatches, ...stack.matches, ...seh.matches];
        const ipName = ((_a = regs.ipName) != null ? _a : pointerSize === 8 ? "rip" : "eip").toLowerCase();
        const ipMatch = registerMatches.find((match) => match.source === ipName && match.type === "register");
        section("INSTRUCTION POINTER");
        if (ipMatch) {
          print(`${ipName.toUpperCase()} overwritten at pattern offset ${ipMatch.offset} (${ipMatch.kind}, ${ipMatch.confidence}).`);
        } else {
          print(`${ipName.toUpperCase()} does not hold cyclic-pattern bytes.`);
        }
        section("PATTERN MATCHES");
        if (matches.length === 0) {
          print("No cyclic-pattern evidence found in registers, stack, SEH, or pointer targets.");
        } else {
          table(
            [
              { key: "source", header: "Source", width: 16 },
              { key: "type", header: "Where", width: 10 },
              { key: "offset", header: "Offset", width: 8 },
              { key: "kind", header: "Pattern", width: 8 },
              { key: "confidence", header: "Conf", width: 12 },
              { key: "detail", header: "Detail" }
            ],
            matches.map((match) => ({
              source: match.source,
              type: match.type,
              offset: `${match.offset}`,
              kind: match.kind,
              confidence: match.confidence,
              detail: match.detail
            }))
          );
        }
        const warnings = [];
        if (!stack.readable) {
          warnings.push("Stack pointer memory was not readable; stack scan skipped.");
        } else if (stack.truncated) {
          warnings.push(`Stack scan stopped after ${MAX_STACK_MATCHES} matches; increase specificity or reduce stackBytes.`);
        }
        if (seh.warning) {
          warnings.push(seh.warning);
        }
        return {
          command: "findmsp",
          args: options,
          success: true,
          findings: [
            {
              pointerSize,
              instructionPointer: {
                register: ipName,
                value: regs.ip,
                matched: ipMatch !== void 0,
                offset: ipMatch == null ? void 0 : ipMatch.offset,
                pattern: ipMatch == null ? void 0 : ipMatch.kind,
                confidence: ipMatch == null ? void 0 : ipMatch.confidence
              },
              matches,
              counts: {
                register: registerMatches.filter((match) => match.type === "register").length,
                pointer: registerMatches.filter((match) => match.type === "pointer").length,
                stack: stack.matches.length,
                seh: seh.matches.length
              }
            }
          ],
          warnings,
          errors: []
        };
      }
    };
  }

  // src/logic/pointer_filter_logic.ts
  var REGISTER_CODE = {
    eax: 0,
    ecx: 1,
    edx: 2,
    ebx: 3,
    esp: 4,
    ebp: 5,
    esi: 6,
    edi: 7,
    rax: 0,
    rcx: 1,
    rdx: 2,
    rbx: 3,
    rsp: 4,
    rbp: 5,
    rsi: 6,
    rdi: 7
  };
  function encodeJumpToRegister(kind, register) {
    const code = REGISTER_CODE[register.trim().toLowerCase()];
    if (code === void 0) {
      return void 0;
    }
    switch (kind) {
      case "jmp":
        return [255, 224 + code];
      case "call":
        return [255, 208 + code];
      case "pushret":
        return [80 + code, 195];
      default:
        return void 0;
    }
  }
  function encodeInstructionSearch(text) {
    const parts = text.trim().toLowerCase().split(/\s+/);
    if (parts.length !== 2) {
      return void 0;
    }
    const [mnemonic, register] = parts;
    if (mnemonic === "jmp" || mnemonic === "call") {
      return encodeJumpToRegister(mnemonic, register);
    }
    if (mnemonic === "pushret" || mnemonic === "push+ret") {
      return encodeJumpToRegister("pushret", register);
    }
    return void 0;
  }
  function addressToBytes(address, pointerSize) {
    const bytes = [];
    let value = address;
    for (let index = 0; index < pointerSize; index += 1) {
      bytes.push(Number(value & BigInt(255)));
      value >>= BigInt(8);
    }
    return bytes;
  }
  function addressHasBadchar(address, pointerSize, badchars) {
    if (badchars.length === 0) {
      return false;
    }
    const bad = new Set(badchars.map((value) => value & 255));
    return addressToBytes(address, pointerSize).some((byte) => bad.has(byte));
  }
  function badcharAddressFilter(badchars, pointerSize) {
    return {
      name: "badchar-free-address",
      predicate: (candidate) => !addressHasBadchar(candidate.address, pointerSize, badchars)
    };
  }
  function applyFilters(addresses, filters) {
    const kept = [];
    const rejected = [];
    for (const address of addresses) {
      const failing = filters.find((filter) => !filter.predicate({ address }));
      if (failing) {
        rejected.push({ address, failed: failing.name });
      } else {
        kept.push(address);
      }
    }
    return { kept, rejected };
  }

  // src/commands/find_ptr.ts
  function annotate(address, pointerSize) {
    const module = findModuleByAddress(address);
    if (!module) {
      return formatAddress(address, pointerSize);
    }
    return `${module.name}+0x${(address - module.base).toString(16).toUpperCase()}`;
  }
  function resolvePattern(options) {
    var _a;
    if (typeof options.instruction === "string" && options.instruction.trim().length > 0) {
      const encoded = encodeInstructionSearch(options.instruction);
      if (!encoded) {
        throw new Error(`Unrecognized instruction search '${options.instruction}'. Use e.g. 'jmp esp', 'call eax', 'pushret esp'.`);
      }
      return encoded;
    }
    const bytes = (_a = options.bytes) != null ? _a : [];
    if (bytes.length === 0 || bytes.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
      throw new Error("Provide an 'instruction' (e.g. 'jmp esp') or a non-empty 'bytes' array of 0x00..0xFF integers.");
    }
    return bytes;
  }
  function createFindPtrCommand() {
    return {
      name: "find_ptr",
      description: "Search executable memory for an instruction or byte pattern and filter surviving pointers by bad characters.",
      usage: "dx @$osed().find_ptr({ instruction: 'jmp esp', badchars: [0, 10, 13] })",
      examples: [
        "dx @$osed().find_ptr({ instruction: 'jmp esp' })",
        "dx @$osed().find_ptr({ instruction: 'call eax', module: 'essfunc', badchars: [0, 10, 13] })",
        "dx @$osed().find_ptr({ bytes: [0x58, 0x5b, 0xc3], badchars: [0] })"
      ],
      schema: {
        instruction: { type: "string" },
        bytes: { type: "array", elementType: "number", default: [] },
        module: { type: "string" },
        executableOnly: { type: "boolean", default: true },
        badchars: { type: "array", elementType: "number", default: [] },
        maxResults: { type: "number", min: 1, max: 200, default: 20 }
      },
      execute(options) {
        var _a;
        const pointerSize = getPointerSize();
        const pattern = resolvePattern(options);
        const normalizedExclude = normalizeByteArray((_a = options.badchars) != null ? _a : []);
        const maxResults = options.maxResults;
        const executableOnly = options.executableOnly !== false;
        const scanCap = Math.min(Math.max(maxResults * 5, maxResults), 200);
        const scan = scanPattern(
          {
            module: options.module,
            executableOnly,
            maxResults: scanCap,
            chunkSize: 16384
          },
          Uint8Array.from(pattern)
        );
        const filters = [badcharAddressFilter(normalizedExclude.values, pointerSize)];
        const outcome = applyFilters(scan.hits, filters);
        const kept = outcome.kept.slice(0, maxResults);
        section("Pointer Search");
        info(`Pattern: ${pattern.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ")}`);
        info(`Hits: ${scan.hits.length} scanned, ${outcome.rejected.length} rejected by bad chars, ${outcome.kept.length} surviving.`);
        if (kept.length === 0) {
          warn("No pointers survived the filter stack.");
        } else {
          table(
            [
              { key: "address", header: "Address", width: 18 },
              { key: "location", header: "Location", width: 24 },
              { key: "python", header: "Python", width: 14 }
            ],
            kept.map((hit) => ({
              address: formatAddress(hit, pointerSize),
              location: annotate(hit, pointerSize),
              python: `0x${hit.toString(16).toUpperCase()}`
            }))
          );
        }
        whyItMatters("Filtering pointers by bad characters up front prevents choosing an address the target will corrupt.");
        const warnings = scan.warnings.map((warning) => `${warning.region}: ${warning.message}`);
        if (normalizedExclude.warning) {
          warnings.push(normalizedExclude.warning);
        }
        return {
          command: "find_ptr",
          args: __spreadProps(__spreadValues({}, options), { badchars: normalizedExclude.values }),
          success: true,
          findings: [
            {
              pattern,
              badchars: normalizedExclude.values,
              filters: filters.map((filter) => filter.name),
              scanned: scan.hits.length,
              rejected: outcome.rejected.length,
              surviving: kept
            }
          ],
          warnings,
          errors: [],
          stats: scan.stats
        };
      }
    };
  }

  // src/commands/encode.ts
  var MAX_SHELLCODE_LEN = 65535;
  function buildXorStub(key2, payloadLen) {
    const k = key2 & 255;
    if (payloadLen <= 255) {
      return [
        235,
        14,
        // JMP SHORT to CALL (16)
        94,
        // POP ESI
        49,
        201,
        // XOR ECX, ECX
        177,
        payloadLen,
        // MOV CL, lo
        128,
        54,
        k,
        // XOR [ESI], key
        70,
        // INC ESI
        226,
        250,
        // LOOP xor_byte
        235,
        6,
        // JMP SHORT execute
        144,
        // NOP
        232,
        237,
        255,
        255,
        255
        // CALL decode_loop
      ];
    }
    const lo = payloadLen & 255;
    const hi = payloadLen >> 8 & 255;
    return [
      235,
      16,
      // JMP SHORT to CALL (18)
      94,
      // POP ESI
      49,
      201,
      // XOR ECX, ECX
      181,
      hi,
      // MOV CH, hi
      177,
      lo,
      // MOV CL, lo
      128,
      54,
      k,
      // XOR [ESI], key
      70,
      // INC ESI
      226,
      250,
      // LOOP xor_byte
      235,
      6,
      // JMP SHORT execute
      144,
      // NOP
      232,
      235,
      255,
      255,
      255
      // CALL decode_loop
    ];
  }
  function xorEncode(shellcode, key2) {
    return shellcode.map((b) => (b ^ key2) & 255);
  }
  function findXorKey(shellcode, exclude, hint) {
    const candidates2 = hint !== void 0 ? [hint & 255] : Array.from({ length: 255 }, (_, i) => i + 1);
    for (const key2 of candidates2) {
      if (key2 === 0 || exclude.has(key2)) continue;
      if (xorEncode(shellcode, key2).every((b) => !exclude.has(b))) return key2;
    }
    return void 0;
  }
  function parseShellcodeHex(raw) {
    if (Array.isArray(raw)) {
      return raw.map((b) => b & 255);
    }
    if (typeof raw !== "string" || !raw.trim()) {
      throw new Error("shellcode must be a non-empty hex string or byte array.");
    }
    const hex = raw.replace(/[^0-9a-fA-F]/g, "");
    if (hex.length % 2 !== 0) {
      throw new Error("shellcode hex string must have an even number of hex digits.");
    }
    const result3 = [];
    for (let i = 0; i < hex.length; i += 2) {
      result3.push(parseInt(hex.slice(i, i + 2), 16));
    }
    return result3;
  }
  function toPython(bytes) {
    return `b"${bytes.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("")}"`;
  }
  function toHex(bytes) {
    return bytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
  }
  function createEncodeCommand() {
    return {
      name: "encode",
      description: "XOR-encode shellcode to eliminate bad characters.",
      usage: `dx @$osed().encode({ shellcode: "fc e8 82 00 00 00 60...", exclude: [0, 10, 13] })`,
      examples: [
        `dx @$osed().encode({ shellcode: "fc e8 82 00 00 00 60...", exclude: [0x00, 0x0a, 0x0d] })`,
        `dx @$osed().encode({ shellcode: "fc e8...", exclude: [0, 10, 13], key: 0x41 })`
      ],
      schema: {
        shellcode: { type: "string", required: true },
        exclude: { type: "array", elementType: "number", default: [0, 10, 13] },
        key: { type: "number" }
      },
      execute(options) {
        var _a;
        const shellcode = parseShellcodeHex(options.shellcode);
        const normalizedExclude = normalizeByteArray((_a = options.exclude) != null ? _a : [0, 10, 13]);
        const exclude = new Set(normalizedExclude.values);
        const keyHint = options.key !== void 0 ? options.key & 255 : void 0;
        const warnings = [];
        if (normalizedExclude.warning) warnings.push(normalizedExclude.warning);
        if (shellcode.length === 0) {
          throw new Error("shellcode is empty.");
        }
        if (shellcode.length > MAX_SHELLCODE_LEN) {
          throw new Error(
            `Shellcode is ${shellcode.length} bytes; maximum supported is ${MAX_SHELLCODE_LEN}. Use msfvenom --encoder x86/xor_dynamic for very large payloads.`
          );
        }
        const key2 = findXorKey(shellcode, exclude, keyHint);
        if (key2 === void 0) {
          throw new Error(
            keyHint !== void 0 ? `Key 0x${keyHint.toString(16).toUpperCase().padStart(2, "0")} produces bad characters in the encoded output.` : `No XOR key in 0x01..0xFF eliminates all bad characters. Consider a different encoder or revising the bad character list.`
          );
        }
        const encoded = xorEncode(shellcode, key2);
        const stub = buildXorStub(key2, shellcode.length);
        const combined = [...stub, ...encoded];
        const badStubBytes = stub.map((b, i) => ({ b, i })).filter(({ b }) => exclude.has(b));
        if (badStubBytes.length > 0) {
          const detail = badStubBytes.map(({ b, i }) => `0x${b.toString(16).toUpperCase().padStart(2, "0")} at stub[${i}]`).join(", ");
          warnings.push(
            `Decoder stub contains bad byte(s): ${detail}. The stub will be corrupted when delivered through the vulnerable buffer.`
          );
        }
        section("XOR Encoder");
        info(`Key:              0x${key2.toString(16).toUpperCase().padStart(2, "0")}`);
        info(`Shellcode length: ${shellcode.length} bytes`);
        info(`Stub size:        ${stub.length} bytes`);
        info(`Total payload:    ${combined.length} bytes`);
        section("Decoder Stub (hex)");
        print(toHex(stub));
        section("Encoded Shellcode (hex)");
        print(toHex(encoded));
        section("Combined Payload (Python)");
        print(toPython(combined));
        if (warnings.length > 0) {
          section("Warnings");
          for (const warning of warnings) {
            warn(warning);
          }
        }
        whyItMatters("XOR encoding transforms each shellcode byte to avoid characters that corrupt the delivery buffer.");
        return {
          command: "encode",
          args: options,
          success: true,
          findings: [
            {
              key: key2,
              keyHex: `0x${key2.toString(16).toUpperCase().padStart(2, "0")}`,
              stubSize: stub.length,
              encodedSize: encoded.length,
              totalSize: combined.length,
              stub,
              encoded,
              combined
            }
          ],
          warnings,
          errors: []
        };
      }
    };
  }

  // src/commands/nop.ts
  function createNopCommand() {
    return {
      name: "nop",
      description: "Generate a NOP sled of N bytes.",
      usage: "dx @$osed().nop(16)",
      examples: [
        "dx @$osed().nop(16)",
        "dx @$osed().nop({ length: 32 })",
        "dx @$osed().nop({ length: 16, byte: 0x90 })"
      ],
      schema: {
        length: { type: "number", min: 1, max: 4096, required: true },
        byte: { type: "number", default: 144 }
      },
      execute(options) {
        var _a;
        const length = options.length;
        const nopByte = ((_a = options.byte) != null ? _a : 144) & 255;
        const sled = Array.from({ length }, () => nopByte);
        const hexStr = sled.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
        const python = `b"${sled.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("")}"`;
        section("NOP Sled");
        info(`Length: ${length} bytes  Byte: 0x${nopByte.toString(16).toUpperCase().padStart(2, "0")}`);
        print(hexStr);
        print(python);
        whyItMatters("A NOP sled gives the exploit a landing zone \u2014 small ESP variations still slide into shellcode.");
        return {
          command: "nop",
          args: options,
          success: true,
          findings: [{ length, byte: nopByte, sled }],
          warnings: [],
          errors: []
        };
      }
    };
  }

  // src/commands/rop_template.ts
  function vpTemplate(mod) {
    section("VirtualProtect DEP Bypass \u2014 ROP Chain Skeleton");
    print("Prototype: BOOL VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)");
    print("Goal:      mark shellcode region PAGE_EXECUTE_READWRITE (flNewProtect = 0x40)");
    section("Step 1 \u2014 find addresses");
    print(`  VirtualProtect addr:   dx @$osed().sc.iat_find("VirtualProtect")`);
    print(`  jmp esp (dispatch):    dx @$osed().find_bytes({ module: "${mod}", bytes: [0xFF, 0xE4] })`);
    print(`  pushad ; ret:          dx @$osed().find_bytes({ module: "${mod}", bytes: [0x60, 0xC3] })`);
    print(`  Gadgets (pop/inc/neg): dx @$osed().rop_suggest({ module: "${mod}", engine: "semantic" })`);
    print(`  Stack adjustments:     dx @$osed().add_esp({ module: "${mod}" })`);
    print(`  Writable addr:         dx @$osed().modules()  -- pick a .data section address`);
    section("Step 2 \u2014 PUSHAD technique register map");
    print("  After PUSHAD ; RET, the stack looks like:");
    print("    [ESP+0]  = EDI  <- consumed by RET (set to VirtualProtect address)");
    print("    [ESP+4]  = ESI  <- return addr for VP's RETN 10h (set to jmp esp)");
    print("    [ESP+8]  = EBP  <- lpAddress  (set to shellcode start)");
    print("    [ESP+12] = saved_ESP <- dwSize (stack addr \u2014 rounds up, usually OK)");
    print("    [ESP+16] = EBX  <- flNewProtect = 0x40");
    print("    [ESP+20] = EDX  <- lpflOldProtect (writable dummy)");
    print("    [ESP+24] = ECX  <- (unused by VirtualProtect)");
    print("    [ESP+28] = EAX  <- (unused by VirtualProtect)");
    section("Step 3 \u2014 Python skeleton");
    print("import struct");
    print("def p32(v): return struct.pack('<I', v)");
    print("");
    print("OFFSET   = ???           # bytes from buffer start to EIP control");
    print('VP       = 0x????????    # VirtualProtect  dx @$osed().sc.iat_find("VirtualProtect")');
    print("JMP_ESP  = 0x????????    # jmp esp         dx @$osed().find_bytes({bytes:[0xFF,0xE4]})");
    print("WRITABLE = 0x????????    # writable addr   dx @$osed().modules() -> .data section");
    print("LP_ADDR  = 0x????????    # shellcode addr  compute from ESP (see step 4)");
    print("");
    print('rop_chain = b""');
    print("");
    print("# \u2500\u2500 Register setup (PUSHAD technique) \u2500\u2500");
    print("rop_chain += p32(0x????????)  # pop edi ; ret");
    print("rop_chain += p32(VP)          # EDI = VirtualProtect address");
    print("");
    print("rop_chain += p32(0x????????)  # pop esi ; ret");
    print("rop_chain += p32(JMP_ESP)     # ESI = jmp esp (return to shellcode after VP)");
    print("");
    print("rop_chain += p32(0x????????)  # pop ebp ; ret");
    print("rop_chain += p32(LP_ADDR)     # EBP = lpAddress (shellcode start, see step 4)");
    print("");
    print("rop_chain += p32(0x????????)  # pop ebx ; ret");
    print("rop_chain += p32(0x00000040)  # EBX = flNewProtect (PAGE_EXECUTE_READWRITE)");
    print("");
    print("rop_chain += p32(0x????????)  # pop edx ; ret");
    print("rop_chain += p32(WRITABLE)    # EDX = lpflOldProtect dummy");
    print("");
    print("rop_chain += p32(0x????????)  # pop ecx ; ret  (ECX unused \u2014 any writable value)");
    print("rop_chain += p32(WRITABLE)");
    print("");
    print("rop_chain += p32(0x????????)  # pop eax ; ret  (EAX unused \u2014 put 0 or junk)");
    print("rop_chain += p32(0x90909090)");
    print("");
    print("rop_chain += p32(0x????????)  # pushad ; ret");
    print("                               #   dx @$osed().find_bytes({bytes:[0x60,0xC3]})");
    print("");
    print("# \u2500\u2500 NOP sled + shellcode \u2500\u2500");
    print('nop_sled  = b"\\x90" * 16    # dx @$osed().nop(16)');
    print('shellcode = nop_sled + b"\\xfc\\xe8..."  # your payload');
    print('                               # dx @$osed().encode({shellcode:"...",exclude:[0,10,13]})');
    print("");
    print('payload = b"A" * OFFSET + rop_chain + shellcode');
    section("Step 4 \u2014 compute LP_ADDR (shellcode stack address)");
    print("  The PUSHAD technique uses the saved ESP (stack addr before PUSHAD) as dwSize.");
    print("  To find LP_ADDR (EBP = shellcode location on stack):");
    print("  1. Run exploit with 'CC' shellcode; check EBP at VirtualProtect breakpoint.");
    print("  2. Or: prepend gadgets to capture ESP and add the chain-to-shellcode offset:");
    print("       dx @$osed().rop_suggest(...)  ->  push esp ; pop eax ; ret");
    print("       dx @$osed().add_esp(...)      ->  add eax, N ; ret   (N = measured offset)");
    print("     Then use a  mov [writable], eax ; ret  gadget and patch EBP from that addr.");
  }
  function wpmTemplate(mod) {
    section("WriteProcessMemory DEP Bypass \u2014 ROP Chain Skeleton");
    print("Prototype: BOOL WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpBytesWritten)");
    print("Goal:      copy shellcode into a known-executable .text section, then jump to it.");
    section("Find addresses");
    print(`  WriteProcessMemory:  dx @$osed().sc.iat_find("WriteProcessMemory")`);
    print(`  Writable addr:       dx @$osed().modules()  -- any .data section`);
    print(`  Executable target:   dx @$osed().modules()  -- any .text section address`);
    print(`  Gadgets:             dx @$osed().rop_suggest({ module: "${mod}", engine: "semantic" })`);
    section("Python skeleton");
    print("import struct");
    print("def p32(v): return struct.pack('<I', v)");
    print("");
    print("OFFSET      = ???          # EIP control offset");
    print("WPM         = 0x????????   # WriteProcessMemory  dx @$osed().sc.iat_find(...)");
    print("EXEC_TARGET = 0x????????   # executable .text address to write shellcode into");
    print("WRITABLE    = 0x????????   # .data writable addr");
    print("SC_SRC      = 0x????????   # shellcode source (stack addr \u2014 compute dynamically)");
    print("");
    print("# PUSHAD register map for WriteProcessMemory(hProcess, lpBase, lpBuf, nSize, lpWritten):");
    print("#   EDI = WPM            ESI = return addr   EBP = hProcess (0xFFFFFFFF = current)");
    print("#   EBX = lpBaseAddress  EDX = lpBuffer      ECX = nSize    EAX = lpBytesWritten");
    print("");
    print('rop_chain = b""');
    print("rop_chain += p32(0x????????)  # pop edi ; ret");
    print("rop_chain += p32(WPM)");
    print("rop_chain += p32(0x????????)  # pop esi ; ret");
    print("rop_chain += p32(0x????????)  # return addr after WPM (jmp to EXEC_TARGET)");
    print("rop_chain += p32(0x????????)  # pop ebp ; ret");
    print("rop_chain += p32(0xFFFFFFFF)  # hProcess = GetCurrentProcess()");
    print("rop_chain += p32(0x????????)  # pop ebx ; ret");
    print("rop_chain += p32(EXEC_TARGET) # lpBaseAddress");
    print("rop_chain += p32(0x????????)  # pop edx ; ret");
    print("rop_chain += p32(SC_SRC)      # lpBuffer (shellcode source on stack)");
    print("rop_chain += p32(0x????????)  # pop ecx ; ret");
    print("rop_chain += p32(0x00000201)  # nSize");
    print("rop_chain += p32(0x????????)  # pop eax ; ret");
    print("rop_chain += p32(WRITABLE)    # lpBytesWritten (dummy writable)");
    print("rop_chain += p32(0x????????)  # pushad ; ret");
    print("");
    print('shellcode = b"\\x90" * 16 + b"\\xfc\\xe8..."');
    print('payload   = b"A" * OFFSET + rop_chain + shellcode');
  }
  function createRopTemplateCommand() {
    return {
      name: "rop_template",
      description: "Print a commented VirtualProtect or WriteProcessMemory ROP chain skeleton.",
      usage: "dx @$osed().rop_template({ api: 'VirtualProtect', module: 'essfunc' })",
      examples: [
        "dx @$osed().rop_template({ api: 'VirtualProtect', module: 'essfunc' })",
        "dx @$osed().rop_template({ api: 'WriteProcessMemory', module: 'essfunc' })"
      ],
      schema: {
        api: { type: "string", enum: ["VirtualProtect", "WriteProcessMemory"], default: "VirtualProtect" },
        module: { type: "string", default: "TARGET_MODULE" }
      },
      execute(options) {
        var _a, _b;
        const api = (_a = options.api) != null ? _a : "VirtualProtect";
        const mod = (_b = options.module) != null ? _b : "TARGET_MODULE";
        if (api === "WriteProcessMemory") {
          wpmTemplate(mod);
        } else {
          vpTemplate(mod);
        }
        return {
          command: "rop_template",
          args: options,
          success: true,
          findings: [{ api, module: mod }],
          warnings: [],
          errors: []
        };
      }
    };
  }

  // src/logic/fmtstr_logic.ts
  var WIDTHS = {
    byte: { bytes: 1, mask: 255, mod: 256, spec: "hhn" },
    word: { bytes: 2, mask: 65535, mod: 65536, spec: "hn" },
    dword: { bytes: 4, mask: 4294967295, mod: 4294967296, spec: "n" }
  };
  var PAD_WARN_THRESHOLD = 65536;
  function parseU32(value) {
    if (typeof value === "number" && Number.isFinite(value)) {
      return value >>> 0;
    }
    if (typeof value === "string") {
      const text = value.trim();
      if (/^0x[0-9a-fA-F]+$/.test(text)) {
        return Number.parseInt(text, 16) >>> 0;
      }
      if (/^[0-9a-fA-F]+$/.test(text) && /[a-fA-F]/.test(text)) {
        return Number.parseInt(text, 16) >>> 0;
      }
      if (/^[0-9]+$/.test(text)) {
        return Number.parseInt(text, 10) >>> 0;
      }
    }
    throw new Error(`Cannot parse "${String(value)}" as a 32-bit value.`);
  }
  function dwordLE(value) {
    return [value & 255, value >>> 8 & 255, value >>> 16 & 255, value >>> 24 & 255];
  }
  function buildFormatString(options) {
    var _a, _b, _c;
    const width = (_a = options.width) != null ? _a : "word";
    const spec = WIDTHS[width];
    const prefix = (_b = options.prefix) != null ? _b : 0;
    const exclude = new Set(((_c = options.exclude) != null ? _c : []).map((b) => b & 255));
    const warnings = [];
    if (!Number.isInteger(options.argIndex) || options.argIndex < 1) {
      throw new Error("argIndex must be a positive integer (the positional %N$ index of the first buffer dword).");
    }
    if (options.writes.length === 0) {
      throw new Error("writes must contain at least one { addr, value } pair.");
    }
    const chunksPerWrite = 4 / spec.bytes;
    const entries = [];
    for (const write2 of options.writes) {
      const addr = write2.addr >>> 0;
      const value = write2.value >>> 0;
      for (let c = 0; c < chunksPerWrite; c += 1) {
        const shift = c * spec.bytes * 8;
        const chunkVal = width === "dword" ? value >>> 0 : value >>> shift & spec.mask;
        entries.push({ targetAddr: addr + c * spec.bytes >>> 0, chunkVal });
      }
    }
    entries.sort((a, b) => a.chunkVal - b.chunkVal);
    const addressDwords = entries.map((entry) => entry.targetAddr);
    const addressBlock = addressDwords.flatMap(dwordLE);
    const addressBlockLen = addressBlock.length;
    let runningCount = prefix + addressBlockLen >>> 0;
    const rows = [];
    let formatString = "";
    entries.forEach((entry, i) => {
      const arg = options.argIndex + i;
      const current = runningCount % spec.mod;
      const pad2 = (entry.chunkVal - current + spec.mod) % spec.mod;
      if (pad2 > PAD_WARN_THRESHOLD) {
        warnings.push(
          `Chunk ${i} needs ${pad2} padding bytes (target 0x${entry.chunkVal.toString(16)}). Consider a narrower width to shrink the payload.`
        );
      }
      const fragment = (pad2 > 0 ? `%${pad2}c` : "") + `%${arg}$${spec.spec}`;
      formatString += fragment;
      runningCount += pad2;
      const written = runningCount % spec.mod;
      if (written !== entry.chunkVal) {
        throw new Error(`Internal error: chunk ${i} would write 0x${written.toString(16)}, expected 0x${entry.chunkVal.toString(16)}.`);
      }
      rows.push({
        chunk: i,
        targetAddr: entry.targetAddr,
        value: entry.chunkVal,
        arg,
        cumCount: runningCount,
        specifier: fragment
      });
    });
    for (const write2 of options.writes) {
      for (const b of dwordLE(write2.addr >>> 0)) {
        if (exclude.has(b)) {
          warnings.push(`Target address 0x${(write2.addr >>> 0).toString(16).toUpperCase().padStart(8, "0")} contains badchar 0x${b.toString(16).padStart(2, "0")} \u2014 cannot be delivered as-is.`);
          break;
        }
      }
    }
    const formatBytes = [...formatString].map((ch) => ch.charCodeAt(0));
    for (const b of formatBytes) {
      if (exclude.has(b)) {
        warnings.push(`Format string contains badchar 0x${b.toString(16).padStart(2, "0")} (character "${String.fromCharCode(b)}").`);
        break;
      }
    }
    return {
      addressBlock,
      addressDwords,
      formatString,
      payload: [...addressBlock, ...formatBytes],
      rows,
      warnings
    };
  }

  // src/commands/fmtstr.ts
  function hexByte2(value) {
    return value.toString(16).toUpperCase().padStart(2, "0");
  }
  function toPythonBytes(bytes) {
    return `b"${bytes.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("")}"`;
  }
  function isPrintableAscii(bytes) {
    return bytes.every((b) => b >= 32 && b <= 126);
  }
  function parseWrites(raw) {
    if (!Array.isArray(raw)) {
      if (raw && typeof raw === "object") {
        return parseWrites([raw]);
      }
      throw new Error("writes must be an array of { addr, value } pairs.");
    }
    return raw.map((entry, i) => {
      if (!entry || typeof entry !== "object") {
        throw new Error(`writes[${i}] must be an object with addr and value.`);
      }
      const record = entry;
      if (record.addr === void 0 || record.value === void 0) {
        throw new Error(`writes[${i}] requires both addr and value.`);
      }
      return { addr: parseU32(record.addr), value: parseU32(record.value) };
    });
  }
  function normalizeWidth(value) {
    if (value === "byte" || value === "word" || value === "dword") {
      return value;
    }
    return "word";
  }
  function createFmtBuildCommand() {
    return {
      name: "fmt_build",
      description: "Build a format-string %n write-what-where payload.",
      usage: `dx @$osed().fmt.build({ writes: [{ addr: 0x00402118, value: 0x625011AF }], argIndex: 6 })`,
      examples: [
        `dx @$osed().fmt.build({ writes: [{ addr: 0x00402118, value: 0x625011AF }], argIndex: 6 })`,
        `dx @$osed().fmt.build({ writes: [{ addr: 0x00402118, value: 0x625011AF }], argIndex: 6, width: "word", exclude: [0,10,13] })`
      ],
      schema: {
        writes: { type: ["array", "object"], required: true },
        argIndex: { type: "number", min: 1, required: true },
        width: { type: "string", enum: ["byte", "word", "dword"], default: "word" },
        exclude: { type: "array", elementType: "number", default: [0, 10, 13] },
        prefix: { type: "number", min: 0, default: 0 }
      },
      execute(options) {
        var _a, _b;
        const writes = parseWrites(options.writes);
        const argIndex = options.argIndex;
        const width = normalizeWidth(options.width);
        const normalizedExclude = normalizeByteArray((_a = options.exclude) != null ? _a : [0, 10, 13]);
        const prefix = (_b = options.prefix) != null ? _b : 0;
        const result3 = buildFormatString({
          writes,
          argIndex,
          width,
          exclude: normalizedExclude.values,
          prefix
        });
        const warnings = [...result3.warnings];
        if (normalizedExclude.warning) {
          warnings.push(normalizedExclude.warning);
        }
        section("Format String Builder");
        info(`Writes:   ${writes.length} (${width}-granularity, ${result3.rows.length} chunks)`);
        info(`ArgIndex: ${argIndex}  Prefix: ${prefix}`);
        section("Chunk breakdown");
        table(
          [
            { key: "chunk", header: "Chunk", width: 6 },
            { key: "addr", header: "TargetAddr", width: 12 },
            { key: "value", header: "Value", width: 8 },
            { key: "arg", header: "Arg", width: 5 },
            { key: "count", header: "CumCount", width: 10 },
            { key: "spec", header: "Specifier", width: 18 }
          ],
          result3.rows.map((row) => ({
            chunk: `${row.chunk}`,
            addr: `0x${row.targetAddr.toString(16).toUpperCase().padStart(8, "0")}`,
            value: `0x${row.value.toString(16).toUpperCase()}`,
            arg: `${row.arg}`,
            count: `${row.cumCount}`,
            spec: row.specifier
          }))
        );
        section("Address block");
        for (let i = 0; i < result3.addressDwords.length; i += 1) {
          const dword = result3.addressDwords[i];
          const bytes = result3.addressBlock.slice(i * 4, i * 4 + 4).map(hexByte2).join(" ");
          print(`  ${bytes}    ; slot ${i} -> %${argIndex + i}$  (0x${dword.toString(16).toUpperCase().padStart(8, "0")})`);
        }
        section("Format string");
        print(result3.formatString);
        section("Python");
        print("def p32(v): return struct.pack('<I', v)");
        print("payload = (");
        for (const dword of result3.addressDwords) {
          print(`    p32(0x${dword.toString(16).toUpperCase().padStart(8, "0")}) +`);
        }
        const fmtBytes = [...result3.formatString].map((ch) => ch.charCodeAt(0));
        const fmtLiteral = isPrintableAscii(fmtBytes) ? `b"${result3.formatString.replace(/"/g, '\\"')}"` : toPythonBytes(fmtBytes);
        print(`    ${fmtLiteral}`);
        print(")");
        section("Payload (hex)");
        print(result3.payload.map(hexByte2).join(" "));
        if (warnings.length > 0) {
          section("Warnings");
          for (const warning of warnings) {
            warn(warning);
          }
        }
        whyItMatters("Format-string %n writes are pure arithmetic on the printed-byte count \u2014 automating it removes the most error-prone hand calculation in the module.");
        return {
          command: "fmt_build",
          args: options,
          success: true,
          findings: [
            {
              width,
              argIndex,
              prefix,
              addressDwords: result3.addressDwords,
              formatString: result3.formatString,
              payload: result3.payload,
              rows: result3.rows
            }
          ],
          warnings,
          errors: []
        };
      }
    };
  }
  function readStackPointer(pointerSize) {
    var _a, _b;
    const thread = host.currentThread;
    const regsRoot = (_a = thread == null ? void 0 : thread.Registers) != null ? _a : void 0;
    const userRegs = (_b = regsRoot == null ? void 0 : regsRoot.User) != null ? _b : regsRoot;
    if (!userRegs) {
      return void 0;
    }
    const name = pointerSize === 8 ? "rsp" : "esp";
    for (const key2 of Object.keys(userRegs)) {
      if (key2.toLowerCase() === name || key2.toLowerCase() === (pointerSize === 8 ? "esp" : "rsp")) {
        try {
          const value = userRegs[key2];
          if (typeof value === "bigint") return value;
          if (typeof value === "number") return BigInt(value);
          const parsed = BigInt(String(value));
          return parsed;
        } catch (_error) {
          return void 0;
        }
      }
    }
    return void 0;
  }
  function stackBounds(pointerSize) {
    var _a;
    if (pointerSize !== 4) {
      return {};
    }
    const thread = host.currentThread;
    let teb;
    const raw = (_a = thread == null ? void 0 : thread.Teb) != null ? _a : thread == null ? void 0 : thread.TebAddress;
    try {
      if (typeof raw === "bigint") teb = raw;
      else if (typeof raw === "number") teb = BigInt(raw);
      else if (raw !== void 0) teb = BigInt(String(raw));
    } catch (_error) {
      teb = void 0;
    }
    if (teb === void 0) {
      return {};
    }
    try {
      const base = readPointer(teb + BigInt(4), 4);
      const limit = readPointer(teb + BigInt(8), 4);
      return { base, limit };
    } catch (_error) {
      return {};
    }
  }
  function classify(value, marker, bounds, sp) {
    if ((value & BigInt(4294967295)) === BigInt(marker >>> 0)) {
      return "marker";
    }
    const module = findModuleByAddress(value);
    if (module) {
      return `ptr->${module.name}`;
    }
    if (bounds.base !== void 0 && bounds.limit !== void 0 && value >= bounds.limit && value < bounds.base) {
      return "ptr->stack";
    }
    if (bounds.base === void 0 && sp !== void 0) {
      const delta = value > sp ? value - sp : sp - value;
      if (delta < BigInt(1048576)) {
        return "ptr->stack";
      }
    }
    if (tryReadMemory(value, 4)) {
      return "ptr->readable";
    }
    return "";
  }
  function createFmtOffsetCommand() {
    return {
      name: "fmt_offset",
      description: "Locate the controlled parameter index and leakable pointers on the stack at a printf-family call.",
      usage: "dx @$osed().fmt.offset(0x41414141, 40, 8)",
      examples: [
        "dx @$osed().fmt.offset()",
        "dx @$osed().fmt.offset(0x41414141, 40)",
        "dx @$osed().fmt.offset({ marker: 0x41414141, count: 40, firstArg: 8 })"
      ],
      schema: {
        marker: { type: "number", default: 1094795585 },
        count: { type: "number", min: 1, max: 256, default: 40 },
        firstArg: { type: "number", min: 0, default: 8 }
      },
      execute(options) {
        var _a, _b, _c;
        const pointerSize = getPointerSize();
        const marker = ((_a = options.marker) != null ? _a : 1094795585) >>> 0;
        const count = (_b = options.count) != null ? _b : 40;
        const firstArg = (_c = options.firstArg) != null ? _c : 8;
        const warnings = [];
        if (pointerSize !== 4) {
          warnings.push("fmt.offset parameter mapping is calibrated for x86 (cdecl) printf-family calls.");
        }
        const sp = readStackPointer(pointerSize);
        if (sp === void 0) {
          return {
            command: "fmt_offset",
            args: options,
            success: false,
            findings: [],
            warnings,
            errors: ["Stack pointer unavailable \u2014 is the target broken in?"]
          };
        }
        const bounds = stackBounds(pointerSize);
        const base = sp + BigInt(firstArg);
        const rows = [];
        let markerIndex;
        for (let i = 0; i < count; i += 1) {
          const stackAddr = base + BigInt(i * 4);
          const cell = tryReadMemory(stackAddr, 4);
          if (!cell) {
            warnings.push(`Stack read failed at ${formatAddress(stackAddr, pointerSize)}; stopping scan.`);
            break;
          }
          const value = BigInt(cell[0] | cell[1] << 8 | cell[2] << 16 | cell[3] << 24) & BigInt(4294967295);
          const meaning = classify(value, marker, bounds, sp);
          const idx = i + 1;
          if (meaning === "marker" && markerIndex === void 0) {
            markerIndex = idx;
          }
          rows.push({ idx, stackAddr, value, meaning });
        }
        section("Format String Parameter Map");
        info(`${pointerSize === 8 ? "RSP" : "ESP"}: ${formatAddress(sp, pointerSize)}  firstArg: +${firstArg}  marker: 0x${marker.toString(16).toUpperCase().padStart(8, "0")}`);
        info(markerIndex !== void 0 ? `Controlled parameter index: %${markerIndex}$  (use argIndex ${markerIndex} in fmt.build)` : "Marker not found in scanned range \u2014 adjust firstArg/count or check the buffer.");
        table(
          [
            { key: "idx", header: "Idx", width: 5 },
            { key: "stackAddr", header: "StackAddr", width: 12 },
            { key: "value", header: "Value", width: 12 },
            { key: "meaning", header: "Meaning", width: 18 }
          ],
          rows.map((row) => ({
            idx: `%${row.idx}$`,
            stackAddr: formatAddress(row.stackAddr, pointerSize),
            value: `0x${row.value.toString(16).toUpperCase().padStart(8, "0")}`,
            meaning: row.meaning || "-"
          }))
        );
        whyItMatters("Format-string exploitation hinges on knowing which parameter index reaches your buffer and which stack slots leak module/stack pointers for ASLR defeat.");
        return {
          command: "fmt_offset",
          args: options,
          success: true,
          findings: [{ markerIndex, esp: sp, firstArg, marker, slots: rows }],
          warnings,
          errors: []
        };
      }
    };
  }
  function createFmtCommands() {
    return [createFmtBuildCommand(), createFmtOffsetCommand()];
  }

  // src/core/dx_result.ts
  var DxRow = class {
    constructor(values) {
      for (const [key2, value] of Object.entries(values)) {
        this[key2] = value;
      }
    }
    toString() {
      const pairs = Object.entries(this).filter(([, value]) => typeof value === "string");
      return pairs.map(([key2, value]) => `${key2}: ${stripDml(value)}`).join(" | ");
    }
  };
  var DxRows = class {
    constructor(title, values) {
      Object.defineProperty(this, "title", {
        value: title,
        enumerable: false,
        configurable: false,
        writable: false
      });
      Object.defineProperty(this, "values", {
        value: values,
        enumerable: false,
        configurable: false,
        writable: false
      });
      this.length = values.length;
      values.forEach((row, index) => {
        Object.defineProperty(this, index, {
          value: row,
          enumerable: false,
          configurable: false,
          writable: false
        });
      });
    }
    [Symbol.iterator]() {
      return this.values[Symbol.iterator]();
    }
    map(callback) {
      return this.values.map(callback);
    }
    forEach(callback) {
      this.values.forEach(callback);
    }
    slice(start, end) {
      return this.values.slice(start, end);
    }
    toArray() {
      return [...this.values];
    }
    toString() {
      return `${this.title}: ${this.length} row${this.length === 1 ? "" : "s"}; expand rows[N] for details`;
    }
  };
  var DxResult = class {
    constructor(title, rows) {
      this.title = title;
      this.rows = new DxRows(title, rows.map((row) => new DxRow(row)));
      this.length = this.rows.length;
    }
    toString() {
      return `${this.title}: ${this.length} row${this.length === 1 ? "" : "s"}`;
    }
  };
  function toDxResult(title, rows) {
    return new DxResult(title, rows);
  }

  // src/shellcode/index.ts
  var MetasploitRor13Provider = class {
    constructor() {
      this.algorithm = "metasploit_ror13";
      this.aliases = ["ror13", "msf_ror13"];
      this.description = "Classic Metasploit-style API hash: ROR 13 then add byte.";
    }
    ror32(value, bits) {
      const shift = bits & 31;
      return (value >>> shift | value << 32 - shift) >>> 0;
    }
    hash(text) {
      let hash = 0;
      for (const byte of asciiBytes(text)) {
        hash = this.ror32(hash, 13);
        hash = hash + byte >>> 0;
      }
      return hash >>> 0;
    }
  };
  var HashResolver = class {
    constructor(providers) {
      this.defaultAlias = "ror13";
      var _a;
      const configured = providers != null ? providers : [
        new MetasploitRor13Provider(),
        new Crc32Provider(),
        new Rol7AddProvider()
      ];
      this.canonicalProviders = configured;
      this.providers = /* @__PURE__ */ new Map();
      for (const provider of configured) {
        this.providers.set(provider.algorithm.toLowerCase(), provider);
        for (const alias of (_a = provider.aliases) != null ? _a : []) {
          this.providers.set(alias.toLowerCase(), provider);
        }
      }
    }
    compute(exportsList, algorithm) {
      const provider = this.resolveProvider(algorithm);
      if (!provider) {
        throw new Error(`Unknown hash algorithm "${algorithm}". Supported: ${this.supportedAlgorithms().join(", ")}.`);
      }
      const label = this.displayName(provider);
      return exportsList.filter((entry) => entry.name.length > 0).map((entry) => ({
        Algorithm: label,
        Hash: `0x${provider.hash(entry.name).toString(16).toUpperCase().padStart(8, "0")}`,
        Name: entry.name,
        Address: toDmlAddress(entry.va, "u")
      })).sort((a, b) => a.Name.localeCompare(b.Name));
    }
    hashValue(text, algorithm) {
      const provider = this.resolveProvider(algorithm);
      if (!provider) {
        throw new Error(`Unknown hash algorithm "${algorithm}". Supported: ${this.supportedAlgorithms().join(", ")}.`);
      }
      return {
        Input: text,
        Algorithm: this.displayName(provider),
        Hash: `0x${provider.hash(text).toString(16).toUpperCase().padStart(8, "0")}`
      };
    }
    listAlgorithms() {
      const defaultProvider = this.resolveProvider(this.defaultAlias);
      return this.canonicalProviders.map((provider) => {
        var _a;
        return {
          Algorithm: provider.algorithm,
          Aliases: ((_a = provider.aliases) != null ? _a : []).join(", "),
          Description: provider.description,
          Default: provider === defaultProvider ? "yes" : "no"
        };
      }).sort((a, b) => a.Algorithm.localeCompare(b.Algorithm));
    }
    supportedAlgorithms() {
      return Array.from(this.providers.keys()).sort();
    }
    resolveProvider(algorithm) {
      const selected = (algorithm != null ? algorithm : this.defaultAlias).trim().toLowerCase();
      return this.providers.get(selected);
    }
    displayName(provider) {
      return provider.aliases && provider.aliases.length > 0 ? provider.aliases[0].toUpperCase() : provider.algorithm;
    }
  };
  var Crc32Provider = class {
    constructor() {
      this.algorithm = "crc32";
      this.description = "CRC32 (IEEE polynomial 0xEDB88320) over ASCII bytes.";
      this.table = this.buildTable();
    }
    hash(text) {
      let crc = 4294967295;
      for (const byte of asciiBytes(text)) {
        const index = (crc ^ byte) & 255;
        crc = crc >>> 8 ^ this.table[index];
      }
      return (crc ^ 4294967295) >>> 0;
    }
    buildTable() {
      const table2 = [];
      for (let i = 0; i < 256; i += 1) {
        let value = i;
        for (let bit = 0; bit < 8; bit += 1) {
          if ((value & 1) === 1) {
            value = value >>> 1 ^ 3988292384;
          } else {
            value >>>= 1;
          }
        }
        table2.push(value >>> 0);
      }
      return table2;
    }
  };
  var Rol7AddProvider = class {
    constructor() {
      this.algorithm = "rol7_add";
      this.aliases = ["rol7"];
      this.description = "Rotate-left by 7 then add byte (32-bit accumulator).";
    }
    rol32(value, bits) {
      const shift = bits & 31;
      return (value << shift | value >>> 32 - shift) >>> 0;
    }
    hash(text) {
      let hash = 0;
      for (const byte of asciiBytes(text)) {
        hash = this.rol32(hash, 7);
        hash = hash + byte >>> 0;
      }
      return hash >>> 0;
    }
  };
  function asciiBytes(text) {
    const bytes = [];
    for (let i = 0; i < text.length; i += 1) {
      const code = text.charCodeAt(i);
      if (code > 127) {
        throw new Error("Hash input must be ASCII for shellforge parity.");
      }
      bytes.push(code & 255);
    }
    return bytes;
  }
  var PEParser = class {
    constructor(pointerSize) {
      this.pointerSize = pointerSize;
    }
    parseHeaders(module) {
      const base = module.base;
      const mz = readUint16LE(base);
      if (mz !== 23117) {
        throw new Error(`Invalid DOS header for ${module.name}.`);
      }
      const eLfanew = readUint32LE(base + BigInt(60));
      const ntHeader = base + BigInt(eLfanew);
      const signature = readUint32LE(ntHeader);
      if (signature !== 17744) {
        throw new Error(`Invalid NT header signature for ${module.name}.`);
      }
      const machine = readUint16LE(ntHeader + BigInt(4));
      const optionalHeader = ntHeader + BigInt(24);
      const optionalHeaderMagic = readUint16LE(optionalHeader);
      const isPe32Plus = optionalHeaderMagic === 523;
      if (!isPe32Plus && optionalHeaderMagic !== 267) {
        throw new Error(`Unsupported optional header magic 0x${optionalHeaderMagic.toString(16)}.`);
      }
      const entryPointRva = readUint32LE(optionalHeader + BigInt(16));
      const imageBase = isPe32Plus ? readPointer(optionalHeader + BigInt(24), 8) : BigInt(readUint32LE(optionalHeader + BigInt(28)));
      const sizeOfImage = readUint32LE(optionalHeader + BigInt(56));
      const dataDirectoryOffset = optionalHeader + BigInt(isPe32Plus ? 112 : 96);
      const exportDirectoryRva = readUint32LE(dataDirectoryOffset);
      const exportDirectorySize = readUint32LE(dataDirectoryOffset + BigInt(4));
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
        exportDirectorySize
      };
    }
    parseExports(module) {
      var _a;
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
      const namesByIndex = /* @__PURE__ */ new Map();
      for (let i = 0; i < exportInfo.numberOfNames; i += 1) {
        const nameRva = readUint32LE(namesVa + BigInt(i * 4));
        const ordinalIndex = readUint16LE(ordinalsVa + BigInt(i * 2));
        const nameAddress = module.base + BigInt(nameRva);
        namesByIndex.set(ordinalIndex, readAsciiString(nameAddress, 512));
      }
      const entries = [];
      for (let index = 0; index < exportInfo.numberOfFunctions; index += 1) {
        const rva = readUint32LE(functionsVa + BigInt(index * 4));
        const va = module.base + BigInt(rva);
        const ordinal = exportInfo.ordinalBase + index;
        entries.push({
          ordinal,
          rva,
          va,
          name: (_a = namesByIndex.get(index)) != null ? _a : ""
        });
      }
      return entries;
    }
    formatHeaderRows(module) {
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
        { Field: "ExportDir VA", Value: toDmlAddress(headers.exportDirectoryVa, "db") }
      ];
    }
    parseExportDirectory(module) {
      const headers = this.parseHeaders(module);
      if (headers.exportDirectoryRva === 0 || headers.exportDirectorySize === 0) {
        return void 0;
      }
      const exportDir = module.base + BigInt(headers.exportDirectoryRva);
      return {
        exportDirectoryRva: headers.exportDirectoryRva,
        exportDirectoryVa: headers.exportDirectoryVa,
        exportDirectorySize: headers.exportDirectorySize,
        ordinalBase: readUint32LE(exportDir + BigInt(16)),
        numberOfFunctions: readUint32LE(exportDir + BigInt(20)),
        numberOfNames: readUint32LE(exportDir + BigInt(24)),
        addressOfFunctionsRva: readUint32LE(exportDir + BigInt(28)),
        addressOfNamesRva: readUint32LE(exportDir + BigInt(32)),
        addressOfNameOrdinalsRva: readUint32LE(exportDir + BigInt(36))
      };
    }
  };
  var ExportResolver = class {
    constructor(parser) {
      this.parser = parser;
    }
    enumerate(module, filter) {
      const entries = this.parser.parseExports(module);
      const needle = normalizeNeedle(filter);
      return entries.filter((entry) => {
        if (!needle) {
          return true;
        }
        return entry.name.toLowerCase().includes(needle);
      }).sort((a, b) => {
        const left = a.name || `~${a.ordinal.toString(16)}`;
        const right = b.name || `~${b.ordinal.toString(16)}`;
        return left.localeCompare(right);
      }).map((entry) => ({
        Ordinal: entry.ordinal.toString(),
        RVA: `0x${entry.rva.toString(16).toUpperCase().padStart(8, "0")}`,
        VA: toDmlAddress(entry.va, "u"),
        Name: entry.name || "<unnamed>"
      }));
    }
    resolve(module, symbol) {
      const needle = symbol.trim().toLowerCase();
      if (!needle) {
        return void 0;
      }
      return this.parser.parseExports(module).find((entry) => entry.name.toLowerCase() === needle);
    }
    getExports(module) {
      return this.parser.parseExports(module);
    }
    getExportDirectory(module) {
      return this.parser.parseExportDirectory(module);
    }
    findByOrdinalIndex(module, ordinalIndex) {
      if (ordinalIndex < 0) {
        return void 0;
      }
      const exportDir = this.parser.parseExportDirectory(module);
      if (!exportDir) {
        return void 0;
      }
      const targetOrdinal = exportDir.ordinalBase + ordinalIndex;
      return this.parser.parseExports(module).find((entry) => entry.ordinal === targetOrdinal);
    }
    isForwarded(module, entry) {
      const exportDir = this.parser.parseExportDirectory(module);
      if (!exportDir) {
        return { forwarded: false, target: "" };
      }
      const start = exportDir.exportDirectoryRva;
      const end = start + exportDir.exportDirectorySize;
      if (entry.rva >= start && entry.rva < end) {
        return {
          forwarded: true,
          target: readAsciiString(module.base + BigInt(entry.rva), 512)
        };
      }
      return { forwarded: false, target: "" };
    }
    nearestSymbol(module, address) {
      const exportsList = this.parser.parseExports(module).filter((entry) => entry.name.length > 0).sort((a, b) => a.va < b.va ? -1 : 1);
      let nearest;
      for (const entry of exportsList) {
        if (entry.va > address) {
          break;
        }
        nearest = entry;
      }
      if (!nearest) {
        return void 0;
      }
      return { name: nearest.name, offset: address - nearest.va };
    }
  };
  var IATResolver = class {
    constructor(pointerSize, parser, exportResolver, modulesProvider) {
      this.pointerSize = pointerSize;
      this.parser = parser;
      this.exportResolver = exportResolver;
      this.modulesProvider = modulesProvider;
    }
    enumerateIat(owner) {
      const headers = this.parser.parseHeaders(owner);
      const importDirRva = this.readImportDirectoryRva(owner, headers.optionalHeaderMagic, headers.ntHeader);
      if (importDirRva === 0) {
        return [];
      }
      const modules = this.modulesProvider();
      const rows = [];
      const descriptors = this.readImportDescriptors(owner, importDirRva);
      const firstThunkBounds = descriptors.map((descriptor) => descriptor.firstThunk).filter((rva) => rva > 0).sort((left, right) => left - right);
      for (const descriptor of descriptors) {
        const { originalFirstThunk, nameRva, firstThunk } = descriptor;
        const nextFirstThunk = firstThunkBounds.find((rva) => rva > firstThunk);
        const iatEnd = nextFirstThunk ? owner.base + BigInt(nextFirstThunk) : void 0;
        if (firstThunk === 0) {
          continue;
        }
        const dllName = nameRva === 0 ? "<unknown>" : readAsciiString(owner.base + BigInt(nameRva), 260);
        const expectedModule = this.findByDllName(modules, dllName);
        const intBaseRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
        let intPtr = owner.base + BigInt(intBaseRva);
        let iatPtr = owner.base + BigInt(firstThunk);
        const maxThunks = 16384;
        for (let thunkIndex = 0; thunkIndex < maxThunks; thunkIndex += 1) {
          if (iatEnd !== void 0 && iatPtr >= iatEnd) {
            break;
          }
          const intValue = this.readThunk(intPtr);
          const iatValue = this.readThunk(iatPtr);
          if (intValue === BigInt(0) && iatValue === BigInt(0)) {
            break;
          }
          const target = iatValue;
          const actualModule = this.findContainingModule(modules, target);
          const trampoline = this.resolveTrampoline(target);
          const nearest = actualModule ? this.exportResolver.nearestSymbol(actualModule, trampoline.target) : void 0;
          const imported = this.parseImportedName(owner, intValue);
          rows.push({
            ownerModule: owner.name,
            importDll: dllName,
            symbol: this.displayImportedSymbol(imported, nearest, expectedModule, actualModule),
            ordinal: imported.ordinal,
            nameWarning: imported.warning,
            slot: iatPtr,
            target: trampoline.target,
            expectedModule,
            actualModule,
            nearest,
            status: this.classifyStatus(target, trampoline.target, expectedModule, actualModule)
          });
          intPtr += BigInt(this.pointerSize);
          iatPtr += BigInt(this.pointerSize);
        }
      }
      return rows;
    }
    readImportDescriptors(owner, importDirRva) {
      const descriptors = [];
      let descriptorAddress = owner.base + BigInt(importDirRva);
      const maxDescriptors = 4096;
      for (let index = 0; index < maxDescriptors; index += 1) {
        const originalFirstThunk = readUint32LE(descriptorAddress);
        const _timeDateStamp = readUint32LE(descriptorAddress + BigInt(4));
        const _forwarderChain = readUint32LE(descriptorAddress + BigInt(8));
        const nameRva = readUint32LE(descriptorAddress + BigInt(12));
        const firstThunk = readUint32LE(descriptorAddress + BigInt(16));
        if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) {
          break;
        }
        descriptors.push({ originalFirstThunk, nameRva, firstThunk, descriptorAddress });
        descriptorAddress += BigInt(20);
      }
      return descriptors;
    }
    classifyStatus(target, resolvedTarget, expected, actual) {
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
    isMapped(address) {
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
    isExecutable(module, address) {
      try {
        const headers = this.parser.parseHeaders(module);
        const numberOfSections = readUint16LE(headers.ntHeader + BigInt(6));
        const sizeOfOptionalHeader = readUint16LE(headers.ntHeader + BigInt(20));
        let sectionHeader = headers.ntHeader + BigInt(24 + sizeOfOptionalHeader);
        const rva = address - module.base;
        const IMAGE_SCN_MEM_EXECUTE2 = 536870912;
        for (let i = 0; i < numberOfSections; i += 1) {
          const virtualSize = readUint32LE(sectionHeader + BigInt(8));
          const virtualAddress = readUint32LE(sectionHeader + BigInt(12));
          const characteristics = readUint32LE(sectionHeader + BigInt(36));
          const start = BigInt(virtualAddress);
          const end = start + BigInt(Math.max(virtualSize, 1));
          if (rva >= start && rva < end) {
            return (characteristics & IMAGE_SCN_MEM_EXECUTE2) !== 0;
          }
          sectionHeader += BigInt(40);
        }
      } catch (_error) {
        return false;
      }
      return false;
    }
    resolveTrampoline(address) {
      if (address === BigInt(0)) {
        return { target: address, note: "" };
      }
      try {
        const first = readMemory(address, 6);
        const op = first[0];
        if (op === 233 && first.length >= 5) {
          const imm = this.readInt32LE(address + BigInt(1));
          const dest = address + BigInt(5) + BigInt(imm);
          return { target: dest, note: "jmp-rel32" };
        }
        if (op === 235 && first.length >= 2) {
          const rel8 = first[1] >= 128 ? first[1] - 256 : first[1];
          const dest = address + BigInt(2) + BigInt(rel8);
          return { target: dest, note: "jmp-rel8" };
        }
        if (this.pointerSize === 4 && op === 255 && first[1] === 37) {
          const memPtr = BigInt(readUint32LE(address + BigInt(2)));
          const dest = readPointer(memPtr, this.pointerSize);
          return { target: dest, note: "jmp-[imm]" };
        }
      } catch (_error) {
        return { target: address, note: "" };
      }
      return { target: address, note: "" };
    }
    readInt32LE(address) {
      const value = readUint32LE(address);
      return value > 2147483647 ? value - 4294967296 : value;
    }
    readImportDirectoryRva(owner, optionalMagic, ntHeader) {
      const optionalHeader = ntHeader + BigInt(24);
      const dataDirectoryOffset = optionalHeader + BigInt(optionalMagic === 523 ? 112 : 96);
      try {
        return readUint32LE(dataDirectoryOffset + BigInt(8));
      } catch (_error) {
        return 0;
      }
    }
    findContainingModule(modules, address) {
      return modules.find((module) => address >= module.base && address < module.end);
    }
    findByDllName(modules, name) {
      const needle = name.trim().toLowerCase();
      if (!needle) {
        return void 0;
      }
      const noExt = needle.endsWith(".dll") ? needle.slice(0, -4) : needle;
      return modules.find((module) => {
        const lower = module.name.toLowerCase();
        const lowerNoExt = lower.endsWith(".dll") ? lower.slice(0, -4) : lower;
        return lower === needle || lowerNoExt === noExt;
      });
    }
    displayImportedSymbol(imported, nearest, expected, actual) {
      if (!imported.name.startsWith("<")) {
        return imported.name;
      }
      if (expected && actual && expected.name.toLowerCase() !== actual.name.toLowerCase()) {
        return imported.name;
      }
      if (nearest && nearest.offset === BigInt(0)) {
        return nearest.name;
      }
      if (nearest) {
        return `${nearest.name}+0x${nearest.offset.toString(16).toUpperCase()}`;
      }
      return imported.name;
    }
    parseImportedName(owner, intValue) {
      if (intValue === BigInt(0)) {
        return { name: "<null>" };
      }
      const ordinalFlag = this.pointerSize === 8 ? BigInt("0x8000000000000000") : BigInt("0x80000000");
      if ((intValue & ordinalFlag) !== BigInt(0)) {
        return { name: "<ordinal>", ordinal: Number(intValue & BigInt(65535)) };
      }
      if (intValue < BigInt(256) || intValue >= owner.size) {
        return {
          name: "<invalid-name-rva>",
          warning: `Thunk value 0x${intValue.toString(16).toUpperCase()} is not an import-name RVA.`
        };
      }
      const byName = owner.base + intValue + BigInt(2);
      try {
        return { name: readAsciiString(byName, 512) };
      } catch (error2) {
        return {
          name: "<unreadable-name>",
          warning: formatError(error2)
        };
      }
    }
    readThunk(address) {
      return this.pointerSize === 8 ? readPointer(address, 8) : BigInt(readUint32LE(address));
    }
  };
  var ShellcodeHelper = class {
    constructor() {
      this.pointerSize = getPointerSize();
      this.parser = new PEParser(this.pointerSize);
      this.exportResolver = new ExportResolver(this.parser);
      this.hashResolver = new HashResolver();
      this.iatResolver = new IATResolver(this.pointerSize, this.parser, this.exportResolver, () => this.readModules());
    }
    peb() {
      const pebAddress = this.getPebAddress();
      if (!pebAddress) {
        return this.errorRows("Unable to resolve PEB in current context.");
      }
      try {
        const ldrOffset = this.pointerSize === 8 ? 24 : 12;
        const processParametersOffset = this.pointerSize === 8 ? 32 : 16;
        const imageBaseOffset = this.pointerSize === 8 ? 16 : 8;
        const ldr = readPointer(pebAddress + BigInt(ldrOffset), this.pointerSize);
        const processParameters = readPointer(pebAddress + BigInt(processParametersOffset), this.pointerSize);
        const imageBase = readPointer(pebAddress + BigInt(imageBaseOffset), this.pointerSize);
        const beingDebugged = readMemory(pebAddress + BigInt(2), 1)[0] !== 0;
        return [
          { Field: "PEB", Value: toDmlAddress(pebAddress, "db") },
          { Field: "Ldr", Value: toDmlAddress(ldr, "db") },
          { Field: "ProcessParameters", Value: toDmlAddress(processParameters, "db") },
          { Field: "BeingDebugged", Value: beingDebugged ? "true" : "false" },
          { Field: "ImageBase", Value: toDmlAddress(imageBase, "db") }
        ];
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    modules() {
      return this.readModules().map((module) => ({
        Base: toDmlAddress(module.base, "db"),
        End: toDmlAddress(module.end, "db"),
        Size: `0x${module.size.toString(16).toUpperCase()}`,
        Name: module.name,
        Path: module.path
      }));
    }
    modulePages(moduleName) {
      const lookup = this.findModule(moduleName);
      if (lookup.kind !== "ok") {
        return this.lookupFailureRows(lookup);
      }
      const pageSize = BigInt(4096);
      const pages = lookup.module.size === BigInt(0) ? BigInt(0) : (lookup.module.size + pageSize - BigInt(1)) / pageSize;
      return [
        {
          Module: lookup.module.name,
          Base: toDmlAddress(lookup.module.base, "db"),
          End: toDmlAddress(lookup.module.end, "db"),
          Size: `0x${lookup.module.size.toString(16).toUpperCase()}`,
          PageSize: `0x${pageSize.toString(16).toUpperCase()}`,
          Pages: pages.toString()
        }
      ];
    }
    pageSummary(moduleName) {
      const lookup = this.findModule(moduleName);
      if (lookup.kind !== "ok") {
        return this.lookupFailureRows(lookup);
      }
      const summary = this.collectPageProtections(lookup.module);
      const pageSize = BigInt(4096);
      const totalPages = Array.from(summary.values()).reduce((sum, count) => sum + count, 0);
      const executablePages = Array.from(summary.entries()).reduce((sum, [protect, count]) => {
        return sum + (this.isExecutableProtect(protect) ? count : 0);
      }, 0);
      const rows = [
        {
          Module: lookup.module.name,
          Base: toDmlAddress(lookup.module.base, "db"),
          End: toDmlAddress(lookup.module.end, "db"),
          Size: `0x${lookup.module.size.toString(16).toUpperCase()}`,
          PageSize: `0x${pageSize.toString(16).toUpperCase()}`,
          TotalPages: totalPages.toString(),
          ExecutablePages: executablePages.toString()
        },
        {
          Protect: "TOTAL",
          Name: "TOTAL",
          Pages: totalPages.toString(),
          ExecutablePages: executablePages.toString()
        },
        ...[...summary.entries()].sort((left, right) => left[0] - right[0]).map(([protect, count]) => {
          const decoded = decodeProtectValue(protect);
          return {
            Protect: `0x${protect.toString(16).toUpperCase().padStart(2, "0")}`,
            Name: decoded.name,
            Pages: count.toString(),
            Executable: decoded.executable ? "yes" : "no",
            Writable: decoded.writable ? "yes" : "no"
          };
        })
      ];
      return rows;
    }
    base(name) {
      const lookup = this.findModule(name);
      if (lookup.kind === "ok") {
        return [{ Module: lookup.module.name, Base: toDmlAddress(lookup.module.base, "db") }];
      }
      if (lookup.kind === "ambiguous") {
        return this.moduleCandidatesRows(lookup.candidates);
      }
      return this.errorRows(`No module matches "${name}".`);
    }
    pe(name) {
      const lookup = this.findModule(name);
      if (lookup.kind !== "ok") {
        return this.lookupFailureRows(lookup);
      }
      try {
        return this.parser.formatHeaderRows(lookup.module);
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    exports(name, filter) {
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
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    resolve(moduleName, symbol) {
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
          Address: toDmlAddress(entry.va, "u")
        }
      ];
    }
    hashes(moduleName, algorithm) {
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
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    hashresolve(moduleName, hashValue, algorithm = "ROR13") {
      const lookup = this.findModule(moduleName);
      if (lookup.kind !== "ok") {
        return this.lookupFailureRows(lookup);
      }
      const parsed = parseHashValue(hashValue);
      if (parsed === void 0) {
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
                ForwardTo: forward.target || ""
              }
            ];
          }
        }
        return this.errorRows(`No symbol matched hash 0x${parsed.toString(16).toUpperCase().padStart(8, "0")}.`);
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    exportdir(moduleName) {
      const lookup = this.findModule(moduleName);
      if (lookup.kind !== "ok") {
        return this.lookupFailureRows(lookup);
      }
      try {
        const info2 = this.exportResolver.getExportDirectory(lookup.module);
        if (!info2) {
          return this.errorRows(`Module ${lookup.module.name} has no export directory.`);
        }
        return [
          { Field: "Module", Value: lookup.module.name },
          { Field: "Base", Value: toDmlAddress(lookup.module.base, "db") },
          { Field: "Export RVA", Value: `0x${info2.exportDirectoryRva.toString(16).toUpperCase()}` },
          { Field: "Export VA", Value: toDmlAddress(info2.exportDirectoryVa, "db") },
          { Field: "AddressOfNames", Value: `0x${info2.addressOfNamesRva.toString(16).toUpperCase()}` },
          { Field: "NumberOfFunctions", Value: info2.numberOfFunctions.toString() },
          { Field: "NumberOfNames", Value: info2.numberOfNames.toString() },
          { Field: "AddressOfFunctions", Value: `0x${info2.addressOfFunctionsRva.toString(16).toUpperCase()}` },
          { Field: "AddressOfNameOrdinals", Value: `0x${info2.addressOfNameOrdinalsRva.toString(16).toUpperCase()}` }
        ];
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    export(moduleName, symbol) {
      const lookup = this.findModule(moduleName);
      if (lookup.kind !== "ok") {
        return this.lookupFailureRows(lookup);
      }
      const requested = symbol == null ? void 0 : symbol.trim();
      if (!requested) {
        return this.errorRows(`Symbol is required. Use sc.exports("${lookup.module.name}") to list exported functions.`);
      }
      try {
        const entry = this.exportResolver.resolve(lookup.module, requested);
        if (!entry) {
          return this.errorRows(`Symbol "${requested}" was not found in ${lookup.module.name}.`);
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
          { Property: "ForwardTo", Value: forward.target || "" }
        ];
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    exportat(moduleName, ordinalIndex) {
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
            ForwardTo: forward.target || ""
          }
        ];
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    exportwalk(moduleName, symbol = "GetProcAddress", verbose = false) {
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
        const rows = [];
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
        const summary = [
          { Step: "Resolving", Value: symbol },
          { Step: "[1] Module base", Value: toDmlAddress(lookup.module.base, "db") },
          { Step: "[2] DOS header", Value: toDmlAddress(headers.dosHeader, "db") },
          { Step: "[3] DOS.e_lfanew", Value: `0x${headers.eLfanew.toString(16).toUpperCase()}` },
          { Step: "[4] NT header", Value: toDmlAddress(headers.ntHeader, "db") },
          { Step: "[5] Export directory", Value: toDmlAddress(exportDir.exportDirectoryVa, "db") },
          { Step: "[6] AddressOfNames", Value: toDmlAddress(namesVa, "db") },
          { Step: "[7] AddressOfNameOrdinals", Value: toDmlAddress(ordinalsVa, "db") },
          { Step: "[8] AddressOfFunctions", Value: toDmlAddress(functionsVa, "db") }
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
          { Step: "[13] Forwarded", Value: forward.forwarded ? `true (${forward.target})` : "false" }
        );
        return summary.concat(verbose ? rows : []);
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    hash(name, algorithm = "ROR13") {
      const input = name.trim();
      if (!input) {
        return this.errorRows("Input string is required.");
      }
      try {
        return [this.hashResolver.hashValue(input, algorithm)];
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    algorithms() {
      return this.hashResolver.listAlgorithms();
    }
    iat(moduleName, filter) {
      const lookup = moduleName ? this.findModule(moduleName) : this.findMainModule();
      if (lookup.kind !== "ok") {
        return this.lookupFailureRows(lookup);
      }
      try {
        const needle = filter == null ? void 0 : filter.trim().toLowerCase();
        const rows = this.iatResolver.enumerateIat(lookup.module).filter((entry) => {
          if (!needle) return true;
          return entry.symbol.toLowerCase().includes(needle) || entry.importDll.toLowerCase().includes(needle);
        }).map((entry) => {
          var _a, _b, _c;
          return {
            Owner: entry.ownerModule,
            DLL: entry.importDll,
            Symbol: entry.symbol,
            Ordinal: entry.ordinal ? entry.ordinal.toString() : "",
            Slot: toDmlAddress(entry.slot, "dps"),
            Target: toDmlAddress(entry.target, "u"),
            Module: (_b = (_a = entry.actualModule) == null ? void 0 : _a.name) != null ? _b : "unknown",
            "Symbol+Offset": entry.nearest ? `${entry.nearest.name}+0x${entry.nearest.offset.toString(16).toUpperCase()}` : "",
            Status: entry.status,
            Note: (_c = entry.nameWarning) != null ? _c : ""
          };
        });
        if (rows.length === 0) {
          return this.errorRows(filter ? `No IAT entries in ${lookup.module.name} matched "${filter}".` : `No IAT entries found for ${lookup.module.name}.`);
        }
        return rows;
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    iat_find(symbol) {
      var _a, _b, _c;
      const needle = symbol.trim().toLowerCase();
      if (!needle) {
        return this.errorRows("Symbol substring is required.");
      }
      const rows = [];
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
                Module: (_b = (_a = entry.actualModule) == null ? void 0 : _a.name) != null ? _b : "unknown",
                Status: entry.status,
                Note: (_c = entry.nameWarning) != null ? _c : ""
              });
            }
          }
        } catch (_error) {
        }
      }
      if (rows.length === 0) {
        return this.errorRows(`No IAT entries matched "${symbol}".`);
      }
      return rows;
    }
    iat_ptr(moduleName, symbol) {
      var _a, _b, _c;
      const lookup = this.findModule(moduleName);
      if (lookup.kind !== "ok") {
        return this.lookupFailureRows(lookup);
      }
      const needle = symbol.trim().toLowerCase();
      if (!needle) {
        return this.errorRows("Symbol is required.");
      }
      try {
        const match = this.iatResolver.enumerateIat(lookup.module).find((entry) => entry.symbol.toLowerCase() === needle || entry.symbol.toLowerCase().includes(needle));
        if (!match) {
          return this.errorRows(`No IAT slot found for "${symbol}" in ${lookup.module.name}.`);
        }
        return [
          {
            slot: formatAddress(match.slot, this.pointerSize),
            target: formatAddress(match.target, this.pointerSize),
            module: (_b = (_a = match.actualModule) == null ? void 0 : _a.name) != null ? _b : "unknown",
            symbol: match.symbol,
            status: match.status,
            note: (_c = match.nameWarning) != null ? _c : ""
          }
        ];
      } catch (error2) {
        return this.errorRows(formatError(error2));
      }
    }
    findModule(name) {
      const needle = normalizeNeedle(name);
      if (!needle) {
        return { kind: "not_found", name };
      }
      const modules = this.readModules();
      const scored = modules.map((module) => {
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
        return void 0;
      }).filter((entry) => entry !== void 0);
      if (scored.length === 0) {
        return { kind: "not_found", name };
      }
      const bestScore = Math.min(...scored.map((entry) => entry.score));
      const candidates2 = scored.filter((entry) => entry.score === bestScore).map((entry) => entry.module).sort((a, b) => a.base < b.base ? -1 : 1);
      if (candidates2.length === 1) {
        return { kind: "ok", module: candidates2[0] };
      }
      return { kind: "ambiguous", candidates: candidates2 };
    }
    findMainModule() {
      var _a, _b, _c, _d, _e, _f;
      const modules = this.readModules();
      if (modules.length === 0) {
        return { kind: "not_found", name: "<main-executable>" };
      }
      const process = host;
      const executablePath = ((_d = (_c = (_a = process.currentProcess) == null ? void 0 : _a.ExecutablePath) != null ? _c : (_b = process.currentProcess) == null ? void 0 : _b.Path) != null ? _d : "").toLowerCase();
      const processName = ((_f = (_e = process.currentProcess) == null ? void 0 : _e.Name) != null ? _f : "").toLowerCase();
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
      return { kind: "ok", module: modules[0] };
    }
    getPebAddress() {
      var _a, _b, _c, _d, _e, _f, _g;
      const hostAny = host;
      const fromPseudo = tryToBigInt((_e = (_d = (_c = (_b = (_a = hostAny.namespace) == null ? void 0 : _a.Debugger) == null ? void 0 : _b.State) == null ? void 0 : _c.PseudoRegisters) == null ? void 0 : _d.General) == null ? void 0 : _e.peb);
      if (fromPseudo && fromPseudo !== BigInt(0)) {
        return fromPseudo;
      }
      const fromProcess = tryToBigInt((_g = (_f = hostAny.currentProcess) == null ? void 0 : _f.Environment) == null ? void 0 : _g.EnvironmentBlock);
      if (fromProcess && fromProcess !== BigInt(0)) {
        return fromProcess;
      }
      return void 0;
    }
    readModules() {
      var _a;
      const hostAny = host;
      const source = (_a = hostAny.currentProcess) == null ? void 0 : _a.Modules;
      const items = toArray2(source);
      return items.map((entry) => {
        var _a2, _b, _c, _d, _e, _f;
        const moduleAny = entry;
        const rawName = (_a2 = moduleAny.Name) != null ? _a2 : "<unknown>";
        const path = (_b = moduleAny.Path) != null ? _b : rawName;
        const name = moduleBasename(rawName);
        const base = (_e = tryToBigInt((_d = (_c = moduleAny.BaseAddress) != null ? _c : moduleAny.Base) != null ? _d : moduleAny.Address)) != null ? _e : BigInt(0);
        let end = tryToBigInt(moduleAny.EndAddress);
        const sizeFromModule = tryToBigInt((_f = moduleAny.Size) != null ? _f : moduleAny.Length);
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
          size
        };
      }).filter((module) => module.base !== BigInt(0)).sort((a, b) => a.base < b.base ? -1 : 1);
    }
    collectPageProtections(module) {
      var _a;
      const counts = /* @__PURE__ */ new Map();
      const pageSize = BigInt(4096);
      for (let page = module.base; page < module.end; page += pageSize) {
        const protect = this.readPageProtection(page);
        counts.set(protect, ((_a = counts.get(protect)) != null ? _a : 0) + 1);
      }
      return counts;
    }
    readPageProtection(address) {
      const output = executeDebuggerCommand(`!vprot ${formatAddress(address, this.pointerSize)}`);
      const parsed = parseProtectFromVprot(output);
      if (parsed !== void 0) {
        return parsed;
      }
      throw new Error(`Unable to parse !vprot output for ${formatAddress(address, this.pointerSize)}.`);
    }
    isExecutableProtect(protect) {
      return (protect & 255) === 16 || (protect & 255) === 32 || (protect & 255) === 64 || (protect & 255) === 128;
    }
    moduleCandidatesRows(candidates2) {
      return candidates2.map((module) => ({
        Base: toDmlAddress(module.base, "db"),
        End: toDmlAddress(module.end, "db"),
        Name: module.name,
        Path: module.path
      }));
    }
    lookupFailureRows(lookup) {
      if (lookup.kind === "ambiguous") {
        return this.moduleCandidatesRows(lookup.candidates);
      }
      if (lookup.kind === "not_found") {
        return this.errorRows(`No module matches "${lookup.name}".`);
      }
      return this.errorRows(`Unexpected successful module lookup for "${lookup.module.name}".`);
    }
    errorRows(message) {
      return [{ Error: message }];
    }
  };
  function toArray2(value) {
    if (Array.isArray(value)) {
      return value;
    }
    if (value && typeof value[Symbol.iterator] === "function") {
      try {
        return Array.from(value);
      } catch (_error) {
        return [];
      }
    }
    return [];
  }
  function executeDebuggerCommand(command) {
    var _a, _b, _c, _d, _e, _f, _g;
    const hostAny = host;
    const exec = (_d = (_c = (_b = (_a = hostAny.namespace) == null ? void 0 : _a.Debugger) == null ? void 0 : _b.Utility) == null ? void 0 : _c.Control) == null ? void 0 : _d.ExecuteCommand;
    if (typeof exec !== "function") {
      throw new Error("WinDbg command execution is unavailable in this host.");
    }
    const control = (_g = (_f = (_e = hostAny.namespace) == null ? void 0 : _e.Debugger) == null ? void 0 : _f.Utility) == null ? void 0 : _g.Control;
    const result3 = exec.call(control, command);
    return toArray2(result3).map((line) => String(line));
  }
  function parseProtectFromVprot(lines) {
    for (const line of lines) {
      const match = line.match(/^\s*Protect:\s+([0-9a-f`]+)\s+/i);
      if (match) {
        return Number(BigInt(`0x${match[1].replace(/`/g, "")}`) & BigInt(4294967295));
      }
    }
    return void 0;
  }
  function decodeProtectValue(value) {
    const protect = value & 255;
    switch (protect) {
      case 1:
        return { name: "PAGE_NOACCESS", executable: false, writable: false };
      case 2:
        return { name: "PAGE_READONLY", executable: false, writable: false };
      case 4:
        return { name: "PAGE_READWRITE", executable: false, writable: true };
      case 8:
        return { name: "PAGE_WRITECOPY", executable: false, writable: true };
      case 16:
        return { name: "PAGE_EXECUTE", executable: true, writable: false };
      case 32:
        return { name: "PAGE_EXECUTE_READ", executable: true, writable: false };
      case 64:
        return { name: "PAGE_EXECUTE_READWRITE", executable: true, writable: true };
      case 128:
        return { name: "PAGE_EXECUTE_WRITECOPY", executable: true, writable: true };
      default:
        return { name: `0x${protect.toString(16).toUpperCase().padStart(2, "0")}`, executable: false, writable: false };
    }
  }
  function tryToBigInt(value) {
    var _a;
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
      return void 0;
    }
    if (!value || typeof value !== "object") {
      return void 0;
    }
    const addressed = value;
    const fromAddress = tryToBigInt((_a = addressed.address) != null ? _a : addressed.Address);
    if (fromAddress !== void 0) {
      return fromAddress;
    }
    const valueOf = value.valueOf;
    if (typeof valueOf === "function") {
      const unwrapped = valueOf.call(value);
      if (unwrapped !== value) {
        const parsed = tryToBigInt(unwrapped);
        if (parsed !== void 0) {
          return parsed;
        }
      }
    }
    const asString = value.toString;
    if (typeof asString === "function") {
      return tryToBigInt(asString.call(value));
    }
    return void 0;
  }
  function readAsciiString(address, maxLength) {
    const chars = [];
    const chunkSize = 64;
    for (let offset = 0; offset < maxLength; offset += chunkSize) {
      const length = Math.min(chunkSize, maxLength - offset);
      const bytes = tryReadMemory(address + BigInt(offset), length);
      if (!bytes || bytes.length === 0) {
        if (chars.length > 0) {
          break;
        }
        throw new Error(`Unable to read ASCII string at 0x${address.toString(16).toUpperCase()}.`);
      }
      for (let i = 0; i < bytes.length; i += 1) {
        const ch = bytes[i];
        if (ch === 0) {
          return chars.join("");
        }
        chars.push(String.fromCharCode(ch));
      }
    }
    return chars.join("");
  }
  function toDmlAddress(address, command) {
    const hex = `0x${address.toString(16).toUpperCase()}`;
    return `<link cmd="${command} ${hex}">${hex}</link>`;
  }
  function machineToString(machine) {
    switch (machine) {
      case 332:
        return "x86";
      case 34404:
        return "x64";
      default:
        return "unknown";
    }
  }
  function normalizeNeedle(value) {
    if (!value) {
      return "";
    }
    return value.trim().toLowerCase();
  }
  function formatError(error2) {
    if (error2 instanceof Error && error2.message) {
      return error2.message;
    }
    return String(error2);
  }
  function parseHashValue(value) {
    if (typeof value === "number") {
      return Number.isFinite(value) ? value >>> 0 : void 0;
    }
    if (typeof value === "bigint") {
      return Number(value & BigInt(4294967295));
    }
    const text = value.trim().toLowerCase();
    if (!text) {
      return void 0;
    }
    const parsed = text.startsWith("0x") ? parseInt(text, 16) : parseInt(text, 10);
    if (Number.isNaN(parsed)) {
      return void 0;
    }
    return parsed >>> 0;
  }
  function moduleBasename(value) {
    const normalized = value.trim();
    if (!normalized) {
      return "<unknown>";
    }
    const parts = normalized.split(/[\\/]+/);
    return parts[parts.length - 1] || normalized;
  }
  function createShellcodeNamespace() {
    const helper = new ShellcodeHelper();
    const helperHelp = (name) => {
      const entry = findHelpEntry(name);
      return renderAndReturn(`Help: ${name}`, entry ? helpRows(entry) : [{ Error: `Unknown helper '${name}'.` }]);
    };
    const wantsHelp = (value) => value === "help";
    const renderAndReturn = (title, rows) => {
      section(title);
      if (rows.length > 0 && "Error" in rows[0]) {
        error(rows[0].Error);
        return toDxResult(title, rows);
      }
      const maxPrintedRows = title === "sc.exports" || title === "sc.hashes" ? 100 : 200;
      const printedRows = rows.length > maxPrintedRows ? rows.slice(0, maxPrintedRows) : rows;
      const keys = title === "sc.modules" ? ["Base", "End", "Size", "Name"] : [...new Set(printedRows.flatMap((row) => Object.keys(row)))];
      table(keys.map((key2) => ({ key: key2, header: key2 })), printedRows);
      if (printedRows.length < rows.length) {
        info(`Showing first ${printedRows.length} of ${rows.length} rows. Use a filter argument to narrow output; full rows remain available under .rows.`);
      }
      return toDxResult(title, rows);
    };
    return {
      peb: (help) => wantsHelp(help) ? helperHelp("sc.peb") : renderAndReturn("sc.peb", helper.peb()),
      modules: (help) => wantsHelp(help) ? helperHelp("sc.modules") : renderAndReturn("sc.modules", helper.modules()),
      module_pages: (name) => wantsHelp(name) ? helperHelp("sc.module_pages") : renderAndReturn("sc.module_pages", helper.modulePages(name)),
      page_summary: (name) => wantsHelp(name) ? helperHelp("sc.page_summary") : renderAndReturn("sc.page_summary", helper.pageSummary(name)),
      base: (name) => wantsHelp(name) ? helperHelp("sc.base") : renderAndReturn("sc.base", helper.base(name)),
      pe: (name) => wantsHelp(name) ? helperHelp("sc.pe") : renderAndReturn("sc.pe", helper.pe(name)),
      exports: (name, filter) => wantsHelp(name) ? helperHelp("sc.exports") : renderAndReturn("sc.exports", helper.exports(name, filter)),
      resolve: (module, symbol) => wantsHelp(module) ? helperHelp("sc.resolve") : renderAndReturn("sc.resolve", helper.resolve(module, symbol)),
      hashes: (module, algorithm) => wantsHelp(module) ? helperHelp("sc.hashes") : renderAndReturn("sc.hashes", helper.hashes(module, algorithm)),
      hash: (name, algorithm) => wantsHelp(name) ? helperHelp("sc.hash") : renderAndReturn("sc.hash", helper.hash(name, algorithm)),
      hashresolve: (module, hashValue, algorithm) => wantsHelp(module) ? helperHelp("sc.hashresolve") : renderAndReturn("sc.hashresolve", helper.hashresolve(module, hashValue, algorithm)),
      algorithms: (help) => wantsHelp(help) ? helperHelp("sc.algorithms") : renderAndReturn("sc.algorithms", helper.algorithms()),
      exportdir: (module) => wantsHelp(module) ? helperHelp("sc.exportdir") : renderAndReturn("sc.exportdir", helper.exportdir(module)),
      export: (module, symbol) => wantsHelp(module) ? helperHelp("sc.export") : renderAndReturn("sc.export", helper.export(module, symbol)),
      exportat: (module, ordinalIndex) => wantsHelp(module) ? helperHelp("sc.exportat") : renderAndReturn("sc.exportat", helper.exportat(module, ordinalIndex)),
      exportwalk: (module, symbol, verbose) => wantsHelp(module) ? helperHelp("sc.exportwalk") : renderAndReturn("sc.exportwalk", helper.exportwalk(module, symbol, verbose)),
      iat: (module, filter) => wantsHelp(module) ? helperHelp("sc.iat") : renderAndReturn("sc.iat", helper.iat(module, filter)),
      iat_find: (symbol) => wantsHelp(symbol) ? helperHelp("sc.iat_find") : renderAndReturn("sc.iat_find", helper.iat_find(symbol)),
      iat_ptr: (module, symbol) => wantsHelp(module) ? helperHelp("sc.iat_ptr") : renderAndReturn("sc.iat_ptr", helper.iat_ptr(module, symbol))
    };
  }

  // src/analysis/live_gadgets.ts
  function discoverLiveGadgets(options = {}) {
    var _a, _b, _c;
    const pointerSize = getPointerSize();
    const patterns = knownPatternsForPointerSize(pointerSize);
    const filter = badcharAddressFilter((_a = options.badchars) != null ? _a : [], pointerSize);
    const maxPerPattern = (_b = options.maxPerPattern) != null ? _b : 5;
    const hits = [];
    const warningSet = /* @__PURE__ */ new Set();
    let scanned = 0;
    let rejected = 0;
    for (const pattern of patterns) {
      const scan = scanPattern(
        {
          module: options.module,
          executableOnly: true,
          maxResults: Math.min(maxPerPattern * 4, 200),
          chunkSize: 16384
        },
        Uint8Array.from(pattern.bytes)
      );
      scanned += scan.hits.length;
      for (const warning of scan.warnings) {
        warningSet.add(`${warning.region}: ${warning.message}`);
      }
      const outcome = applyFilters(scan.hits, [filter]);
      rejected += outcome.rejected.length;
      for (const address of outcome.kept.slice(0, maxPerPattern)) {
        hits.push({ mnemonic: pattern.mnemonic, address, module: (_c = findModuleByAddress(address)) == null ? void 0 : _c.name });
      }
    }
    return {
      hits,
      warnings: [...warningSet],
      stats: { patterns: patterns.length, scanned, rejected, discovered: hits.length }
    };
  }

  // src/semantics/live-provider.ts
  function sequenceFromLiveHit(hit) {
    const parts = hit.mnemonic.split(";").map((part) => part.trim()).filter((part) => part.length > 0);
    const instructions = parts.map((part) => parseInstruction(part));
    const canonical = canonicalizeTextSequence(parts.join(" ; "));
    const addressNumber = Number(hit.address);
    return {
      schemaVersion: SEMANTIC_SCHEMA_VERSION,
      id: `live:${hit.address.toString(16)}:${canonical}`,
      source: { kind: "source-adapter", name: "live", format: "windbg-memory", version: "v1" },
      originalText: `0x${hit.address.toString(16)}: ${parts.join(" ; ")} ;`,
      instructions,
      provenance: {
        module: hit.module,
        // The full address survives in id/originalText; the numeric field is exact
        // for realistic user-space addresses (< 2^53).
        virtualAddress: Number.isSafeInteger(addressNumber) ? addressNumber : void 0,
        // Discovered by scanning executable sections, so executability is proven.
        executable: "EXACT",
        writable: "UNKNOWN",
        aslr: "UNKNOWN",
        rebaseable: "UNKNOWN"
      }
    };
  }
  function sequencesFromLiveHits(hits) {
    return [...hits].map(sequenceFromLiveHit);
  }

  // src/commands/memory.ts
  function flag(value) {
    return value === null ? "unknown" : value ? "yes" : "no";
  }
  function createMemoryCommand() {
    return {
      name: "memory",
      description: "Inspect normalized memory-region evidence for an address.",
      usage: "dx @$osed().memory(0x41414141)",
      examples: ["dx @$osed().memory(0x41414141)", 'dx @$osed().memory("0012F800")'],
      schema: { address: { type: ["number", "string"], required: true } },
      execute(options) {
        const address = normalizeAddress(options.address);
        const evidence = memoryRegion(address);
        section("Memory Evidence");
        info(`Address: ${formatAddress(address, 8)}`);
        table(
          [
            { key: "read", header: "Read" },
            { key: "write", header: "Write" },
            { key: "exec", header: "Exec" },
            { key: "guard", header: "Guard" },
            { key: "noAccess", header: "No access" },
            { key: "commit", header: "Committed" },
            { key: "type", header: "Type" }
          ],
          [{
            read: flag(evidence.readable),
            write: flag(evidence.writable),
            exec: flag(evidence.executable),
            guard: flag(evidence.guarded),
            noAccess: flag(evidence.noAccess),
            commit: flag(evidence.committed),
            type: evidence.regionType
          }]
        );
        for (const warning of evidence.warnings) warn(warning);
        return { command: "memory", args: options, success: true, findings: [serializeMemoryRegionEvidence(evidence)], warnings: evidence.warnings, errors: [] };
      }
    };
  }

  // src/commands/landing.ts
  function createLandingCommand() {
    return {
      name: "landing",
      description: "Analyze exploit-relevant evidence at ESP/RSP or an explicit address.",
      usage: "dx @$osed().landing()",
      examples: ["dx @$osed().landing()", "dx @$osed().landing(0x0012F800)"],
      schema: { address: { type: ["number", "string"] } },
      execute(options) {
        const address = options.address === void 0 ? void 0 : normalizeAddress(options.address);
        const evidence = landing(address);
        section("Landing Evidence");
        if (evidence.address !== void 0) info(`Address: ${formatAddress(evidence.address, 8)}`);
        table(
          [
            { key: "kind", header: "Observation" },
            { key: "address", header: "Address" },
            { key: "length", header: "Length" },
            { key: "confidence", header: "Confidence" }
          ],
          evidence.observations.map((item) => {
            var _a, _b;
            return {
              kind: item.kind,
              address: item.address === void 0 ? "" : formatAddress(item.address, 8),
              length: (_b = (_a = item.length) == null ? void 0 : _a.toString()) != null ? _b : "",
              confidence: item.confidence.toFixed(2)
            };
          })
        );
        info(evidence.recommendation);
        const available = evidence.address !== void 0;
        return {
          command: "landing",
          args: options,
          success: available,
          findings: [serializeLandingEvidence(evidence)],
          warnings: available ? [] : [evidence.recommendation],
          errors: []
        };
      }
    };
  }

  // src/logic/math_logic.ts
  var VALID_BITS = /* @__PURE__ */ new Set([8, 16, 32, 64]);
  function normalizeMathBits(value) {
    const bits = value === void 0 ? 32 : value;
    if (typeof bits !== "number" || !Number.isInteger(bits) || !VALID_BITS.has(bits)) {
      throw new Error("bits must be one of: 8, 16, 32, 64.");
    }
    return bits;
  }
  function parseMathValue(value) {
    if (typeof value === "bigint") return value;
    if (typeof value === "number") {
      if (!Number.isFinite(value) || !Number.isInteger(value)) {
        throw new Error("value must be an integer.");
      }
      return BigInt(value);
    }
    if (typeof value !== "string") {
      throw new Error("value must be an integer, bigint, decimal string, or hex string.");
    }
    const text = value.trim().replace(/`/g, "");
    if (/^-?0x[0-9a-f]+$/i.test(text)) {
      const negative = text.startsWith("-");
      const hex = negative ? text.slice(3) : text.slice(2);
      const parsed = BigInt(`0x${hex}`);
      return negative ? -parsed : parsed;
    }
    if (/^-?[0-9]+$/.test(text)) {
      return BigInt(text);
    }
    if (/^[0-9a-f]+$/i.test(text) && /[a-f]/i.test(text)) {
      return BigInt(`0x${text}`);
    }
    throw new Error("value strings must be decimal or hex, e.g. -42, 0xFFFFFFD6, or FFD6.");
  }
  function analyzeMathValue(rawValue, rawBits) {
    const bits = normalizeMathBits(rawBits);
    const value = parseMathValue(rawValue);
    const modulus = BigInt(1) << BigInt(bits);
    const mask = modulus - BigInt(1);
    const unsigned = value & mask;
    const signBit = BigInt(1) << BigInt(bits - 1);
    const signed = (unsigned & signBit) !== BigInt(0) ? unsigned - modulus : unsigned;
    const width = bits / 4;
    const byteCount = bits / 8;
    const hex = `0x${unsigned.toString(16).toUpperCase().padStart(width, "0")}`;
    const littleEndianBytes = [];
    for (let i = 0; i < byteCount; i += 1) {
      const byte = Number(unsigned >> BigInt(i * 8) & BigInt(255));
      littleEndianBytes.push(byte.toString(16).toUpperCase().padStart(2, "0"));
    }
    return {
      input: typeof rawValue === "string" ? rawValue : value.toString(),
      bits,
      hex,
      unsigned: unsigned.toString(),
      signed: signed.toString(),
      littleEndianBytes: littleEndianBytes.join(" "),
      twosComplement: hex
    };
  }

  // src/commands/math.ts
  function createMathCommand() {
    return {
      name: "math",
      description: "Format an integer as hex, signed, unsigned, little-endian bytes, and two's complement.",
      usage: "dx @$osed().math(value, bits?)",
      examples: [
        "dx @$osed().math(0xFFFFFFD6)",
        "dx @$osed().math(-42, 32)",
        "dx @$osed().math(0x625011D3, 32)"
      ],
      schema: {
        value: { type: ["number", "string"], required: true },
        bits: { type: "number", default: 32 }
      },
      execute(options) {
        const evidence = analyzeMathValue(options.value, options.bits);
        section("Math");
        table(
          [
            { key: "field", header: "Field", width: 18 },
            { key: "value", header: "Value", width: 24 }
          ],
          [
            { field: "Input", value: evidence.input },
            { field: "Bits", value: evidence.bits.toString() },
            { field: "Hex", value: evidence.hex },
            { field: "Unsigned", value: evidence.unsigned },
            { field: "Signed", value: evidence.signed },
            { field: "Little-endian", value: evidence.littleEndianBytes },
            { field: "Two's complement", value: evidence.twosComplement }
          ]
        );
        return {
          command: "math",
          args: options,
          success: true,
          findings: [evidence],
          warnings: [],
          errors: []
        };
      }
    };
  }

  // src/core/version.ts
  function getVersionInfo() {
    return {
      name: "osed-windbg",
      version: "1.0.2",
      buildTime: "2026-07-23T02:54:50.191Z",
      gitCommit: "db48f26348d4",
      gitDirty: true
    };
  }

  // src/commands/version.ts
  function createVersionCommand() {
    return {
      name: "version",
      description: "Show the loaded osed-windbg build identity.",
      usage: "dx @$osed().version()",
      examples: ["dx @$osed().version()", 'dx @$osed().help("version")'],
      schema: {},
      execute(options) {
        const info2 = getVersionInfo();
        const rows = [
          { Field: "Name", Value: info2.name },
          { Field: "Version", Value: info2.version },
          { Field: "BuildTime", Value: info2.buildTime },
          { Field: "GitCommit", Value: info2.gitCommit },
          { Field: "GitDirty", Value: info2.gitDirty ? "yes" : "no" }
        ];
        section("OSED Version");
        table(
          [
            { key: "Field", header: "Field" },
            { key: "Value", header: "Value" }
          ],
          rows
        );
        return {
          command: "version",
          args: options,
          success: true,
          findings: [info2],
          warnings: [],
          errors: []
        };
      }
    };
  }

  // src/index.ts
  var registry = new CommandRegistry();
  var osed = {};
  var lastResult;
  var currentRopCorpus;
  var NO_ROP_CORPUS_MESSAGE = "No ROP corpus loaded. Run rop.scan(...) for RP++ text or rop.scan_live(...) for live target memory first.";
  function getGlobalObject() {
    if (typeof globalThis !== "undefined") {
      return globalThis;
    }
    if (typeof self !== "undefined") {
      return self;
    }
    return void 0;
  }
  function publishOsed() {
    const globalObject = getGlobalObject();
    if (globalObject) {
      globalObject.osed = osed;
    }
  }
  function registerAll() {
    const commands = [
      ...createPatternCommands(),
      createBadcharsCommand(),
      createBadcharArrayCommand(),
      createBadcharFindCommand(),
      createEgghunterCommand(),
      createSehCommand(),
      createModulesCommand(),
      ...createRopCommands(),
      createPivotCommand(),
      createSehPprCommand(),
      createTriageCommand(),
      createFindMspCommand(),
      createFindPtrCommand(),
      createMemoryCommand(),
      createLandingCommand(),
      createMathCommand(),
      createVersionCommand(),
      createEncodeCommand(),
      createNopCommand(),
      createRopTemplateCommand(),
      ...createFmtCommands(),
      createExploitCommand(),
      createHelpCommand(registry),
      createReloadCommand(registry)
    ];
    for (const command of commands) {
      registry.register(command);
    }
  }
  function bindApi() {
    const api = {};
    const invoke = (commandName, args) => {
      if (args.length === 1 && args[0] === "help") {
        const result4 = registry.execute("help", { command: commandName });
        lastResult = result4;
        return result4.success;
      }
      const result3 = registry.execute(commandName, normalizeInvocation(commandName, args));
      lastResult = result3;
      return result3.success;
    };
    const setResult = (result3) => {
      lastResult = result3;
    };
    const renderRows = (title, rows) => {
      section(title);
      if (rows.length > 0 && "Error" in rows[0]) {
        error(rows[0].Error);
        return;
      }
      const keys = [...new Set(rows.flatMap((row) => Object.keys(row)))];
      table(keys.map((key2) => ({ key: key2, header: key2 })), rows);
    };
    const formatSet = (values) => {
      return [...values].map((value) => String(value)).join(", ");
    };
    const formatSemanticField = (field) => {
      if (field.values.unknown) {
        return "unknown";
      }
      const parts = [];
      if (field.values.exact.size > 0) {
        parts.push(`exact=${formatSet(field.values.exact)}`);
      }
      if (field.values.conservative.size > 0) {
        parts.push(`conservative=${formatSet(field.values.conservative)}`);
      }
      return parts.length > 0 ? `${field.confidence.toLowerCase()}(${parts.join("; ")})` : "none";
    };
    const queryRows = (query) => {
      if (!currentRopCorpus) {
        return [{ Error: NO_ROP_CORPUS_MESSAGE }];
      }
      const gadgets = currentRopCorpus.query(query);
      const pointerSize = getPointerSize();
      return gadgets.map((gadget) => {
        var _a;
        const location = gadget.locations[0];
        return {
          Address: (location == null ? void 0 : location.virtualAddress) !== void 0 ? formatAddress(BigInt(location.virtualAddress), pointerSize) : "n/a",
          Module: (_a = location == null ? void 0 : location.module) != null ? _a : "n/a",
          Score: gadget.score.toString(),
          Terminator: [...gadget.semanticSummary.summary.flowEffects.values.exact].join(", ") || "none",
          Reads: formatSemanticField(gadget.semanticSummary.summary.reads),
          Writes: formatSemanticField(gadget.semanticSummary.summary.writes),
          MemoryReads: formatSemanticField(gadget.semanticSummary.summary.memoryReads),
          MemoryWrites: formatSemanticField(gadget.semanticSummary.summary.memoryWrites),
          StackDelta: formatSemanticField(gadget.semanticSummary.summary.stackDelta),
          Capabilities: gadget.capabilities.map((capability) => capability.kind).join(", "),
          Sequence: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; ")
        };
      });
    };
    const capabilityRows = () => {
      if (!currentRopCorpus) {
        return [{ Error: NO_ROP_CORPUS_MESSAGE }];
      }
      return summarizeCapabilities(currentRopCorpus);
    };
    const helperHelp = (name) => {
      const entry = findHelpEntry(name);
      const rows = entry ? helpRows(entry) : [{ Error: `Unknown helper '${name}'.` }];
      renderRows(`Help: ${name}`, rows);
      setResult({
        command: "help",
        args: { command: name },
        success: entry !== void 0,
        findings: rows,
        warnings: [],
        errors: entry ? [] : [`Unknown helper '${name}'.`]
      });
      return toDxResult(`Help: ${name}`, rows);
    };
    const scanCorpus = (text, options = {}) => {
      currentRopCorpus = buildCapabilityIndexFromRpPlusText(text, options);
      const rows = summarizeCapabilities(currentRopCorpus);
      section("ROP Corpus Loaded");
      info(`Gadgets: ${currentRopCorpus.gadgets.length}`);
      info(`Capabilities: ${rows.length}`);
      setResult({
        command: "rop.scan",
        args: __spreadValues({ text }, options),
        success: true,
        findings: [{ gadgets: currentRopCorpus.gadgets.length, capabilities: rows.length }],
        warnings: [],
        errors: []
      });
      return toDxResult("ROP Corpus Loaded", [
        { Corpus: "loaded", Gadgets: currentRopCorpus.gadgets.length.toString(), Capabilities: rows.length.toString() }
      ]);
    };
    const scanLiveCorpus = (options) => {
      const discovery = discoverLiveGadgets(options);
      currentRopCorpus = buildCapabilityIndexFromSequences(sequencesFromLiveHits(discovery.hits));
      const rows = summarizeCapabilities(currentRopCorpus);
      section("Live ROP Corpus Loaded");
      info(`Gadgets: ${currentRopCorpus.gadgets.length} (from ${discovery.stats.discovered} live hits)`);
      info(`Capabilities: ${rows.length}`);
      if (discovery.stats.rejected > 0) {
        info(`Rejected by bad chars: ${discovery.stats.rejected}`);
      }
      setResult({
        command: "rop.scan_live",
        args: options,
        success: true,
        findings: [__spreadValues({ gadgets: currentRopCorpus.gadgets.length, capabilities: rows.length }, discovery.stats)],
        warnings: discovery.warnings,
        errors: []
      });
      return toDxResult("Live ROP Corpus Loaded", [
        { Corpus: "live", Gadgets: currentRopCorpus.gadgets.length.toString(), Capabilities: rows.length.toString() }
      ]);
    };
    const executeRopScanLive = (...args) => {
      if (args.length === 1 && args[0] === "help") {
        return helperHelp("rop.scan_live");
      }
      const options = isPlainObject(args[0]) ? args[0] : {};
      return scanLiveCorpus({
        module: options.module,
        badchars: options.badchars,
        maxPerPattern: options.maxPerPattern
      });
    };
    const executeRopScan = (...args) => {
      var _a, _b, _c;
      if (args.length === 1 && args[0] === "help") {
        return helperHelp("rop.scan");
      }
      if (args.length === 0) {
        const rows = [{ Error: "rop.scan requires RP++ text input." }];
        setResult({
          command: "rop.scan",
          args: {},
          success: false,
          findings: [],
          warnings: [],
          errors: ["RP++ text input is required."]
        });
        return toDxResult("ROP Scan", rows);
      }
      if (args.length === 1 && typeof args[0] === "string") {
        return scanCorpus(args[0]);
      }
      const options = isPlainObject(args[0]) ? args[0] : {};
      const text = (_c = (_b = (_a = options.text) != null ? _a : options.output) != null ? _b : options.value) != null ? _c : args[0];
      if (typeof text !== "string" || text.trim().length === 0) {
        const rows = [{ Error: "rop.scan requires a text property containing RP++ output." }];
        setResult({
          command: "rop.scan",
          args: options,
          success: false,
          findings: [],
          warnings: [],
          errors: ["RP++ text input is required."]
        });
        return toDxResult("ROP Scan", rows);
      }
      return scanCorpus(text, {
        source: options.source,
        provenance: options.provenance,
        preserveEmptyLines: options.preserveEmptyLines
      });
    };
    const executeRopQuery = (...args) => {
      if (args.length === 1 && args[0] === "help") {
        return helperHelp("rop.query");
      }
      const query = isPlainObject(args[0]) ? args[0] : void 0;
      if (!query) {
        const rows2 = [{ Error: "rop.query requires a query object." }];
        renderRows("ROP Query", rows2);
        setResult({
          command: "rop.query",
          args: {},
          success: false,
          findings: [],
          warnings: [],
          errors: ["Query object is required."]
        });
        return toDxResult("ROP Query", rows2);
      }
      if (!currentRopCorpus) {
        const rows2 = [{ Error: NO_ROP_CORPUS_MESSAGE }];
        renderRows("ROP Query", rows2);
        setResult({
          command: "rop.query",
          args: query,
          success: false,
          findings: [],
          warnings: [],
          errors: [NO_ROP_CORPUS_MESSAGE]
        });
        return toDxResult("ROP Query", rows2);
      }
      const gadgets = currentRopCorpus.query(query);
      const rows = queryRows(query);
      renderRows("ROP Query", rows);
      setResult({
        command: "rop.query",
        args: query,
        success: true,
        findings: gadgets,
        warnings: [],
        errors: []
      });
      return toDxResult("ROP Query", rows);
    };
    const executeRopCapabilities = (...args) => {
      if (args.length === 1 && args[0] === "help") {
        return helperHelp("rop.capabilities");
      }
      const rows = capabilityRows();
      renderRows("ROP Capabilities", rows);
      setResult({
        command: "rop.capabilities",
        args: {},
        success: currentRopCorpus !== void 0,
        findings: currentRopCorpus ? currentRopCorpus.gadgets : [],
        warnings: [],
        errors: currentRopCorpus ? [] : [NO_ROP_CORPUS_MESSAGE]
      });
      return toDxResult("ROP Capabilities", rows);
    };
    const parseChainTargets = (spec) => {
      if (Array.isArray(spec)) {
        return spec.filter((entry) => isPlainObject(entry)).map((entry) => {
          var _a, _b;
          return { register: String((_a = entry.register) != null ? _a : ""), value: Number((_b = entry.value) != null ? _b : 0) };
        }).filter((target) => target.register.length > 0);
      }
      if (isPlainObject(spec)) {
        return Object.entries(spec).map(([register, value]) => ({ register, value: Number(value) }));
      }
      return [];
    };
    const executeRopChain = (...args) => {
      var _a, _b;
      if (args.length === 1 && args[0] === "help") {
        return helperHelp("rop.chain");
      }
      if (!currentRopCorpus) {
        const rows2 = [{ Error: NO_ROP_CORPUS_MESSAGE }];
        renderRows("ROP Chain", rows2);
        setResult({ command: "rop.chain", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
        return toDxResult("ROP Chain", rows2);
      }
      const options = isPlainObject(args[0]) ? args[0] : {};
      const targets = parseChainTargets((_b = (_a = options.set) != null ? _a : options.targets) != null ? _b : options);
      if (targets.length === 0) {
        const rows2 = [{ Error: "rop.chain requires a register->value map, e.g. { set: { eax: 0xDEADBEEF } }." }];
        renderRows("ROP Chain", rows2);
        setResult({ command: "rop.chain", args: options, success: false, findings: [], warnings: [], errors: ["No chain targets provided."] });
        return toDxResult("ROP Chain", rows2);
      }
      const plan = planRegisterSetup(currentRopCorpus, targets);
      const python = formatChainPython(plan);
      section("ROP Chain (register setup)");
      info(`Satisfied: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
      for (const line of python) {
        print(line);
      }
      const warnings = plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`);
      for (const warning of warnings) {
        warn(warning);
      }
      const rows = plan.steps.map((step) => ({
        Word: step.kind === "gadget" ? `0x${step.address.toString(16).toUpperCase().padStart(8, "0")}` : `0x${(step.value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
        Meaning: step.comment
      }));
      renderRows("ROP Chain", rows);
      setResult({
        command: "rop.chain",
        args: options,
        success: plan.unsatisfied.length === 0,
        findings: [__spreadProps(__spreadValues({}, plan), { python })],
        warnings,
        errors: []
      });
      return toDxResult("ROP Chain", rows);
    };
    for (const command of registry.getAll()) {
      api[command.name] = (...args) => {
        return invoke(command.name, args);
      };
    }
    api.rop = {
      find: (...args) => {
        if (args.length === 1 && args[0] === "help") {
          return helperHelp("rop.find");
        }
        return invoke("rop", args);
      },
      scan: executeRopScan,
      scan_live: executeRopScanLive,
      query: executeRopQuery,
      capabilities: executeRopCapabilities,
      chain: executeRopChain
    };
    api.rop_find = (...args) => invoke("rop", args);
    api.pattern = {
      create: (...args) => invoke("pattern_create", args),
      offset: (...args) => invoke("pattern_offset", args)
    };
    api.seh = {
      visualize: (...args) => invoke("seh", args)
    };
    api.fmt = {
      build: (...args) => invoke("fmt_build", args),
      offset: (...args) => invoke("fmt_offset", args)
    };
    api.last_result = () => lastResult;
    api.version = (...args) => {
      if (args.length === 1 && args[0] === "help") {
        return invoke("version", args);
      }
      invoke("version", []);
      return getVersionInfo();
    };
    api.last_summary = () => {
      if (!lastResult) {
        return {
          success: false,
          command: "",
          warnings: 0,
          errors: 0,
          findings: 0
        };
      }
      return {
        success: lastResult.success,
        command: lastResult.command,
        warnings: lastResult.warnings.length,
        errors: lastResult.errors.length,
        findings: lastResult.findings.length
      };
    };
    api.clear_last_result = () => {
      lastResult = void 0;
      return true;
    };
    api.sc = createShellcodeNamespace();
    const analysisAddress = (value) => {
      if (typeof value === "bigint" && value >= BigInt(0)) return value;
      if (typeof value === "number" && Number.isInteger(value) && value >= 0) return BigInt(value);
      if (typeof value === "string" && /^(0x)?[0-9a-f`]+$/i.test(value.trim())) {
        return BigInt(`0x${value.trim().replace(/^0x/i, "").replace(/`/g, "")}`);
      }
      throw new Error("Address must be a non-negative integer, bigint, or hex string.");
    };
    const commandAddress = (value) => {
      const address = analysisAddress(value);
      return address <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(address) : `0x${address.toString(16)}`;
    };
    api.memory = (address) => {
      invoke("memory", [commandAddress(address)]);
      return lastResult == null ? void 0 : lastResult.findings[0];
    };
    api.can_execute = (address) => {
      const evidence = api.memory(address);
      return evidence.executable;
    };
    api.landing = (address) => {
      invoke("landing", address === void 0 ? [] : [commandAddress(address)]);
      return lastResult == null ? void 0 : lastResult.findings[0];
    };
    api.math = (...args) => {
      invoke("math", args);
      return lastResult == null ? void 0 : lastResult.findings[0];
    };
    return api;
  }
  function isPlainObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
  }
  function parseHexByteList(value) {
    if (Array.isArray(value)) {
      return value;
    }
    if (typeof value !== "string") {
      return value;
    }
    const tokens = value.split(/[,\s]+/).filter((token) => token.length > 0);
    if (tokens.length === 0) {
      return [];
    }
    const parsed = [];
    for (const token of tokens) {
      if (/^[0-9a-fA-F]{1,2}$/.test(token)) {
        parsed.push(parseInt(token, 16));
        continue;
      }
      if (/^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0) {
        for (let i = 0; i < token.length; i += 2) {
          parsed.push(parseInt(token.slice(i, i + 2), 16));
        }
        continue;
      }
      return value;
    }
    return parsed;
  }
  function normalizeInvocation(commandName, args) {
    if (args.length === 0 || args.length === 1 && args[0] === void 0) {
      return {};
    }
    if (args.length === 1 && isPlainObject(args[0])) {
      return args[0];
    }
    switch (commandName) {
      case "help":
        return { command: args[0] };
      case "pattern_create":
        return { length: args[0], type: args[1] };
      case "pattern_offset":
        return { value: args[0], type: args[1] };
      case "badchars":
        return { address: args[0], exclude: parseHexByteList(args[1]) };
      case "egghunter":
        return { tag: args[0], mode: args[1], wow64: args[2] };
      case "exploit":
        return { mode: args[0], tag: args[1], offset: args[2], address: args[3] };
      case "modules":
        return { filter: args[0] };
      case "math":
        return { value: args[0], bits: args[1] };
      case "rop":
      case "rop_suggest":
      case "pivots":
      case "retn":
      case "add_esp":
        return commandName === "rop_suggest" ? {
          module: args[0],
          maxResults: args[1],
          executableOnly: args[2],
          mode: args[3],
          engine: args[4]
        } : {
          module: args[0],
          maxResults: args[1],
          executableOnly: args[2],
          mode: args[3]
        };
      case "nop":
        return { length: args[0], byte: args[1] };
      case "rop_template":
        return { api: args[0], module: args[1] };
      case "fmt_build":
        return {
          writes: [{ addr: args[0], value: args[1] }],
          argIndex: args[2],
          width: args[3],
          exclude: parseHexByteList(args[4]),
          prefix: args[5]
        };
      case "fmt_offset":
        return { marker: args[0], count: args[1], firstArg: args[2] };
      case "encode":
        return {
          shellcode: args[0],
          exclude: parseHexByteList(args[1]),
          key: args[2]
        };
      case "find_bytes":
        return {
          module: args[0],
          bytes: parseHexByteList(args[1]),
          maxResults: args[2],
          executableOnly: args[3],
          mode: args[4]
        };
      case "reload":
      case "seh":
        return {};
      case "seh_ppr":
        return {
          module: args[0],
          exclude: parseHexByteList(args[1]),
          maxResults: args[2],
          executableOnly: args[3],
          mode: args[4]
        };
      case "triage":
        return {
          patternLength: args[0],
          badchars: parseHexByteList(args[1]),
          module: args[2],
          stackBytes: args[3]
        };
      case "memory":
      case "landing":
        return { address: args[0] };
      default:
        return { value: args[0] };
    }
  }
  function initialize() {
    currentRopCorpus = void 0;
    registry.setReloader(() => {
      currentRopCorpus = void 0;
      registerAll();
      osed = bindApi();
      publishOsed();
    });
    registerAll();
    osed = bindApi();
    publishOsed();
  }
  function initializeScript() {
    const registrations = [];
    const hostAny = host;
    if (hostAny.apiVersionSupport) {
      registrations.push(new hostAny.apiVersionSupport(1, 7));
    }
    initialize();
    if (hostAny.functionAlias) {
      try {
        registrations.push(new hostAny.functionAlias(() => osed, "osed"));
      } catch (error2) {
        const message = error2 instanceof Error ? error2.message : String(error2);
        const globalObject = getGlobalObject();
        if (globalObject) {
          globalObject.osed = osed;
        }
        if (typeof host !== "undefined" && host.diagnostics && typeof host.diagnostics.debugLog === "function") {
          host.diagnostics.debugLog(`osed: functionAlias registration failed, using global object fallback: ${message}
`);
        }
      }
    }
    return registrations;
  }
  return __toCommonJS(index_exports);
})();
var __osed_global = (typeof globalThis !== 'undefined') ? globalThis : (typeof self !== 'undefined' ? self : (typeof this !== 'undefined' ? this : undefined));
if (__osed_global && __osed_global.osed_bundle && __osed_global.osed_bundle.initializeScript) { __osed_global.initializeScript = __osed_global.osed_bundle.initializeScript; }
