export type ValidationIssue = {
  path: string;
  message: string;
};

export type ValidationResult<T> = {
  success: boolean;
  value?: T;
  errors: ValidationIssue[];
  warnings: string[];
};

export type PrimitiveType = "number" | "string" | "boolean" | "array" | "object";

export type FieldSchema = {
  type: PrimitiveType | PrimitiveType[];
  required?: boolean;
  enum?: string[];
  min?: number;
  max?: number;
  default?: unknown;
  elementType?: "number" | "string" | "boolean";
};

export type ObjectSchema = Record<string, FieldSchema>;

function kindOf(value: unknown): PrimitiveType {
  if (Array.isArray(value)) {
    return "array";
  }

  if (value === null) {
    return "object";
  }

  return typeof value as PrimitiveType;
}

export function validateOptions(options: unknown, schema: ObjectSchema): ValidationResult<Record<string, unknown>> {
  const errors: ValidationIssue[] = [];
  const warnings: string[] = [];

  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    return {
      success: false,
      errors: [{ path: "$", message: "Options must be an object." }],
      warnings,
    };
  }

  const input = options as Record<string, unknown>;
  const normalized: Record<string, unknown> = {};

  for (const key of Object.keys(input)) {
    if (!(key in schema)) {
      errors.push({ path: key, message: "Unknown option key." });
    }
  }

  for (const [key, rules] of Object.entries(schema)) {
    const value = input[key];

    if (value === undefined) {
      if (rules.default !== undefined) {
        normalized[key] = rules.default;
      } else if (rules.required) {
        errors.push({ path: key, message: "Missing required option." });
      }
      continue;
    }

    const expectedTypes = Array.isArray(rules.type) ? rules.type : [rules.type];
    const actual = kindOf(value);
    if (!expectedTypes.includes(actual)) {
      errors.push({ path: key, message: `Expected ${expectedTypes.join(" | ")}.` });
      continue;
    }

    if (rules.enum && typeof value === "string" && !rules.enum.includes(value)) {
      errors.push({ path: key, message: `Expected one of: ${rules.enum.join(", ")}.` });
      continue;
    }

    if (typeof value === "number") {
      if (!Number.isFinite(value) || !Number.isInteger(value)) {
        errors.push({ path: key, message: "Expected finite integer." });
        continue;
      }

      if (rules.min !== undefined && value < rules.min) {
        errors.push({ path: key, message: `Must be >= ${rules.min}.` });
        continue;
      }

      if (rules.max !== undefined && value > rules.max) {
        normalized[key] = rules.max;
        warnings.push(`${key} clamped to ${rules.max}.`);
        continue;
      }
    }

    if (Array.isArray(value) && rules.elementType) {
      const invalid = value.find((entry) => typeof entry !== rules.elementType);
      if (invalid !== undefined) {
        errors.push({ path: key, message: `Array entries must be ${rules.elementType}.` });
        continue;
      }
    }

    normalized[key] = value;
  }

  if (errors.length > 0) {
    return { success: false, errors, warnings };
  }

  return {
    success: true,
    value: normalized,
    errors: [],
    warnings,
  };
}

export function normalizeAddress(value: unknown): bigint {
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

export function normalizeByteArray(values: number[]): { values: number[]; warning?: string } {
  const invalid = values.find((value) => !Number.isInteger(value) || value < 0 || value > 0xff);
  if (invalid !== undefined) {
    throw new Error("Byte arrays must contain integers in range 0x00..0xFF.");
  }

  const sorted = [...values].sort((a, b) => a - b);
  const unique: number[] = [];
  for (const value of sorted) {
    if (unique.length === 0 || unique[unique.length - 1] !== value) {
      unique.push(value);
    }
  }

  if (unique.length !== values.length) {
    return {
      values: unique,
      warning: "Duplicate exclude bytes were removed during normalization.",
    };
  }

  return { values: unique };
}
