import { stripDml } from "./output";

class DxRow {
  public constructor(values: Record<string, string>) {
    for (const [key, value] of Object.entries(values)) {
      (this as unknown as Record<string, string>)[key] = value;
    }
  }

  public toString(): string {
    const pairs = Object.entries(this as unknown as Record<string, string>).filter(([, value]) => typeof value === "string");
    return pairs.map(([key, value]) => `${key}: ${stripDml(value)}`).join(" | ");
  }
}

class DxRows implements Iterable<DxRow> {
  [index: number]: DxRow;
  public readonly length: number;
  private readonly title!: string;
  private readonly values!: DxRow[];

  public constructor(title: string, values: DxRow[]) {
    Object.defineProperty(this, "title", {
      value: title,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    Object.defineProperty(this, "values", {
      value: values,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    this.length = values.length;
    values.forEach((row, index) => {
      Object.defineProperty(this, index, {
        value: row,
        enumerable: false,
        configurable: false,
        writable: false,
      });
    });
  }

  public [Symbol.iterator](): Iterator<DxRow> {
    return this.values[Symbol.iterator]();
  }

  public map<T>(callback: (row: DxRow, index: number, rows: DxRow[]) => T): T[] {
    return this.values.map(callback);
  }

  public forEach(callback: (row: DxRow, index: number, rows: DxRow[]) => void): void {
    this.values.forEach(callback);
  }

  public slice(start?: number, end?: number): DxRow[] {
    return this.values.slice(start, end);
  }

  public toArray(): DxRow[] {
    return [...this.values];
  }

  public toString(): string {
    return `${this.title}: ${this.length} row${this.length === 1 ? "" : "s"}; expand rows[N] for details`;
  }
}

export class DxResult {
  public readonly rows: DxRows;
  public readonly length: number;

  public constructor(
    public readonly title: string,
    rows: Array<Record<string, string>>,
  ) {
    this.rows = new DxRows(title, rows.map((row) => new DxRow(row)));
    this.length = this.rows.length;
  }

  public toString(): string {
    return `${this.title}: ${this.length} row${this.length === 1 ? "" : "s"}`;
  }
}

export function toDxResult(title: string, rows: Array<Record<string, string>>): DxResult {
  return new DxResult(title, rows);
}
