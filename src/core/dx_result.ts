class DxRow {
  public constructor(values: Record<string, string>) {
    for (const [key, value] of Object.entries(values)) {
      (this as unknown as Record<string, string>)[key] = value;
    }
  }

  public toString(): string {
    const pairs = Object.entries(this as unknown as Record<string, string>).filter(([, value]) => typeof value === "string");
    return pairs.map(([key, value]) => `${key}: ${value}`).join(" | ");
  }
}

export class DxResult {
  public readonly rows: DxRow[];
  public readonly length: number;

  public constructor(
    public readonly title: string,
    rows: Array<Record<string, string>>,
  ) {
    this.rows = rows.map((row) => new DxRow(row));
    this.length = this.rows.length;
  }

  public toString(): string {
    return `${this.title}: ${this.length} row${this.length === 1 ? "" : "s"}`;
  }
}

export function toDxResult(title: string, rows: Array<Record<string, string>>): DxResult {
  return new DxResult(title, rows);
}
