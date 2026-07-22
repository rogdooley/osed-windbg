export type TableColumn = {
  key: string;
  header: string;
  width?: number;
};

function write(line = ""): void {
  host.diagnostics.debugLog(`${line}\n`);
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : `${value}${" ".repeat(width - value.length)}`;
}

export function stripDml(value: string): string {
  return value.replace(/<link\b[^>]*>(.*?)<\/link>/gi, "$1");
}

function visibleLength(value: string): number {
  return stripDml(value).length;
}

export function print(message: string): void {
  write(message);
}

export function section(title: string): void {
  write();
  write(`=== ${title} ===`);
}

export function info(message: string): void {
  write(`[+] ${message}`);
}

export function warn(message: string): void {
  write(`[!] ${message}`);
}

export function error(message: string): void {
  write(`[-] ${message}`);
}

export function whyItMatters(line: string): void {
  write(`Why this matters for exploitation: ${line}`);
}

export function formatAddress(address: bigint, pointerSize: 4 | 8): string {
  const width = pointerSize === 8 ? 16 : 8;
  return `0x${address.toString(16).toUpperCase().padStart(width, "0")}`;
}

export function formatHexByte(byte: number): string {
  return `0x${(byte & 0xff).toString(16).toUpperCase().padStart(2, "0")}`;
}

export function table(columns: TableColumn[], rows: Array<Record<string, string>>): void {
  const hasVisibleValues = rows.some((row) =>
    columns.some((column) => {
      const value = row[column.key];
      return value !== undefined && value !== "";
    }),
  );

  if (rows.length === 0 || !hasVisibleValues) {
    write("(no rows)");
    return;
  }

  const widths = columns.map((column) => {
    const maxValueWidth = rows.reduce((max, row) => {
      const value = row[column.key] ?? "";
      return Math.max(max, visibleLength(value));
    }, 0);

    return Math.max(column.width ?? 0, column.header.length, maxValueWidth);
  });

  const render = (values: string[]) => values.map((value, i) => pad(stripDml(value), widths[i])).join("  ");

  write(render(columns.map((column) => column.header)));
  write(render(widths.map((width) => "-".repeat(width))));

  for (const row of rows) {
    write(render(columns.map((column) => row[column.key] ?? "")));
  }
}
