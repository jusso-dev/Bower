/** Upper bound on lines per side; larger documents get a fallback message instead of a diff. */
export const maxDiffLines = 4000;

export type DiffLineKind = "same" | "add" | "remove";

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
  /** 1-based line number in the previous document (absent for added lines). */
  oldLine?: number;
  /** 1-based line number in the new document (absent for removed lines). */
  newLine?: number;
}

export type LineDiff =
  | { tooLarge: false; lines: DiffLine[]; added: number; removed: number }
  | { tooLarge: true };

function splitLines(value: string): string[] {
  if (value === "") {
    return [];
  }
  const lines = value.replace(/\r\n?/g, "\n").split("\n");
  // A trailing newline does not introduce an extra empty line.
  if (lines.length > 1 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

/**
 * Line diff using a longest-common-subsequence table. Common prefix and suffix are
 * trimmed first so typical small edits stay cheap; inputs are bounded by
 * {@link maxDiffLines} per side.
 */
export function diffLines(previous: string, next: string, limit = maxDiffLines): LineDiff {
  const a = splitLines(previous);
  const b = splitLines(next);
  if (a.length > limit || b.length > limit) {
    return { tooLarge: true };
  }

  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) {
    start++;
  }
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }

  const n = endA - start;
  const m = endB - start;
  const width = m + 1;
  // table[i * width + j] = LCS length of a[start + i..endA) and b[start + j..endB).
  const table = new Uint16Array((n + 1) * width);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      table[i * width + j] =
        a[start + i] === b[start + j]
          ? (table[(i + 1) * width + j + 1] ?? 0) + 1
          : Math.max(table[(i + 1) * width + j] ?? 0, table[i * width + j + 1] ?? 0);
    }
  }

  const lines: DiffLine[] = [];
  let added = 0;
  let removed = 0;
  for (let k = 0; k < start; k++) {
    lines.push({ kind: "same", text: a[k] ?? "", oldLine: k + 1, newLine: k + 1 });
  }
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    const oldIndex = start + i;
    const newIndex = start + j;
    if (i < n && j < m && a[oldIndex] === b[newIndex]) {
      lines.push({ kind: "same", text: a[oldIndex] ?? "", oldLine: oldIndex + 1, newLine: newIndex + 1 });
      i++;
      j++;
    } else if (
      i < n &&
      (j >= m || (table[(i + 1) * width + j] ?? 0) >= (table[i * width + j + 1] ?? 0))
    ) {
      // Removals are emitted before additions so a changed line reads old then new.
      lines.push({ kind: "remove", text: a[oldIndex] ?? "", oldLine: oldIndex + 1 });
      removed++;
      i++;
    } else {
      lines.push({ kind: "add", text: b[newIndex] ?? "", newLine: newIndex + 1 });
      added++;
      j++;
    }
  }
  for (let k = 0; k < a.length - endA; k++) {
    lines.push({
      kind: "same",
      text: a[endA + k] ?? "",
      oldLine: endA + k + 1,
      newLine: endB + k + 1
    });
  }
  return { tooLarge: false, lines, added, removed };
}

export type DiffSegment =
  | { kind: "lines"; lines: DiffLine[] }
  | { kind: "collapsed"; count: number };

/** Keeps `context` unchanged lines around each change and collapses longer unchanged runs. */
export function collapseUnchanged(lines: DiffLine[], context = 3): DiffSegment[] {
  const keep = lines.map(() => false);
  lines.forEach((line, index) => {
    if (line.kind !== "same") {
      for (
        let k = Math.max(0, index - context);
        k <= Math.min(lines.length - 1, index + context);
        k++
      ) {
        keep[k] = true;
      }
    }
  });

  const segments: DiffSegment[] = [];
  let index = 0;
  while (index < lines.length) {
    const kept = keep[index] ?? false;
    let end = index;
    while (end < lines.length && (keep[end] ?? false) === kept) {
      end++;
    }
    // Hiding one or two lines saves nothing; show them instead.
    const show = kept || end - index <= 2;
    const previous = segments[segments.length - 1];
    if (show && previous?.kind === "lines") {
      previous.lines.push(...lines.slice(index, end));
    } else {
      segments.push(
        show
          ? { kind: "lines", lines: lines.slice(index, end) }
          : { kind: "collapsed", count: end - index }
      );
    }
    index = end;
  }
  return segments;
}
