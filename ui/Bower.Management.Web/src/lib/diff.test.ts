import { describe, expect, it } from "vitest";
import { collapseUnchanged, diffLines } from "./diff";

describe("line diff", () => {
  it("reports removed then added lines with line numbers", () => {
    const diff = diffLines("a\nb\nc\n", "a\nB\nc\nd\n");
    expect(diff.tooLarge).toBe(false);
    if (diff.tooLarge) return;
    expect(diff.lines.map((line) => `${line.kind}:${line.text}`)).toEqual([
      "same:a",
      "remove:b",
      "add:B",
      "same:c",
      "add:d"
    ]);
    expect(diff.added).toBe(2);
    expect(diff.removed).toBe(1);
    expect(diff.lines[1]).toMatchObject({ oldLine: 2 });
    expect(diff.lines[2]).toMatchObject({ newLine: 2 });
    expect(diff.lines[4]).toMatchObject({ newLine: 4 });
  });

  it("finds the longest common subsequence in the changed middle", () => {
    const diff = diffLines("x\n1\n2\n3\ny", "x\n2\n3\n4\ny");
    if (diff.tooLarge) throw new Error("unexpected");
    expect(diff.lines.filter((line) => line.kind === "same").map((line) => line.text)).toEqual([
      "x",
      "2",
      "3",
      "y"
    ]);
  });

  it("treats identical content and CRLF line endings as unchanged", () => {
    const diff = diffLines("a\r\nb\r\n", "a\nb");
    if (diff.tooLarge) throw new Error("unexpected");
    expect(diff.added + diff.removed).toBe(0);
  });

  it("falls back when a side exceeds the line limit", () => {
    expect(diffLines("a\nb\nc", "a", 2).tooLarge).toBe(true);
  });

  it("collapses long unchanged runs outside the context window", () => {
    const previous = Array.from({ length: 20 }, (_, index) => `line ${index}`).join("\n");
    const next = previous.replace("line 10", "line ten");
    const diff = diffLines(previous, next);
    if (diff.tooLarge) throw new Error("unexpected");
    const segments = collapseUnchanged(diff.lines, 2);
    expect(segments.map((segment) => segment.kind)).toEqual(["collapsed", "lines", "collapsed"]);
    expect(segments[0]).toEqual({ kind: "collapsed", count: 8 });
    expect(segments[2]).toEqual({ kind: "collapsed", count: 7 });
  });

  it("shows short unchanged runs instead of collapsing them", () => {
    const diff = diffLines("a\nb\nc\nd\ne", "a\nb\nc\nd\nE");
    if (diff.tooLarge) throw new Error("unexpected");
    const segments = collapseUnchanged(diff.lines, 3);
    expect(segments).toHaveLength(1);
    expect(segments[0]?.kind).toBe("lines");
  });
});
