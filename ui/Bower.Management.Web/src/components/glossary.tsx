import { Fragment, type ReactNode, useCallback, useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import entries from "./glossary.json";

/*
 * Plain-English glossary for guided views. Terms in page text link to /help#<id>, so a
 * word that might be unfamiliar is always one click from its meaning. No third-party
 * help scripts: the help content ships with the console.
 */

export interface GlossaryEntry {
  id: string;
  term: string;
  definition: string;
  /** Phrases that link to this entry, matched case-insensitively on word boundaries. */
  matches: string[];
}

export const glossary: GlossaryEntry[] = entries;

const phrases = glossary
  .flatMap((entry) => entry.matches.map((phrase) => ({ phrase, entry })))
  .sort((left, right) => right.phrase.length - left.phrase.length);

const pattern = new RegExp(
  `\\b(${phrases.map(({ phrase }) => phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\b`,
  "gi"
);

/**
 * Renders plain text with the first mention of each glossary term linked to its help entry.
 * The text is never parsed as markup.
 */
export function GlossaryText({ text }: { text: string }) {
  const linked = new Set<string>();
  const parts: ReactNode[] = [];
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    const entry = phrases.find(({ phrase }) => phrase.toLowerCase() === match[0].toLowerCase())?.entry;
    if (!entry || linked.has(entry.id) || match.index === undefined) {
      continue;
    }
    linked.add(entry.id);
    parts.push(text.slice(last, match.index));
    parts.push(
      <GlossaryTerm key={match.index} entry={entry}>{match[0]}</GlossaryTerm>
    );
    last = match.index + match[0].length;
  }
  parts.push(text.slice(last));
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>{part}</Fragment>
      ))}
    </>
  );
}

/** Keyboard and pointer help; following the link also works on touch screens. */
function GlossaryTerm({ entry, children }: { entry: GlossaryEntry; children: ReactNode }) {
  const id = useId();
  const link = useRef<HTMLAnchorElement>(null);
  const hovered = useRef(false);
  const [position, setPosition] = useState<{ left: number; top?: number; bottom?: number; maxHeight: number } | null>(null);
  const show = useCallback(() => {
    const bounds = link.current?.getBoundingClientRect();
    if (!bounds || bounds.bottom < 0 || bounds.top > window.innerHeight) {
      setPosition(null);
      return;
    }
    const width = Math.min(18.5 * parseFloat(getComputedStyle(document.documentElement).fontSize || "16"), window.innerWidth - 16);
    setPosition({
      left: Math.max(8, Math.min(bounds.left, window.innerWidth - width - 8)),
      maxHeight: Math.max(0, (bounds.bottom < window.innerHeight / 2 ? window.innerHeight - bounds.bottom : bounds.top) - 8),
      ...(bounds.bottom < window.innerHeight / 2 ? { top: bounds.bottom } : { bottom: window.innerHeight - bounds.top })
    });
  }, []);
  const visible = position !== null;
  useEffect(() => {
    if (!visible) return;
    const hide = () => setPosition(null);
    const key = (event: KeyboardEvent) => { if (event.key === "Escape") hide(); };
    window.addEventListener("keydown", key);
    window.addEventListener("resize", show);
    window.addEventListener("scroll", show, true);
    return () => {
      window.removeEventListener("keydown", key);
      window.removeEventListener("resize", show);
      window.removeEventListener("scroll", show, true);
    };
  }, [visible, show]);
  return <span
    className="glossary-anchor"
    onMouseEnter={() => { hovered.current = true; show(); }}
    onMouseLeave={() => { hovered.current = false; if (document.activeElement !== link.current) setPosition(null); }}
    onKeyDown={(event) => { if (event.key === "Escape") { setPosition(null); event.stopPropagation(); } }}
  >
    <Link ref={link} className="glossary-term" to={`/help#${entry.id}`}
      aria-describedby={position ? id : undefined}
      onFocus={show} onBlur={() => { if (!hovered.current) setPosition(null); }}
      onClick={() => setPosition(null)}>
      {children}
    </Link>
    {position && <span id={id} role="tooltip" className="glossary-tooltip" style={position}>
      {entry.definition}
    </span>}
  </span>;
}
