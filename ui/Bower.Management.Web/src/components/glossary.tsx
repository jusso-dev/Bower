import { Fragment, type ReactNode } from "react";
import { Link } from "react-router-dom";

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

export const glossary: GlossaryEntry[] = [
  {
    id: "collector",
    term: "Collector",
    definition:
      "The small Bower program on one of your machines. It gathers security events, removes sensitive details and sends the events on.",
    matches: ["collectors", "collector"]
  },
  {
    id: "sentinel",
    term: "Microsoft Sentinel",
    definition:
      "Microsoft's security monitoring service. Your security team searches the events Bower sends there.",
    matches: ["Microsoft Sentinel", "Sentinel"]
  },
  {
    id: "test-event",
    term: "Test event",
    definition:
      "A harmless event Bower sends on purpose and then looks for in Microsoft Sentinel. Finding it proves the whole path works. A simulated test skips that check, so it is not proof.",
    matches: ["test event"]
  },
  {
    id: "privacy-profile",
    term: "Privacy profile",
    definition:
      "Your rules for which sensitive details Bower removes or masks before anything is stored or sent.",
    matches: ["privacy profile"]
  },
  {
    id: "event-rules",
    term: "Event rules",
    definition:
      "The approved rules that decide which security events Bower keeps and sends. Everything else is dropped.",
    matches: ["event rules"]
  },
  {
    id: "set-aside",
    term: "Set aside",
    definition:
      "Events Bower could not send after many tries. They are kept, not deleted, so someone can review them.",
    matches: ["set aside"]
  },
  {
    id: "group",
    term: "Group",
    definition:
      "Collectors that share an environment name, such as production or staging. Each group gets one traffic light.",
    matches: []
  }
];

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
      <Link key={match.index} className="glossary-term" to={`/help#${entry.id}`}>
        {match[0]}
      </Link>
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
