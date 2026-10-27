import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { glossary } from "../components/glossary";
import { Page } from "../components/ui";

/** Glossary for the plain-English views. A link to /help#<term> moves focus to that entry. */
export function HelpPage() {
  const { hash } = useLocation();

  useEffect(() => {
    const target = hash ? document.getElementById(decodeURIComponent(hash.slice(1))) : null;
    if (target) {
      target.focus();
      target.scrollIntoView?.({ block: "start" });
    }
  }, [hash]);

  return (
    <Page title="Help" description="What the words on the home and setup pages mean.">
      <section className="sheet section-gap" aria-labelledby="glossary-title">
        <div className="section-heading">
          <h2 id="glossary-title">Glossary</h2>
        </div>
        <dl className="glossary-list">
          {glossary.map((entry) => (
            <div key={entry.id}>
              <dt id={entry.id} tabIndex={-1}>
                {entry.term}
              </dt>
              <dd>{entry.definition}</dd>
            </div>
          ))}
        </dl>
      </section>
    </Page>
  );
}
