import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { GlossaryText, glossary } from "../components/glossary";
import { helpGuides } from "../components/helpGuides";
import { SetupChecklist } from "../components/SetupChecklist";
import { Page } from "../components/ui";

/** Glossary for the plain-English views. A link to /help#<term> moves focus to that entry. */
export function HelpPage() {
  const { hash } = useLocation();

  useEffect(() => {
    let id: string;
    try { id = decodeURIComponent(hash.slice(1)); } catch { return; }
    const target = id ? document.getElementById(id) : null;
    if (target) {
      target.focus();
      target.scrollIntoView?.({ block: "start" });
    }
  }, [hash]);

  return (
    <Page title="Help" description="Find your next step, check setup progress and understand Bower’s terms.">
      <SetupChecklist />
      <section className="sheet section-gap" aria-labelledby="guides-title">
        <div className="section-heading"><h2 id="guides-title">Help for each page</h2></div>
        <div className="help-guides">
          {helpGuides.map(guide => <article key={guide.id}>
            <h3 id={guide.id} tabIndex={-1}>{guide.title}</h3>
            <p><GlossaryText text={guide.text} /></p>
            <Link to={guide.to}>{guide.action}</Link>
          </article>)}
        </div>
      </section>
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
