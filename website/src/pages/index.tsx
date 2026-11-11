import { useState } from "react";
import Layout from "@theme/Layout";
import Link from "@docusaurus/Link";
import useBaseUrl from "@docusaurus/useBaseUrl";
import CodeBlock from "@theme/CodeBlock";
import ConsoleGallery from "../components/ConsoleGallery";
import styles from "./index.module.css";

// Every claim here is taken from the README and the docs it links to. Keep it that way: when a
// page changes what Bower does, change the matching line here.

const INSTALLS = [
  {
    id: "linux",
    label: "Linux",
    language: "bash",
    code: `tar -xzf bower-collector-offline-0.1.0-linux-amd64.tar.gz
cd bower-collector-offline-0.1.0-linux-amd64
(umask 077; cat >seed/enrolment-token)   # paste the one-time token, then Ctrl-D
sudo ./install.sh --endpoint https://bower-management.example.com/ --environment production`,
    guide: "/deployment/installers/"
  },
  {
    id: "windows",
    label: "Windows",
    language: "powershell",
    code: `msiexec /i bower-collector-0.1.0-x64.msi /qn \`
  MANAGEMENTENDPOINT=https://bower-management.example.com/ BOWERENVIRONMENT=production`,
    guide: "/deployment/installers/"
  },
  {
    id: "containers",
    label: "Containers",
    language: "bash",
    code: `# edge: the last published main build. Pin production by version or digest.
docker pull ghcr.io/jusso-dev/bower-collector:edge
docker pull ghcr.io/jusso-dev/bower-management:edge
docker pull ghcr.io/jusso-dev/bower-web:edge`,
    guide: "/deployment/container-images/"
  },
  {
    id: "test",
    label: "First event",
    language: "bash",
    code: `bower test emit                      # a synthetic event through the whole pipeline
bower doctor --policy-directory /etc/bower/policies
bower evidence run --collector-url http://127.0.0.1:4319`,
    guide: "/getting-started/first-event/"
  }
];

const STAGES = [
  { n: "01", name: "Collect", text: "Applications, machines and cloud sources send security events to a collector you run." },
  { n: "02", name: "Select", text: "An approved, versioned policy keeps only the event types it names. Everything else is denied and explained." },
  { n: "03", name: "Arrange", text: "Events are structured and sensitive details are redacted before anything is stored." },
  { n: "04", name: "Deliver", text: "A durable, hash-chained queue delivers with retries, dead letters and audited replay." },
  { n: "05", name: "Prove", text: "A canary is queried in Sentinel. An evidence bundle records what was found." }
];

const FEATURES = [
  { title: "Proof of arrival", text: "bower evidence run queries a canary in Sentinel and records the observed result. Acceptance by a collector or an API is never reported as delivery.", to: "/operations/evidence-bundles/" },
  { title: "Redaction before it leaves the host", text: "Deterministic, checksum-validated detection of TFN, Medicare, IHI, ABN, ACN, cards and secrets. Any failure quarantines the event.", to: "/privacy/privacy-secret-engine/" },
  { title: "Default deny", text: "Only event types an approved policy names are kept. Unknown events are rejected with a reason you can read.", to: "/getting-started/concepts/" },
  { title: "Delivery accounting", text: "Acknowledged retention, bounded outages, retained dead letters, preflight and DCR drift checks.", to: "/operations/fleet-and-queue-integrity/" },
  { title: "Tamper evidence", text: "A hash-chained queue ledger whose head is witnessed by the management plane.", to: "/operations/queue-v5-durability/" },
  { title: "Signed packs", text: "Policy, privacy profile, parsers, detections and DCR ship together, signed, hash-pinned and tested before signing.", to: "/deployment/packs/" }
];

const PATHS = [
  { title: "Linux and Windows hosts", text: "deb, rpm and MSI packages, offline bundles and an Ansible role.", to: "/deployment/installers/" },
  { title: "Azure Monitor Agent", text: "Send events through local syslog and a collection rule into BowerSecurity_CL.", to: "/getting-started/azure-monitor-agent/" },
  { title: "AWS CloudWatch agent", text: "Write a file the agent ships; the cloud forwarder brings it to the collector.", to: "/getting-started/aws-cloudwatch-agent/" },
  { title: "Containers and sidecars", text: "Collector, console and API images, plus a Docker sidecar for labelled containers.", to: "/deployment/container-images/" },
  { title: "AWS and Google Cloud", text: "GuardDuty, Security Hub, CloudTrail and Security Command Center through one contract.", to: "/deployment/aws/" },
  { title: "Relay networks", text: "Mutual TLS between segmented networks, with an allow-list of collectors.", to: "/deployment/relay/" }
];

const SOURCES = ["ASP.NET Core", "Next.js", "Express · Fastify · NestJS", "Django · Flask · FastAPI", "Rails", "Laravel", "Spring Boot", "Go log/slog", "Syslog", "Windows Event Log", "Local files", "Docker containers"];

const COMPARE = [
  ["Proof of arrival", "A canary is queried in Sentinel and the result is recorded", "Stops at \"the API accepted it\"; checking Sentinel is manual"],
  ["Redaction", "On the host, deterministic, before anything is stored", "In Azure after transfer, or a paid redaction processor"],
  ["What is kept", "Only event types an approved policy names", "Everything configured, filtered later"],
  ["Delivery accounting", "Durable queue, dead letters, audited replay, drift checks", "Rows can be dropped without a per-record error"],
  ["Tamper evidence", "Hash-chained queue ledger, witnessed head", "Not offered at the collector"],
  ["Content", "Signed, hash-pinned, tested packs", "Unsigned community content"],
  ["Where it runs", "Your infrastructure; the console belongs to your tenant", "Often a hosted control plane"]
];

function InstallTabs() {
  const [active, setActive] = useState(0);
  const item = INSTALLS[active];
  return (
    <div className={styles.install}>
      <div role="tablist" aria-label="Install" className={styles.installTabs}>
        {INSTALLS.map((entry, index) => (
          <button key={entry.id} role="tab" type="button" aria-selected={index === active}
            className={index === active ? styles.installTabActive : styles.installTab}
            onClick={() => setActive(index)}>{entry.label}</button>
        ))}
      </div>
      <div role="tabpanel" aria-label={item.label}>
        <CodeBlock language={item.language}>{item.code}</CodeBlock>
      </div>
      <Link className={styles.installGuide} to={item.guide}>Full {item.label.toLowerCase()} guide →</Link>
    </div>
  );
}

function SectionHead({ n, eyebrow, title, children }: { n: string; eyebrow: string; title: string; children?: React.ReactNode }) {
  return (
    <header className={styles.sectionHead}>
      <p className={styles.eyebrow}><span>{n}</span> {eyebrow}</p>
      <h2>{title}</h2>
      {children && <p className={styles.lede}>{children}</p>}
    </header>
  );
}

export default function Home() {
  const hero = useBaseUrl("/img/bower-readme-hero.png");
  return (
    <Layout title="Security telemetry, from source to proof" description="Bower is a self-hosted security telemetry bridge. Collect useful security events, remove sensitive details before storage and verify their arrival in Microsoft Sentinel.">
      <main className={styles.home}>
        <section className={styles.hero}>
          <div className={styles.heroGlow} aria-hidden="true" />
          <div className={styles.heroInner}>
            <p className={styles.pill}>Open source · MIT licence · Self-hosted</p>
            <h1>From application noise <span>to trusted security signal.</span></h1>
            <p className={styles.heroLede}>
              Bower collects the security events that matter, removes sensitive details before they are stored,
              and proves their arrival in Microsoft Sentinel.
            </p>
            <div className={styles.ctas}>
              <Link className={styles.primary} to="/getting-started/">Get started</Link>
              <Link className={styles.secondary} to="/guides/console-tour/">Tour the console</Link>
              <Link className={styles.ghost} href="https://github.com/jusso-dev/Bower">GitHub ↗</Link>
            </div>
            <InstallTabs />
            <p className={styles.runs}>Collectors run on Linux, Windows and containers. The console runs in your tenant.</p>
          </div>
        </section>

        <section className={styles.gallerySection} aria-labelledby="gallery-title">
          <h2 id="gallery-title" className={styles.srOnly}>The management console</h2>
          <ConsoleGallery />
        </section>

        <section className={styles.strip} aria-label="Bower at a glance">
          <div><strong>5</strong><span>stages, Collect to Prove</span></div>
          <div><strong>6</strong><span>outputs, from Logs Ingestion to S3</span></div>
          <div><strong>7</strong><span>signed packs</span></div>
          <div><strong>0</strong><span>events kept that policy does not name</span></div>
        </section>

        <section className={styles.section}>
          <SectionHead n="01" eyebrow="How it works" title="A deliberate path, at every step.">
            Inspired by the bowerbird, which selects and arranges what is valuable. Bower is a security telemetry bridge,
            not a general log shipper, a SIEM or a replacement for Azure Monitor Agent.
          </SectionHead>
          <ol className={styles.stages}>
            {STAGES.map((stage) => (
              <li key={stage.n}>
                <span className={styles.stageN}>{stage.n}</span>
                <h3>{stage.name}</h3>
                <p>{stage.text}</p>
              </li>
            ))}
          </ol>
          <img className={styles.heroArt} src={hero} width={1774} height={887} loading="lazy"
            alt="Bower: scattered application events pass through a bowerbird-shaped network into selected blue security signals. Collect, Select, Arrange, Deliver, Prove." />
        </section>

        <section className={styles.section}>
          <SectionHead n="02" eyebrow="What you get" title="Security events you can trust, and show you can." />
          <div className={styles.cards}>
            {FEATURES.map((feature) => (
              <Link key={feature.title} className={styles.card} to={feature.to}>
                <h3>{feature.title}</h3>
                <p>{feature.text}</p>
                <span className={styles.more}>Read more →</span>
              </Link>
            ))}
          </div>
        </section>

        <section className={styles.section}>
          <SectionHead n="03" eyebrow="Deploy" title="Run it where your events already are.">
            Start with the guide for your environment, then send your first verified event.
          </SectionHead>
          <div className={styles.paths}>
            {PATHS.map((path, index) => (
              <Link key={path.title} className={styles.path} to={path.to}>
                <span className={styles.pathN}>{String(index + 1).padStart(2, "0")}</span>
                <div><h3>{path.title}</h3><p>{path.text}</p></div>
              </Link>
            ))}
          </div>
        </section>

        <section className={styles.section}>
          <SectionHead n="04" eyebrow="Connect" title="Sources and frameworks.">
            SDK guides for common web frameworks, plus host sources selected by signed pack parsers.
          </SectionHead>
          <ul className={styles.chips}>
            {SOURCES.map((source) => <li key={source}>{source}</li>)}
          </ul>
          <p className={styles.center}><Link to="/guides/">All guides →</Link></p>
        </section>

        <section className={styles.section}>
          <SectionHead n="05" eyebrow="Compare" title="Bower and a typical log shipper.">
            From vendor documentation reviewed in October 2026. Local tests do not prove tenant delivery.
          </SectionHead>
          <div className={styles.compareWrap}>
            <table className={styles.compare}>
              <thead><tr><th scope="col"><span className={styles.srOnly}>Topic</span></th><th scope="col">Bower</th><th scope="col">Typical alternative</th></tr></thead>
              <tbody>
                {COMPARE.map(([row, bower, other]) => (
                  <tr key={row}><th scope="row">{row}</th><td>{bower}</td><td>{other}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className={styles.final}>
          <h2>Send your first verified event.</h2>
          <p>A harmless test event, through policy, privacy, the queue and delivery, found by a query in Sentinel.</p>
          <div className={styles.ctas}>
            <Link className={styles.primary} to="/getting-started/first-event/">Start the walkthrough</Link>
            <Link className={styles.secondary} to="/getting-started/concepts/">Learn the concepts</Link>
          </div>
        </section>
      </main>
    </Layout>
  );
}
