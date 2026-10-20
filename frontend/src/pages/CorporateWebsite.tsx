import { ArrowRight, Check, Eye, MailCheck, Network, ShieldCheck } from "lucide-react";
import "./CorporateWebsite.css";

const operatingPrinciples = [
  {
    icon: ShieldCheck,
    title: "Security that holds its shape",
    description:
      "Policy, identity and evidence stay connected from the first SMTP decision through to a documented administrative action.",
  },
  {
    icon: MailCheck,
    title: "Mail flow with context",
    description:
      "Give teams a clear path to inspect, contain and release messages without turning the console into a source of new risk.",
  },
  {
    icon: Eye,
    title: "Evidence before confidence",
    description:
      "Make the decision trail legible: what happened, why it happened, and which authorised change followed.",
  },
];

const deliveryPillars = [
  "Protect the mail boundary",
  "Preserve tenant boundaries",
  "Keep administrator actions accountable",
];

export function CorporateWebsite() {
  return (
    <div className="corporate-page">
      <a className="corporate-skip-link" href="#corporate-main">
        Skip to main content
      </a>

      <header className="corporate-header">
        <a className="corporate-brand" href="/" aria-label="Nullapart home">
          <img src="/brand/logos/horizontal-logo-dark.png" alt="Nullapart" />
        </a>
        <nav className="corporate-nav" aria-label="Public site">
          <a href="#approach">Our approach</a>
          <a href="#operations">Operations</a>
          <a className="corporate-sign-in" href="/login">
            Sign in <ArrowRight size={16} aria-hidden="true" />
          </a>
        </nav>
      </header>

      <main id="corporate-main">
        <section className="corporate-hero" aria-labelledby="corporate-hero-title">
          <img
            className="corporate-hero-art"
            src="/brand/web/corporate-security-network-16x9.png"
            alt=""
            aria-hidden="true"
          />
          <div className="corporate-hero-shade" aria-hidden="true" />
          <div className="corporate-hero-content">
            <p className="corporate-eyebrow">Email security, built for accountability</p>
            <h1 id="corporate-hero-title">
              Protect the mail boundary. <span>Keep work moving.</span>
            </h1>
            <p className="corporate-hero-copy">
              Nullapart helps organisations operate a safer email environment with clear evidence,
              careful controls and a console designed for people who need to make the next decision.
            </p>
            <div className="corporate-hero-actions">
              <a className="corporate-button corporate-button-primary" href="#approach">
                See the approach <ArrowRight size={17} aria-hidden="true" />
              </a>
              <a className="corporate-button corporate-button-secondary" href="/login">
                Open your console
              </a>
            </div>
          </div>
          <div className="corporate-hero-signal" aria-label="Built for resilient mail operations">
            <span className="corporate-signal-dot" aria-hidden="true" />
            Built for resilient mail operations
          </div>
        </section>

        <section className="corporate-statement" id="approach" aria-labelledby="approach-title">
          <div>
            <p className="corporate-eyebrow">A clearer operating model</p>
            <h2 id="approach-title">
              The security control should help the business move with care.
            </h2>
          </div>
          <p>
            The useful signal is not another dashboard. It is the ability to understand what the
            system saw, act within an approved boundary, and prove what changed afterwards.
          </p>
        </section>

        <section className="corporate-principles" aria-label="Nullapart operating principles">
          {operatingPrinciples.map(({ icon: Icon, title, description }) => (
            <article className="corporate-principle" key={title}>
              <span className="corporate-principle-icon" aria-hidden="true">
                <Icon size={22} strokeWidth={1.65} />
              </span>
              <h3>{title}</h3>
              <p>{description}</p>
            </article>
          ))}
        </section>

        <section
          className="corporate-operations"
          id="operations"
          aria-labelledby="operations-title"
        >
          <div className="corporate-operations-art" aria-hidden="true">
            <img src="/brand/generated/nullapart-wave-command-bg@2x.png" alt="" />
          </div>
          <div className="corporate-operations-copy">
            <p className="corporate-eyebrow">Designed for the people on the boundary</p>
            <h2 id="operations-title">From detection to a defensible next step.</h2>
            <p>
              Nullapart brings the operational path into one place: assess the evidence, apply the
              control your role permits, and confirm the result without losing the thread.
            </p>
            <ul>
              {deliveryPillars.map((pillar) => (
                <li key={pillar}>
                  <Check size={17} aria-hidden="true" />
                  {pillar}
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="corporate-closing" aria-labelledby="corporate-closing-title">
          <Network
            className="corporate-closing-mark"
            size={30}
            strokeWidth={1.35}
            aria-hidden="true"
          />
          <p className="corporate-eyebrow">A safer way to run email</p>
          <h2 id="corporate-closing-title">Your control plane is ready when your team is.</h2>
          <a className="corporate-button corporate-button-primary" href="/login">
            Sign in to your console <ArrowRight size={17} aria-hidden="true" />
          </a>
        </section>
      </main>

      <footer className="corporate-footer">
        <img src="/brand/logos/horizontal-logo-dark.png" alt="Nullapart" />
        <span>Cleaner mail. A safer world.</span>
        <a href="/login">Administrator sign-in</a>
      </footer>
    </div>
  );
}
