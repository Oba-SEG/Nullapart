import { useId, type ReactNode } from "react";

import "./ControlRail.css";

export type ControlSignal = {
  label: string;
  value: ReactNode;
  detail: string;
  tone?: "attention" | "healthy" | "neutral";
};

type ControlRailProps = {
  title: string;
  summary: string;
  signals: ControlSignal[];
  actions?: ReactNode;
};

/**
 * Route-specific operator state. Operational values are supplied by the page
 * from the server response already used by that route. Pages may also show
 * explicitly-labelled local UI state, but the component owns no authority or
 * client-side approximation of a security decision.
 */
export function ControlRail({ title, summary, signals, actions }: ControlRailProps) {
  const titleId = useId();
  return (
    <section className="control-rail" aria-labelledby={titleId}>
      <div className="control-rail-intro">
        <p>Control state</p>
        <h2 id={titleId}>{title}</h2>
        <span>{summary}</span>
      </div>
      <dl className="control-rail-signals">
        {signals.map((signal) => (
          <div
            key={signal.label}
            className={`control-signal control-signal-${signal.tone ?? "neutral"}`}
          >
            <dt>{signal.label}</dt>
            <dd>{signal.value}</dd>
            <span>{signal.detail}</span>
          </div>
        ))}
      </dl>
      {actions ? <div className="control-rail-actions">{actions}</div> : null}
    </section>
  );
}
