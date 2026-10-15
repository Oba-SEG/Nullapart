import type { ReactNode } from "react";

import "./WorkflowGuide.css";

export type WorkflowGuideStep = {
  label: string;
  detail: string;
};

type WorkflowGuideProps = {
  title: string;
  description: string;
  steps: WorkflowGuideStep[];
  children?: ReactNode;
};

/**
 * Makes the order of a privileged admin workflow explicit. The guide does not
 * grant access or describe an action as available when the server rejects it;
 * it merely puts the existing controls in their operational context.
 */
export function WorkflowGuide({ title, description, steps, children }: WorkflowGuideProps) {
  return (
    <aside className="workflow-guide" aria-label={title}>
      <div className="workflow-guide-intro">
        <p className="workflow-guide-eyebrow">Operator workflow</p>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
      <ol className="workflow-guide-steps">
        {steps.map((step, index) => (
          <li key={step.label}>
            <span aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
            <div>
              <strong>{step.label}</strong>
              <p>{step.detail}</p>
            </div>
          </li>
        ))}
      </ol>
      {children ? <div className="workflow-guide-actions">{children}</div> : null}
    </aside>
  );
}
