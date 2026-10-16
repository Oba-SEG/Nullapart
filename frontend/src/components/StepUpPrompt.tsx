import { beginStepUp, isStepUpRequired } from "../auth/session";
import { Button } from "./primitives/Button";
import { Hint } from "./primitives/Hint";

interface StepUpPromptProps {
  error: unknown;
}

/**
 * Inline re-authentication affordance for a `STEP_UP_REQUIRED` API failure.
 * The server-side session stays valid; only the step-up freshness window is
 * stale, so the browser restarts an interactive IdP round trip and returns
 * to the page that failed.
 */
export function StepUpPrompt({ error }: StepUpPromptProps) {
  if (!isStepUpRequired(error)) {
    return null;
  }
  return (
    <div className="step-up-prompt" role="status">
      <span className="step-up-text">Re-authentication is required for this action.</span>
      <Hint label="Your sign-in is still valid. Only this action needs a fresh check-in for safety.">
        <Button type="button" size="sm" onClick={() => beginStepUp()}>
          Re-authenticate
        </Button>
      </Hint>
    </div>
  );
}
