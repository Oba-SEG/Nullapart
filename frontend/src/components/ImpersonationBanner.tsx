import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { endImpersonation, type Session } from "../auth/session";
import { Button } from "./primitives/Button";

interface ImpersonationBannerProps {
  session: Session | null;
}

/**
 * Persistent customer-entry indicator (docs/03-IDENTITY-RBAC-IMPERSONATION.md).
 * Rendered for the whole authenticated shell so an entered customer can never
 * be mistaken for the operator's own scope; Exit is always offered without
 * any extra step-up or rate-limit gate.
 */
export function ImpersonationBanner({ session }: ImpersonationBannerProps) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const impersonation = session?.impersonation;

  if (!impersonation) {
    return null;
  }

  async function handleStop() {
    setBusy(true);
    setError(null);
    try {
      await endImpersonation();
      await queryClient.invalidateQueries({ queryKey: ["session"] });
    } catch (err) {
      setError(
        typeof err === "object" && err !== null && "message" in err
          ? String((err as { message: unknown }).message)
          : "Could not exit the customer.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="impersonation-banner" role="status" aria-live="polite">
      <span className="impersonation-text">
        Entered customer <strong>{impersonation.customerDisplayName}</strong> (
        {impersonation.customerId}) · reason: {impersonation.reason}
      </span>
      {error ? <span className="impersonation-error">{error}</span> : null}
      <Button
        type="button"
        size="sm"
        variant="danger"
        onClick={() => void handleStop()}
        disabled={busy}
        aria-label="Exit the entered customer"
      >
        Exit customer
      </Button>
    </div>
  );
}
