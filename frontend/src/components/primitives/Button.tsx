/**
 * Nullapart accessible Button primitive
 *
 * Wraps native button with neumorphic styling and proper ARIA semantics.
 * Follows: docs/23-FRONTEND-ARCHITECTURE.md accessibility requirements.
 */

import { forwardRef, type ButtonHTMLAttributes } from "react";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "primary" | "danger" | "clean" | "ghost";
  size?: "sm" | "md" | "lg";
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "default", size = "md", loading, disabled, className, children, ...props }, ref) => {
    const classes = [
      "btn",
      variant === "primary" ? "btn-primary" : "",
      variant === "danger" ? "btn-danger" : "",
      variant === "clean" ? "btn-clean" : "",
      variant === "ghost" ? "btn-ghost" : "",
      size === "sm" ? "btn-sm" : "",
      size === "lg" ? "btn-lg" : "",
      className ?? "",
    ]
      .filter(Boolean)
      .join(" ");

    return (
      <button
        ref={ref}
        className={classes}
        disabled={disabled || loading}
        aria-disabled={disabled || loading}
        aria-busy={loading}
        {...props}
      >
        {loading && (
          <span className="sr-only" aria-live="polite">
            Loading...
          </span>
        )}
        {children}
      </button>
    );
  },
);
