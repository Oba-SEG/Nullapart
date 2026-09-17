/**
 * Nullapart accessible Input primitive
 *
 * Wraps native input with neumorphic styling, proper labels, and ARIA.
 */

import { forwardRef, type InputHTMLAttributes, useId } from "react";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string;
  hint?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, hint, id: idProp, className, ...props }, ref) => {
    const autoId = useId();
    const id = idProp ?? autoId;
    const errorId = `${id}-error`;
    const hintId = `${id}-hint`;

    return (
      <div className="input-group">
        <label htmlFor={id} className="input-label">
          {label}
        </label>
        <input
          ref={ref}
          id={id}
          className={`input ${error ? "input-error" : ""} ${className ?? ""}`}
          aria-invalid={!!error}
          aria-describedby={
            [error ? errorId : "", hint ? hintId : ""].filter(Boolean).join(" ") || undefined
          }
          {...props}
        />
        {hint && !error && (
          <p id={hintId} className="input-hint">
            {hint}
          </p>
        )}
        {error && (
          <p id={errorId} className="input-error-message" role="alert">
            {error}
          </p>
        )}
      </div>
    );
  },
);
