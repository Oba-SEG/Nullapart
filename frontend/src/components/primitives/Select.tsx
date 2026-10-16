/**
 * Nullapart accessible Select primitive
 *
 * Wraps native select with neumorphic styling and proper ARIA.
 */

import { forwardRef, type SelectHTMLAttributes, useId } from "react";

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string;
  options: SelectOption[];
  placeholder?: string;
  error?: string;
  /** Explained once, next to the choice that needs it. Read out to assistive
   * tech through `aria-describedby`, the same contract as `Input`. */
  hint?: string;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, options, placeholder, error, hint, id: idProp, className, ...props }, ref) => {
    const autoId = useId();
    const id = idProp ?? autoId;
    const errorId = `${id}-error`;
    const hintId = `${id}-hint`;

    return (
      <div className="select-group">
        <label htmlFor={id} className="select-label">
          {label}
        </label>
        <select
          ref={ref}
          id={id}
          className={`select ${error ? "select-error" : ""} ${className ?? ""}`}
          aria-invalid={!!error}
          aria-describedby={
            [error ? errorId : "", hint ? hintId : ""].filter(Boolean).join(" ") || undefined
          }
          {...props}
        >
          {placeholder && (
            <option value="" disabled>
              {placeholder}
            </option>
          )}
          {options.map((opt) => (
            <option key={opt.value} value={opt.value} disabled={opt.disabled}>
              {opt.label}
            </option>
          ))}
        </select>
        {hint && !error && (
          <p id={hintId} className="select-hint">
            {hint}
          </p>
        )}
        {error && (
          <p id={errorId} className="select-error-message" role="alert">
            {error}
          </p>
        )}
      </div>
    );
  },
);
