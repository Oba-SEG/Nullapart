/**
 * Nullapart Error Boundary
 *
 * Catches React errors and displays a safe error UI.
 * Never displays stack traces, SQL internals, or auth tokens.
 */

import { Component, type ErrorInfo, type ReactNode } from "react";
import { captureException } from "../../lib/telemetry";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  correlationId: string;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      correlationId: "",
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return {
      hasError: true,
      error,
      correlationId: `err_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Fire-and-forget telemetry: the scrub gate lives in telemetry.ts, and
    // a report failure is silent by contract (the Fallback UI does not
    // depend on any network).
    try {
      captureException(error, this.state.correlationId, {
        component: "ErrorBoundary",
      });
    } catch {
      // Reporting must never break the falling-back boundary.
    }
    console.error("ErrorBoundary caught:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="error-boundary" role="alert">
          <div className="error-boundary-content">
            <h2>Something went wrong</h2>
            <p>An unexpected error occurred. Please try again or contact support.</p>
            {this.state.correlationId && (
              <p className="error-correlation">Reference: {this.state.correlationId}</p>
            )}
            <button
              className="btn btn-primary"
              onClick={() =>
                this.setState({
                  hasError: false,
                  error: null,
                  correlationId: "",
                })
              }
            >
              Try again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
