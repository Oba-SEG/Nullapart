/**
 * Nullapart toast stack.
 *
 * Fixed-position confirmation notices for mutation results. Rendered once at
 * the shell level; announced politely to assistive technology.
 */

import { CheckCircle, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { dismissNotify, subscribeNotify, type NotifyMessage } from "../lib/notify";
import "./Toasts.css";

export function Toasts() {
  const [messages, setMessages] = useState<NotifyMessage[]>([]);

  useEffect(() => subscribeNotify(setMessages), []);

  if (messages.length === 0) return null;

  return (
    <div className="toast-stack" role="status" aria-live="polite">
      {messages.map((item) => (
        <div key={item.id} className={`toast toast-${item.tone}`}>
          {item.tone === "success" ? (
            <CheckCircle size={16} aria-hidden="true" />
          ) : (
            <XCircle size={16} aria-hidden="true" />
          )}
          <span className="toast-message">{item.message}</span>
          <button
            type="button"
            className="toast-dismiss"
            aria-label="Dismiss notification"
            onClick={() => dismissNotify(item.id)}
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
