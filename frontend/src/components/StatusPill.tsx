import type { ReactNode } from "react";
import { AlertTriangle, Check, Clock, Info, Mail, Minus } from "lucide-react";
import type { StatusTone } from "../lib/status";
import "./StatusPill.css";

const ICONS: Record<StatusTone, ReactNode> = {
  clean: <Check size={11} strokeWidth={3} />,
  threat: <Info size={11} strokeWidth={3} />,
  review: <AlertTriangle size={10} strokeWidth={2.75} />,
  processing: <Clock size={11} strokeWidth={2.5} />,
  delivered: <Mail size={11} strokeWidth={2.5} />,
  muted: <Minus size={11} strokeWidth={2.5} />,
};

export function StatusPill({ tone, label }: { tone: StatusTone; label: string }) {
  return (
    <span className={`status-pill status-${tone}`}>
      <span className="status-pill-icon" aria-hidden="true">
        {ICONS[tone]}
      </span>
      {label}
    </span>
  );
}
