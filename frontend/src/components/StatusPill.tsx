import type { ReactNode } from "react";
import { Minus } from "lucide-react";
import type { StatusTone } from "../lib/status";
import "./StatusPill.css";

const STATUS_ASSETS: Partial<Record<StatusTone, string>> = {
  clean: "/brand/status/status-clean-256.png",
  threat: "/brand/status/status-threat-256.png",
  review: "/brand/status/status-review-256.png",
  processing: "/brand/status/status-processing.svg",
  delivered: "/brand/status/status-delivered.svg",
};

const ICONS: Partial<Record<StatusTone, ReactNode>> = {
  muted: <Minus size={11} strokeWidth={2.5} />,
};

export function StatusPill({ tone, label }: { tone: StatusTone; label: string }) {
  return (
    <span className={`status-pill status-${tone}`}>
      <span className="status-pill-icon" aria-hidden="true">
        {STATUS_ASSETS[tone] ? <img src={STATUS_ASSETS[tone]} alt="" /> : ICONS[tone]}
      </span>
      {label}
    </span>
  );
}
