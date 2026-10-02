import { useState } from "react";

import type { MessageContentData } from "../api/trace";
import { sanitizeHtml } from "../security/content";
import { Button } from "./primitives/Button";
import "./MessageContent.css";

const PREVIEW_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";

const PREVIEW_CSP_META = `<meta http-equiv="Content-Security-Policy" content="${PREVIEW_CSP}">`;

function buildPreviewDocument(html: string): string {
  const safe = sanitizeHtml(html);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">${PREVIEW_CSP_META}</head><body>${safe}</body></html>`;
}

function formatTimestamp(value: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

function formatSize(size: number | null): string {
  return typeof size === "number" ? `${size} bytes` : "size unknown";
}

type TabKey = "plain" | "html" | "headers";

const TABS: { key: TabKey; label: string }[] = [
  { key: "plain", label: "Plain text" },
  { key: "html", label: "HTML" },
  { key: "headers", label: "Headers" },
];

export interface MessageContentProps {
  data: MessageContentData;
  onClose?: () => void;
}

export function MessageContent({ data, onClose }: MessageContentProps) {
  const [activeTab, setActiveTab] = useState<TabKey>("plain");

  const hasPlain = data.plain_text !== null && data.plain_text.length > 0;
  const hasHtml = data.html !== null && data.html.length > 0;

  return (
    <article className="message-content" aria-label="Message content">
      <header className="message-content-header">
        <div className="message-content-heading">
          <h3 className="message-content-subject">{data.subject ?? "No subject"}</h3>
          {onClose && (
            <Button variant="ghost" size="sm" onClick={onClose}>
              Close
            </Button>
          )}
        </div>
        <dl className="message-content-meta">
          <dt>From</dt>
          <dd>{data.from ?? "—"}</dd>
          <dt>To</dt>
          <dd>{data.to.length > 0 ? data.to.join(", ") : "—"}</dd>
          <dt>Date</dt>
          <dd>{formatTimestamp(data.date)}</dd>
        </dl>
      </header>

      {data.truncated && (
        <p className="message-content-notice" role="status">
          This message was truncated for display.
        </p>
      )}

      <div className="message-content-tabs" role="tablist" aria-label="Message parts">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            role="tab"
            id={`message-content-tab-${tab.key}`}
            aria-selected={activeTab === tab.key}
            aria-controls="message-content-panel"
            className={`message-content-tab${activeTab === tab.key ? " active" : ""}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div
        role="tabpanel"
        id="message-content-panel"
        aria-labelledby={`message-content-tab-${activeTab}`}
        className="message-content-panel"
      >
        {activeTab === "plain" &&
          (hasPlain ? (
            <pre className="message-content-pre">{data.plain_text}</pre>
          ) : (
            <p>No plain text part.</p>
          ))}

        {activeTab === "html" &&
          (hasHtml ? (
            <>
              <iframe
                className="message-content-frame"
                sandbox=""
                srcDoc={buildPreviewDocument(data.html ?? "")}
                title="Sanitized message preview"
              />
              <p className="message-content-note">
                Active content is blocked; images and links inside the preview are disabled.
              </p>
            </>
          ) : (
            <p>No HTML part.</p>
          ))}

        {activeTab === "headers" &&
          (data.headers.length === 0 ? (
            <p>No headers are available for this message.</p>
          ) : (
            <dl className="message-content-headers">
              {data.headers.map((header, index) => (
                <div key={`${header.name}-${index}`} className="message-content-header-row">
                  <dt>{header.name}</dt>
                  <dd>{header.value}</dd>
                </div>
              ))}
            </dl>
          ))}
      </div>

      <section className="message-content-attachments" aria-label="Attachments">
        <h4 className="message-content-subheading">Attachments</h4>
        {data.attachments.length === 0 ? (
          <p>No attachments.</p>
        ) : (
          <ul className="message-content-attachment-list">
            {data.attachments.map((attachment, index) => (
              <li key={`${attachment.filename ?? "attachment"}-${index}`}>
                <span className="message-content-attachment-name">
                  {attachment.filename ?? "Unnamed attachment"}
                </span>
                <span className="message-content-attachment-meta">
                  {attachment.content_type ?? "unknown content type"} ·{" "}
                  {formatSize(attachment.size_bytes)}
                </span>
              </li>
            ))}
          </ul>
        )}
        <p className="message-content-note">
          Attachment download is not available in this environment.
        </p>
      </section>
    </article>
  );
}
