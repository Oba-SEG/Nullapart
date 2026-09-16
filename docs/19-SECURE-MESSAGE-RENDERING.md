# Secure Message Rendering and Artifact Access

**Status:** mandatory UI/security architecture.

## Threat model

Email content is attacker-controlled input. A message opened by an administrator may contain:

- hostile HTML;
- JavaScript/event-handler payloads;
- CSS-based UI deception;
- tracking pixels;
- remote images/resources;
- malicious links;
- forms;
- SVG/script content;
- crafted attachments;
- content intended to steal control-plane credentials or execute in the administrator's browser.

Nullapart must never render received message HTML directly inside the trusted administration application DOM.

## Rendering model

### Plain text

Plain-text parts are rendered as text, never interpreted as HTML.

### HTML

HTML rendering requires all of the following:

1. strict server-side or trusted-library sanitization;
2. script, event handler, form and active-content removal;
3. remote resource blocking by default;
4. isolated rendering using a sandboxed iframe and/or a separate untrusted rendering origin;
5. no access to the parent application DOM;
6. no access to Nullapart session cookies or credentials;
7. restrictive Content Security Policy;
8. link rewriting/inspection and clear external-navigation warning where appropriate.

Do not rely on CSP alone as the sanitizer.

## Remote content

Remote images and other tracking resources are blocked by default.

If an authorized administrator explicitly chooses to load remote content, the UI must warn that this may disclose viewing information to the sender. Prefer a privacy proxy if remote-resource display is introduced later.

## Links

Links are displayed safely and should expose the actual normalized destination on inspection.

Clicking an external link must not silently inherit privileged Nullapart browser context. Apply appropriate `noopener`/`noreferrer` behaviour and URL-safety handling.

## Attachments

Attachments are not rendered inline merely because the browser recognizes their MIME type.

Downloads/previews use a dedicated artifact access path with:

- server-side RBAC;
- short-lived authorization;
- audit logging;
- safe `Content-Disposition`;
- correct `X-Content-Type-Options`;
- no control-plane session cookies on the artifact origin where practical;
- malware/security state shown before download;
- explicit warning for risky types.

A separate artifact/download hostname or origin is preferred so hostile files cannot inherit the control-plane origin's browser trust.

## SVG and active documents

SVG is treated as active content unless sanitized specifically for the relevant use case.

Office/PDF previews must not execute macros, scripts or embedded active content in the control-plane browser. Prefer safe server-side extraction/rendering for previews.

## Raw message and headers

Raw headers and raw MIME are shown as escaped text, never interpreted as HTML.

Raw MIME download is a privileged action and must be audited.

## Permission model

### System Admin

May receive full-message access where policy permits. All full-content access is audited.

### Support

Support does not receive message body, raw MIME or attachment content through rendering, preview, downloads, audit logs, search snippets or exported diagnostics.

### Customer Admin

Content/attachment access follows customer-owner RBAC and is enforced server-side.

## Mandatory audit events

Audit at minimum:

- full message/body view opened;
- raw headers viewed when classified as sensitive;
- raw MIME viewed/downloaded;
- attachment preview/download;
- remote content explicitly loaded;
- quarantine release;
- remediation action.

The audit entry records the access action but not the message content itself.

## UI design

The UI clearly distinguishes:

- sanitized rendered view;
- plain-text view;
- raw headers;
- raw MIME;
- attachment preview/download.

Never label sanitized HTML as "raw" content.

## Testing

Security tests must include:

- stored XSS payloads;
- SVG/script payloads;
- hostile CSS;
- tracking pixels;
- forms;
- `javascript:` and unusual URL schemes;
- malformed HTML;
- MIME type confusion;
- attachment content-disposition attacks;
- iframe escape attempts;
- cross-origin/session-cookie checks;
- Support-role attempts to retrieve restricted artifacts directly.
