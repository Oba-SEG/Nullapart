//! Bounded, versioned canonical input representation for inline ML.
//!
//! [`build`] turns raw MIME bytes, pass-1 scanner findings and explicitly
//! authorized context into a deterministic, size-bounded, versioned
//! structure (`docs/phases/PHASE-4-INLINE-ML.md`, "Input contract"). The
//! builder is pure: no model, no I/O, no tenant lookup. Every section is
//! capped with an explicit truncation strategy, control characters are
//! stripped, and only allowlisted headers are admitted. Production messages
//! are never read from storage for this path beyond the bytes already under
//! scan, and VIP/tenant context is only present when a caller passes it as
//! authorized.

use std::panic::{catch_unwind, AssertUnwindSafe};

use mailparse::{DispositionType, ParsedMail};
use nullapart_mail_contracts::{
    FindingCategory, FindingSeverity, ScannerStatus, ScannerType, SecurityFinding,
};
use serde::{Deserialize, Serialize};

/// Current version of the inline-ML input representation contract.
pub const INLINE_ML_REPRESENTATION_VERSION: u32 = 1;

/// Maximum number of allowlisted header fields carried into the model input.
pub const MAX_HEADER_FIELDS: usize = 16;
/// Maximum characters kept per header value.
pub const MAX_HEADER_VALUE_CHARS: usize = 1024;
/// Maximum characters kept for the subject.
pub const MAX_SUBJECT_CHARS: usize = 256;
/// Maximum characters kept for the cleaned body text.
pub const MAX_TEXT_CHARS: usize = 8192;
/// Maximum extracted URL candidates.
pub const MAX_URLS: usize = 64;
/// Maximum characters kept per URL candidate.
pub const MAX_URL_CHARS: usize = 2048;
/// Maximum attachment signals carried into the model input.
pub const MAX_ATTACHMENTS: usize = 32;
/// Maximum characters kept per attachment filename.
pub const MAX_ATTACHMENT_NAME_CHARS: usize = 256;
/// Maximum pass-1 finding summaries carried into the model input.
pub const MAX_FINDINGS: usize = 64;
/// Maximum characters kept per finding description.
pub const MAX_FINDING_DESCRIPTION_CHARS: usize = 512;
/// Maximum VIP principals when authorized context is supplied.
pub const MAX_VIP_PRINCIPALS: usize = 8;
/// Maximum MIME parts visited during the bounded walk.
pub const MAX_PARTS: usize = 128;
/// Maximum MIME nesting depth visited during the bounded walk.
pub const MAX_DEPTH: u32 = 16;
/// Maximum raw bytes decoded per individual MIME part.
pub const MAX_RAW_PART_BYTES: usize = 1024 * 1024;
/// Maximum characters scanned per individual part before HTML cleaning.
pub const MAX_RAW_PART_CHARS: usize = 65536;

/// Allowlisted headers admitted into the model input. The subject is
/// carried in its own field, not duplicated here.
pub const ALLOWED_HEADERS: [&str; 7] = [
    "from",
    "reply-to",
    "return-path",
    "to",
    "cc",
    "x-mailer",
    "authentication-results",
];

/// A text section with an explicit truncation record.
///
/// `original_chars` counts cleaned characters before the length clamp; it
/// excludes content dropped by part/depth limits (which also force
/// `truncated`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedText {
    pub text: String,
    pub truncated: bool,
    pub original_chars: usize,
}

impl BoundedText {
    fn clamp(cleaned: String, max_chars: usize) -> Self {
        let original_chars = cleaned.chars().count();
        if original_chars <= max_chars {
            return Self {
                text: cleaned,
                truncated: false,
                original_chars,
            };
        }
        let mut text = String::new();
        for (count, ch) in cleaned.chars().enumerate() {
            if count >= max_chars {
                break;
            }
            text.push(ch);
        }
        Self {
            text,
            truncated: true,
            original_chars,
        }
    }
}

/// One allowlisted header field (single-line, sanitized, bounded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

/// Sender/domain signals derived from headers or supplied envelope context.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderSignals {
    pub from_domain: Option<String>,
    pub envelope_sender: Option<String>,
}

/// Extracted URL candidate (bounded length, never fetched or resolved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlSignal {
    pub url: String,
}

/// Attachment metadata signal (name, type, raw part size).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentSignal {
    pub filename: String,
    pub content_type: String,
    pub raw_size_bytes: usize,
}

/// Summary of one deterministic pass-1 scanner finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingSignal {
    pub scanner: ScannerType,
    pub status: ScannerStatus,
    pub severity: FindingSeverity,
    pub category: FindingCategory,
    pub description: String,
}

/// Authorized VIP/tenant context — only ever present when a caller passes
/// it with an authorization basis; never looked up by this module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VipSignal {
    pub principals: Vec<String>,
}

/// Versioned canonical inline-ML input representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InlineMlRepresentation {
    pub representation_version: u32,
    pub mime_parsed: bool,
    pub headers: Vec<HeaderField>,
    pub sender: SenderSignals,
    pub subject: BoundedText,
    pub text: BoundedText,
    pub urls: Vec<UrlSignal>,
    pub attachments: Vec<AttachmentSignal>,
    pub findings: Vec<FindingSignal>,
    pub vip: Option<VipSignal>,
}

/// Inputs to [`build`]. All references are already under scan or
/// explicitly authorized; the builder reads nothing else.
#[derive(Debug, Clone, Copy)]
pub struct RepresentationSources<'a> {
    pub mime: &'a [u8],
    pub findings: &'a [SecurityFinding],
    pub envelope_sender: Option<&'a str>,
    pub vip: Option<&'a VipSignal>,
}

/// Build the versioned representation from bounded sources.
pub fn build(sources: &RepresentationSources<'_>) -> InlineMlRepresentation {
    let parsed = catch_unwind(AssertUnwindSafe(|| mailparse::parse_mail(sources.mime)));
    let parsed = match parsed {
        Ok(Ok(parsed)) => Some(parsed),
        _ => None,
    };

    let mut headers = Vec::new();
    let mut subject = String::new();
    let mut sender = SenderSignals {
        from_domain: None,
        envelope_sender: sources
            .envelope_sender
            .map(sanitize_field)
            .map(|s| s.chars().take(MAX_HEADER_VALUE_CHARS).collect()),
    };

    if let Some(parsed) = parsed.as_ref() {
        for header in &parsed.headers {
            let name = header.get_key().to_ascii_lowercase();
            if name == "subject" {
                subject = sanitize_field(&header.get_value());
                continue;
            }
            if !ALLOWED_HEADERS.contains(&name.as_str()) {
                continue;
            }
            if headers.len() >= MAX_HEADER_FIELDS {
                break;
            }
            let value = header.get_value();
            if sender.from_domain.is_none() && name == "from" {
                sender.from_domain = email_domain(&value);
            }
            headers.push(HeaderField {
                name,
                value: sanitize_field(&value)
                    .chars()
                    .take(MAX_HEADER_VALUE_CHARS)
                    .collect(),
            });
        }
    }
    if sender.from_domain.is_none() {
        sender.from_domain = sources
            .envelope_sender
            .and_then(email_domain)
            .map(|d| d.to_ascii_lowercase());
    }

    let mut walk = WalkState::default();
    if let Some(parsed) = parsed.as_ref() {
        walk_part(parsed, 0, &mut walk);
    }
    if walk.parts_capped {
        walk.truncated = true;
    }

    let subject = BoundedText::clamp(subject, MAX_SUBJECT_CHARS);
    let mut text = BoundedText::clamp(walk.text, MAX_TEXT_CHARS);
    if walk.truncated {
        text.truncated = true;
    }

    let findings = sources
        .findings
        .iter()
        .take(MAX_FINDINGS)
        .map(|finding| FindingSignal {
            scanner: finding.scanner,
            status: finding.scanner_status,
            severity: finding.severity,
            category: finding.category,
            description: finding
                .description
                .chars()
                .take(MAX_FINDING_DESCRIPTION_CHARS)
                .collect(),
        })
        .collect();

    let vip = sources.vip.map(|vip| VipSignal {
        principals: vip
            .principals
            .iter()
            .take(MAX_VIP_PRINCIPALS)
            .map(|p| {
                sanitize_field(p)
                    .chars()
                    .take(MAX_ATTACHMENT_NAME_CHARS)
                    .collect()
            })
            .collect(),
    });

    InlineMlRepresentation {
        representation_version: INLINE_ML_REPRESENTATION_VERSION,
        mime_parsed: parsed.is_some(),
        headers,
        sender,
        subject,
        text,
        urls: walk.urls,
        attachments: walk.attachments,
        findings,
        vip,
    }
}

#[derive(Default)]
struct WalkState {
    text: String,
    urls: Vec<UrlSignal>,
    attachments: Vec<AttachmentSignal>,
    parts: usize,
    parts_capped: bool,
    truncated: bool,
}

impl WalkState {
    fn push_text(&mut self, chunk: &str) {
        if !self.text.is_empty() {
            self.text.push('\n');
        }
        self.text.push_str(chunk);
    }

    fn note_urls(&mut self, chunk: &str) {
        collect_urls(chunk, |url| {
            if self.urls.len() >= MAX_URLS {
                return;
            }
            if self.urls.iter().any(|existing| existing.url == url) {
                return;
            }
            self.urls.push(UrlSignal { url });
        });
    }
}

fn walk_part<'a>(mail: &'a ParsedMail<'a>, depth: u32, state: &mut WalkState) {
    if depth > MAX_DEPTH {
        state.truncated = true;
        return;
    }
    if state.parts >= MAX_PARTS {
        state.parts_capped = true;
        return;
    }
    state.parts += 1;

    if !mail.subparts.is_empty() {
        for subpart in &mail.subparts {
            walk_part(subpart, depth + 1, state);
            if state.parts_capped {
                return;
            }
        }
        return;
    }

    let mimetype = mail.ctype.mimetype.to_ascii_lowercase();
    if mimetype.starts_with("text/") {
        let raw_len = mail.raw_bytes.len();
        if raw_len > MAX_RAW_PART_BYTES {
            state.push_text("[omitted: text part exceeds per-part size limit]");
            state.truncated = true;
            state.note_urls(&sanitize_field(&String::from_utf8_lossy(
                &mail.raw_bytes[..raw_len.min(MAX_RAW_PART_BYTES)],
            )));
            return;
        }
        let decoded_bytes = match mail.get_body_raw() {
            Ok(decoded) => decoded,
            Err(_) => {
                state.truncated = true;
                return;
            },
        };
        let decoded = String::from_utf8_lossy(&decoded_bytes);
        let bounded: String = decoded.chars().take(MAX_RAW_PART_CHARS).collect::<String>();
        if bounded.chars().count() < decoded.chars().count() {
            state.truncated = true;
        }
        if mimetype == "text/html" {
            let cleaned = strip_html(&bounded);
            state.note_urls(&bounded);
            state.push_text(&sanitize_field(&cleaned));
        } else {
            state.note_urls(&bounded);
            state.push_text(&sanitize_field(&bounded));
        }
        return;
    }

    let disposition = mail.get_content_disposition();
    let filename = disposition
        .params
        .get("filename")
        .cloned()
        .or_else(|| mail.ctype.params.get("filename").cloned());
    if disposition.disposition == DispositionType::Attachment || filename.is_some() {
        if state.attachments.len() >= MAX_ATTACHMENTS {
            state.truncated = true;
            return;
        }
        let filename = filename
            .map(|name| sanitize_field(&name))
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "unnamed".to_string());
        state.attachments.push(AttachmentSignal {
            filename: filename.chars().take(MAX_ATTACHMENT_NAME_CHARS).collect(),
            content_type: sanitize_field(&mail.ctype.mimetype)
                .chars()
                .take(MAX_ATTACHMENT_NAME_CHARS)
                .collect(),
            raw_size_bytes: mail.raw_bytes.len(),
        });
    }
}

/// Neutralize control characters as spaces while preserving structural
/// whitespace (`\n`, `\t`). Training-side `clean_text` replaced control
/// characters with spaces before collapsing (`prepare_dataset.py`), so
/// dropping them would merge words and diverge from the checkpoint's text
/// contract; a space is inert for stored evidence (no log/UI injection).
fn sanitize_field(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

fn email_domain(raw: &str) -> Option<String> {
    let candidate = match raw.find('<') {
        Some(open) => raw
            .get((open + 1)..raw.find('>')?)
            .map(|inner| inner.to_string()),
        None => raw.split_whitespace().next().map(|token| token.to_string()),
    }?;
    if candidate.contains(char::is_whitespace) {
        return None;
    }
    let domain = candidate.rsplit_once('@').map(|(_, domain)| domain)?;
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    let labels_valid = domain.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    });
    if !labels_valid {
        return None;
    }
    Some(domain)
}

/// Strip HTML tags deterministically: comments, `<script>`/`<style>`
/// element content, tag markup (replaced by a space so adjacent words never
/// join) and a minimal entity set. Bounded input, no regex, no allocation
/// beyond the output buffer.
fn strip_html(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '<' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        if starts_with_ci(&chars, i, "<!--") {
            i += 4;
            while i < chars.len() && !starts_with_ci(&chars, i, "-->") {
                i += 1;
            }
            i = (i + 3).min(chars.len());
            out.push(' ');
            continue;
        }
        if (starts_with_ci(&chars, i, "<script") || starts_with_ci(&chars, i, "<style"))
            && (tag_name_boundary(&chars, i, "<script") || tag_name_boundary(&chars, i, "<style"))
        {
            let closing = if starts_with_ci(&chars, i, "<script") {
                "</script"
            } else {
                "</style"
            };
            i += 1;
            while i < chars.len() && chars[i] != '>' {
                i += 1;
            }
            i = (i + 1).min(chars.len());
            while i < chars.len()
                && !(starts_with_ci(&chars, i, closing) && tag_name_boundary(&chars, i, closing))
            {
                i += 1;
            }
            while i < chars.len() && chars[i] != '>' {
                i += 1;
            }
            i = (i + 1).min(chars.len());
            out.push(' ');
            continue;
        }
        while i < chars.len() && chars[i] != '>' {
            i += 1;
        }
        i = (i + 1).min(chars.len());
        out.push(' ');
    }
    decode_entities(&out)
}

fn starts_with_ci(chars: &[char], at: usize, needle: &str) -> bool {
    let needle: Vec<char> = needle.chars().collect();
    if at + needle.len() > chars.len() {
        return false;
    }
    chars[at..at + needle.len()]
        .iter()
        .zip(needle.iter())
        .all(|(have, want)| have.eq_ignore_ascii_case(want))
}

/// A tag name starting at `at` must be terminated by whitespace, `/` or
/// `>` so `<scripty>` or `</scripty>` never matches `<script`.
fn tag_name_boundary(chars: &[char], at: usize, name: &str) -> bool {
    let name_len: usize = name.chars().count();
    match chars.get(at + name_len) {
        None => false,
        Some(&next) => matches!(next, ' ' | '\t' | '\r' | '\n' | '>' | '/'),
    }
}

fn decode_entities(source: &str) -> String {
    let replacements = [
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&#x27;", "'"),
    ];
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let matched = replacements
            .iter()
            .find(|(entity, _)| tail.starts_with(entity))
            .map(|(entity, value)| (*entity, *value));
        match matched {
            Some((entity, value)) => {
                out.push_str(value);
                rest = &tail[entity.len()..];
            },
            None => {
                out.push('&');
                rest = &tail[1..];
            },
        }
    }
    out.push_str(rest);
    out
}

const URL_TERMINATORS: [u8; 9] = [b' ', b'\t', b'\r', b'\n', b'"', b'\'', b'<', b'>', b')'];
const URL_TRAILING_PUNCTUATION: [u8; 5] = [b'.', b',', b';', b':', b'!'];

/// Collect bounded `http(s)://` candidates in one forward pass over the
/// given text. Candidates embedded in HTML attributes are found as well
/// because callers pass raw HTML source. Nothing is fetched or resolved.
/// Scheme and host are lowercased so obvious duplicates collapse.
fn collect_urls(text: &str, mut visit: impl FnMut(String)) {
    let bytes = text.as_bytes();
    let folded: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    let mut found = 0;
    let mut at = 0;
    while at + 6 <= folded.len() {
        let rest = &folded[at..];
        let scheme_len = if rest.starts_with(b"https://") {
            7
        } else if rest.starts_with(b"http://") {
            6
        } else {
            0
        };
        if scheme_len == 0 {
            at += 1;
            continue;
        }
        if found >= MAX_URLS {
            return;
        }
        let start = at;
        let mut end = at + scheme_len;
        while end < folded.len() && !URL_TERMINATORS.contains(&folded[end]) {
            end += 1;
        }
        while end > start + scheme_len && URL_TRAILING_PUNCTUATION.contains(&folded[end - 1]) {
            end -= 1;
        }
        if end > start {
            let mut stop = end;
            while stop > start && !text.is_char_boundary(stop) {
                stop -= 1;
            }
            if let Some(candidate) = text.get(start..stop) {
                let candidate: String = candidate.chars().take(MAX_URL_CHARS).collect();
                if candidate.chars().count() > scheme_len {
                    visit(normalize_url(&candidate));
                    found += 1;
                }
            }
        }
        at = end.max(at + 1);
    }
}

fn normalize_url(candidate: &str) -> String {
    match candidate.split_once("://") {
        Some((scheme, rest)) => {
            let (host, tail) = match rest.find('/') {
                Some(at) => (&rest[..at], &rest[at..]),
                None => (rest, ""),
            };
            format!(
                "{}://{}{}",
                scheme.to_ascii_lowercase(),
                host.to_ascii_lowercase(),
                tail
            )
        },
        None => candidate.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use nullapart_mail_contracts::{Confidence, FindingId, FindingScope};

    fn sample_mime() -> Vec<u8> {
        [
            "From: Alice <alice@example.test>\r\n",
            "Reply-To: alice@example.test\r\n",
            "Return-Path: <bounce@example.test>\r\n",
            "To: bob@example.test\r\n",
            "Subject: verify your account today\r\n",
            "X-Mailer: mailer\r\n",
            "Authentication-Results: mx.example.test; spf=pass\r\n",
            "X-Internal-Tag: secret\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Visit https://login.example.test/now and HTTPS://login.example.test/now\r\n",
            "--b\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<html><script>alert(1)</script><a href=\"https://evil.example.test/x\">click</a></html>\r\n",
            "--b\r\n",
            "Content-Type: application/pdf\r\n",
            "Content-Disposition: attachment; filename=\"report.pdf\"\r\n",
            "\r\n",
            "%PDF-fake\r\n",
            "--b--\r\n",
        ]
        .concat()
        .into_bytes()
    }

    fn finding(description: &str) -> SecurityFinding {
        SecurityFinding {
            id: FindingId::new(),
            scope: FindingScope::Transaction,
            scanner: ScannerType::UrlAnalysis,
            scanner_status: ScannerStatus::Threat,
            severity: FindingSeverity::High,
            confidence: Confidence::High,
            category: FindingCategory::MaliciousUrl,
            description: description.to_string(),
            details: None,
            indicators: Vec::new(),
            created_at: Utc::now(),
            false_positive: false,
            transaction_id: None,
            tenant_message_id: None,
        }
    }

    #[test]
    fn builds_versioned_representation_from_bounded_sources() {
        let findings = vec![finding("denied host matched")];
        let representation = build(&RepresentationSources {
            mime: &sample_mime(),
            findings: &findings,
            envelope_sender: None,
            vip: None,
        });

        assert_eq!(
            representation.representation_version,
            INLINE_ML_REPRESENTATION_VERSION
        );
        assert!(representation.mime_parsed);
        assert!(representation
            .headers
            .iter()
            .all(|header| ALLOWED_HEADERS.contains(&header.name.as_str())));
        assert!(!representation
            .headers
            .iter()
            .any(|header| header.name == "x-internal-tag"));
        assert_eq!(representation.subject.text, "verify your account today");
        assert_eq!(
            representation.sender.from_domain.as_deref(),
            Some("example.test")
        );
        assert_eq!(representation.findings.len(), 1);
        assert_eq!(
            representation.findings[0].description,
            "denied host matched"
        );
        assert_eq!(representation.attachments.len(), 1);
        assert_eq!(representation.attachments[0].filename, "report.pdf");
        assert_eq!(
            representation.attachments[0].content_type,
            "application/pdf"
        );
        assert!(representation
            .text
            .text
            .contains("Visit https://login.example.test/now"));
        assert!(!representation.text.text.contains("alert(1)"));
        assert!(representation.text.text.contains("click"));

        let urls: Vec<&str> = representation
            .urls
            .iter()
            .map(|url| url.url.as_str())
            .collect();
        assert_eq!(
            urls.iter()
                .filter(|u| **u == "https://login.example.test/now")
                .count(),
            1
        );
        assert!(urls.contains(&"https://evil.example.test/x"));
        assert!(representation
            .text
            .text
            .contains("Visit https://login.example.test/now"));
    }

    #[test]
    fn build_is_deterministic() {
        let findings = vec![finding("one")];
        let first = build(&RepresentationSources {
            mime: &sample_mime(),
            findings: &findings,
            envelope_sender: Some("bounce@example.test"),
            vip: None,
        });
        let second = build(&RepresentationSources {
            mime: &sample_mime(),
            findings: &findings,
            envelope_sender: Some("bounce@example.test"),
            vip: None,
        });
        assert_eq!(first, second);
    }

    #[test]
    fn text_truncation_is_char_boundary_safe_and_recorded() {
        let long_text = "é".repeat(MAX_TEXT_CHARS + 500);
        let mime = [
            "From: a@example.test\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            long_text.as_str(),
        ]
        .concat();
        let representation = build(&RepresentationSources {
            mime: mime.as_bytes(),
            findings: &[],
            envelope_sender: None,
            vip: None,
        });
        assert!(representation.text.truncated);
        assert_eq!(representation.text.text.chars().count(), MAX_TEXT_CHARS);
        assert_eq!(representation.text.original_chars, MAX_TEXT_CHARS + 500);
        assert!(representation.text.text.chars().all(|ch| ch == 'é'));
    }

    #[test]
    fn control_characters_are_neutralized_to_spaces_in_headers_and_text() {
        let mime = [
            "From: a@example.test\r\n",
            "Subject: hi\u{0000}there\u{0007} done\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "line\u{0008}one\r\nline\u{001b}[2Jtwo\r\n",
        ]
        .concat();
        let representation = build(&RepresentationSources {
            mime: mime.as_bytes(),
            findings: &[],
            envelope_sender: None,
            vip: None,
        });
        assert_eq!(representation.subject.text, "hi there  done");
        assert!(!representation.text.text.contains('\u{0008}'));
        assert!(!representation.text.text.contains('\u{001b}'));
        assert!(representation.text.text.contains("line one \nline [2Jtwo"));
    }

    #[test]
    fn url_count_is_bounded() {
        let urls: String = (0..MAX_URLS + 20)
            .map(|index| format!("https://host{index}.test/path "))
            .collect();
        let mime = [
            "From: a@example.test\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            urls.as_str(),
        ]
        .concat();
        let representation = build(&RepresentationSources {
            mime: mime.as_bytes(),
            findings: &[],
            envelope_sender: None,
            vip: None,
        });
        assert_eq!(representation.urls.len(), MAX_URLS);
    }

    #[test]
    fn header_field_count_is_bounded() {
        let mut mime = String::from("From: a@example.test\r\n");
        for index in 0..MAX_HEADER_FIELDS + 5 {
            mime.push_str(&format!("To: user{index}@example.test\r\n"));
        }
        mime.push_str("Content-Type: text/plain\r\n\r\nbody\r\n");
        let representation = build(&RepresentationSources {
            mime: mime.as_bytes(),
            findings: &[],
            envelope_sender: None,
            vip: None,
        });
        assert_eq!(representation.headers.len(), MAX_HEADER_FIELDS);
    }

    #[test]
    fn attachment_and_finding_counts_are_bounded() {
        let mut mime = String::from(
            "From: a@example.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n",
        );
        for index in 0..MAX_ATTACHMENTS + 8 {
            mime.push_str(&format!(
                "--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"f{index}.bin\"\r\n\r\ndata\r\n"
            ));
        }
        mime.push_str("--b--\r\n");
        let findings: Vec<SecurityFinding> = (0..MAX_FINDINGS + 6)
            .map(|index| finding(&format!("f{index}")))
            .collect();
        let representation = build(&RepresentationSources {
            mime: mime.as_bytes(),
            findings: &findings,
            envelope_sender: None,
            vip: None,
        });
        assert_eq!(representation.attachments.len(), MAX_ATTACHMENTS);
        assert_eq!(representation.findings.len(), MAX_FINDINGS);
    }

    #[test]
    fn malformed_mime_does_not_panic_and_stays_bounded() {
        let mime = b" overhanging-header-line\r\nContent-Type: text/plain\r\n\r\nbody";
        let representation = build(&RepresentationSources {
            mime,
            findings: &[],
            envelope_sender: None,
            vip: None,
        });
        assert!(!representation.mime_parsed);
        assert_eq!(
            representation.representation_version,
            INLINE_ML_REPRESENTATION_VERSION
        );
        assert!(representation.urls.is_empty());
        assert!(representation.attachments.is_empty());
    }

    #[test]
    fn html_entities_and_obfuscated_control_text_are_cleaned() {
        let mime = [
            "From: a@example.test\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>Pay &amp; verify &#39;now&#39; &lt;urgency&gt;</p>\r\n",
        ]
        .concat();
        let representation = build(&RepresentationSources {
            mime: mime.as_bytes(),
            findings: &[],
            envelope_sender: None,
            vip: None,
        });
        assert!(representation
            .text
            .text
            .contains("Pay & verify 'now' <urgency>"));
        assert!(!representation.text.text.contains("<p>"));
    }

    #[test]
    fn email_domain_extraction_is_strict() {
        assert_eq!(
            email_domain("Alice <alice@Example.Test>"),
            Some("example.test".to_string())
        );
        assert_eq!(
            email_domain("alice@example.test"),
            Some("example.test".to_string())
        );
        assert_eq!(email_domain("not-an-address"), None);
        assert_eq!(email_domain("<a@b c@example.test>"), None);
        assert_eq!(email_domain("<a@-bad-.example>"), None);
    }

    #[test]
    fn vip_context_is_present_only_when_supplied() {
        let vip = VipSignal {
            principals: vec!["ceo@example.test".to_string()],
        };
        let with = build(&RepresentationSources {
            mime: b"From: a@example.test\r\n\r\nbody\r\n",
            findings: &[],
            envelope_sender: None,
            vip: Some(&vip),
        });
        assert_eq!(with.vip.as_ref().map(|v| v.principals.len()), Some(1));
        let without = build(&RepresentationSources {
            mime: b"From: a@example.test\r\n\r\nbody\r\n",
            findings: &[],
            envelope_sender: None,
            vip: None,
        });
        assert!(without.vip.is_none());
    }
}
