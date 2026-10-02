//! Deterministic model-text composition for inline ML.
//!
//! [`compose_model_text`] is the Rust equivalent of the training-side
//! `compose_text`/`clean_text` pair in `ml/inline/prepare_dataset.py`: the
//! exact byte sequence the tokenizer consumes must be reproducible from the
//! bounded [`InlineMlRepresentation`] alone, so live scoring matches the
//! text contract the checkpoint was trained and evaluated under
//! (`docs/phases/PHASE-4-INLINE-ML.md` input contract).

use super::representation::{InlineMlRepresentation, MAX_TEXT_CHARS};

/// Final composed-text cap: training used `MAX_BODY_CHARS + 2048`.
pub const MAX_COMPOSED_TEXT_CHARS: usize = MAX_TEXT_CHARS + 2048;

/// Per-section caps matching the dataset record builders
/// (`prepare_dataset.py`: subject 256, auth 512, from display 256).
const MAX_SUBJECT_SECTION_CHARS: usize = 256;
const MAX_AUTH_SECTION_CHARS: usize = 512;
const MAX_FROM_SECTION_CHARS: usize = 256;

/// URL count cap matching `prepare_dataset.MAX_URLS`.
const MAX_COMPOSED_URLS: usize = 8;

/// Control characters the training `CONTROL_CHARS` regex replaced with a
/// space before whitespace collapsing.
const fn is_python_control(ch: char) -> bool {
    matches!(ch,
        '\u{00}'..='\u{08}' | '\u{0b}' | '\u{0c}' | '\u{0e}'..='\u{1f}' | '\u{7f}')
}

/// Python `clean_text`: control characters become spaces, whitespace runs
/// collapse to one space, the result is stripped and truncated to `limit`
/// Unicode scalar values.
pub(crate) fn clean_text(value: &str, limit: usize) -> String {
    let mut out = String::with_capacity(value.len().min(limit + 1));
    let mut out_chars = 0usize;
    let mut pending_space = false;
    for ch in value.chars() {
        if is_python_control(ch) || ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            if out_chars >= limit {
                break;
            }
            out.push(' ');
            out_chars += 1;
        }
        pending_space = false;
        if out_chars >= limit {
            break;
        }
        out.push(ch);
        out_chars += 1;
    }
    out
}

fn header_value<'a>(representation: &'a InlineMlRepresentation, name: &str) -> Option<&'a str> {
    representation
        .headers
        .iter()
        .find(|header| header.name == name)
        .map(|header| header.value.as_str())
}

/// Compose the exact model input text from the bounded representation,
/// mirroring `prepare_dataset.compose_text` part order and limits.
pub fn compose_model_text(representation: &InlineMlRepresentation) -> String {
    let mut parts: Vec<String> = Vec::new();

    let subject = clean_text(&representation.subject.text, MAX_SUBJECT_SECTION_CHARS);
    if !subject.is_empty() {
        parts.push(format!("Subject: {subject}"));
    }
    if let Some(from) = header_value(representation, "from") {
        let cleaned = clean_text(from, MAX_FROM_SECTION_CHARS);
        if !cleaned.is_empty() {
            parts.push(format!("From: {cleaned}"));
        }
    }
    if let Some(auth) = header_value(representation, "authentication-results") {
        let cleaned = clean_text(auth, MAX_AUTH_SECTION_CHARS);
        if !cleaned.is_empty() {
            parts.push(format!("Authentication-Results: {cleaned}"));
        }
    }
    if !representation.urls.is_empty() {
        let urls = representation
            .urls
            .iter()
            .take(MAX_COMPOSED_URLS)
            .map(|url| url.url.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        parts.push(format!("URLs: {urls}"));
    }
    if let Some(attachment) = representation.attachments.first() {
        parts.push(format!(
            "Attachment: {} ({})",
            attachment.filename, attachment.content_type
        ));
    }
    parts.push(representation.text.text.clone());

    clean_text(&parts.join("\n"), MAX_COMPOSED_TEXT_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_representation() -> InlineMlRepresentation {
        super::super::representation::build(&super::super::representation::RepresentationSources {
            mime: [
                "From: Alice <alice@example.test>\r\n",
                "Subject: verify   your account\ttoday\r\n",
                "Authentication-Results: mx.example.test; spf=fail\r\n",
                "MIME-Version: 1.0\r\n",
                "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                "\r\n",
                "--b\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "\r\n",
                "Visit https://login.example.test/now now\r\n",
                "--b\r\n",
                "Content-Type: application/pdf\r\n",
                "Content-Disposition: attachment; filename=\"report.pdf\"\r\n",
                "\r\n",
                "%PDF-fake\r\n",
                "--b--\r\n",
            ]
            .concat()
            .as_bytes(),
            findings: &[],
            envelope_sender: None,
            vip: None,
        })
    }

    #[test]
    fn clean_text_collapses_whitespace_and_strips_like_python() {
        assert_eq!(clean_text("  a \t\n b  ", 64), "a b");
        assert_eq!(clean_text("\u{01}secret\u{1f}tail", 64), "secret tail");
        assert_eq!(clean_text("", 64), "");
        assert_eq!(clean_text("only   \n spaces ", 64), "only spaces");
    }

    #[test]
    fn clean_text_truncates_at_limit_chars() {
        assert_eq!(clean_text("abcdef", 3), "abc");
        assert_eq!(clean_text("éééé", 2), "éé");
    }

    #[test]
    fn compose_matches_training_part_order() {
        let text = compose_model_text(&sample_representation());
        assert_eq!(
            text,
            "Subject: verify your account today From: Alice <alice@example.test> \
             Authentication-Results: mx.example.test; spf=fail \
             URLs: https://login.example.test/now \
             Attachment: report.pdf (application/pdf) \
             Visit https://login.example.test/now now"
        );
    }

    #[test]
    fn compose_omits_absent_sections() {
        let representation = super::super::representation::build(
            &super::super::representation::RepresentationSources {
                mime: b"Subject: hi\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
                findings: &[],
                envelope_sender: None,
                vip: None,
            },
        );
        assert_eq!(compose_model_text(&representation), "Subject: hi body");
    }

    #[test]
    fn compose_caps_url_section_at_eight() {
        let body = (0..12)
            .map(|index| format!("https://host{index}.test/p"))
            .collect::<Vec<_>>()
            .join(" ");
        let mime = format!("Subject: many\r\nContent-Type: text/plain\r\n\r\n{body}\r\n");
        let representation = super::super::representation::build(
            &super::super::representation::RepresentationSources {
                mime: mime.as_bytes(),
                findings: &[],
                envelope_sender: None,
                vip: None,
            },
        );
        let text = compose_model_text(&representation);
        assert!(
            representation.urls.len() > MAX_COMPOSED_URLS,
            "fixture extracts more urls than the compose cap"
        );
        let capped = representation
            .urls
            .iter()
            .take(MAX_COMPOSED_URLS)
            .map(|url| url.url.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains(&format!("URLs: {capped}")));
        assert_eq!(capped.split_whitespace().count(), MAX_COMPOSED_URLS);
    }

    #[test]
    fn compose_respects_final_char_cap() {
        let long_urls = (0..10)
            .map(|index| format!("https://host{index}.test/{}", "a".repeat(2100)))
            .collect::<Vec<_>>()
            .join(" ");
        let mime = format!("Subject: s\r\nContent-Type: text/plain\r\n\r\n{long_urls}\r\n");
        let representation = super::super::representation::build(
            &super::super::representation::RepresentationSources {
                mime: mime.as_bytes(),
                findings: &[],
                envelope_sender: None,
                vip: None,
            },
        );
        let text = compose_model_text(&representation);
        assert_eq!(text.chars().count(), MAX_COMPOSED_TEXT_CHARS);
    }
}
