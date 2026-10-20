//! Telemetry scrub gate.
//!
//! Every string that enters a SegLumberjack envelope passes through this
//! gate. The instrumented code paths are expected to pass static messages
//! and opaque identifiers; this layer is the defense in depth that keeps a
//! mistake (a dynamic value carrying message content, a secret, or an
//! over-large dump) from becoming an envelope leak.
//!
//! Documented contract (docs/11-OBSERVABILITY-SECRETS.md): no message body,
//! raw MIME, attachments, tokens/cookies/passwords, secrets or private keys;
//! addresses/PII minimized to opaque identifiers only.

/// Hard bound on a single scrubbed string field.
const MAX_FIELD_BYTES: usize = 512;

/// A suspicious-content marker list, intentionally small and cheap to run
/// against short static strings. All markers are lowercase and matched
/// against the case-insensitive form of the input. String containment is a
/// heuristic net, not a parser: the primary defense is that callers never
/// pass dynamic content in the first place. Over-aggressive matches are
/// accepted deliberately — losing a diagnostic string is acceptable,
/// leaking it is not.
const SCRUB_MARKERS: &[&str] = &[
    "begin private key",
    "begin certificate",
    "akia",
    "aws_secret_access_key",
    "sk_live_",
    "ghp_",
    "gho_",
    "bearer",
    "authorization",
    "set-cookie",
    "cookie:",
    "password",
    "passwd",
    "x-spam",
    "x-rspamd",
    "subject:",
    "received: from",
    "content-transfer-encoding",
    "--bounda",
    "select * from",
    "insert into",
    "psql:",
    "postgres://",
    "postgresql://",
    "ssh://",
];

/// Scrubs one field for telemetry inclusion. Returns a best-effort,
/// bounded string. `None` means the value must not be included at all.
pub fn scrub_text(value: &str) -> Option<String> {
    let lowered = value.to_lowercase();
    for marker in SCRUB_MARKERS {
        if lowered.contains(marker) {
            return None;
        }
    }
    if value.trim().is_empty() {
        return None;
    }
    let mut bounded = String::new();
    let mut truncated = false;
    for character in value.chars() {
        let byte_len = character.len_utf8();
        if bounded.len() + byte_len > MAX_FIELD_BYTES {
            truncated = true;
            break;
        }
        if character.is_control() {
            bounded.push('\u{fffd}');
        } else {
            bounded.push(character);
        }
    }
    if truncated {
        bounded.push('…');
    }
    Some(bounded)
}

/// Scrubs a key used in maps (tags/extra): shorter bound, and markers are
/// checked like values in case a dynamic key leaked a secret.
pub fn scrub_key(value: &str) -> Option<String> {
    let candidate = {
        let mut bounded = String::new();
        for character in value.chars() {
            if bounded.len() + character.len_utf8() > 64 {
                return None;
            }
            bounded.push(character);
        }
        bounded
    };
    let lowered = candidate.to_lowercase();
    if SCRUB_MARKERS.iter().any(|marker| lowered.contains(marker)) {
        return None;
    }
    if candidate.is_empty() {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_static_messages() {
        assert_eq!(
            scrub_text("handoff rejected: signature mismatch"),
            Some("handoff rejected: signature mismatch".to_string())
        );
    }

    #[test]
    fn drops_private_key_material() {
        let value = "-----BEGIN PRIVATE KEY-----MIIEv";
        assert_eq!(scrub_text(value), None);
    }

    #[test]
    fn drops_aws_and_github_credential_shapes() {
        assert_eq!(scrub_text("AKIA...--ENV--"), None);
        assert_eq!(scrub_text("token ghp_16CharactersXXXXXXXX"), None);
    }

    #[test]
    fn drops_header_and_mime_fragments() {
        assert_eq!(scrub_text("Subject: you have won"), None);
        assert_eq!(scrub_text("--boundary--\r\nContent-Type"), None);
        assert_eq!(scrub_text("X-Spam: yes"), None);
    }

    #[test]
    fn drops_database_and_url_credentials() {
        assert_eq!(scrub_text("SELECT * FROM customers"), None);
        assert_eq!(scrub_text("postgresql://user:secret@host/db"), None);
        assert_eq!(scrub_text("psql: FATAL role does not exist"), None);
    }

    #[test]
    fn truncates_long_values() {
        let value = "a".repeat(4096);
        let scrubbed = scrub_text(&value).expect("plain text must survive");
        assert!(
            scrubbed.chars().count() <= MAX_FIELD_BYTES + 1,
            "content is byte-bounded with room for the truncation marker"
        );
        assert!(scrubbed.ends_with('…'));
    }

    #[test]
    fn strips_control_characters() {
        assert_eq!(
            scrub_text("line\u{0001}break"),
            Some("line\u{fffd}break".to_string())
        );
    }

    #[test]
    fn empty_text_is_dropped() {
        assert_eq!(scrub_text(""), None);
    }

    #[test]
    fn keys_are_bounded() {
        assert!(scrub_key("transaction_id").is_some());
        assert_eq!(scrub_key(""), None);
        assert!(scrub_key("a".repeat(80).as_str()).is_none());
    }

    #[test]
    fn keys_carry_no_secrets() {
        assert_eq!(scrub_key("Authorization"), None);
        assert_eq!(scrub_key("Set-Cookie"), None);
    }

    #[test]
    fn envelope_identifiers_are_minimized() {
        // Identifiers stay stable: no e-mail-shaped minimization loss on ids.
        let id = "5fe45b32-96df-5850-93f7-6081cbe715ba";
        assert_eq!(
            scrub_text(id),
            Some("5fe45b32-96df-5850-93f7-6081cbe715ba".to_string())
        );
    }
}
