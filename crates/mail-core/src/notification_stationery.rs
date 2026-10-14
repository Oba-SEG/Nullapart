//! Branded, content-safe stationery for future Nullapart service notices.
//!
//! This module deliberately renders a complete HTML and plain-text alternative
//! but does **not** send mail. Dispatch remains an explicit, audited workflow
//! owned by the phase that introduces it. Keeping the template pure avoids a
//! styling change accidentally becoming a new outbound side effect.

/// Content supplied by a trusted server-side notification workflow.
///
/// Fields are escaped at the rendering boundary. Callers must still avoid
/// placing secrets, raw MIME, attachment content, or unredacted scanner/model
/// internals in a notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceNotice<'a> {
    pub category: &'a str,
    pub title: &'a str,
    pub preview: &'a str,
    pub summary: &'a str,
    pub reference: Option<&'a str>,
}

/// A bundled asset a future sender can attach with a content ID rather than
/// making an email client fetch a remote image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InlineStationeryAsset {
    pub content_id: &'static str,
    pub media_type: &'static str,
    pub bytes: &'static [u8],
}

/// The content ID reserved for the optional stationery artwork.
pub const EMAIL_STATIONERY_BANNER_CONTENT_ID: &str = "nullapart-stationery-banner";

const EMAIL_STATIONERY_BANNER_PNG: &[u8] =
    include_bytes!("../assets/brand/nullapart-email-stationery-banner@2x.png");

/// Return the high-density artwork that a future mail composer may attach as
/// a CID part. `render_html` intentionally does not reference it yet: this
/// repository has no reviewed notification dispatch/attachment composer.
#[must_use]
pub fn inline_assets() -> [InlineStationeryAsset; 1] {
    [InlineStationeryAsset {
        content_id: EMAIL_STATIONERY_BANNER_CONTENT_ID,
        media_type: "image/png",
        bytes: EMAIL_STATIONERY_BANNER_PNG,
    }]
}

/// Render an email-client-safe HTML document using Nullapart's stationery.
///
/// The template intentionally has no remote images, tracking pixels, scripts,
/// forms, or caller-controlled markup. Many mail clients block remote images;
/// avoiding them also prevents the stationery itself from creating recipient
/// tracking or privacy surprises.
#[must_use]
pub fn render_html(notice: &ServiceNotice<'_>) -> String {
    let category = escape_html(notice.category);
    let title = escape_html(notice.title);
    let preview = escape_html(notice.preview);
    let summary = escape_html_with_breaks(notice.summary);
    let reference = notice.reference.map(escape_html);

    let reference_row = reference.map_or_else(String::new, |reference| {
        format!(
            r#"<tr><td style="padding:0 32px 28px;color:#aeb8b6;font:12px/18px -apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,sans-serif;letter-spacing:.02em">Reference: {reference}</td></tr>"#
        )
    });

    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="x-apple-disable-message-reformatting">
    <title>{title}</title>
  </head>
  <body style="margin:0;padding:0;background:#050505;color:#fafafa">
    <span style="display:none!important;visibility:hidden;mso-hide:all;font-size:1px;color:#050505;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden">{preview}</span>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#050505">
      <tr><td align="center" style="padding:32px 16px">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:620px;background:#001010;border:1px solid #28443d;border-radius:20px;overflow:hidden">
          <tr><td style="height:5px;background:#a8ff00;font-size:0;line-height:0">&nbsp;</td></tr>
          <tr><td style="padding:30px 32px 22px;background:linear-gradient(120deg,#0e211d 0%,#001010 64%,#052d2b 100%)">
            <div style="margin:0;color:#a8ff00;font:700 12px/16px -apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,sans-serif;letter-spacing:.18em">NULLAPART</div>
            <div style="margin:12px 0 0;color:#b8c2c0;font:600 11px/15px -apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,sans-serif;letter-spacing:.12em;text-transform:uppercase">{category}</div>
          </td></tr>
          <tr><td style="padding:8px 32px 16px"><h1 style="margin:0;color:#fafafa;font:700 28px/35px -apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,sans-serif;letter-spacing:-.02em">{title}</h1></td></tr>
          <tr><td style="padding:0 32px 28px;color:#dce5e2;font:400 16px/25px -apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,sans-serif">{summary}</td></tr>
          {reference_row}
          <tr><td style="padding:22px 32px;background:#061714;border-top:1px solid #28443d;color:#8e9b98;font:400 12px/18px -apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,sans-serif">This is a Nullapart service notice. Do not reply to this message.</td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>"#
    )
}

/// Render the required plain-text alternative for clients that do not accept
/// HTML. It follows the same information hierarchy as [`render_html`].
#[must_use]
pub fn render_text(notice: &ServiceNotice<'_>) -> String {
    let mut output = format!(
        "NULLAPART\n{}\n\n{}\n\n{}",
        notice.category.trim(),
        notice.title.trim(),
        notice.summary.trim(),
    );
    if let Some(reference) = notice
        .reference
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        output.push_str("\n\nReference: ");
        output.push_str(reference);
    }
    output.push_str("\n\nThis is a Nullapart service notice. Do not reply to this message.");
    output
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn escape_html_with_breaks(input: &str) -> String {
    escape_html(input)
        .replace("\r\n", "<br>")
        .replace('\n', "<br>")
}

#[cfg(test)]
mod tests {
    use image::GenericImageView;

    use super::{inline_assets, render_html, render_text, ServiceNotice};

    fn notice() -> ServiceNotice<'static> {
        ServiceNotice {
            category: "Security posture",
            title: "A domain needs attention",
            preview: "A domain security record needs review.",
            summary: "Review the configured DMARC record before it affects reporting.",
            reference: Some("dns-observation-014"),
        }
    }

    #[test]
    fn renders_branded_html_without_remote_or_active_content() {
        let html = render_html(&notice());

        assert!(html.contains("NULLAPART"));
        assert!(html.contains(r#"<html lang="en">"#));
        assert!(!html.contains(r#"\\\""#));
        assert!(html.contains("#a8ff00"));
        assert!(html.contains("Reference: dns-observation-014"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<form"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn escapes_untrusted_values_at_the_rendering_boundary() {
        let html = render_html(&ServiceNotice {
            category: "<b>Security</b>",
            title: "<script>alert('x')</script>",
            preview: "<img src=x>",
            summary: "First line\n<a href=\"bad\">second line</a>",
            reference: Some("'unsafe' & <tag>"),
        });

        assert!(html.contains("&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"));
        assert!(html.contains("First line<br>&lt;a href=&quot;bad&quot;&gt;second line&lt;/a&gt;"));
        assert!(html.contains("&#x27;unsafe&#x27; &amp; &lt;tag&gt;"));
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("<a href"));
    }

    #[test]
    fn renders_a_plain_text_alternative() {
        let text = render_text(&notice());

        assert!(text.starts_with("NULLAPART\nSecurity posture"));
        assert!(text.contains("Reference: dns-observation-014"));
        assert!(text.ends_with("Do not reply to this message."));
    }

    #[test]
    fn includes_a_high_density_cid_ready_banner() {
        let [banner] = inline_assets();
        let decoded =
            image::load_from_memory(banner.bytes).expect("bundled banner must be valid PNG");

        assert_eq!(banner.content_id, "nullapart-stationery-banner");
        assert_eq!(banner.media_type, "image/png");
        assert_eq!(decoded.dimensions(), (2172, 724));
    }
}
