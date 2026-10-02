//! Local scanner adapters for the Phase 2 fabric.
//!
//! These adapters run after queue acceptance and analyse only the
//! fabric-supplied immutable [`ScanContent`] snapshot through a single bounded
//! read. A scan never re-fetches bytes by artifact ID and never reconstructs
//! MIME from a path. They are intentionally modest; native parser and malware
//! engines remain separate, resource-isolated adapters.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::ops::Range;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use image::{DynamicImage, ImageReader, Limits};
use mailparse::{DispositionType, ParsedMail};
use nullapart_scanner_sdk::{
    trait_defs::{ScanContent, ScanContentError, ScanError, Scanner, ScannerId},
    types::{
        FindingSeverity, LatencyClass, ScanRequest, ScanResult, ScannerCapabilities,
        ScannerFinding, ScannerHealth, ScannerProvenance, ScannerStatus,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Stable, content-free rejection text for the URL-candidate budget. It never
/// embeds counts, tokens or message bytes, so a resource-limit failure cannot
/// leak raw content or unstable engine state to a caller.
const URL_CANDIDATE_LIMIT_MESSAGE: &str = "URL candidate count limit exceeded";

/// Stable, content-free rejection text for a URL candidate whose authority
/// carries any ampersand or any percent sign — that covers numeric and named
/// HTML character references alike and every percent-encoded octet. It never
/// embeds counts, tokens or message bytes: the adapter fails closed and defers
/// to a reviewed parser integration instead of decoding or parsing the raw
/// form.
const URL_AUTHORITY_ENCODING_REQUIRES_REVIEW: &str = "URL_AUTHORITY_ENCODING_REQUIRES_REVIEW";

/// Isolated ClamAV `clamd` adapter using the bounded INSTREAM protocol. The
/// scanner receives only the immutable fabric snapshot; the TCP endpoint is a
/// private scanner container/node and is never exposed to a browser or public
/// network.
#[derive(Clone)]
pub struct ClamAvScanner {
    endpoint: String,
    max_input_bytes: u64,
}

impl ClamAvScanner {
    pub fn new(endpoint: impl Into<String>, max_input_bytes: u64) -> Self {
        Self {
            endpoint: endpoint.into(),
            max_input_bytes,
        }
    }
}

#[async_trait]
impl Scanner for ClamAvScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("clamav")
    }

    fn name(&self) -> &str {
        "Malware analysis"
    }

    fn version(&self) -> &str {
        "clamd-instream-v1"
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Medium,
            requires_network: true,
            milter_compatible: false,
            extra: serde_json::Value::Null,
        }
    }

    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        let mut stream = TcpStream::connect(&self.endpoint)
            .await
            .map_err(|_| ScanError::Unavailable("malware scanner unavailable".to_string()))?;
        stream
            .write_all(b"zINSTREAM\0")
            .await
            .map_err(|_| ScanError::Unavailable("malware scanner unavailable".to_string()))?;
        for chunk in bytes.chunks(64 * 1024) {
            let length = u32::try_from(chunk.len()).map_err(|_| {
                ScanError::ResourceLimit("malware chunk limit exceeded".to_string())
            })?;
            stream
                .write_all(&length.to_be_bytes())
                .await
                .map_err(|_| ScanError::Unavailable("malware scanner unavailable".to_string()))?;
            stream
                .write_all(chunk)
                .await
                .map_err(|_| ScanError::Unavailable("malware scanner unavailable".to_string()))?;
        }
        stream
            .write_all(&0_u32.to_be_bytes())
            .await
            .map_err(|_| ScanError::Unavailable("malware scanner unavailable".to_string()))?;
        let mut response = Vec::with_capacity(256);
        stream
            .take(4096)
            .read_to_end(&mut response)
            .await
            .map_err(|_| ScanError::Failed("malware scanner response failed".to_string()))?;
        let response = String::from_utf8_lossy(&response);
        let (status, findings) = if response.contains(" FOUND") {
            (
                ScannerStatus::Threat,
                vec![finding(
                    "malware",
                    "Malware signature matched",
                    FindingSeverity::Critical,
                )],
            )
        } else if response.contains(" OK") {
            (ScannerStatus::Clean, Vec::new())
        } else {
            return Err(ScanError::Failed(
                "malware scanner returned an invalid response".to_string(),
            ));
        };
        Ok(adapter_result(
            self, &request, status, findings, started, started_at,
        ))
    }

    async fn health(&self) -> ScannerHealth {
        ScannerHealth {
            healthy: TcpStream::connect(&self.endpoint).await.is_ok(),
            message: None,
            checked_at: Utc::now(),
            uptime_seconds: None,
            queue_depth: None,
        }
    }
}

/// Offline static-rule scanner for content signatures. The initial rule set is
/// intentionally tiny and deterministic for local development; production
/// rule distribution and native/YARA execution belong in an isolated scanner
/// runtime behind this same contract.
#[derive(Clone)]
pub struct StaticRuleScanner {
    max_input_bytes: u64,
}

impl StaticRuleScanner {
    pub fn new(max_input_bytes: u64) -> Self {
        Self { max_input_bytes }
    }
}

#[async_trait]
impl Scanner for StaticRuleScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("static-rule")
    }
    fn name(&self) -> &str {
        "Static rule analysis"
    }
    fn version(&self) -> &str {
        "1"
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: false,
            extra: serde_json::Value::Null,
        }
    }
    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        // EICAR is a safe, industry-standard malware-test signature. It is
        // used only to verify detection wiring, never as an executable fixture.
        let findings = if contains_marker(&bytes, b"X5O!P%@AP") {
            vec![finding(
                "malware",
                "Static malware rule matched",
                FindingSeverity::High,
            )]
        } else {
            Vec::new()
        };
        let status = if findings.is_empty() {
            ScannerStatus::Clean
        } else {
            ScannerStatus::Threat
        };
        Ok(adapter_result(
            self, &request, status, findings, started, started_at,
        ))
    }
    async fn health(&self) -> ScannerHealth {
        healthy()
    }
}

/// URL/domain reputation adapter with an explicitly configured local denylist.
/// It avoids an implicit third-party data export in local development; a
/// production reputation provider must be separately reviewed and isolated.
///
/// The adapter is offline: it never resolves, fetches or follows a URL. It
/// extracts `http://`/`https://` candidates in one forward pass over the
/// already-read decoded bytes — including occurrences embedded in quoted HTML
/// attributes — compares their normalized hosts against the local denylist and
/// enforces `ResourceLimits::max_url_count` before inspecting any further
/// candidate.
#[derive(Clone)]
pub struct UrlReputationScanner {
    max_input_bytes: u64,
    denied_domains: Vec<String>,
}

/// Bounded archive structure inspection. It never expands an archive: the
/// production deep parser runs separately with the same limits.
#[derive(Clone)]
pub struct ArchiveSafetyScanner {
    max_input_bytes: u64,
    max_entries: usize,
}

impl ArchiveSafetyScanner {
    pub fn new(max_input_bytes: u64, max_entries: usize) -> Self {
        Self {
            max_input_bytes,
            max_entries,
        }
    }
}

#[async_trait]
impl Scanner for ArchiveSafetyScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("archive")
    }
    fn name(&self) -> &str {
        "Archive structure analysis"
    }
    fn version(&self) -> &str {
        "1"
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: false,
            extra: serde_json::Value::Null,
        }
    }
    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        let local_headers = bytes
            .windows(4)
            .filter(|window| *window == b"PK\x03\x04")
            .count();
        if local_headers > self.max_entries {
            return Err(ScanError::ResourceLimit(format!(
                "archive entry limit exceeded: {local_headers} entries, max {}",
                self.max_entries
            )));
        }
        let encrypted = bytes
            .windows(8)
            .any(|window| window.starts_with(b"PK\x03\x04") && window[6] & 1 == 1);
        let findings = if encrypted {
            vec![finding(
                "malicious_attachment",
                "Encrypted archive requires explicit review",
                FindingSeverity::Medium,
            )]
        } else {
            Vec::new()
        };
        let status = if findings.is_empty() {
            ScannerStatus::Clean
        } else {
            ScannerStatus::Suspicious
        };
        Ok(adapter_result(
            self, &request, status, findings, started, started_at,
        ))
    }
    async fn health(&self) -> ScannerHealth {
        healthy()
    }
}

/// Detects active document markers without parsing or rendering the document.
#[derive(Clone)]
pub struct DocumentSafetyScanner {
    max_input_bytes: u64,
}

/// Bounded image metadata inspection. This adapter does not decode or render
/// image pixels; it rejects PNG dimensions above its explicit pixel budget and
/// treats SVG script content as active content.
#[derive(Clone)]
pub struct ImageSafetyScanner {
    max_input_bytes: u64,
    max_pixels: u64,
}

impl ImageSafetyScanner {
    pub fn new(max_input_bytes: u64, max_pixels: u64) -> Self {
        Self {
            max_input_bytes,
            max_pixels,
        }
    }
}

#[async_trait]
impl Scanner for ImageSafetyScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("image")
    }
    fn name(&self) -> &str {
        "Image safety analysis"
    }
    fn version(&self) -> &str {
        "1"
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: false,
            extra: serde_json::Value::Null,
        }
    }
    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        let svg_active = String::from_utf8_lossy(&bytes)
            .to_ascii_lowercase()
            .contains("<script");
        if let Some(pixels) = png_pixel_count(&bytes) {
            if pixels > self.max_pixels {
                return Err(ScanError::ResourceLimit(format!(
                    "image pixel budget exceeded: {pixels} pixels, max {}",
                    self.max_pixels
                )));
            }
        }
        let findings = if svg_active {
            vec![finding(
                "malicious_attachment",
                "Active SVG content requires policy review",
                FindingSeverity::Medium,
            )]
        } else {
            Vec::new()
        };
        let status = if findings.is_empty() {
            ScannerStatus::Clean
        } else {
            ScannerStatus::Suspicious
        };
        Ok(adapter_result(
            self, &request, status, findings, started, started_at,
        ))
    }
    async fn health(&self) -> ScannerHealth {
        healthy()
    }
}

impl DocumentSafetyScanner {
    pub fn new(max_input_bytes: u64) -> Self {
        Self { max_input_bytes }
    }
}

#[async_trait]
impl Scanner for DocumentSafetyScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("document")
    }
    fn name(&self) -> &str {
        "Document active-content analysis"
    }
    fn version(&self) -> &str {
        "1"
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: false,
            extra: serde_json::Value::Null,
        }
    }
    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        let upper = String::from_utf8_lossy(&bytes).to_ascii_uppercase();
        let active = upper.contains("/JAVASCRIPT")
            || upper.contains("/JS")
            || upper.contains("VBAPROJECT.BIN");
        let findings = if active {
            vec![finding(
                "malicious_attachment",
                "Document contains an active-content marker",
                FindingSeverity::High,
            )]
        } else {
            Vec::new()
        };
        let status = if findings.is_empty() {
            ScannerStatus::Clean
        } else {
            ScannerStatus::Suspicious
        };
        Ok(adapter_result(
            self, &request, status, findings, started, started_at,
        ))
    }
    async fn health(&self) -> ScannerHealth {
        healthy()
    }
}

impl UrlReputationScanner {
    pub fn new(max_input_bytes: u64, denied_domains: Vec<String>) -> Self {
        Self {
            max_input_bytes,
            denied_domains: denied_domains
                .into_iter()
                .map(|domain| domain.to_ascii_lowercase())
                .collect(),
        }
    }
}

#[async_trait]
impl Scanner for UrlReputationScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("url-reputation")
    }
    fn name(&self) -> &str {
        "URL reputation analysis"
    }
    fn version(&self) -> &str {
        "1"
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: false,
            extra: serde_json::Value::Null,
        }
    }
    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        let text = String::from_utf8_lossy(&bytes);
        let max_url_count = u64::from(request.limits.max_url_count);
        let mut candidates_seen: u64 = 0;
        let mut matched_domains: Vec<&str> = Vec::new();
        // One deterministic forward pass over the decoded text. Every ASCII
        // case-insensitive `http://`/`https://` occurrence is a candidate in
        // encounter order — including ones embedded in quoted HTML attributes
        // such as `href="…"` — and each is counted before host normalization
        // or denylist inspection. Body text outside a candidate is never
        // searched for denied domains.
        visit_url_candidates(&text, |candidate| {
            candidates_seen += 1;
            if candidates_seen > max_url_count {
                return Err(ScanError::ResourceLimit(
                    URL_CANDIDATE_LIMIT_MESSAGE.to_string(),
                ));
            }
            // Fail closed before any host normalization or denylist
            // comparison: an authority holding `&` or `%` is never reported
            // clean, and the rejection happens only after this candidate has
            // been counted.
            if authority_requires_encoding_review(candidate) {
                return Err(ScanError::ResourceLimit(
                    URL_AUTHORITY_ENCODING_REQUIRES_REVIEW.to_string(),
                ));
            }
            let Some(host) = normalized_candidate_host(candidate) else {
                return Ok(());
            };
            for domain in &self.denied_domains {
                let denied = domain.as_str();
                if host_matches_denied_domain(&host, denied) && !matched_domains.contains(&denied) {
                    matched_domains.push(denied);
                }
            }
            Ok(())
        })?;
        let findings: Vec<ScannerFinding> = matched_domains
            .iter()
            .map(|domain| {
                finding(
                    "reputation",
                    &format!("URL/domain reputation policy matched {domain}"),
                    FindingSeverity::High,
                )
            })
            .collect();
        let status = if findings.is_empty() {
            ScannerStatus::Clean
        } else {
            ScannerStatus::Suspicious
        };
        Ok(adapter_result(
            self, &request, status, findings, started, started_at,
        ))
    }
    async fn health(&self) -> ScannerHealth {
        healthy()
    }
}

/// Bounded MIME/file-type validation adapter. It flags malformed MIME and
/// active SVG/HTML attachments as suspicious evidence; it does not render or
/// execute message content.
#[derive(Clone)]
pub struct FileTypeScanner {
    max_input_bytes: u64,
}

impl FileTypeScanner {
    pub fn new(max_input_bytes: u64) -> Self {
        Self { max_input_bytes }
    }
}

#[async_trait]
impl Scanner for FileTypeScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("file-type")
    }

    fn name(&self) -> &str {
        "File type analysis"
    }

    fn version(&self) -> &str {
        "1"
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: false,
            extra: serde_json::Value::Null,
        }
    }

    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]);
        let has_header_boundary = prefix.contains("\n\n") || prefix.contains("\r\n\r\n");
        let active_attachment = prefix.contains("Content-Type: image/svg+xml")
            || prefix.contains("Content-Type: text/html") && prefix.contains("<script");
        let findings = if active_attachment {
            vec![finding(
                "malicious_attachment",
                "Active attachment content requires policy review",
                FindingSeverity::Medium,
            )]
        } else if !has_header_boundary {
            vec![finding(
                "malicious_attachment",
                "Malformed MIME structure could not be safely normalized",
                FindingSeverity::Medium,
            )]
        } else {
            Vec::new()
        };
        let status = if findings.is_empty() {
            ScannerStatus::Clean
        } else {
            ScannerStatus::Suspicious
        };
        Ok(adapter_result(
            self, &request, status, findings, started, started_at,
        ))
    }

    async fn health(&self) -> ScannerHealth {
        healthy()
    }
}

/// Composite local attachment-analysis adapter.
///
/// One bounded pass normalizes the fabric-supplied MIME snapshot exactly once
/// and then applies file-type, archive, PDF, Office, image, QR and OCR
/// analysis to the decoded attachment parts it finds. It replaces the four
/// former single-purpose local registrations so MIME is never re-parsed
/// four times and so every part is decoded under one shared resource
/// envelope.
///
/// Honest limits of this adapter:
///
/// - archive contents are never expanded: only stored entry names,
///   structure, encryption flags and the end-of-central-directory record are
///   inspected;
/// - image pixels are decoded only for the reviewed PNG/JPEG codecs, QR
///   payloads are counted (never decoded into findings) and OCR runs in a
///   bounded external process that may be unavailable at runtime;
/// - a required scanner outcome is never derived from an engine failure:
///   deadline, resource-limit and engine failures are returned as typed
///   [`ScanError`]s so the fabric records inconclusive evidence instead of a
///   clean result.
#[derive(Clone)]
pub struct AttachmentAnalysisScanner {
    max_input_bytes: u64,
    max_pixels: u64,
    ocr: Arc<dyn OcrEngine>,
}

impl AttachmentAnalysisScanner {
    /// Adapter with the platform OCR program resolved from `PATH`.
    pub fn new(max_input_bytes: u64, max_pixels: u64) -> Self {
        Self::with_ocr(max_input_bytes, max_pixels, Arc::new(TesseractOcr))
    }

    /// Adapter with an injected [`OcrEngine`], used to keep text extraction
    /// substitutable and testable without an installed OCR program.
    pub fn with_ocr(max_input_bytes: u64, max_pixels: u64, ocr: Arc<dyn OcrEngine>) -> Self {
        Self {
            max_input_bytes,
            max_pixels,
            ocr,
        }
    }
}

#[async_trait]
impl Scanner for AttachmentAnalysisScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new("attachment-analysis")
    }

    fn name(&self) -> &str {
        "Attachment analysis"
    }

    fn version(&self) -> &str {
        "1"
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Medium,
            requires_network: false,
            milter_compatible: false,
            extra: serde_json::json!({
                "analysis": [
                    "file_type",
                    "archive",
                    "pdf",
                    "office",
                    "image",
                    "ocr",
                    "qr",
                ],
            }),
        }
    }

    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        if bytes.len() as u64 > request.limits.max_input_bytes {
            return Err(ScanError::ResourceLimit(format!(
                "content length {} exceeds request input limit {}",
                bytes.len(),
                request.limits.max_input_bytes
            )));
        }
        let budget = analysis_budget(&request, self.max_pixels);
        let deadline = Instant::now() + Duration::from_millis(request.timeout_ms.max(1));

        // The MIME walk is synchronous, CPU- and allocation-heavy work: it
        // runs on the blocking pool so a hostile part cannot stall the
        // scanner runtime, and it is awaited under the same deadline that
        // bounds the OCR phase below. A panicking parse/decoder surfaces as
        // the stable failure text below — never as a clean result and never
        // with payload bytes.
        let bounded = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
            tokio::task::spawn_blocking(move || analyze_message(&bytes, &budget, deadline)),
        )
        .await;
        let analysis = match bounded {
            Err(_) => return Err(scan_deadline_error()),
            Ok(join_result) => match join_result {
                Ok(Ok(analysis)) => analysis,
                Ok(Err(failure)) => return Err(failure),
                Err(_) => {
                    return Err(ScanError::Failed(ANALYSIS_PANIC_MESSAGE.to_string()));
                },
            },
        };

        let mut findings = analysis.findings;
        for page in analysis.ocr_pages {
            if findings.len() >= MAX_ANALYSIS_FINDINGS {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(scan_deadline_error());
            }
            // The deadline is enforced by this caller as well as by the
            // engine, so a misbehaving engine can never outlive the scan.
            match tokio::time::timeout(remaining, self.ocr.extract(page, remaining)).await {
                Err(_) => return Err(scan_deadline_error()),
                Ok(Err(OcrError::Timeout)) => return Err(scan_deadline_error()),
                Ok(Err(OcrError::Unavailable)) => {
                    // A required scanner never degrades to a clean result
                    // because its text-extraction engine is missing: the
                    // page is reported as unextracted exactly as a failing
                    // engine would be.
                    findings.push(finding_with_details(
                        SUSPICIOUS_CATEGORY,
                        OCR_FAILURE_DESCRIPTION,
                        FindingSeverity::Medium,
                        None,
                    ));
                    break;
                },
                Ok(Err(_)) => findings.push(finding_with_details(
                    SUSPICIOUS_CATEGORY,
                    OCR_FAILURE_DESCRIPTION,
                    FindingSeverity::Medium,
                    None,
                )),
                Ok(Ok(text)) => {
                    if extracted_text_has_active_content(&text) {
                        findings.push(finding_with_details(
                            SUSPICIOUS_CATEGORY,
                            OCR_ACTIVE_CONTENT_DESCRIPTION,
                            FindingSeverity::Medium,
                            None,
                        ));
                    }
                },
            }
        }

        let status = if findings.is_empty() {
            ScannerStatus::Clean
        } else {
            ScannerStatus::Suspicious
        };
        Ok(adapter_result(
            self, &request, status, findings, started, started_at,
        ))
    }

    async fn health(&self) -> ScannerHealth {
        let available = self.ocr.is_available();
        ScannerHealth {
            healthy: available,
            // Content-free: never names the OCR program or any endpoint.
            message: if available {
                None
            } else {
                Some(OCR_UNAVAILABLE_HEALTH_MESSAGE.to_string())
            },
            checked_at: Utc::now(),
            uptime_seconds: None,
            queue_depth: None,
        }
    }
}

/// Text-extraction seam for [`AttachmentAnalysisScanner`].
///
/// Implementations receive bounded image bytes plus the caller's remaining
/// deadline and never get shell, network, filesystem or browser authority.
#[async_trait]
pub trait OcrEngine: Send + Sync {
    /// Whether the engine can run right now; used for content-free health.
    fn is_available(&self) -> bool;

    /// Extract text from one image, bounded by `timeout`.
    async fn extract(&self, image: Arc<[u8]>, timeout: Duration) -> Result<String, OcrError>;
}

/// Typed OCR failure. Messages are content-free and are never echoed into
/// findings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OcrError {
    /// The engine is not installed or cannot be started.
    #[error("text extraction unavailable")]
    Unavailable,
    /// The engine did not finish inside the supplied deadline.
    #[error("text extraction timed out")]
    Timeout,
    /// The engine ran and produced no trustworthy output.
    #[error("text extraction failed")]
    Failed,
}

/// Platform text-extraction engine: one bounded external process per page,
/// image bytes on stdin, text on stdout, diagnostics discarded. The program
/// name is private to this module so it can never reach findings, health
/// text or an operations projection.
struct TesseractOcr;

const OCR_PROGRAM: &str = "tesseract";
const OCR_UNAVAILABLE_HEALTH_MESSAGE: &str = "text extraction unavailable";

#[async_trait]
impl OcrEngine for TesseractOcr {
    fn is_available(&self) -> bool {
        executable_on_path(OCR_PROGRAM)
    }

    async fn extract(&self, image: Arc<[u8]>, timeout: Duration) -> Result<String, OcrError> {
        let mut child = tokio::process::Command::new(OCR_PROGRAM)
            .args(["stdin", "stdout", "--psm", "3"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| OcrError::Unavailable)?;

        let mut stdin = child.stdin.take().ok_or(OcrError::Failed)?;
        let write = async move {
            stdin
                .write_all(&image[..])
                .await
                .map_err(|_| OcrError::Failed)?;
            stdin.shutdown().await.map_err(|_| OcrError::Failed)
        };
        tokio::time::timeout(timeout, write)
            .await
            .map_err(|_| OcrError::Timeout)??;

        let stdout = child.stdout.take().ok_or(OcrError::Failed)?;
        let mut stdout = stdout.take(MAX_OCR_TEXT_BYTES);
        let mut output = Vec::new();
        tokio::time::timeout(timeout, stdout.read_to_end(&mut output))
            .await
            .map_err(|_| OcrError::Timeout)?
            .map_err(|_| OcrError::Failed)?;

        // A textless page is a normal zero-exit outcome with no output; a
        // non-zero exit with no output means the engine could not analyse
        // the page, which is reported as a failure rather than as no text.
        let truncated = output.len() as u64 >= MAX_OCR_TEXT_BYTES;
        if !truncated {
            let exited = tokio::time::timeout(timeout, child.wait())
                .await
                .map_err(|_| OcrError::Timeout)?
                .map_err(|_| OcrError::Failed)?;
            if !exited.success() && output.is_empty() {
                return Err(OcrError::Failed);
            }
        }
        // `kill_on_drop` reaps a still-running or already-exited child.
        drop(child);
        Ok(String::from_utf8_lossy(&output).into_owned())
    }
}

/// Whether `program` resolves on the current `PATH`. Used only for health;
/// the caller never receives the program name.
fn executable_on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| directory.join(program).is_file())
}

/// Stable, content-free rejection texts returned as typed [`ScanError`]s.
const NESTING_DEPTH_LIMIT_MESSAGE: &str = "attachment nesting depth limit exceeded";
const ATTACHMENT_COUNT_LIMIT_MESSAGE: &str = "attachment entry count limit exceeded";
const EXPANDED_BYTES_LIMIT_MESSAGE: &str = "expanded attachment byte limit exceeded";
const IMAGE_PIXEL_LIMIT_MESSAGE: &str = "image pixel budget exceeded";
const ANALYSIS_PANIC_MESSAGE: &str = "attachment analysis could not complete";
const ANALYSIS_DEADLINE_MESSAGE: &str = "attachment analysis exceeded its deadline";

/// Stable, content-free finding descriptions. None embed an engine name, a
/// file name, a path, a URL or any message byte.
const MALFORMED_MIME_DESCRIPTION: &str = "Malformed MIME structure could not be safely normalized";
const UNDECODABLE_ATTACHMENT_DESCRIPTION: &str = "Attachment content could not be decoded safely";
const TYPE_MISMATCH_DESCRIPTION: &str = "Attachment content does not match its declared type";
const EXECUTABLE_ATTACHMENT_DESCRIPTION: &str = "Executable attachment requires explicit review";
const ACTIVE_MARKUP_DESCRIPTION: &str = "Active HTML or SVG attachment requires policy review";
const ENCRYPTED_ARCHIVE_DESCRIPTION: &str = "Encrypted archive requires explicit review";
const MALFORMED_ARCHIVE_DESCRIPTION: &str = "Archive structure is malformed";
const MALFORMED_DOCUMENT_DESCRIPTION: &str = "Document structure is malformed";
const UNINSPECTABLE_ARCHIVE_DESCRIPTION: &str = "Archive contents could not be inspected";
const MACRO_MARKER_DESCRIPTION: &str = "Document contains an active macro marker";
const EXTERNAL_LINK_MARKER_DESCRIPTION: &str = "Document contains an external link marker";
const ACTIVE_DOCUMENT_DESCRIPTION: &str = "Document contains active content";
const ENCRYPTED_DOCUMENT_DESCRIPTION: &str = "Encrypted document requires explicit review";
const UNDECODABLE_IMAGE_DESCRIPTION: &str = "Image content could not be decoded safely";
const QR_CODE_DESCRIPTION: &str = "QR code content requires policy review";
const OCR_FAILURE_DESCRIPTION: &str = "Text extraction could not complete for an image attachment";
const OCR_ACTIVE_CONTENT_DESCRIPTION: &str =
    "Extracted image text contains an active content scheme";
const ARCHIVE_UNSAFE_PATH_DESCRIPTION: &str = "Archive entry path could escape the extraction root";
const ARCHIVE_DUPLICATE_PATH_DESCRIPTION: &str = "Archive contains duplicate entry names";
const ARCHIVE_NAME_MISMATCH_DESCRIPTION: &str = "Archive entry name differs between headers";

/// Finding categories used here; both are recognized by the fabric's
/// category normalization.
const ATTACHMENT_CATEGORY: &str = "malicious_attachment";
const SUSPICIOUS_CATEGORY: &str = "suspicious_content";

/// Ceiling on findings one run reports, so a hostile message cannot make one
/// scan produce unbounded evidence.
const MAX_ANALYSIS_FINDINGS: usize = 24;

/// Ceiling on QR codes decoded and reported by one run; decoding stops here
/// so a page of repeated codes stays bounded.
const MAX_REPORTED_QR_CODES: usize = 16;

/// Ceiling on extracted OCR text retained for one page.
const MAX_OCR_TEXT_BYTES: u64 = 64 * 1024;

/// Bytes of a candidate PDF inspected for the `%PDF-` header.
const PDF_HEADER_SCAN_BYTES: usize = 1024;
/// Tail bytes of a candidate PDF inspected for `startxref`/`%%EOF`/`/Encrypt`.
const PDF_TAIL_SCAN_BYTES: usize = 4096;
/// Bytes of a candidate XML/HTML document inspected for an SVG payload.
const MARKUP_SCAN_BYTES: usize = 4096;
/// Bytes of a candidate snapshot inspected for the header/body separator.
const HEADER_PROBE_BYTES: usize = 64 * 1024;
/// Bytes probed when deciding whether an unidentified part is text.
const TEXT_PROBE_BYTES: usize = 8192;
/// Bytes before the end of an archive inspected for the end-of-central-
/// directory record (`22`-byte record plus the maximum `65535`-byte comment).
const ARCHIVE_TAIL_SCAN_BYTES: usize = 66_000;

/// Stable, content-free rejection text for the archive compression-ratio
/// limits. It never embeds an entry name, a size or any payload byte.
const ARCHIVE_RATIO_LIMIT_MESSAGE: &str = "archive compression ratio limit exceeded";

/// Maximum uncompressed-to-compressed ratio accepted for one archive entry
/// and for the archive in total. Absolute expanded-byte budgets remain the
/// primary defence; the ratio limits reject a decompression bomb before a
/// single byte is inflated.
const ARCHIVE_MAX_COMPRESSION_RATIO: u64 = 1_000;

/// Smallest declared uncompressed size for which the ratio limit carries any
/// signal: a forty-byte header compressing to four bytes is not a bomb, so
/// tiny entries are exempt from the ratio test and still bounded by the
/// absolute budgets.
const ARCHIVE_RATIO_FLOOR_BYTES: u64 = 1024 * 1024;

/// Largest archive handled in one pass, matching the request input ceiling.
/// An archive larger than this is a resource-limit failure, never a partial
/// or silent inspection.
const ARCHIVE_MAX_INSPECTION_BYTES: u64 = 50 * 1024 * 1024;

/// Bytes read per iteration while inflating an archive entry, so the
/// expansion buffer grows in bounded steps rather than in one allocation.
const INFLATE_CHUNK_BYTES: usize = 16 * 1024;

/// Largest pre-allocation for one inflated entry, so a lying declared size
/// cannot drive a single huge allocation.
const INFLATE_PREALLOC_BYTES: usize = 64 * 1024;

/// Approximate bytes of decode, grayscale and recognizer buffer held per
/// analysed pixel.
const BYTES_PER_ANALYZED_PIXEL: u64 = 7;

/// Share of the request memory budget usable by one decoded image plus its
/// retained OCR pages.
const MEMORY_BUDGET_SHARE_DIVISOR: u64 = 4;

fn scan_deadline_error() -> ScanError {
    ScanError::Failed(ANALYSIS_DEADLINE_MESSAGE.to_string())
}

/// Reviewed resource envelope for one composite run, derived from the
/// fabric-carried request limits and this adapter's pixel ceiling. The
/// pixel budget also folds in the request memory budget so decode buffers
/// can never exceed a quarter of the declared envelope.
#[derive(Clone)]
struct AnalysisBudget {
    max_expanded_bytes: u64,
    max_nesting_depth: u32,
    max_attachment_count: u32,
    max_ocr_pages: u32,
    max_pixels: u64,
    max_memory_bytes: u64,
    max_ocr_bytes: u64,
}

fn analysis_budget(request: &ScanRequest, max_pixels: u64) -> AnalysisBudget {
    let limits = &request.limits;
    let memory_share = limits
        .max_memory_bytes
        .saturating_div(MEMORY_BUDGET_SHARE_DIVISOR);
    let memory_pixel_budget = memory_share.saturating_div(BYTES_PER_ANALYZED_PIXEL).max(1);
    AnalysisBudget {
        max_expanded_bytes: limits.max_expanded_bytes,
        max_nesting_depth: limits.max_nesting_depth,
        max_attachment_count: limits.max_attachment_count,
        max_ocr_pages: limits.max_ocr_pages,
        max_pixels: max_pixels
            .min(limits.max_ocr_pixels)
            .min(memory_pixel_budget),
        max_memory_bytes: limits.max_memory_bytes.max(1),
        max_ocr_bytes: memory_share,
    }
}

/// Outcome of the static (MIME walk) phase: bounded evidence plus the
/// image pages queued for the OCR phase.
struct StaticAnalysis {
    findings: Vec<ScannerFinding>,
    ocr_pages: Vec<Arc<[u8]>>,
}

/// Parse the snapshot once and walk it under the reviewed budget. Runs on
/// the blocking pool; every panic path is converted into stable evidence
/// rather than being allowed to escape as a scanner failure.
fn analyze_message(
    bytes: &[u8],
    budget: &AnalysisBudget,
    deadline: Instant,
) -> Result<StaticAnalysis, ScanError> {
    let parsed = match catch_unwind(AssertUnwindSafe(|| mailparse::parse_mail(bytes))) {
        Ok(Ok(parsed)) => parsed,
        _ => {
            return Ok(StaticAnalysis {
                findings: vec![finding(
                    ATTACHMENT_CATEGORY,
                    MALFORMED_MIME_DESCRIPTION,
                    FindingSeverity::Medium,
                )],
                ocr_pages: Vec::new(),
            });
        },
    };
    let mut state = AnalysisState::new(budget, deadline);
    // Structural parity with the former file-type pass: a snapshot with no
    // header/body separator at all is not a normalizable message.
    let prefix = &bytes[..bytes.len().min(HEADER_PROBE_BYTES)];
    if find(prefix, b"\n\n").is_none() && find(prefix, b"\r\n\r\n").is_none() {
        state.push(ATTACHMENT_CATEGORY, MALFORMED_MIME_DESCRIPTION, None);
    }
    walk_part(&parsed, 0, &mut state)?;
    if state.qr_codes > 0 {
        state.push(
            SUSPICIOUS_CATEGORY,
            QR_CODE_DESCRIPTION,
            Some(serde_json::json!({ "qr_codes": state.qr_codes })),
        );
    }
    Ok(StaticAnalysis {
        findings: state.findings,
        ocr_pages: state.ocr_pages,
    })
}

/// Mutable state shared by the MIME walk.
struct AnalysisState<'a> {
    budget: &'a AnalysisBudget,
    /// Wall-clock deadline for this run. The blocking task that owns this
    /// state cannot be cancelled from outside, so every unbounded loop —
    /// MIME parts, archive entries, nested payloads — checks it and returns
    /// an explicit deadline failure instead of running on.
    deadline: Instant,
    findings: Vec<ScannerFinding>,
    ocr_pages: Vec<Arc<[u8]>>,
    expanded_bytes: u64,
    attachment_count: usize,
    ocr_page_count: usize,
    ocr_bytes: u64,
    qr_codes: usize,
}

impl<'a> AnalysisState<'a> {
    fn new(budget: &'a AnalysisBudget, deadline: Instant) -> Self {
        Self {
            budget,
            deadline,
            findings: Vec::new(),
            ocr_pages: Vec::new(),
            expanded_bytes: 0,
            attachment_count: 0,
            ocr_page_count: 0,
            ocr_bytes: 0,
            qr_codes: 0,
        }
    }

    /// Cooperative cancellation point for the blocking analysis task.
    fn check_deadline(&self) -> Result<(), ScanError> {
        if Instant::now() >= self.deadline {
            return Err(scan_deadline_error());
        }
        Ok(())
    }

    /// Charges `bytes` against the expanded-byte budget and fails closed
    /// when the budget would be exceeded.
    fn charge_expanded(&mut self, bytes: u64) -> Result<(), ScanError> {
        if self.expanded_bytes.saturating_add(bytes) > self.budget.max_expanded_bytes {
            return Err(ScanError::ResourceLimit(
                EXPANDED_BYTES_LIMIT_MESSAGE.to_string(),
            ));
        }
        self.expanded_bytes = self.expanded_bytes.saturating_add(bytes);
        Ok(())
    }

    fn push(&mut self, category: &str, description: &str, details: Option<serde_json::Value>) {
        if self.findings.len() >= MAX_ANALYSIS_FINDINGS {
            return;
        }
        self.findings.push(finding_with_details(
            category,
            description,
            FindingSeverity::Medium,
            details,
        ));
    }
}

/// Walk one MIME part. Multipart parts are containers only; `message/rfc822`
/// parts are re-parsed as nested messages under the same depth, entry and
/// byte budget; everything else is an attachment candidate.
fn walk_part(
    mail: &ParsedMail<'_>,
    depth: u32,
    state: &mut AnalysisState,
) -> Result<(), ScanError> {
    state.check_deadline()?;
    if depth > state.budget.max_nesting_depth {
        return Err(ScanError::ResourceLimit(
            NESTING_DEPTH_LIMIT_MESSAGE.to_string(),
        ));
    }
    let mimetype = mail.ctype.mimetype.to_ascii_lowercase();
    if mimetype.starts_with("multipart/") {
        // A container whose boundary never matched would otherwise drop its
        // entire content silently, which would read as a clean scan.
        if mail.subparts.is_empty() {
            if let Some(body) = decode_body(mail, state, false)? {
                if body.iter().any(|byte| !byte.is_ascii_whitespace()) {
                    state.push(ATTACHMENT_CATEGORY, MALFORMED_MIME_DESCRIPTION, None);
                }
            }
            return Ok(());
        }
        for subpart in &mail.subparts {
            walk_part(subpart, depth + 1, state)?;
        }
        return Ok(());
    }
    if mimetype == "message/rfc822" {
        return walk_nested_message(mail, depth, state);
    }

    if !is_attachment(mail) {
        // Inline HTML bodies are reviewed for active markup exactly as the
        // former file-type pass did.
        if mimetype == "text/html" {
            if let Some(body) = decode_body(mail, state, false)? {
                if has_active_markup(&body) {
                    state.push(ATTACHMENT_CATEGORY, ACTIVE_MARKUP_DESCRIPTION, None);
                }
            }
        }
        return Ok(());
    }

    let Some(body) = decode_body(mail, state, true)? else {
        return Ok(());
    };
    let sniffed = sniff_type(&body);
    let declared = normalized_declared_type(&mimetype);

    if !declared_matches_sniffed(&declared, sniffed) {
        state.push(ATTACHMENT_CATEGORY, TYPE_MISMATCH_DESCRIPTION, None);
    }
    if mimetype == "image/svg+xml" || matches!(sniffed, SniffedType::Svg) {
        // SVG is active content by construction: scripting, embedded
        // external references and nested documents all run when the part is
        // rendered, so every SVG attachment is policy evidence.
        state.push(ATTACHMENT_CATEGORY, ACTIVE_MARKUP_DESCRIPTION, None);
    } else if (mimetype == "text/html" || matches!(sniffed, SniffedType::Html))
        && has_active_markup(&body)
    {
        state.push(ATTACHMENT_CATEGORY, ACTIVE_MARKUP_DESCRIPTION, None);
    }

    match sniffed {
        SniffedType::Empty
        | SniffedType::Text
        | SniffedType::Unknown
        | SniffedType::Html
        | SniffedType::Svg => Ok(()),
        SniffedType::Script
        | SniffedType::Elf
        | SniffedType::DosExecutable
        | SniffedType::MachO => {
            state.push(ATTACHMENT_CATEGORY, EXECUTABLE_ATTACHMENT_DESCRIPTION, None);
            Ok(())
        },
        SniffedType::Pdf => {
            analyze_pdf(&body, state);
            Ok(())
        },
        SniffedType::Zip => analyze_archive(&body, state, 0),
        SniffedType::Ole2 => {
            analyze_legacy_office(&body, state);
            Ok(())
        },
        SniffedType::Gzip => analyze_gzip(&body, state, 0),
        SniffedType::Bzip2
        | SniffedType::Xz
        | SniffedType::Tar
        | SniffedType::Rar
        | SniffedType::SevenZ => {
            state.push(ATTACHMENT_CATEGORY, UNINSPECTABLE_ARCHIVE_DESCRIPTION, None);
            Ok(())
        },
        SniffedType::Png | SniffedType::Jpeg | SniffedType::Gif => {
            analyze_image(&body, sniffed, state)
        },
    }
}

/// Re-parse a nested RFC822 part under the same budget and keep walking.
fn walk_nested_message(
    mail: &ParsedMail<'_>,
    depth: u32,
    state: &mut AnalysisState,
) -> Result<(), ScanError> {
    let Some(body) = decode_body(mail, state, true)? else {
        return Ok(());
    };
    let nested = match catch_unwind(AssertUnwindSafe(|| mailparse::parse_mail(&body))) {
        Ok(Ok(nested)) => nested,
        _ => {
            state.push(ATTACHMENT_CATEGORY, MALFORMED_MIME_DESCRIPTION, None);
            return Ok(());
        },
    };
    walk_part(&nested, depth + 1, state)
}

/// A part is an attachment when it carries a filename or an `attachment`
/// disposition, or when it is neither a text, multipart nor message part.
fn is_attachment(mail: &ParsedMail<'_>) -> bool {
    let disposition = mail.get_content_disposition();
    if disposition.params.contains_key("filename")
        || mail.ctype.params.contains_key("name")
        || matches!(disposition.disposition, DispositionType::Attachment)
    {
        return true;
    }
    let mimetype = mail.ctype.mimetype.to_ascii_lowercase();
    !(mimetype.starts_with("text/")
        || mimetype.starts_with("multipart/")
        || mimetype.starts_with("message/"))
}

/// Charge the entry budget and the expanded-byte budget before decoding, so
/// the decode allocation itself is bounded. A transfer-decoding failure is
/// evidence, never a clean skip.
fn decode_body(
    mail: &ParsedMail<'_>,
    state: &mut AnalysisState,
    count_as_attachment: bool,
) -> Result<Option<Vec<u8>>, ScanError> {
    if count_as_attachment {
        if state.attachment_count >= state.budget.max_attachment_count as usize {
            return Err(ScanError::ResourceLimit(
                ATTACHMENT_COUNT_LIMIT_MESSAGE.to_string(),
            ));
        }
        state.attachment_count += 1;
    }
    // Decoded output never exceeds the raw part length, so charging the raw
    // length up front bounds the allocation this call is about to make.
    if state
        .expanded_bytes
        .saturating_add(mail.raw_bytes.len() as u64)
        > state.budget.max_expanded_bytes
    {
        return Err(ScanError::ResourceLimit(
            EXPANDED_BYTES_LIMIT_MESSAGE.to_string(),
        ));
    }
    match mail.get_body_raw() {
        Ok(body) => {
            state.expanded_bytes = state.expanded_bytes.saturating_add(body.len() as u64);
            Ok(Some(body))
        },
        Err(_) => {
            state.push(
                ATTACHMENT_CATEGORY,
                UNDECODABLE_ATTACHMENT_DESCRIPTION,
                None,
            );
            Ok(None)
        },
    }
}

/// File type of an attachment candidate, decided from its leading bytes
/// only. Unidentified binary stays [`SniffedType::Unknown`] so a declared
/// type it cannot corroborate still counts as a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SniffedType {
    Empty,
    Png,
    Jpeg,
    Gif,
    Pdf,
    Zip,
    Ole2,
    Html,
    Svg,
    Script,
    Elf,
    DosExecutable,
    MachO,
    Gzip,
    Bzip2,
    Xz,
    Tar,
    Rar,
    SevenZ,
    Text,
    Unknown,
}

fn sniff_type(bytes: &[u8]) -> SniffedType {
    if bytes.is_empty() {
        return SniffedType::Empty;
    }
    if bytes_starts_with(bytes, b"\x89PNG\r\n\x1a\n") {
        return SniffedType::Png;
    }
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return SniffedType::Jpeg;
    }
    if bytes_starts_with(bytes, b"GIF87a") || bytes_starts_with(bytes, b"GIF89a") {
        return SniffedType::Gif;
    }
    if find_ascii_ci(&bytes[..bytes.len().min(PDF_HEADER_SCAN_BYTES)], b"%pdf-").is_some() {
        return SniffedType::Pdf;
    }
    if bytes_starts_with(bytes, b"PK\x03\x04")
        || bytes_starts_with(bytes, b"PK\x05\x06")
        || bytes_starts_with(bytes, b"PK\x07\x08")
    {
        return SniffedType::Zip;
    }
    if bytes_starts_with(bytes, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        return SniffedType::Ole2;
    }
    if bytes_starts_with(bytes, b"#!") {
        return SniffedType::Script;
    }
    if bytes_starts_with(bytes, b"\x7FELF") {
        return SniffedType::Elf;
    }
    if bytes_starts_with(bytes, b"MZ") {
        return SniffedType::DosExecutable;
    }
    if is_macho(bytes) {
        return SniffedType::MachO;
    }
    if bytes_starts_with(bytes, b"\x1F\x8B") {
        return SniffedType::Gzip;
    }
    if bytes_starts_with(bytes, b"BZh") {
        return SniffedType::Bzip2;
    }
    if bytes_starts_with(bytes, b"\xFD7zXZ\x00") {
        return SniffedType::Xz;
    }
    if bytes_starts_with(bytes, b"Rar!\x1A\x07") {
        return SniffedType::Rar;
    }
    if bytes_starts_with(bytes, b"7z\xBC\xAF\x27\x1C") {
        return SniffedType::SevenZ;
    }
    if bytes.len() > 262 && bytes[257..262] == *b"ustar" {
        return SniffedType::Tar;
    }
    if let Some(markup) = markup_type(bytes) {
        return markup;
    }
    if looks_like_text(bytes) {
        return SniffedType::Text;
    }
    SniffedType::Unknown
}

fn bytes_starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && bytes[..prefix.len()] == *prefix
}

fn is_macho(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && matches!(
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            0xfeed_face | 0xfeed_facf | 0xce_fa_ed_fe | 0xcf_fa_ed_fe | 0xcafe_babe | 0xbe_ba_fe_ca
        )
}

/// HTML or SVG detection over a leading whitespace/BOM-trimmed prefix.
fn markup_type(bytes: &[u8]) -> Option<SniffedType> {
    let trimmed = trim_markup_prefix(bytes);
    if starts_with_ascii_ci(trimmed, b"<svg") {
        return Some(SniffedType::Svg);
    }
    if starts_with_ascii_ci(trimmed, b"<!doctype html") || starts_with_ascii_ci(trimmed, b"<html") {
        return Some(SniffedType::Html);
    }
    if starts_with_ascii_ci(trimmed, b"<?xml") {
        let probe = &trimmed[..trimmed.len().min(MARKUP_SCAN_BYTES)];
        if find_ascii_ci(probe, b"<svg").is_some() {
            return Some(SniffedType::Svg);
        }
    }
    None
}

fn trim_markup_prefix(bytes: &[u8]) -> &[u8] {
    let bytes = if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        &bytes[3..]
    } else {
        bytes
    };
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Text heuristic: no NUL or other ASCII control byte outside the tab/line
/// family in the probe window, plus explicit UTF-16 byte-order marks. Binary
/// formats matched by their magic above never reach this check.
fn looks_like_text(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        return true;
    }
    bytes
        .iter()
        .take(TEXT_PROBE_BYTES)
        .all(|byte| *byte >= 0x20 || matches!(byte, 0x09..=0x0d))
}

/// A declared type is corroborated when it is generic (no claim made) or
/// when the sniffed family is one the declaration can legitimately describe.
fn declared_matches_sniffed(declared: &str, sniffed: SniffedType) -> bool {
    if declared.is_empty()
        || declared == "application/octet-stream"
        || declared == "binary/octet-stream"
    {
        return true;
    }
    match sniffed {
        SniffedType::Empty => true,
        // Only a declaration this pass can positively identify can be
        // contradicted by a body that stayed unidentified or text-looking:
        // vendor, protocol and crypto-container declarations (signature
        // parts of signed mail, for example) make no claim the sniff can
        // test, so they are never treated as a mismatch.
        SniffedType::Unknown => !declared_is_recognized_format(declared),
        SniffedType::Text => {
            !declared_is_recognized_format(declared) || declared == "image/svg+xml"
        },
        SniffedType::Png => declared == "image/png",
        SniffedType::Jpeg => matches!(declared, "image/jpeg" | "image/jpg" | "image/pjpeg"),
        SniffedType::Gif => declared == "image/gif",
        SniffedType::Pdf => matches!(declared, "application/pdf" | "application/x-pdf"),
        SniffedType::Zip => {
            declared == "application/zip"
                || declared == "application/x-zip-compressed"
                || declared == "application/epub+zip"
                || declared == "application/java-archive"
                || declared.starts_with("application/vnd.openxmlformats-officedocument.")
                || declared.starts_with("application/vnd.oasis.opendocument.")
        },
        SniffedType::Ole2 => {
            declared.starts_with("application/vnd.ms-")
                || declared.starts_with("application/x-ole-")
                || declared == "application/x-ole-storage"
                || declared == "application/msword"
                || declared == "application/cdfv2"
        },
        SniffedType::Html => {
            declared == "text/html"
                || declared == "application/xhtml+xml"
                || declared.starts_with("text/")
        },
        SniffedType::Svg => {
            declared == "image/svg+xml"
                || declared == "application/xml"
                || declared.starts_with("text/")
        },
        SniffedType::Script => declared.starts_with("text/") || declared == "application/x-sh",
        SniffedType::Elf => {
            declared.starts_with("application/x-executable")
                || declared.starts_with("application/x-sharedlib")
                || declared.starts_with("application/x-elf")
        },
        SniffedType::DosExecutable | SniffedType::MachO => {
            matches!(
                declared,
                "application/x-msdownload"
                    | "application/x-msdos-program"
                    | "application/x-mach-binary"
            )
        },
        SniffedType::Gzip => matches!(declared, "application/gzip" | "application/x-gzip"),
        SniffedType::Bzip2 => declared == "application/x-bzip2",
        SniffedType::Xz => declared == "application/x-xz",
        SniffedType::Tar => declared == "application/x-tar",
        SniffedType::Rar => {
            matches!(
                declared,
                "application/vnd.rar" | "application/x-rar" | "application/x-rar-compressed"
            )
        },
        SniffedType::SevenZ => declared == "application/x-7z-compressed",
    }
}

/// Whether a declared type names a format this pass positively identifies by
/// content. Only these declarations can produce a mismatch against an
/// unidentified or text-looking body, so declarations of formats the sniff
/// cannot see (audio, video, vendor containers, signature parts) never cause
/// a false hold.
fn declared_is_recognized_format(declared: &str) -> bool {
    matches!(
        declared,
        "image/png"
            | "image/jpeg"
            | "image/jpg"
            | "image/pjpeg"
            | "image/gif"
            | "image/svg+xml"
            | "application/pdf"
            | "application/x-pdf"
            | "application/zip"
            | "application/x-zip-compressed"
            | "application/epub+zip"
            | "application/java-archive"
            | "application/gzip"
            | "application/x-gzip"
            | "application/x-bzip2"
            | "application/x-xz"
            | "application/x-tar"
            | "application/vnd.rar"
            | "application/x-rar"
            | "application/x-rar-compressed"
            | "application/x-7z-compressed"
            | "application/msword"
            | "application/cdfv2"
            | "application/x-sh"
            | "application/x-mach-binary"
            | "application/x-msdownload"
            | "application/x-msdos-program"
            | "application/x-executable"
            | "application/x-sharedlib"
            | "application/x-elf"
    ) || declared.starts_with("application/vnd.ms-")
        || declared.starts_with("application/vnd.openxmlformats-officedocument.")
        || declared.starts_with("application/vnd.oasis.opendocument.")
        || declared.starts_with("application/x-ole-")
}

fn normalized_declared_type(mimetype: &str) -> String {
    mimetype
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Active-content markers in HTML/SVG text. Case-insensitive and
/// byte-level: this is a bounded heuristic, not a parser.
fn has_active_markup(bytes: &[u8]) -> bool {
    find_ascii_ci(bytes, b"<script").is_some()
        || find_ascii_ci(bytes, b"onload=").is_some()
        || find_ascii_ci(bytes, b"onerror=").is_some()
        || find_ascii_ci(bytes, b"javascript:").is_some()
}

/// PDF structure and active-content markers, inspected on bytes only.
fn analyze_pdf(bytes: &[u8], state: &mut AnalysisState) {
    let tail_start = bytes.len().saturating_sub(PDF_TAIL_SCAN_BYTES);
    let tail = &bytes[tail_start..];
    if find_ascii_ci(tail, b"startxref").is_none() || find_ascii_ci(tail, b"%%eof").is_none() {
        state.push(ATTACHMENT_CATEGORY, MALFORMED_DOCUMENT_DESCRIPTION, None);
        return;
    }
    if find_ascii_ci(tail, b"/encrypt").is_some() {
        state.push(ATTACHMENT_CATEGORY, ENCRYPTED_DOCUMENT_DESCRIPTION, None);
        return;
    }
    for marker in [
        b"/javascript".as_slice(),
        b"/openaction",
        b"/richmedia",
        b"/launch",
        b"/xfa",
        b"/aa",
        b"/js",
    ] {
        if find_ascii_ci_token(bytes, marker).is_some() {
            state.push(ATTACHMENT_CATEGORY, ACTIVE_DOCUMENT_DESCRIPTION, None);
            return;
        }
    }
}

/// One entry read from an archive's central directory record. The central
/// directory is authoritative: it carries the flags, compression method and
/// both sizes for every entry, so limits can be evaluated before any
/// decompression happens.
#[derive(Debug)]
struct CentralEntry {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
}

/// Why a central directory could not be trusted as the inspection index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CentralDirectoryError {
    /// Missing, truncated, self-inconsistent or ZIP64-marked directory.
    Malformed,
    /// More entries than this run's entry budget allows.
    TooManyEntries,
}

/// Result of inflating a bounded slice of archive data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InflateOutcome {
    /// The stream expands past the cap that was granted.
    Overflow,
    /// The stream is truncated or not a valid raw-deflate stream.
    Malformed,
}

/// Locates the end-of-central-directory record in the archive tail and
/// returns its offset. The comment length recorded in the candidate must fit
/// inside the buffer, so a forged signature inside a comment is rejected.
fn find_end_of_central_directory(body: &[u8]) -> Option<usize> {
    if body.len() < 22 {
        return None;
    }
    let scan_start = body.len().saturating_sub(ARCHIVE_TAIL_SCAN_BYTES);
    let tail = &body[scan_start..];
    let mut offset = tail.len() - 22;
    loop {
        if tail[offset..offset + 4] == *b"PK\x05\x06" {
            let comment_len =
                usize::from(u16::from_le_bytes([tail[offset + 20], tail[offset + 21]]));
            if offset + 22 + comment_len <= tail.len() {
                return Some(scan_start + offset);
            }
        }
        if offset == 0 {
            return None;
        }
        offset -= 1;
    }
}

/// Parses the central directory named by the end-of-central-directory record
/// into at most `max_entries` entries. Every arithmetic step is checked and
/// every length is validated against the buffer, so a hostile offset, a
/// forged record count or a ZIP64 marker is `Malformed` rather than a panic
/// or an unbounded allocation.
fn parse_central_directory(
    body: &[u8],
    max_entries: usize,
) -> Result<Vec<CentralEntry>, CentralDirectoryError> {
    let eocd = find_end_of_central_directory(body).ok_or(CentralDirectoryError::Malformed)?;
    let declared_entries = usize::from(u16::from_le_bytes([body[eocd + 10], body[eocd + 11]]));
    let cd_size = u32::from_le_bytes([
        body[eocd + 12],
        body[eocd + 13],
        body[eocd + 14],
        body[eocd + 15],
    ]);
    let cd_offset = u32::from_le_bytes([
        body[eocd + 16],
        body[eocd + 17],
        body[eocd + 18],
        body[eocd + 19],
    ]);
    if declared_entries > max_entries {
        return Err(CentralDirectoryError::TooManyEntries);
    }
    if declared_entries == 0 {
        return Ok(Vec::new());
    }
    // ZIP64 sizes/offsets are outside this pass's reviewed envelope; the
    // absolute budgets this archive is bounded by are far below the ZIP64
    // threshold, so a ZIP64 archive is structurally out of scope.
    if cd_size == u32::MAX || cd_offset == u32::MAX {
        return Err(CentralDirectoryError::Malformed);
    }
    let start = cd_offset as usize;
    let end = start
        .checked_add(cd_size as usize)
        .ok_or(CentralDirectoryError::Malformed)?;
    if end > body.len() {
        return Err(CentralDirectoryError::Malformed);
    }
    let region = &body[start..end];
    let mut cursor = 0_usize;
    let mut entries = Vec::with_capacity(declared_entries.min(max_entries));
    while cursor < region.len() {
        if entries.len() >= max_entries {
            return Err(CentralDirectoryError::TooManyEntries);
        }
        let header = region
            .get(cursor..cursor + 46)
            .ok_or(CentralDirectoryError::Malformed)?;
        if header[..4] != *b"PK\x01\x02" {
            return Err(CentralDirectoryError::Malformed);
        }
        let name_len = usize::from(u16::from_le_bytes([header[28], header[29]]));
        let extra_len = usize::from(u16::from_le_bytes([header[30], header[31]]));
        let comment_len = usize::from(u16::from_le_bytes([header[32], header[33]]));
        let name_start = cursor + 46;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(CentralDirectoryError::Malformed)?;
        let next = name_end
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
            .ok_or(CentralDirectoryError::Malformed)?;
        if next > region.len() {
            return Err(CentralDirectoryError::Malformed);
        }
        let name = region[name_start..name_end].to_vec();
        entries.push(CentralEntry {
            name,
            flags: u16::from_le_bytes([header[8], header[9]]),
            method: u16::from_le_bytes([header[10], header[11]]),
            compressed_size: u32::from_le_bytes([header[20], header[21], header[22], header[23]]),
            uncompressed_size: u32::from_le_bytes([header[24], header[25], header[26], header[27]]),
            local_header_offset: u32::from_le_bytes([
                header[42], header[43], header[44], header[45],
            ]),
        });
        cursor = next;
    }
    if entries.len() != declared_entries {
        return Err(CentralDirectoryError::Malformed);
    }
    Ok(entries)
}

/// Locates one entry's payload through its local header and returns the
/// payload range together with the name the local header declares. A missing
/// signature, an out-of-bounds offset or a truncated header is `None`, which
/// the caller records as structural evidence.
fn entry_payload_source<'a>(
    body: &'a [u8],
    entry: &CentralEntry,
) -> Option<(Range<usize>, &'a [u8])> {
    let local = entry.local_header_offset as usize;
    let header = body.get(local..local.checked_add(30)?)?;
    if header[..4] != *b"PK\x03\x04" {
        return None;
    }
    let name_len = usize::from(u16::from_le_bytes([header[26], header[27]]));
    let extra_len = usize::from(u16::from_le_bytes([header[28], header[29]]));
    let name_start = local + 30;
    let name_end = name_start.checked_add(name_len)?;
    let data_start = name_end.checked_add(extra_len)?;
    let data_end = data_start.checked_add(entry.compressed_size as usize)?;
    if data_end > body.len() {
        return None;
    }
    Some((data_start..data_end, body.get(name_start..name_end)?))
}

/// Lower-cases the ASCII bytes of an entry name, unifies Windows and POSIX
/// separators and drops leading `./` components, so duplicate and traversal
/// detection cannot be defeated by case or separator tricks.
fn normalize_archive_path(name: &[u8]) -> Vec<u8> {
    let mut normalized: Vec<u8> = name
        .iter()
        .map(|byte| match byte {
            b'A'..=b'Z' => byte.to_ascii_lowercase(),
            b'\\' => b'/',
            other => *other,
        })
        .collect();
    while normalized.starts_with(b"./") {
        normalized.drain(..2);
    }
    normalized
}

/// Whether a normalized entry name could escape an extraction root: empty,
/// NUL-bearing, absolute, drive-qualified or containing a `..` component.
/// Such names are reported as evidence and their payload is never expanded.
fn archive_path_is_unsafe(normalized: &[u8]) -> bool {
    if normalized.is_empty() || normalized.contains(&0) {
        return true;
    }
    if normalized.starts_with(b"/") {
        return true;
    }
    if normalized.len() >= 3 && normalized[1] == b':' && normalized[2] == b'/' {
        return true;
    }
    normalized
        .split(|byte| *byte == b'/')
        .any(|part| part == b"..")
}

/// Per-entry and whole-archive compression-ratio limits. Ratios are only
/// evaluated once the declared uncompressed size clears
/// [`ARCHIVE_RATIO_FLOOR_BYTES`], and both limits are checked before any
/// byte is inflated.
fn compression_ratio_exceeds(uncompressed: u64, compressed: u64) -> bool {
    if uncompressed < ARCHIVE_RATIO_FLOOR_BYTES {
        return false;
    }
    uncompressed.saturating_div(compressed.max(1)) > ARCHIVE_MAX_COMPRESSION_RATIO
}

/// Inflates a raw-deflate slice, producing at most `cap` bytes.
///
/// The decoder is fed from the immutable slice only; no temporary file, no
/// subprocess and no unbounded allocation is involved. Producing exactly
/// `cap` bytes is followed by one probe byte: a stream that still has output
/// is an [`InflateOutcome::Overflow`], so a payload that lies about its
/// declared size cannot slip through a cap derived from that lie.
fn inflate_bounded(data: &[u8], cap: usize) -> Result<Vec<u8>, InflateOutcome> {
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(INFLATE_PREALLOC_BYTES));
    let mut chunk = [0_u8; INFLATE_CHUNK_BYTES];
    loop {
        if out.len() >= cap {
            let mut probe = [0_u8; 1];
            return match decoder.read(&mut probe) {
                Ok(0) => Ok(out),
                Ok(_) => Err(InflateOutcome::Overflow),
                Err(_) => Err(InflateOutcome::Malformed),
            };
        }
        let want = chunk.len().min(cap - out.len());
        match decoder.read(&mut chunk[..want]) {
            Ok(0) => return Ok(out),
            Ok(read) => out.extend_from_slice(&chunk[..read]),
            Err(_) => return Err(InflateOutcome::Malformed),
        }
    }
}

/// Inflates a gzip member, producing at most `cap` bytes, with the same
/// probe-byte overflow rule as [`inflate_bounded`].
fn gunzip_bounded(data: &[u8], cap: usize) -> Result<Vec<u8>, InflateOutcome> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(INFLATE_PREALLOC_BYTES));
    let mut chunk = [0_u8; INFLATE_CHUNK_BYTES];
    loop {
        if out.len() >= cap {
            let mut probe = [0_u8; 1];
            return match decoder.read(&mut probe) {
                Ok(0) => Ok(out),
                Ok(_) => Err(InflateOutcome::Overflow),
                Err(_) => Err(InflateOutcome::Malformed),
            };
        }
        let want = chunk.len().min(cap - out.len());
        match decoder.read(&mut chunk[..want]) {
            Ok(0) => return Ok(out),
            Ok(read) => out.extend_from_slice(&chunk[..read]),
            Err(_) => return Err(InflateOutcome::Malformed),
        }
    }
}

/// Bounded archive inspection for one archive payload.
///
/// The central directory is parsed first, so every entry budget, ratio limit
/// and expanded-byte limit is evaluated from declared sizes before a single
/// byte is inflated. Payloads are then inflated in memory under the shared
/// expanded-byte budget — never to disk, never in a subprocess — and each
/// inflated payload is re-sniffed so a nested archive is inspected under the
/// same depth, entry and byte budgets. Encrypted, unsafe-pathed, duplicate
/// and unsupported entries produce explicit evidence and are not expanded.
///
/// Structure that cannot be indexed falls back to a local-header pass, which
/// still proves entry names, encryption and the entry budget while the
/// missing directory itself is reported as malformed.
fn analyze_archive(
    body: &[u8],
    state: &mut AnalysisState,
    archive_depth: u32,
) -> Result<(), ScanError> {
    if archive_depth > state.budget.max_nesting_depth {
        return Err(ScanError::ResourceLimit(
            NESTING_DEPTH_LIMIT_MESSAGE.to_string(),
        ));
    }
    state.check_deadline()?;
    if body.len() as u64 > ARCHIVE_MAX_INSPECTION_BYTES {
        return Err(ScanError::ResourceLimit(
            EXPANDED_BYTES_LIMIT_MESSAGE.to_string(),
        ));
    }
    let max_entries = state.budget.max_attachment_count as usize;
    match parse_central_directory(body, max_entries) {
        Ok(entries) => inspect_archive_entries(body, &entries, state, archive_depth),
        Err(CentralDirectoryError::TooManyEntries) => Err(ScanError::ResourceLimit(
            ATTACHMENT_COUNT_LIMIT_MESSAGE.to_string(),
        )),
        Err(CentralDirectoryError::Malformed) => {
            state.push(ATTACHMENT_CATEGORY, MALFORMED_ARCHIVE_DESCRIPTION, None);
            inspect_archive_local_headers(body, state)
        },
    }
}

/// Entry-budget, ratio and path pass over the parsed central directory,
/// followed by bounded expansion and recursive inspection of each payload.
fn inspect_archive_entries(
    body: &[u8],
    entries: &[CentralEntry],
    state: &mut AnalysisState,
    archive_depth: u32,
) -> Result<(), ScanError> {
    if entries.len() > state.budget.max_attachment_count as usize {
        return Err(ScanError::ResourceLimit(
            ATTACHMENT_COUNT_LIMIT_MESSAGE.to_string(),
        ));
    }

    let mut encrypted = false;
    let mut macro_marker = false;
    let mut external_link_marker = false;
    let mut unsafe_path = false;
    let mut duplicate_path = false;
    let mut name_mismatch = false;
    let mut malformed = false;
    let mut uninspectable = false;
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(entries.len());
    let mut total_uncompressed = 0_u64;
    let mut total_compressed = 0_u64;

    // Pass 1: everything derivable from headers, so a declared bomb is
    // rejected before any payload is inflated.
    for entry in entries {
        state.check_deadline()?;
        let normalized = normalize_archive_path(&entry.name);
        if archive_path_is_unsafe(&normalized) {
            unsafe_path = true;
        }
        if !seen.insert(normalized) {
            duplicate_path = true;
        }
        inspect_zip_name(&entry.name, &mut macro_marker, &mut external_link_marker);
        let declared = u64::from(entry.uncompressed_size);
        if compression_ratio_exceeds(declared, u64::from(entry.compressed_size)) {
            return Err(ScanError::ResourceLimit(
                ARCHIVE_RATIO_LIMIT_MESSAGE.to_string(),
            ));
        }
        total_uncompressed = total_uncompressed.saturating_add(declared);
        total_compressed = total_compressed.saturating_add(u64::from(entry.compressed_size));
        let Some((_, local_name)) = entry_payload_source(body, entry) else {
            malformed = true;
            continue;
        };
        if local_name != entry.name.as_slice() {
            name_mismatch = true;
        }
        if entry.flags & 1 == 1 {
            encrypted = true;
        }
    }
    if compression_ratio_exceeds(total_uncompressed, total_compressed) {
        return Err(ScanError::ResourceLimit(
            ARCHIVE_RATIO_LIMIT_MESSAGE.to_string(),
        ));
    }

    // Pass 2: bounded expansion and recursive inspection.
    for entry in entries {
        state.check_deadline()?;
        if entry.flags & 1 == 1 {
            // An encrypted entry cannot be decrypted here, so it is reported
            // as evidence below and never expanded.
            continue;
        }
        if archive_path_is_unsafe(&normalize_archive_path(&entry.name)) {
            // An entry whose path could escape an extraction root is never
            // expanded; it is reported as evidence below.
            continue;
        }
        let Some((range, _)) = entry_payload_source(body, entry) else {
            malformed = true;
            continue;
        };
        let data = &body[range];
        let payload: Cow<'_, [u8]> = match entry.method {
            0 => {
                if u64::from(entry.uncompressed_size) != u64::from(entry.compressed_size) {
                    malformed = true;
                }
                Cow::Borrowed(data)
            },
            8 => {
                let remaining = state
                    .budget
                    .max_expanded_bytes
                    .saturating_sub(state.expanded_bytes);
                let cap = u64::from(entry.uncompressed_size).min(remaining) as usize;
                match inflate_bounded(data, cap) {
                    Ok(inflated) => {
                        if inflated.len() as u64 > u64::from(entry.uncompressed_size) {
                            return Err(ScanError::ResourceLimit(
                                EXPANDED_BYTES_LIMIT_MESSAGE.to_string(),
                            ));
                        }
                        Cow::Owned(inflated)
                    },
                    Err(InflateOutcome::Overflow) => {
                        return Err(ScanError::ResourceLimit(
                            EXPANDED_BYTES_LIMIT_MESSAGE.to_string(),
                        ));
                    },
                    Err(InflateOutcome::Malformed) => {
                        malformed = true;
                        continue;
                    },
                }
            },
            _ => {
                uninspectable = true;
                continue;
            },
        };
        state.charge_expanded(payload.len() as u64)?;
        analyze_nested_payload(&payload, state, archive_depth)?;
    }

    if malformed {
        state.push(ATTACHMENT_CATEGORY, MALFORMED_ARCHIVE_DESCRIPTION, None);
    }
    if name_mismatch {
        state.push(ATTACHMENT_CATEGORY, ARCHIVE_NAME_MISMATCH_DESCRIPTION, None);
    }
    if unsafe_path {
        state.push(ATTACHMENT_CATEGORY, ARCHIVE_UNSAFE_PATH_DESCRIPTION, None);
    }
    if duplicate_path {
        state.push(
            ATTACHMENT_CATEGORY,
            ARCHIVE_DUPLICATE_PATH_DESCRIPTION,
            None,
        );
    }
    if encrypted {
        state.push(ATTACHMENT_CATEGORY, ENCRYPTED_ARCHIVE_DESCRIPTION, None);
    }
    if uninspectable {
        state.push(ATTACHMENT_CATEGORY, UNINSPECTABLE_ARCHIVE_DESCRIPTION, None);
    }
    if macro_marker {
        state.push(ATTACHMENT_CATEGORY, MACRO_MARKER_DESCRIPTION, None);
    }
    if external_link_marker {
        state.push(ATTACHMENT_CATEGORY, EXTERNAL_LINK_MARKER_DESCRIPTION, None);
    }
    Ok(())
}

/// Fallback pass for an archive whose central directory cannot be trusted:
/// the local headers still prove the entry budget, encryption flags and
/// entry names, and every one of those still produces explicit evidence.
fn inspect_archive_local_headers(body: &[u8], state: &mut AnalysisState) -> Result<(), ScanError> {
    let mut encrypted = false;
    let mut macro_marker = false;
    let mut external_link_marker = false;
    let mut unsafe_path = false;
    let mut duplicate_path = false;
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut entries = 0_usize;
    let mut offset = 0_usize;

    while offset + 30 <= body.len() {
        state.check_deadline()?;
        if body[offset..offset + 4] != *b"PK\x03\x04" {
            break;
        }
        entries += 1;
        if entries > state.budget.max_attachment_count as usize {
            return Err(ScanError::ResourceLimit(
                ATTACHMENT_COUNT_LIMIT_MESSAGE.to_string(),
            ));
        }
        let flags = u16::from_le_bytes([body[offset + 6], body[offset + 7]]);
        if flags & 1 == 1 {
            encrypted = true;
        }
        let name_len = usize::from(u16::from_le_bytes([body[offset + 26], body[offset + 27]]));
        let extra_len = usize::from(u16::from_le_bytes([body[offset + 28], body[offset + 29]]));
        let Some(header_end) = (30_usize)
            .checked_add(name_len)
            .and_then(|length| length.checked_add(extra_len))
            .and_then(|length| offset.checked_add(length))
        else {
            break;
        };
        if header_end > body.len() || 30 + name_len > body.len() - offset {
            break;
        }
        let name = &body[offset + 30..offset + 30 + name_len];
        let normalized = normalize_archive_path(name);
        if archive_path_is_unsafe(&normalized) {
            unsafe_path = true;
        }
        if !seen.insert(normalized) {
            duplicate_path = true;
        }
        inspect_zip_name(name, &mut macro_marker, &mut external_link_marker);

        let compressed = u32::from_le_bytes([
            body[offset + 18],
            body[offset + 19],
            body[offset + 20],
            body[offset + 21],
        ]);
        if flags & 0x08 != 0 || compressed == 0 {
            // A data-descriptor entry carries no usable size: resume at the
            // next stored local header instead of guessing a length.
            match find(&body[header_end..], b"PK\x03\x04") {
                Some(relative) => offset = header_end + relative,
                None => break,
            }
        } else {
            match header_end.checked_add(compressed as usize) {
                Some(next) if next <= body.len() => offset = next,
                _ => break,
            }
        }
    }

    if unsafe_path {
        state.push(ATTACHMENT_CATEGORY, ARCHIVE_UNSAFE_PATH_DESCRIPTION, None);
    }
    if duplicate_path {
        state.push(
            ATTACHMENT_CATEGORY,
            ARCHIVE_DUPLICATE_PATH_DESCRIPTION,
            None,
        );
    }
    if encrypted {
        state.push(ATTACHMENT_CATEGORY, ENCRYPTED_ARCHIVE_DESCRIPTION, None);
    }
    if macro_marker {
        state.push(ATTACHMENT_CATEGORY, MACRO_MARKER_DESCRIPTION, None);
    }
    if external_link_marker {
        state.push(ATTACHMENT_CATEGORY, EXTERNAL_LINK_MARKER_DESCRIPTION, None);
    }
    Ok(())
}

/// Bounded gzip inspection: the member is inflated in memory under the
/// shared expanded-byte budget and the decompressed payload is inspected
/// exactly like any other nested payload.
fn analyze_gzip(
    body: &[u8],
    state: &mut AnalysisState,
    archive_depth: u32,
) -> Result<(), ScanError> {
    if archive_depth > state.budget.max_nesting_depth {
        return Err(ScanError::ResourceLimit(
            NESTING_DEPTH_LIMIT_MESSAGE.to_string(),
        ));
    }
    state.check_deadline()?;
    let remaining = state
        .budget
        .max_expanded_bytes
        .saturating_sub(state.expanded_bytes);
    match gunzip_bounded(body, remaining as usize) {
        Ok(inflated) => {
            let produced = inflated.len() as u64;
            state.charge_expanded(produced)?;
            analyze_nested_payload(&inflated, state, archive_depth)
        },
        Err(InflateOutcome::Overflow) => Err(ScanError::ResourceLimit(
            EXPANDED_BYTES_LIMIT_MESSAGE.to_string(),
        )),
        Err(InflateOutcome::Malformed) => {
            state.push(ATTACHMENT_CATEGORY, MALFORMED_ARCHIVE_DESCRIPTION, None);
            Ok(())
        },
    }
}

/// Dispatches one already-bounded payload — an inflated archive entry or a
/// decompressed gzip member — to the same reviewed analyzers the top-level
/// MIME walk uses, so nested content is inspected rather than merely counted.
fn analyze_nested_payload(
    payload: &[u8],
    state: &mut AnalysisState,
    archive_depth: u32,
) -> Result<(), ScanError> {
    if payload.is_empty() {
        return Ok(());
    }
    state.check_deadline()?;
    let sniffed = sniff_type(payload);
    match sniffed {
        SniffedType::Empty | SniffedType::Text | SniffedType::Unknown => Ok(()),
        SniffedType::Script
        | SniffedType::Elf
        | SniffedType::DosExecutable
        | SniffedType::MachO => {
            state.push(ATTACHMENT_CATEGORY, EXECUTABLE_ATTACHMENT_DESCRIPTION, None);
            Ok(())
        },
        SniffedType::Pdf => {
            analyze_pdf(payload, state);
            Ok(())
        },
        SniffedType::Ole2 => {
            analyze_legacy_office(payload, state);
            Ok(())
        },
        SniffedType::Zip => analyze_archive(payload, state, archive_depth + 1),
        SniffedType::Gzip => analyze_gzip(payload, state, archive_depth + 1),
        SniffedType::Bzip2
        | SniffedType::Xz
        | SniffedType::Tar
        | SniffedType::Rar
        | SniffedType::SevenZ => {
            state.push(ATTACHMENT_CATEGORY, UNINSPECTABLE_ARCHIVE_DESCRIPTION, None);
            Ok(())
        },
        SniffedType::Svg => {
            state.push(ATTACHMENT_CATEGORY, ACTIVE_MARKUP_DESCRIPTION, None);
            Ok(())
        },
        SniffedType::Html => {
            if has_active_markup(payload) {
                state.push(ATTACHMENT_CATEGORY, ACTIVE_MARKUP_DESCRIPTION, None);
            }
            Ok(())
        },
        SniffedType::Png | SniffedType::Jpeg | SniffedType::Gif => {
            analyze_image(payload, sniffed, state)
        },
    }
}

/// Office marker search over one entry name: VBA/macro and external-link
/// member names are policy evidence regardless of the payload's bytes.
fn inspect_zip_name(name: &[u8], macro_marker: &mut bool, external_link_marker: &mut bool) {
    let lowered = String::from_utf8_lossy(name).to_ascii_lowercase();
    if lowered.contains("vbaproject.bin")
        || lowered.starts_with("basic/")
        || lowered.starts_with("scripting/")
    {
        *macro_marker = true;
    }
    if lowered.contains("externallinks/") {
        *external_link_marker = true;
    }
}

/// Legacy OLE2 Office markers, searched in both the ASCII and UTF-16LE
/// forms a compound file may store them in.
fn analyze_legacy_office(body: &[u8], state: &mut AnalysisState) {
    let macro_marker = find_ascii_ci(body, b"_VBA_PROJECT").is_some()
        || find_utf16le_ascii_ci(body, "_VBA_PROJECT");
    let external_link_marker = find_ascii_ci(body, b"includepicture \"").is_some()
        || find_utf16le_ascii_ci(body, "includepicture \"");
    if macro_marker {
        state.push(ATTACHMENT_CATEGORY, MACRO_MARKER_DESCRIPTION, None);
    }
    if external_link_marker {
        state.push(ATTACHMENT_CATEGORY, EXTERNAL_LINK_MARKER_DESCRIPTION, None);
    }
}

/// Bounded image analysis: header dimensions before any pixel allocation,
/// then (for the reviewed codecs only) grayscale conversion, QR
/// recognition and OCR page retention.
fn analyze_image(
    body: &[u8],
    sniffed: SniffedType,
    state: &mut AnalysisState,
) -> Result<(), ScanError> {
    if !matches!(sniffed, SniffedType::Png | SniffedType::Jpeg) {
        // GIF and other formats have no reviewed decoder enabled here.
        return Ok(());
    }
    let decoded = match catch_unwind(AssertUnwindSafe(|| {
        decode_image_bounded(body, state.budget)
    })) {
        Ok(Ok(decoded)) => decoded,
        Ok(Err(ImageDecodeOutcome::Limited)) => {
            return Err(ScanError::ResourceLimit(
                IMAGE_PIXEL_LIMIT_MESSAGE.to_string(),
            ));
        },
        Ok(Err(ImageDecodeOutcome::Malformed)) | Err(_) => {
            state.push(ATTACHMENT_CATEGORY, UNDECODABLE_IMAGE_DESCRIPTION, None);
            return Ok(());
        },
    };

    let width = decoded.width();
    let height = decoded.height();
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if pixels > state.budget.max_pixels {
        return Err(ScanError::ResourceLimit(
            IMAGE_PIXEL_LIMIT_MESSAGE.to_string(),
        ));
    }
    if width == 0 || height == 0 {
        state.push(ATTACHMENT_CATEGORY, UNDECODABLE_IMAGE_DESCRIPTION, None);
        return Ok(());
    }
    // The QR recognizer indexes cells through 16-bit coordinates.
    if width > u16::MAX as u32 || height > u16::MAX as u32 {
        return Err(ScanError::ResourceLimit(
            IMAGE_PIXEL_LIMIT_MESSAGE.to_string(),
        ));
    }

    match catch_unwind(AssertUnwindSafe(|| count_qr_codes(&decoded))) {
        Ok(codes) => state.qr_codes = state.qr_codes.saturating_add(codes),
        Err(_) => {
            state.push(ATTACHMENT_CATEGORY, UNDECODABLE_IMAGE_DESCRIPTION, None);
        },
    }

    if state.ocr_page_count < state.budget.max_ocr_pages as usize
        && state.ocr_bytes.saturating_add(body.len() as u64) <= state.budget.max_ocr_bytes
    {
        state.ocr_page_count += 1;
        state.ocr_bytes = state.ocr_bytes.saturating_add(body.len() as u64);
        state.ocr_pages.push(Arc::from(body));
    }
    Ok(())
}

#[derive(Debug)]
enum ImageDecodeOutcome {
    /// The part is not a decodable image under the reviewed codecs.
    Malformed,
    /// The image exceeds the reviewed pixel budget.
    Limited,
}

/// Decode header dimensions first so a hostile dimension is rejected before
/// any pixel buffer is allocated, then decode under the memory budget.
fn decode_image_bounded(
    body: &[u8],
    budget: &AnalysisBudget,
) -> Result<DynamicImage, ImageDecodeOutcome> {
    let limits = || {
        let mut limits = Limits::default();
        limits.max_alloc = Some(budget.max_memory_bytes);
        limits
    };
    let mut reader = ImageReader::new(Cursor::new(body))
        .with_guessed_format()
        .map_err(|_| ImageDecodeOutcome::Malformed)?;
    reader.limits(limits());
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| ImageDecodeOutcome::Malformed)?;
    if u64::from(width).saturating_mul(u64::from(height)) > budget.max_pixels {
        return Err(ImageDecodeOutcome::Limited);
    }

    let mut reader = ImageReader::new(Cursor::new(body))
        .with_guessed_format()
        .map_err(|_| ImageDecodeOutcome::Malformed)?;
    reader.limits(limits());
    reader.decode().map_err(|_| ImageDecodeOutcome::Malformed)
}

/// Count decodable QR codes, stopping at the reported-code ceiling. Code
/// payloads are never retained or surfaced.
fn count_qr_codes(image: &DynamicImage) -> usize {
    let gray = image.to_luma8();
    let width = gray.width() as usize;
    let height = gray.height() as usize;
    if width == 0 || height == 0 {
        return 0;
    }
    let mut recognizer = quircs::Quirc::default();
    let mut codes = 0;
    for code in recognizer.identify(width, height, gray.as_raw()) {
        if codes >= MAX_REPORTED_QR_CODES {
            break;
        }
        let Ok(code) = code else {
            continue;
        };
        if code.decode().is_ok() {
            codes += 1;
        }
    }
    codes
}

/// Active-content schemes in extracted text. Only the bounded text itself
/// is inspected; nothing derived from it is ever stored in a finding.
fn extracted_text_has_active_content(text: &str) -> bool {
    let bounded: String = text
        .chars()
        .take(MAX_OCR_TEXT_BYTES as usize)
        .collect::<String>()
        .to_ascii_lowercase();
    [
        "javascript:",
        "vbscript:",
        "data:text/html",
        "data:application/xhtml",
    ]
    .iter()
    .any(|scheme| bounded.contains(scheme))
}

/// First ASCII case-insensitive occurrence of `needle` in `haystack`.
fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let last = haystack.len() - needle.len();
    (0..=last).find(|index| {
        haystack[*index].eq_ignore_ascii_case(&first)
            && haystack[*index..*index + needle.len()].eq_ignore_ascii_case(needle)
    })
}

/// Occurrence of `needle` whose next byte is not ASCII alphanumeric, so a
/// short marker such as `/js` or `/aa` cannot match inside a longer token.
fn find_ascii_ci_token(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(offset) = find_ascii_ci(&haystack[from..], needle) {
        let index = from + offset;
        let next = index + needle.len();
        if next >= haystack.len() || !haystack[next].is_ascii_alphanumeric() {
            return Some(index);
        }
        from = index + 1;
    }
    None
}

/// First exact occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn starts_with_ascii_ci(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// ASCII case-insensitive search for a needle stored as UTF-16LE (even
/// bytes are ASCII, odd bytes are zero), as OLE compound-file names are.
fn find_utf16le_ascii_ci(haystack: &[u8], needle: &str) -> bool {
    let needle_len = needle.len().saturating_mul(2);
    if needle.is_empty() || haystack.len() < needle_len {
        return false;
    }
    let mut first = needle.bytes().next().expect("needle is not empty");
    first = first.to_ascii_lowercase();
    let last = haystack.len() - needle_len;
    (0..=last).any(|index| {
        haystack[index].eq_ignore_ascii_case(&first)
            && needle.bytes().enumerate().all(|(position, byte)| {
                let offset = index + position * 2;
                haystack[offset + 1] == 0 && haystack[offset].eq_ignore_ascii_case(&byte)
            })
    })
}

fn finding_with_details(
    category: &str,
    description: &str,
    severity: FindingSeverity,
    details: Option<serde_json::Value>,
) -> ScannerFinding {
    ScannerFinding {
        id: uuid::Uuid::new_v4(),
        severity,
        category: category.to_string(),
        description: description.to_string(),
        details,
        indicators: Vec::new(),
        false_positive: false,
    }
}

/// Read the fabric-supplied immutable snapshot at most once, bounded by the
/// adapter's own max input. Content-limit and read failures map to canonical
/// fail-safe [`ScanError`]s; a misbehaving provider that yields more bytes
/// than the bound is rejected as a resource limit rather than analysed.
pub(crate) async fn read_content_bounded(
    content: &dyn ScanContent,
    max_input_bytes: u64,
) -> Result<Arc<[u8]>, ScanError> {
    let bytes = content
        .read_all_bounded(max_input_bytes)
        .await
        .map_err(map_scan_content_error)?;
    if bytes.len() as u64 > max_input_bytes {
        return Err(ScanError::ResourceLimit(format!(
            "content length {} exceeds max input {max_input_bytes}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Map a [`ScanContent`] failure onto the typed [`ScanError`] contract
/// without ever echoing content bytes.
fn map_scan_content_error(error: ScanContentError) -> ScanError {
    match error {
        ScanContentError::LimitExceeded => ScanError::ResourceLimit(error.to_string()),
        ScanContentError::Unavailable => ScanError::Unavailable(error.to_string()),
        ScanContentError::Integrity => ScanError::Failed(error.to_string()),
    }
}

fn contains_marker(bytes: &[u8], marker: &[u8]) -> bool {
    bytes.windows(marker.len()).any(|window| window == marker)
}

/// True when a byte ends a URL candidate: ASCII whitespace or a markup
/// delimiter (quote, apostrophe, backtick or angle bracket). Every other byte
/// — including `/`, `?`, `#`, `&` and `=` — may legitimately appear inside a
/// candidate and never truncates it.
fn is_candidate_terminator(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'`' | b'<' | b'>')
}

/// Deterministic single-pass extractor over decoded text. It visits every
/// ASCII case-insensitive `http://`/`https://` occurrence: a candidate starts
/// at the scheme and ends before the first terminator byte, so quoted HTML
/// `href` attributes are covered exactly like bare body URLs. Scanning resumes
/// at the candidate end, which keeps candidates non-overlapping and free of
/// duplicates, and the whole pass is linear in the already-read byte length.
/// The visitor may return an error to stop extraction immediately (for example
/// at the URL-candidate budget).
fn visit_url_candidates<F>(text: &str, mut visit: F) -> Result<(), ScanError>
where
    F: FnMut(&str) -> Result<(), ScanError>,
{
    const SCHEMES: [&str; 2] = ["https://", "http://"];
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let Some(scheme_len) = SCHEMES.iter().find_map(|scheme| {
            let end = index + scheme.len();
            (end <= bytes.len() && bytes[index..end].eq_ignore_ascii_case(scheme.as_bytes()))
                .then_some(scheme.len())
        }) else {
            index += 1;
            continue;
        };
        let start = index;
        let mut end = index + scheme_len;
        while end < bytes.len() && !is_candidate_terminator(bytes[end]) {
            end += 1;
        }
        visit(&text[start..end])?;
        index = end;
    }
    Ok(())
}

/// The candidate text after its ASCII case-insensitive `http://`/`https://`
/// scheme, or `None` when the token carries no accepted scheme.
fn candidate_after_scheme(token: &str) -> Option<&str> {
    let bytes = token.as_bytes();
    for scheme in ["https://", "http://"] {
        let len = scheme.len();
        if bytes.len() >= len && bytes[..len].eq_ignore_ascii_case(scheme.as_bytes()) {
            return Some(&token[len..]);
        }
    }
    None
}

/// Conservative fail-closed inspection of one candidate's authority: the text
/// after the scheme and before the first slash, query, fragment or candidate
/// terminator. Returns `true` when that authority holds any ampersand `&`
/// anywhere in it — numeric (`&#46;`) and named (`&period;`) HTML character
/// references alike — or any percent sign, so the caller rejects the candidate
/// before host normalization, denylist matching or any clean status. Because
/// an ampersand alone rejects, a `&` that directly precedes a `#` never reaches
/// the fragment-delimiter branch, so no accepted candidate is delimited
/// differently than the existing normalization. This performs no decoding and
/// no standards parsing — it is intentionally coarse until a reviewed parser
/// integration exists. It never resolves, fetches or follows a candidate.
fn authority_requires_encoding_review(token: &str) -> bool {
    let Some(after_scheme) = candidate_after_scheme(token) else {
        return false;
    };
    let authority = after_scheme.as_bytes();
    let mut index = 0;
    while index < authority.len() {
        let byte = authority[index];
        if byte == b'%' {
            return true;
        }
        if byte == b'&' {
            return true;
        }
        if byte == b'/' || byte == b'?' || byte == b'#' || is_candidate_terminator(byte) {
            return false;
        }
        index += 1;
    }
    false
}

/// Normalize one candidate token to its comparison host: scheme, userinfo,
/// port, path/query/fragment and harmless trailing punctuation are removed and
/// the remainder is ASCII-lowercased. Returns `None` when no usable host
/// remains (for example a bare `http://` token).
fn normalized_candidate_host(token: &str) -> Option<String> {
    let lowered = token.to_ascii_lowercase();
    let after_scheme = lowered
        .strip_prefix("https://")
        .or_else(|| lowered.strip_prefix("http://"))?;
    let authority = match after_scheme.find(|c| ['/', '?', '#'].contains(&c)) {
        Some(end) => &after_scheme[..end],
        None => after_scheme,
    };
    let without_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    let without_port = strip_port(without_userinfo);
    let host = trim_harmless_trailing_punctuation(without_port);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Drop a `:port` suffix from an authority host while keeping a bracketed
/// IPv6 literal intact.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

/// Punctuation that may trail a token (sentence period, comma, closing
/// bracket or quote) without belonging to the host itself.
fn trim_harmless_trailing_punctuation(host: &str) -> &str {
    host.trim_end_matches(|c: char| {
        matches!(
            c,
            '.' | ',' | ';' | ':' | '!' | '?' | '\'' | '"' | ')' | ']' | '}' | '>'
        )
    })
}

/// Exact-host or dot-prefixed-subdomain match only: `evil.test` and
/// `a.evil.test` match the denied domain `evil.test`, while a mere substring
/// such as `notevil.test` never does.
fn host_matches_denied_domain(host: &str, denied_domain: &str) -> bool {
    match host.strip_suffix(denied_domain) {
        Some(prefix) => prefix.is_empty() || prefix.ends_with('.'),
        None => false,
    }
}

fn finding(category: &str, description: &str, severity: FindingSeverity) -> ScannerFinding {
    ScannerFinding {
        id: uuid::Uuid::new_v4(),
        severity,
        category: category.to_string(),
        description: description.to_string(),
        details: None,
        indicators: Vec::new(),
        false_positive: false,
    }
}

/// Build a fully valid [`ScanResult`]: the request's contract version is
/// echoed unchanged and provenance records this adapter's identity and scan
/// start time.
fn adapter_result<S: Scanner + ?Sized>(
    scanner: &S,
    request: &ScanRequest,
    status: ScannerStatus,
    findings: Vec<ScannerFinding>,
    started: Instant,
    started_at: DateTime<Utc>,
) -> ScanResult {
    ScanResult {
        request_id: request.request_id,
        contract_version: request.contract_version,
        scanner_id: scanner.id(),
        status,
        message: None,
        findings,
        completed_at: Utc::now(),
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        details: None,
        provenance: ScannerProvenance {
            scanner_node_id: None,
            scanner_profile_id: None,
            scanner_profile_version: None,
            engine_version: Some(scanner.version().to_string()),
            ruleset_version: None,
            started_at,
        },
    }
}

fn healthy() -> ScannerHealth {
    ScannerHealth {
        healthy: true,
        message: None,
        checked_at: Utc::now(),
        uptime_seconds: None,
        queue_depth: None,
    }
}

fn png_pixel_count(bytes: &[u8]) -> Option<u64> {
    const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
    if bytes.get(..8)? != PNG_SIGNATURE || bytes.get(12..16)? != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?);
    let height = u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?);
    Some(u64::from(width).saturating_mul(u64::from(height)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use nullapart_mail_contracts::{
        transaction::{ContentHash, CustomerId, DeploymentId, TenantMessageId, TransactionId},
        ArtifactId, ContentType,
    };
    use nullapart_scanner_sdk::{
        contract::DEFAULT_SCANNER_CONTRACT_VERSION, types::ResourceLimits,
    };

    /// Deterministic immutable [`ScanContent`] test provider: one bounded
    /// read yields the same shared snapshot bytes.
    struct StaticScanContent {
        bytes: Vec<u8>,
        content_type: ContentType,
    }

    impl StaticScanContent {
        fn new(bytes: impl Into<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                bytes: bytes.into(),
                content_type: ContentType::new("message/rfc822"),
            })
        }
    }

    #[async_trait::async_trait]
    impl ScanContent for StaticScanContent {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn content_type(&self) -> &ContentType {
            &self.content_type
        }

        async fn read_all_bounded(&self, max_bytes: u64) -> Result<Arc<[u8]>, ScanContentError> {
            if max_bytes < self.bytes.len() as u64 {
                return Err(ScanContentError::LimitExceeded);
            }
            Ok(Arc::from(self.bytes.as_slice()))
        }
    }

    /// Hostile [`ScanContent`] test provider: every bounded read fails with
    /// the configured typed error and never yields bytes.
    struct FailingScanContent {
        content_type: ContentType,
        error: ScanContentError,
    }

    impl FailingScanContent {
        fn new(error: ScanContentError) -> Arc<Self> {
            Arc::new(Self {
                content_type: ContentType::new("message/rfc822"),
                error,
            })
        }
    }

    #[async_trait::async_trait]
    impl ScanContent for FailingScanContent {
        fn len(&self) -> u64 {
            0
        }

        fn content_type(&self) -> &ContentType {
            &self.content_type
        }

        async fn read_all_bounded(&self, _max_bytes: u64) -> Result<Arc<[u8]>, ScanContentError> {
            Err(self.error.clone())
        }
    }

    fn scan_request(artifact_size_bytes: u64) -> ScanRequest {
        ScanRequest {
            request_id: uuid::Uuid::new_v4(),
            contract_version: DEFAULT_SCANNER_CONTRACT_VERSION,
            transaction_id: TransactionId::new(),
            tenant_message_id: Some(TenantMessageId::new()),
            customer_id: Some(CustomerId::new("customer-test")),
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            artifact_id: ArtifactId::new(),
            content_type: ContentType::new("message/rfc822"),
            content_hash: ContentHash::new("test"),
            artifact_size_bytes,
            timeout_ms: 100,
            limits: ResourceLimits::bounded_defaults(),
            requested_at: Utc::now(),
            params: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn file_type_scanner_flags_active_svg_from_scan_content() {
        let bytes = b"Content-Type: image/svg+xml\r\n\r\n<svg/>".to_vec();
        let request = scan_request(bytes.len() as u64);
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let scanner = FileTypeScanner::new(1024);
        let result = scanner.scan(request, content).await.unwrap();

        assert_eq!(result.status, ScannerStatus::Suspicious);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].category, "malicious_attachment");
        assert!(result.validate_contract().is_ok());
    }

    #[tokio::test]
    async fn static_rule_and_url_scanners_find_scan_content_evidence() {
        let bytes = b"From: sender@example.test\r\n\r\nhttps://malicious.test X5O!P%@AP".to_vec();
        let request = scan_request(bytes.len() as u64);
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let static_result = StaticRuleScanner::new(1024)
            .scan(request.clone(), Arc::clone(&content))
            .await
            .unwrap();
        let url_result = UrlReputationScanner::new(1024, vec!["malicious.test".to_string()])
            .scan(request, content)
            .await
            .unwrap();
        assert_eq!(static_result.status, ScannerStatus::Threat);
        assert_eq!(static_result.findings[0].category, "malware");
        assert_eq!(url_result.status, ScannerStatus::Suspicious);
        assert_eq!(url_result.findings[0].category, "reputation");
    }

    #[tokio::test]
    async fn archive_and_document_scanners_enforce_safe_local_inspection() {
        let bytes = b"PK\x03\x04\x00\x00\x01\x00 vbaProject.bin".to_vec();
        let request = scan_request(bytes.len() as u64);
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let archive_result = ArchiveSafetyScanner::new(1024, 10)
            .scan(request.clone(), Arc::clone(&content))
            .await
            .unwrap();
        let document_result = DocumentSafetyScanner::new(1024)
            .scan(request, content)
            .await
            .unwrap();
        assert_eq!(archive_result.status, ScannerStatus::Suspicious);
        assert_eq!(document_result.status, ScannerStatus::Suspicious);
    }

    #[tokio::test]
    async fn image_scanner_rejects_png_above_pixel_budget() {
        let png_header = [
            b"\x89PNG\r\n\x1a\n".as_slice(),
            &[0, 0, 0, 13],
            b"IHDR",
            &10_000_u32.to_be_bytes(),
            &10_000_u32.to_be_bytes(),
        ]
        .concat();
        let request = scan_request(png_header.len() as u64);
        let content: Arc<dyn ScanContent> = StaticScanContent::new(png_header);
        let error = ImageSafetyScanner::new(1024, 1_000_000)
            .scan(request, content)
            .await
            .unwrap_err();
        match error {
            ScanError::ResourceLimit(message) => {
                assert!(message.contains("pixel"), "unexpected message: {message}")
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hostile_content_failures_map_to_fail_safe_scanner_errors() {
        let request = scan_request(64);

        let unavailable = FileTypeScanner::new(1024)
            .scan(
                request.clone(),
                FailingScanContent::new(ScanContentError::Unavailable),
            )
            .await
            .unwrap_err();
        assert!(matches!(unavailable, ScanError::Unavailable(_)));

        let integrity = StaticRuleScanner::new(1024)
            .scan(
                request.clone(),
                FailingScanContent::new(ScanContentError::Integrity),
            )
            .await
            .unwrap_err();
        assert!(matches!(integrity, ScanError::Failed(_)));

        let oversized: Arc<dyn ScanContent> = StaticScanContent::new(vec![0u8; 2048]);
        let limit = ImageSafetyScanner::new(1024, 1_000_000)
            .scan(request, oversized)
            .await
            .unwrap_err();
        assert!(matches!(limit, ScanError::ResourceLimit(_)));
    }

    #[tokio::test]
    async fn url_candidate_limit_permits_exactly_two_candidates() {
        let bytes =
            b"From: sender@example.test\r\n\r\nhttps://one.test/a http://two.test/b".to_vec();
        let mut request = scan_request(bytes.len() as u64);
        request.limits.max_url_count = 2;
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let result = UrlReputationScanner::new(1024, vec!["evil.test".to_string()])
            .scan(request, content)
            .await
            .unwrap();

        assert_eq!(result.status, ScannerStatus::Clean);
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn url_candidate_limit_rejects_a_third_candidate_with_stable_message() {
        let bytes = b"https://one.test/a http://two.test/b https://three.test/c".to_vec();
        let mut request = scan_request(bytes.len() as u64);
        request.limits.max_url_count = 2;
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let error = UrlReputationScanner::new(1024, vec!["evil.test".to_string()])
            .scan(request, content)
            .await
            .unwrap_err();

        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, URL_CANDIDATE_LIMIT_MESSAGE)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn url_reputation_matches_only_exact_denied_hosts() {
        let scanner = UrlReputationScanner::new(1024, vec!["evil.test".to_string()]);

        let miss_bytes =
            b"Contact evil.test directly or browse https://notevil.test/path for details.".to_vec();
        let mut miss_request = scan_request(miss_bytes.len() as u64);
        miss_request.limits.max_url_count = 2;
        let miss_content: Arc<dyn ScanContent> = StaticScanContent::new(miss_bytes);
        let miss_result = scanner
            .clone()
            .scan(miss_request, miss_content)
            .await
            .unwrap();
        assert_eq!(miss_result.status, ScannerStatus::Clean);
        assert!(miss_result.findings.is_empty());

        let hit_bytes = b"Open HTTPS://Evil.Test:8443/login.".to_vec();
        let mut hit_request = scan_request(hit_bytes.len() as u64);
        hit_request.limits.max_url_count = 2;
        let hit_content: Arc<dyn ScanContent> = StaticScanContent::new(hit_bytes);
        let hit_result = scanner.scan(hit_request, hit_content).await.unwrap();
        assert_eq!(hit_result.status, ScannerStatus::Suspicious);
        assert_eq!(hit_result.findings.len(), 1);
        assert_eq!(hit_result.findings[0].category, "reputation");
    }

    #[tokio::test]
    async fn url_reputation_detects_denied_host_inside_html_href_attribute() {
        let scanner = UrlReputationScanner::new(1024, vec!["evil.test".to_string()]);

        for body in [
            b"<a HREF=\"HTTPS://Evil.Test/login\">Sign in</a>".as_slice(),
            b"<a href='http://evil.test/alt'>Alt</a>".as_slice(),
            b"<a href=https://evil.test/unquoted>Raw</a>".as_slice(),
        ] {
            let mut request = scan_request(body.len() as u64);
            request.limits.max_url_count = 4;
            let content: Arc<dyn ScanContent> = StaticScanContent::new(body.to_vec());
            let result = scanner.clone().scan(request, content).await.unwrap();

            assert_eq!(
                result.status,
                ScannerStatus::Suspicious,
                "unexpected status for {body:?}"
            );
            assert_eq!(result.findings.len(), 1);
            assert_eq!(result.findings[0].category, "reputation");
            assert!(result.validate_contract().is_ok());
        }
    }

    /// HTML body of `count` anchor tags, each embedding exactly one
    /// `https://` candidate inside a quoted `href` attribute.
    fn html_href_body(count: usize) -> String {
        (0..count)
            .map(|index| format!("<a href=\"https://host{index}.test/path?from={index}\">l</a>"))
            .collect()
    }

    #[tokio::test]
    async fn url_candidate_limit_permits_exactly_n_embedded_html_urls() {
        let bytes = html_href_body(4).into_bytes();
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes.clone());
        let scanner = UrlReputationScanner::new(1024, vec!["evil.test".to_string()]);

        let mut allowed_request = scan_request(bytes.len() as u64);
        allowed_request.limits.max_url_count = 4;
        let allowed = scanner
            .clone()
            .scan(allowed_request, Arc::clone(&content))
            .await
            .unwrap();
        assert_eq!(allowed.status, ScannerStatus::Clean);
        assert!(allowed.findings.is_empty());

        // The same body already exceeds a budget of three, proving the pass
        // counted every embedded candidate exactly once, in encounter order.
        let mut tight_request = scan_request(bytes.len() as u64);
        tight_request.limits.max_url_count = 3;
        let error = scanner.scan(tight_request, content).await.unwrap_err();
        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, URL_CANDIDATE_LIMIT_MESSAGE)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn url_candidate_limit_rejects_n_plus_one_embedded_html_urls_with_stable_message() {
        let bytes = html_href_body(5).into_bytes();
        let mut request = scan_request(bytes.len() as u64);
        request.limits.max_url_count = 4;
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let error = UrlReputationScanner::new(1024, vec!["evil.test".to_string()])
            .scan(request, content)
            .await
            .unwrap_err();

        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, URL_CANDIDATE_LIMIT_MESSAGE)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    /// Assert that a scan of `body` fails closed with exactly `expected`.
    async fn assert_encoded_authority_rejected(
        scanner: &UrlReputationScanner,
        body: &[u8],
        expected: &str,
    ) {
        let mut request = scan_request(body.len() as u64);
        request.limits.max_url_count = 4;
        let content: Arc<dyn ScanContent> = StaticScanContent::new(body.to_vec());
        let error = scanner
            .clone()
            .scan(request, content)
            .await
            .expect_err("encoded authority must never be reported clean");
        match error {
            ScanError::ResourceLimit(message) => assert_eq!(message, expected),
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn encoded_href_html_character_reference_authority_fails_closed() {
        let scanner = UrlReputationScanner::new(1024, vec!["evil.test".to_string()]);

        for body in [
            b"<a href=\"https://evil&#46;test\">Sign in</a>".as_slice(),
            b"<a href=\"https://evil&#x2e;test\">Sign in</a>".as_slice(),
        ] {
            assert_encoded_authority_rejected(
                &scanner,
                body,
                URL_AUTHORITY_ENCODING_REQUIRES_REVIEW,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn named_html_character_reference_authority_fails_closed() {
        let scanner = UrlReputationScanner::new(1024, vec!["evil.test".to_string()]);

        assert_encoded_authority_rejected(
            &scanner,
            b"<a href=\"https://evil&period;test\">Sign in</a>",
            URL_AUTHORITY_ENCODING_REQUIRES_REVIEW,
        )
        .await;
    }

    #[tokio::test]
    async fn percent_encoded_authority_delimiter_fails_closed() {
        let scanner = UrlReputationScanner::new(1024, vec!["evil.test".to_string()]);

        for body in [
            b"<a href=\"https://evil.test%2Fpath@attacker.test/\">x</a>".as_slice(),
            b"<a href=\"https://evil.test%40attacker.test/\">x</a>".as_slice(),
        ] {
            assert_encoded_authority_rejected(
                &scanner,
                body,
                URL_AUTHORITY_ENCODING_REQUIRES_REVIEW,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn url_candidate_limit_is_applied_before_encoded_authority_rejection() {
        let mut bytes = html_href_body(4).into_bytes();
        bytes.extend_from_slice(b"<a href=\"https://evil&#46;test/path\">l</a>");
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes.clone());
        let scanner = UrlReputationScanner::new(1024, vec!["evil.test".to_string()]);

        // N plain candidates plus one encoded candidate: at a budget of N the
        // over-budget candidate is stopped by the count check before its
        // authority is inspected, so the stable count message wins.
        let mut over_budget = scan_request(bytes.len() as u64);
        over_budget.limits.max_url_count = 4;
        let error = scanner
            .clone()
            .scan(over_budget, Arc::clone(&content))
            .await
            .unwrap_err();
        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, URL_CANDIDATE_LIMIT_MESSAGE)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }

        // At a budget of N+1 every candidate is within the count limit, so the
        // encoded authority itself is the rejection that surfaces.
        let mut within_budget = scan_request(bytes.len() as u64);
        within_budget.limits.max_url_count = 5;
        let error = scanner.scan(within_budget, content).await.unwrap_err();
        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, URL_AUTHORITY_ENCODING_REQUIRES_REVIEW)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    /// One-part MIME message carrying `body` as a named attachment with the
    /// given declared type, transferred as base64 so arbitrary bytes
    /// survive the round trip.
    fn attachment_message(content_type: &str, body: &[u8]) -> Vec<u8> {
        let encoded = STANDARD.encode(body);
        format!(
            "From: sender@example.test\r\n\
             Subject: sample\r\n\
             Content-Type: {content_type}\r\n\
             Content-Disposition: attachment; filename=\"sample.bin\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {encoded}"
        )
        .into_bytes()
    }

    /// Run one composite scan and require a version-valid contract result.
    async fn analysis_scan(scanner: &AttachmentAnalysisScanner, bytes: Vec<u8>) -> ScanResult {
        let request = scan_request(bytes.len() as u64);
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let result = scanner
            .scan(request, content)
            .await
            .expect("composite analysis must resolve");
        assert!(result.validate_contract().is_ok());
        result
    }

    fn descriptions_of(result: &ScanResult) -> Vec<&str> {
        result
            .findings
            .iter()
            .map(|f| f.description.as_str())
            .collect()
    }

    /// Deterministic synthetic PNG used to exercise the image pipeline
    /// without shipping binary fixtures.
    fn png_bytes(width: u32, height: u32) -> Vec<u8> {
        let image = image::RgbaImage::from_pixel(width, height, image::Rgba([20, 40, 60, 255]));
        let dynamic = image::DynamicImage::ImageRgba8(image);
        let mut buffer = Cursor::new(Vec::new());
        dynamic
            .write_to(&mut buffer, image::ImageFormat::Png)
            .expect("encode png");
        buffer.into_inner()
    }

    /// Deterministic QR-code PNG carrying `payload` for the recognition
    /// path.
    fn qr_png(payload: &str) -> Vec<u8> {
        let code = qrcode::QrCode::new(payload.as_bytes()).expect("encode qr");
        let rendered = code
            .render::<image::Luma<u8>>()
            .min_dimensions(400, 400)
            .build();
        let dynamic = image::DynamicImage::ImageLuma8(rendered);
        let mut buffer = Cursor::new(Vec::new());
        dynamic
            .write_to(&mut buffer, image::ImageFormat::Png)
            .expect("encode png");
        buffer.into_inner()
    }

    /// One local file header plus `data`. Sizes are always the declared
    /// uncompressed/compressed pair so a fixture can lie about them the way a
    /// hostile archive would.
    fn zip_entry(name: &str, flags: u16, compressed: u32, uncompressed: u32) -> Vec<u8> {
        let name = name.as_bytes();
        let mut entry = Vec::new();
        entry.extend_from_slice(b"PK\x03\x04");
        entry.extend_from_slice(&20u16.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(&0u32.to_le_bytes());
        entry.extend_from_slice(&compressed.to_le_bytes());
        entry.extend_from_slice(&uncompressed.to_le_bytes());
        entry.extend_from_slice(&(name.len() as u16).to_le_bytes());
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(name);
        entry
    }

    /// Appends one central-directory record for the entry that starts at
    /// `local_offset`.
    fn push_central_entry(
        central: &mut Vec<u8>,
        name: &str,
        flags: u16,
        method: u16,
        compressed: u32,
        uncompressed: u32,
        local_offset: u32,
    ) {
        let name = name.as_bytes();
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&compressed.to_le_bytes());
        central.extend_from_slice(&uncompressed.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name);
    }

    /// Raw-deflate compression, the method a ZIP entry with method `8`
    /// carries.
    fn deflate(data: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data).expect("deflate encoding must work");
        encoder.finish().expect("deflate encoder must finish")
    }

    /// Gzip member over `data`.
    fn gzip(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data).expect("gzip encoding must work");
        encoder.finish().expect("gzip encoder must finish")
    }

    struct ZipSpec {
        name: String,
        flags: u16,
        method: u16,
        /// Bytes as they appear in the archive body.
        data: Vec<u8>,
        /// Declared uncompressed size; defaults to `data.len()` when `None`.
        declared_uncompressed: Option<u32>,
    }

    impl ZipSpec {
        fn stored(name: &str, data: Vec<u8>) -> Self {
            Self {
                name: name.to_string(),
                flags: 0,
                method: 0,
                declared_uncompressed: None,
                data,
            }
        }

        fn with_flags(name: &str, flags: u16) -> Self {
            Self {
                name: name.to_string(),
                flags,
                method: 0,
                declared_uncompressed: None,
                data: Vec::new(),
            }
        }

        fn deflated(name: &str, raw: Vec<u8>, declared_uncompressed: Option<u32>) -> Self {
            let declared_uncompressed = declared_uncompressed.unwrap_or(raw.len() as u32);
            Self {
                name: name.to_string(),
                flags: 0,
                method: 8,
                declared_uncompressed: Some(declared_uncompressed),
                data: deflate(&raw),
            }
        }
    }

    /// A well-formed ZIP: local headers, payloads, a real central directory
    /// and an end-of-central-directory record that agrees with it.
    fn build_zip(specs: &[ZipSpec]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut central = Vec::new();
        let mut offsets = Vec::new();
        for spec in specs {
            let local_offset = body.len() as u32;
            let declared = spec.declared_uncompressed.unwrap_or(spec.data.len() as u32);
            body.extend(zip_entry(
                &spec.name,
                spec.flags,
                spec.data.len() as u32,
                declared,
            ));
            body.extend_from_slice(&spec.data);
            offsets.push((spec, local_offset));
        }
        for (spec, local_offset) in &offsets {
            push_central_entry(
                &mut central,
                &spec.name,
                spec.flags,
                spec.method,
                spec.data.len() as u32,
                spec.declared_uncompressed.unwrap_or(spec.data.len() as u32),
                *local_offset,
            );
        }
        let cd_offset = body.len() as u32;
        body.extend_from_slice(&central);
        let cd_size = central.len() as u32;
        body.extend_from_slice(b"PK\x05\x06");
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&(specs.len() as u16).to_le_bytes());
        body.extend_from_slice(&(specs.len() as u16).to_le_bytes());
        body.extend_from_slice(&cd_size.to_le_bytes());
        body.extend_from_slice(&cd_offset.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    fn minimal_zip(entries: &[(&str, u16)]) -> Vec<u8> {
        build_zip(
            &entries
                .iter()
                .map(|(name, flags)| ZipSpec::with_flags(name, *flags))
                .collect::<Vec<_>>(),
        )
    }

    /// Fake [`OcrEngine`] so text extraction is exercised without an
    /// installed OCR program.
    struct FakeOcr {
        available: bool,
        outcome: Result<String, OcrError>,
        delay: Duration,
    }

    impl FakeOcr {
        fn available_with(text: &str) -> Self {
            Self {
                available: true,
                outcome: Ok(text.to_string()),
                delay: Duration::ZERO,
            }
        }

        fn unavailable() -> Self {
            Self {
                available: false,
                outcome: Err(OcrError::Unavailable),
                delay: Duration::ZERO,
            }
        }
    }

    #[async_trait::async_trait]
    impl OcrEngine for FakeOcr {
        fn is_available(&self) -> bool {
            self.available
        }

        async fn extract(&self, _image: Arc<[u8]>, _timeout: Duration) -> Result<String, OcrError> {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            self.outcome.clone()
        }
    }

    fn scanner_with_ocr(ocr: FakeOcr) -> AttachmentAnalysisScanner {
        AttachmentAnalysisScanner::with_ocr(64 * 1024, 4_000_000, Arc::new(ocr))
    }

    #[tokio::test]
    async fn attachment_analysis_flags_executable_with_declared_type_mismatch() {
        let bytes = attachment_message("application/pdf", b"\x7FELF\x02\x01\x01\x00payload");
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(found.len(), 2, "unexpected findings: {found:?}");
        assert!(found.contains(&EXECUTABLE_ATTACHMENT_DESCRIPTION));
        assert!(found.contains(&TYPE_MISMATCH_DESCRIPTION));
        for finding in &result.findings {
            assert_eq!(finding.severity, FindingSeverity::Medium);
            assert_eq!(finding.category, ATTACHMENT_CATEGORY);
        }
        let serialized = serde_json::to_string(&result.findings).expect("serialize findings");
        assert!(
            !serialized.contains("payload"),
            "payload leaked into evidence"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_reports_malformed_mime_structure() {
        let scanner = AttachmentAnalysisScanner::new(64 * 1024, 4_000_000);
        for bytes in [
            b"From: a@b.test\r\n\rbody".to_vec(),
            b"From: a@b.test".to_vec(),
        ] {
            let result = analysis_scan(&scanner, bytes.clone()).await;
            assert_eq!(
                result.status,
                ScannerStatus::Suspicious,
                "unexpected status for {bytes:?}"
            );
            assert_eq!(result.findings.len(), 1);
            assert_eq!(result.findings[0].description, MALFORMED_MIME_DESCRIPTION);
            assert_eq!(result.findings[0].category, ATTACHMENT_CATEGORY);
        }
    }

    #[tokio::test]
    async fn attachment_analysis_reports_undecodable_attachment_body() {
        let message = b"From: a@b.test\r\n\
             Content-Type: application/pdf\r\n\
             Content-Disposition: attachment; filename=\"sample.pdf\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             !!!!not-base64"
            .to_vec();
        let result = analysis_scan(
            &AttachmentAnalysisScanner::new(64 * 1024, 4_000_000),
            message,
        )
        .await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].description,
            UNDECODABLE_ATTACHMENT_DESCRIPTION
        );
    }

    #[tokio::test]
    async fn attachment_analysis_flags_active_html_as_attachment_and_inline_body() {
        let scanner = AttachmentAnalysisScanner::new(64 * 1024, 4_000_000);

        let attached = attachment_message("text/html", b"<html><script>alert(1)</script></html>");
        let attached_result = analysis_scan(&scanner, attached).await;
        assert_eq!(attached_result.status, ScannerStatus::Suspicious);
        assert_eq!(attached_result.findings.len(), 1);
        assert_eq!(
            attached_result.findings[0].description,
            ACTIVE_MARKUP_DESCRIPTION
        );

        let inline = b"From: a@b.test\r\n\
             Content-Type: text/html\r\n\
             \r\n\
             <html><script>x()</script></html>"
            .to_vec();
        let inline_result = analysis_scan(&scanner, inline).await;
        assert_eq!(inline_result.status, ScannerStatus::Suspicious);
        assert_eq!(inline_result.findings.len(), 1);
        assert_eq!(
            inline_result.findings[0].description,
            ACTIVE_MARKUP_DESCRIPTION
        );
    }

    #[tokio::test]
    async fn attachment_analysis_flags_every_svg_attachment() {
        let bytes = attachment_message("image/svg+xml", b"<svg/>");
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].description, ACTIVE_MARKUP_DESCRIPTION);
        assert_eq!(result.findings[0].category, ATTACHMENT_CATEGORY);
    }

    #[tokio::test]
    async fn attachment_analysis_flags_encrypted_zip_macro_and_external_link_markers() {
        let body = minimal_zip(&[
            ("word/vbaProject.bin", 1),
            ("xl/externalLinks/externalLink1.xml", 0),
        ]);
        let bytes = attachment_message("application/zip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(found.len(), 3, "unexpected findings: {found:?}");
        assert!(found.contains(&ENCRYPTED_ARCHIVE_DESCRIPTION));
        assert!(found.contains(&MACRO_MARKER_DESCRIPTION));
        assert!(found.contains(&EXTERNAL_LINK_MARKER_DESCRIPTION));
        assert!(!found.contains(&MALFORMED_ARCHIVE_DESCRIPTION));
        assert!(!found.contains(&TYPE_MISMATCH_DESCRIPTION));
    }

    #[tokio::test]
    async fn attachment_analysis_flags_zip_without_central_directory_as_malformed() {
        let body = zip_entry("word/vbaProject.bin", 0, 0, 0);
        let bytes = attachment_message("application/zip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert!(found.contains(&MALFORMED_ARCHIVE_DESCRIPTION));
        assert!(found.contains(&MACRO_MARKER_DESCRIPTION));
    }

    /// Run one scan and return the resource-limit message, so every budget
    /// rejection below asserts on the exact bounded reason.
    async fn analysis_resource_limit(bytes: Vec<u8>, request: ScanRequest) -> String {
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        match AttachmentAnalysisScanner::new(64 * 1024, 4_000_000)
            .scan(request, content)
            .await
        {
            Err(ScanError::ResourceLimit(message)) => message,
            Err(other) => panic!("expected resource limit, got {other:?}"),
            Ok(_) => panic!("expected resource limit, got a clean result"),
        }
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_declared_archive_ratio_before_inflating() {
        // Declared 512 MiB from ~1 KiB of deflate output: the ratio is read
        // from headers alone, so no payload is ever expanded.
        let body = build_zip(&[ZipSpec::deflated(
            "nested.bin",
            vec![0_u8; 1 << 20],
            Some(512 * 1024 * 1024),
        )]);
        let bytes = attachment_message("application/zip", &body);
        let request = scan_request(bytes.len() as u64);
        let message = analysis_resource_limit(bytes, request).await;
        assert_eq!(message, ARCHIVE_RATIO_LIMIT_MESSAGE);
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_archive_member_that_inflates_past_declared_size() {
        // The declared size is small and honest-looking; the stream still
        // holds far more output, so the probe byte must fail closed.
        let body = build_zip(&[ZipSpec::deflated(
            "nested.bin",
            vec![0_u8; 1 << 20],
            Some(100),
        )]);
        let bytes = attachment_message("application/zip", &body);
        let request = scan_request(bytes.len() as u64);
        let message = analysis_resource_limit(bytes, request).await;
        assert_eq!(message, EXPANDED_BYTES_LIMIT_MESSAGE);
    }

    #[tokio::test]
    async fn attachment_analysis_inspects_deflated_archive_members() {
        let raw = b"<!doctype html><script>alert(1)</script>".to_vec();
        let body = build_zip(&[ZipSpec::deflated("page.html", raw, None)]);
        let bytes = attachment_message("application/zip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(
            found,
            vec![ACTIVE_MARKUP_DESCRIPTION],
            "unexpected: {found:?}"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_nested_archive_past_nesting_budget() {
        let inner = build_zip(&[ZipSpec::stored("inner.txt", b"hi".to_vec())]);
        let outer = build_zip(&[ZipSpec::stored("inner.zip", inner)]);
        let bytes = attachment_message("application/zip", &outer);
        let mut request = scan_request(bytes.len() as u64);
        request.limits.max_nesting_depth = 0;
        let message = analysis_resource_limit(bytes, request).await;
        assert_eq!(message, NESTING_DEPTH_LIMIT_MESSAGE);
    }

    #[tokio::test]
    async fn attachment_analysis_flags_archive_path_traversal_without_expanding_it() {
        let body = build_zip(&[ZipSpec::stored("../../etc/passwd", b"root:x:0:0".to_vec())]);
        let bytes = attachment_message("application/zip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(
            found,
            vec![ARCHIVE_UNSAFE_PATH_DESCRIPTION],
            "unexpected: {found:?}"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_flags_absolute_archive_path() {
        let body = build_zip(&[ZipSpec::stored("/var/mail/drop", b"payload".to_vec())]);
        let bytes = attachment_message("application/zip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(
            found,
            vec![ARCHIVE_UNSAFE_PATH_DESCRIPTION],
            "unexpected: {found:?}"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_flags_duplicate_archive_entry_names() {
        let body = build_zip(&[
            ZipSpec::stored("report.txt", b"first".to_vec()),
            ZipSpec::stored("REPORT.TXT", b"second".to_vec()),
        ]);
        let bytes = attachment_message("application/zip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(
            found,
            vec![ARCHIVE_DUPLICATE_PATH_DESCRIPTION],
            "unexpected: {found:?}"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_flags_archive_local_header_name_mismatch() {
        let mut body = Vec::new();
        body.extend(zip_entry("real.txt", 0, 5, 5));
        body.extend_from_slice(b"hello");
        let mut central = Vec::new();
        push_central_entry(&mut central, "other.txt", 0, 0, 5, 5, 0);
        let cd_offset = body.len() as u32;
        body.extend_from_slice(&central);
        let cd_size = central.len() as u32;
        body.extend_from_slice(b"PK\x05\x06");
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&cd_size.to_le_bytes());
        body.extend_from_slice(&cd_offset.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());

        let bytes = attachment_message("application/zip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(
            found,
            vec![ARCHIVE_NAME_MISMATCH_DESCRIPTION],
            "unexpected: {found:?}"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_archive_entry_count_past_budget() {
        let body = build_zip(&[
            ZipSpec::stored("a.txt", b"one".to_vec()),
            ZipSpec::stored("b.txt", b"two".to_vec()),
        ]);
        let bytes = attachment_message("application/zip", &body);
        let mut request = scan_request(bytes.len() as u64);
        request.limits.max_attachment_count = 1;
        let message = analysis_resource_limit(bytes, request).await;
        assert_eq!(message, ATTACHMENT_COUNT_LIMIT_MESSAGE);
    }

    #[tokio::test]
    async fn attachment_analysis_flags_unsupported_archive_method_as_uninspectable() {
        let body = build_zip(&[ZipSpec {
            name: "legacy.bin".to_string(),
            flags: 0,
            method: 2,
            data: vec![0x01, 0x02, 0x03],
            declared_uncompressed: None,
        }]);
        let bytes = attachment_message("application/zip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(
            found,
            vec![UNINSPECTABLE_ARCHIVE_DESCRIPTION],
            "unexpected: {found:?}"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_decompresses_gzip_members_before_content_checks() {
        let body = gzip(b"<!doctype html><script>alert(1)</script>");
        let bytes = attachment_message("application/gzip", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(
            found,
            vec![ACTIVE_MARKUP_DESCRIPTION],
            "unexpected: {found:?}"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_gzip_expansion_past_budget() {
        let body = gzip(&vec![0_u8; 1 << 20]);
        let bytes = attachment_message("application/gzip", &body);
        let mut request = scan_request(bytes.len() as u64);
        request.limits.max_expanded_bytes = bytes.len() as u64 + 2_048;
        let message = analysis_resource_limit(bytes, request).await;
        assert_eq!(message, EXPANDED_BYTES_LIMIT_MESSAGE);
    }

    #[tokio::test]
    async fn attachment_analysis_reports_malformed_gzip_as_evidence_not_clean() {
        let bytes = attachment_message("application/gzip", b"\x1f\x8bnot-a-gzip-member");
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(
            found,
            vec![MALFORMED_ARCHIVE_DESCRIPTION],
            "unexpected: {found:?}"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_flags_legacy_office_macro_and_external_link_markers() {
        let mut body = Vec::new();
        body.extend_from_slice(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
        body.extend_from_slice(b"directory-_VBA_PROJECT\x00");
        body.extend(
            "INCLUDEPICTURE \"http://x.test\""
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        );
        let bytes = attachment_message("application/msword", &body);
        let result =
            analysis_scan(&AttachmentAnalysisScanner::new(64 * 1024, 4_000_000), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(found.len(), 2, "unexpected findings: {found:?}");
        assert!(found.contains(&MACRO_MARKER_DESCRIPTION));
        assert!(found.contains(&EXTERNAL_LINK_MARKER_DESCRIPTION));
        assert!(!found.contains(&TYPE_MISMATCH_DESCRIPTION));
    }

    #[tokio::test]
    async fn attachment_analysis_flags_pdf_active_content_encryption_and_malformed_shape() {
        let scanner = AttachmentAnalysisScanner::new(64 * 1024, 4_000_000);

        let active = b"%PDF-1.7\n1 0 obj\n<</JavaScript(this)>>\nendobj\n\
             trailer\nstartxref\n9\n%%EOF"
            .to_vec();
        let active_result =
            analysis_scan(&scanner, attachment_message("application/pdf", &active)).await;
        assert_eq!(active_result.status, ScannerStatus::Suspicious);
        assert_eq!(active_result.findings.len(), 1);
        assert_eq!(
            active_result.findings[0].description,
            ACTIVE_DOCUMENT_DESCRIPTION
        );

        let encrypted = b"%PDF-1.7\ntrailer\n<</Encrypt 2 0 R>>\nstartxref\n9\n%%EOF".to_vec();
        let encrypted_result =
            analysis_scan(&scanner, attachment_message("application/pdf", &encrypted)).await;
        assert_eq!(encrypted_result.findings.len(), 1);
        assert_eq!(
            encrypted_result.findings[0].description,
            ENCRYPTED_DOCUMENT_DESCRIPTION
        );

        let malformed = b"%PDF-1.7\nno trailer here".to_vec();
        let malformed_result =
            analysis_scan(&scanner, attachment_message("application/pdf", &malformed)).await;
        assert_eq!(malformed_result.status, ScannerStatus::Suspicious);
        assert_eq!(malformed_result.findings.len(), 1);
        assert_eq!(
            malformed_result.findings[0].description,
            MALFORMED_DOCUMENT_DESCRIPTION
        );
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_image_above_pixel_budget() {
        let bytes = attachment_message("image/png", &png_bytes(64, 64));
        let request = scan_request(bytes.len() as u64);
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let error = AttachmentAnalysisScanner::new(64 * 1024, 1)
            .scan(request, content)
            .await
            .unwrap_err();

        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, IMAGE_PIXEL_LIMIT_MESSAGE)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attachment_analysis_reports_undecodable_image_as_evidence() {
        let bytes = attachment_message("image/png", b"\x89PNG\r\n\x1a\nnot-a-real-image");
        let result = analysis_scan(&scanner_with_ocr(FakeOcr::available_with("")), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].description,
            UNDECODABLE_IMAGE_DESCRIPTION
        );
    }

    #[tokio::test]
    async fn attachment_analysis_reports_qr_codes_without_surfacing_payload() {
        let payload = "qr-secret-payload-9f3a";
        let bytes = attachment_message("image/png", &qr_png(payload));
        let result = analysis_scan(&scanner_with_ocr(FakeOcr::available_with("")), bytes).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let qr = result
            .findings
            .iter()
            .find(|finding| finding.description == QR_CODE_DESCRIPTION)
            .expect("qr evidence must be reported");
        assert_eq!(qr.severity, FindingSeverity::Medium);
        let count = qr
            .details
            .as_ref()
            .and_then(|details| details.get("qr_codes"))
            .and_then(|count| count.as_u64())
            .expect("code count must be recorded");
        assert!(count >= 1, "expected at least one code, got {count}");

        let serialized = serde_json::to_string(&result.findings).expect("serialize findings");
        assert!(
            !serialized.contains(payload),
            "qr payload leaked into evidence"
        );
    }

    #[tokio::test]
    async fn attachment_analysis_ocr_outcomes_stay_fail_safe() {
        let png_message = || attachment_message("image/png", &png_bytes(32, 32));

        // Inert extracted text carries no active scheme: still clean.
        let clean = analysis_scan(
            &scanner_with_ocr(FakeOcr::available_with("invoice total 42")),
            png_message(),
        )
        .await;
        assert_eq!(clean.status, ScannerStatus::Clean);
        assert!(clean.findings.is_empty());

        // Active scheme in extracted text is evidence.
        let active = analysis_scan(
            &scanner_with_ocr(FakeOcr::available_with("open javascript:alert(1) now")),
            png_message(),
        )
        .await;
        assert_eq!(active.status, ScannerStatus::Suspicious);
        assert_eq!(active.findings.len(), 1);
        assert_eq!(
            active.findings[0].description,
            OCR_ACTIVE_CONTENT_DESCRIPTION
        );

        // A failing engine is never silently clean.
        let failing = analysis_scan(
            &scanner_with_ocr(FakeOcr {
                available: true,
                outcome: Err(OcrError::Failed),
                delay: Duration::ZERO,
            }),
            png_message(),
        )
        .await;
        assert_eq!(failing.status, ScannerStatus::Suspicious);
        assert_eq!(failing.findings.len(), 1);
        assert_eq!(failing.findings[0].description, OCR_FAILURE_DESCRIPTION);

        // A missing engine is the same unextracted outcome, never clean.
        let missing = analysis_scan(&scanner_with_ocr(FakeOcr::unavailable()), png_message()).await;
        assert_eq!(missing.status, ScannerStatus::Suspicious);
        assert_eq!(missing.findings.len(), 1);
        assert_eq!(missing.findings[0].description, OCR_FAILURE_DESCRIPTION);
    }

    #[tokio::test]
    async fn attachment_analysis_deadline_fails_closed_instead_of_clean() {
        let bytes = attachment_message("image/png", &png_bytes(16, 16));
        let scanner = scanner_with_ocr(FakeOcr {
            available: true,
            outcome: Ok(String::new()),
            delay: Duration::from_millis(1_000),
        });
        let request = {
            let mut request = scan_request(bytes.len() as u64);
            request.timeout_ms = 150;
            request
        };
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let error = scanner.scan(request, content).await.unwrap_err();

        match error {
            ScanError::Failed(message) => {
                assert_eq!(message, ANALYSIS_DEADLINE_MESSAGE)
            },
            other => panic!("expected deadline failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attachment_analysis_health_is_content_free_and_tracks_ocr_availability() {
        let available = scanner_with_ocr(FakeOcr::available_with("")).health().await;
        assert!(available.healthy);
        assert!(available.message.is_none());

        let unavailable = scanner_with_ocr(FakeOcr::unavailable()).health().await;
        assert!(!unavailable.healthy);
        let message = unavailable.message.as_deref();
        assert_eq!(message, Some(OCR_UNAVAILABLE_HEALTH_MESSAGE));
        assert!(!message.expect("message present").contains("tesseract"));

        // The platform adapter must mirror availability exactly and still
        // never name the OCR program, whether or not it is installed.
        let platform = AttachmentAnalysisScanner::new(64 * 1024, 4_000_000)
            .health()
            .await;
        assert_eq!(platform.healthy, platform.message.is_none());
        if let Some(message) = platform.message.as_deref() {
            assert_eq!(message, OCR_UNAVAILABLE_HEALTH_MESSAGE);
            assert!(!message.contains("tesseract"));
        }
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_nesting_past_budget() {
        let multipart = b"From: a@b.test\r\n\
             Content-Type: multipart/mixed; boundary=\"x\"\r\n\
             \r\n\
             --x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x--\r\n"
            .to_vec();
        let request = {
            let mut request = scan_request(multipart.len() as u64);
            request.limits.max_nesting_depth = 0;
            request
        };
        let content: Arc<dyn ScanContent> = StaticScanContent::new(multipart);
        let error = AttachmentAnalysisScanner::new(64 * 1024, 4_000_000)
            .scan(request, content)
            .await
            .unwrap_err();

        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, NESTING_DEPTH_LIMIT_MESSAGE)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_entries_past_budget() {
        let message = b"From: a@b.test\r\n\
             Content-Type: multipart/mixed; boundary=\"x\"\r\n\
             \r\n\
             --x\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"a.txt\"\r\n\r\n\
             one\r\n\
             --x\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"b.txt\"\r\n\r\n\
             two\r\n--x--\r\n"
            .to_vec();
        let request = {
            let mut request = scan_request(message.len() as u64);
            request.limits.max_attachment_count = 1;
            request
        };
        let content: Arc<dyn ScanContent> = StaticScanContent::new(message);
        let error = AttachmentAnalysisScanner::new(64 * 1024, 4_000_000)
            .scan(request, content)
            .await
            .unwrap_err();

        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, ATTACHMENT_COUNT_LIMIT_MESSAGE)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attachment_analysis_rejects_expansion_past_budget() {
        let bytes = attachment_message("text/plain", b"hello expanded world");
        let request = {
            let mut request = scan_request(bytes.len() as u64);
            request.limits.max_expanded_bytes = 4;
            request
        };
        let content: Arc<dyn ScanContent> = StaticScanContent::new(bytes);
        let error = AttachmentAnalysisScanner::new(64 * 1024, 4_000_000)
            .scan(request, content)
            .await
            .unwrap_err();

        match error {
            ScanError::ResourceLimit(message) => {
                assert_eq!(message, EXPANDED_BYTES_LIMIT_MESSAGE)
            },
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attachment_analysis_descends_into_nested_message() {
        let inner = attachment_message("application/pdf", b"\x7FELF\x02\x01\x01\x00inner");
        let outer = attachment_message("message/rfc822", &inner);
        let result = analysis_scan(&scanner_with_ocr(FakeOcr::available_with("")), outer).await;

        assert_eq!(result.status, ScannerStatus::Suspicious);
        let found = descriptions_of(&result);
        assert_eq!(found.len(), 2, "unexpected findings: {found:?}");
        assert!(found.contains(&EXECUTABLE_ATTACHMENT_DESCRIPTION));
        assert!(found.contains(&TYPE_MISMATCH_DESCRIPTION));
    }

    #[tokio::test]
    async fn attachment_analysis_leaves_plain_text_message_clean() {
        let message = b"From: a@b.test\r\n\
             Subject: hello\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             hello world\r\n"
            .to_vec();
        let result = analysis_scan(
            &AttachmentAnalysisScanner::new(64 * 1024, 4_000_000),
            message,
        )
        .await;

        assert_eq!(result.status, ScannerStatus::Clean);
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn attachment_analysis_identity_capability_labels_composite_scope() {
        let scanner = AttachmentAnalysisScanner::new(64 * 1024, 4_000_000);
        assert_eq!(scanner.id().0, "attachment-analysis");
        assert_eq!(scanner.version(), "1");
        let capabilities = scanner.capabilities();
        assert_eq!(capabilities.supported_content_types, vec!["message/rfc822"]);
        assert!(!capabilities.requires_network);
        assert_eq!(capabilities.latency_class, LatencyClass::Medium);
        assert_eq!(
            capabilities.extra,
            serde_json::json!({
                "analysis": [
                    "file_type",
                    "archive",
                    "pdf",
                    "office",
                    "image",
                    "ocr",
                    "qr",
                ],
            })
        );
    }
}
