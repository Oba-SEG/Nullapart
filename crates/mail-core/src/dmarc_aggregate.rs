//! Phase 5 DMARC aggregate-report ingestion foundation.
//!
//! This module deliberately stops at bounded parsing/normalization. It does
//! not poll mailboxes, mutate DNS, expose UI, or store raw XML. Report bytes
//! are untrusted: compressed input is bounded before XML parsing, and XML
//! constructs that can carry entity/DTD attacks are rejected before the
//! event parser runs.

use std::io::Read;
use std::net::IpAddr;

use chrono::{DateTime, TimeZone, Utc};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub const DMARC_AGGREGATE_PARSER_VERSION: &str = "dmarc-aggregate-v1";

const DEFAULT_MAX_COMPRESSED_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_DECOMPRESSED_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_RECORDS: usize = 25_000;
const DEFAULT_MAX_XML_DEPTH: usize = 32;
const DEFAULT_MAX_TEXT_BYTES: usize = 4096;
const INFLATE_CHUNK_BYTES: usize = 8192;
const INFLATE_PREALLOC_BYTES: usize = 64 * 1024;
const ZIP_LOCAL_FILE_HEADER_SIGNATURE: &[u8; 4] = b"PK\x03\x04";
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const ZIP_MAX_ENTRIES: usize = 8;
const ZIP_METHOD_STORED: u16 = 0;
const ZIP_METHOD_DEFLATED: u16 = 8;
const ZIP_FLAG_ENCRYPTED: u16 = 0x0001;
const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcAggregateLimits {
    pub max_compressed_bytes: usize,
    pub max_decompressed_bytes: usize,
    pub max_records: usize,
    pub max_xml_depth: usize,
    pub max_text_bytes: usize,
}

impl Default for DmarcAggregateLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: DEFAULT_MAX_COMPRESSED_BYTES,
            max_decompressed_bytes: DEFAULT_MAX_DECOMPRESSED_BYTES,
            max_records: DEFAULT_MAX_RECORDS,
            max_xml_depth: DEFAULT_MAX_XML_DEPTH,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcReportCompression {
    Auto,
    Xml,
    Gzip,
    Zip,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DmarcAggregateError {
    #[error("compressed report exceeds the maximum accepted size")]
    CompressedSizeLimit,
    #[error("decompressed report exceeds the maximum accepted size")]
    DecompressedSizeLimit,
    #[error("unsupported report compression")]
    UnsupportedCompression,
    #[error("compressed report is malformed")]
    MalformedCompression,
    #[error("report XML uses forbidden DTD/entity constructs")]
    ForbiddenXmlConstruct,
    #[error("report XML is malformed")]
    MalformedXml,
    #[error("report XML exceeds the maximum accepted nesting depth")]
    XmlDepthLimit,
    #[error("report text field exceeds the maximum accepted size")]
    TextSizeLimit,
    #[error("report contains too many records")]
    RecordLimit,
    #[error("report is missing a required field: {0}")]
    MissingField(&'static str),
    #[error("report contains an invalid field: {0}")]
    InvalidField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcAggregateReport {
    pub reporter_org_name: String,
    pub report_id: String,
    pub date_range_begin: DateTime<Utc>,
    pub date_range_end: DateTime<Utc>,
    pub policy_domain: String,
    pub policy_adkim: Option<String>,
    pub policy_aspf: Option<String>,
    pub policy_p: String,
    pub records: Vec<DmarcAggregateRecord>,
    pub duplicate_key: String,
    pub parser_version: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcAggregateRecord {
    pub source_ip: IpAddr,
    pub message_count: u64,
    pub header_from_domain: String,
    pub envelope_from_domain: Option<String>,
    pub disposition: String,
    pub dkim_aligned_result: Option<String>,
    pub spf_aligned_result: Option<String>,
    pub dkim_auth_results: Vec<DkimAuthResult>,
    pub spf_auth_results: Vec<SpfAuthResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DkimAuthResult {
    pub domain: String,
    pub selector: Option<String>,
    pub result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpfAuthResult {
    pub domain: String,
    pub result: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PartialRecord {
    source_ip: Option<IpAddr>,
    message_count: Option<u64>,
    header_from_domain: Option<String>,
    envelope_from_domain: Option<String>,
    disposition: Option<String>,
    dkim_aligned_result: Option<String>,
    spf_aligned_result: Option<String>,
    dkim_auth_results: Vec<DkimAuthResult>,
    spf_auth_results: Vec<SpfAuthResult>,
}

impl PartialRecord {
    fn finish(self) -> Result<DmarcAggregateRecord, DmarcAggregateError> {
        let message_count = self
            .message_count
            .ok_or(DmarcAggregateError::MissingField("record.row.count"))?;
        if message_count == 0 {
            return Err(DmarcAggregateError::InvalidField("record.row.count"));
        }
        Ok(DmarcAggregateRecord {
            source_ip: self
                .source_ip
                .ok_or(DmarcAggregateError::MissingField("record.row.source_ip"))?,
            message_count,
            header_from_domain: self.header_from_domain.ok_or(
                DmarcAggregateError::MissingField("record.identifiers.header_from"),
            )?,
            envelope_from_domain: self.envelope_from_domain,
            disposition: self.disposition.ok_or(DmarcAggregateError::MissingField(
                "record.row.policy_evaluated.disposition",
            ))?,
            dkim_aligned_result: self.dkim_aligned_result,
            spf_aligned_result: self.spf_aligned_result,
            dkim_auth_results: self.dkim_auth_results,
            spf_auth_results: self.spf_auth_results,
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PartialReport {
    reporter_org_name: Option<String>,
    report_id: Option<String>,
    date_range_begin: Option<i64>,
    date_range_end: Option<i64>,
    policy_domain: Option<String>,
    policy_adkim: Option<String>,
    policy_aspf: Option<String>,
    policy_p: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PartialDkimAuthResult {
    domain: Option<String>,
    selector: Option<String>,
    result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PartialSpfAuthResult {
    domain: Option<String>,
    result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMappingCandidate {
    pub customer_id: String,
    pub domain_id: Uuid,
    pub domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcAggregateSource {
    pub artifact_id: Option<Uuid>,
    pub artifact_hash: Option<String>,
    pub compressed_size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcAggregateIngestStatus {
    Inserted,
    Duplicate,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcAggregateIngestOutcome {
    pub status: DmarcAggregateIngestStatus,
    pub report_row_id: Option<Uuid>,
    pub records_inserted: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DmarcAggregateIngestError {
    #[error("dmarc aggregate ingestion input is invalid")]
    InvalidInput,
    #[error("dmarc aggregate ingestion is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct PostgresDmarcAggregateIngestor {
    pool: PgPool,
    deployment_id: DeploymentId,
}

impl PostgresDmarcAggregateIngestor {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self {
            pool,
            deployment_id,
        }
    }

    pub async fn ingest_bytes(
        &self,
        input: &[u8],
        compression: DmarcReportCompression,
        limits: &DmarcAggregateLimits,
        source: DmarcAggregateSource,
    ) -> Result<DmarcAggregateIngestOutcome, DmarcAggregateIngestError> {
        validate_source(&source)?;
        if source.compressed_size_bytes != input.len() as u64 {
            return Err(DmarcAggregateIngestError::InvalidInput);
        }
        if input.len() > limits.max_compressed_bytes {
            self.quarantine_report(
                &source,
                "compressed_size_limit",
                DmarcAggregateError::CompressedSizeLimit.to_string(),
                None,
            )
            .await?;
            return Ok(DmarcAggregateIngestOutcome {
                status: DmarcAggregateIngestStatus::Quarantined,
                report_row_id: None,
                records_inserted: 0,
            });
        }

        let parsed = match parse_dmarc_aggregate_report(input, compression, limits) {
            Ok(report) => report,
            Err(error) => {
                self.quarantine_report(&source, error.code(), error.to_string(), None)
                    .await?;
                return Ok(DmarcAggregateIngestOutcome {
                    status: DmarcAggregateIngestStatus::Quarantined,
                    report_row_id: None,
                    records_inserted: 0,
                });
            },
        };

        let Some(mapping) = self.resolve_report_domain(&parsed.policy_domain).await? else {
            self.quarantine_report(
                &source,
                "domain_unmapped",
                "report policy domain is not a verified active customer domain".to_string(),
                Some(&parsed),
            )
            .await?;
            return Ok(DmarcAggregateIngestOutcome {
                status: DmarcAggregateIngestStatus::Quarantined,
                report_row_id: None,
                records_inserted: 0,
            });
        };

        self.persist_report(parsed, mapping, source).await
    }

    async fn resolve_report_domain(
        &self,
        policy_domain: &str,
    ) -> Result<Option<ResolvedReportDomain>, DmarcAggregateIngestError> {
        let row = sqlx::query(
            "SELECT customer_id, domain_id, domain \
             FROM resolve_verified_report_domain($1, $2)",
        )
        .bind(policy_domain)
        .bind(&self.deployment_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DmarcAggregateIngestError::Unavailable)?;

        row.map(|row| {
            Ok(ResolvedReportDomain {
                customer_id: CustomerId(
                    row.try_get("customer_id")
                        .map_err(|_| DmarcAggregateIngestError::Unavailable)?,
                ),
                domain_id: row
                    .try_get("domain_id")
                    .map_err(|_| DmarcAggregateIngestError::Unavailable)?,
                domain: row
                    .try_get("domain")
                    .map_err(|_| DmarcAggregateIngestError::Unavailable)?,
            })
        })
        .transpose()
    }

    async fn persist_report(
        &self,
        report: DmarcAggregateReport,
        mapping: ResolvedReportDomain,
        source: DmarcAggregateSource,
    ) -> Result<DmarcAggregateIngestOutcome, DmarcAggregateIngestError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
        set_report_scope(&mut transaction, &self.deployment_id, &mapping.customer_id).await?;

        let inserted_report = sqlx::query(
            "INSERT INTO dmarc_aggregate_reports \
                (deployment_id, customer_id, domain_id, policy_domain, reporter_org_name, \
                 report_id, date_range_begin, date_range_end, policy_adkim, policy_aspf, \
                 policy_p, parser_version, duplicate_key, source_artifact_id, \
                 source_artifact_hash) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
             ON CONFLICT (deployment_id, duplicate_key) DO NOTHING \
             RETURNING id",
        )
        .bind(&self.deployment_id.0)
        .bind(&mapping.customer_id.0)
        .bind(mapping.domain_id)
        .bind(&mapping.domain)
        .bind(&report.reporter_org_name)
        .bind(&report.report_id)
        .bind(report.date_range_begin)
        .bind(report.date_range_end)
        .bind(&report.policy_adkim)
        .bind(&report.policy_aspf)
        .bind(&report.policy_p)
        .bind(report.parser_version)
        .bind(&report.duplicate_key)
        .bind(source.artifact_id)
        .bind(&source.artifact_hash)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| DmarcAggregateIngestError::Unavailable)?;

        let Some(report_row) = inserted_report else {
            let existing_id = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM dmarc_aggregate_reports \
                 WHERE deployment_id = $1 AND duplicate_key = $2",
            )
            .bind(&self.deployment_id.0)
            .bind(&report.duplicate_key)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| DmarcAggregateIngestError::Unavailable)?;

            transaction
                .commit()
                .await
                .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
            return Ok(DmarcAggregateIngestOutcome {
                status: DmarcAggregateIngestStatus::Duplicate,
                report_row_id: existing_id,
                records_inserted: 0,
            });
        };

        let report_row_id: Uuid = report_row
            .try_get("id")
            .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
        for record in &report.records {
            sqlx::query(
                "INSERT INTO dmarc_aggregate_records \
                    (deployment_id, customer_id, domain_id, report_id, source_ip, \
                     message_count, header_from_domain, envelope_from_domain, disposition, \
                     dkim_aligned_result, spf_aligned_result, dkim_auth_results, \
                     spf_auth_results) \
                 VALUES ($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind(&self.deployment_id.0)
            .bind(&mapping.customer_id.0)
            .bind(mapping.domain_id)
            .bind(report_row_id)
            .bind(record.source_ip.to_string())
            .bind(record_count_to_i64(record.message_count)?)
            .bind(&record.header_from_domain)
            .bind(&record.envelope_from_domain)
            .bind(&record.disposition)
            .bind(&record.dkim_aligned_result)
            .bind(&record.spf_aligned_result)
            .bind(sqlx::types::Json(record.dkim_auth_results.clone()))
            .bind(sqlx::types::Json(record.spf_auth_results.clone()))
            .execute(&mut *transaction)
            .await
            .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
        }

        transaction
            .commit()
            .await
            .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
        Ok(DmarcAggregateIngestOutcome {
            status: DmarcAggregateIngestStatus::Inserted,
            report_row_id: Some(report_row_id),
            records_inserted: report.records.len(),
        })
    }

    async fn quarantine_report(
        &self,
        source: &DmarcAggregateSource,
        error_code: &str,
        error_detail: String,
        report: Option<&DmarcAggregateReport>,
    ) -> Result<(), DmarcAggregateIngestError> {
        let compressed_size_bytes = source_size_to_i64(source.compressed_size_bytes)?;
        let detail = truncate_error_detail(&error_detail);
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
        set_deployment_scope(&mut transaction, &self.deployment_id).await?;
        sqlx::query(
            "INSERT INTO dmarc_report_quarantine \
                (deployment_id, source_artifact_id, source_artifact_hash, compressed_size_bytes, \
                 error_code, error_detail, reporter_org_name, report_id, policy_domain, \
                 duplicate_key, parser_version) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(&self.deployment_id.0)
        .bind(source.artifact_id)
        .bind(&source.artifact_hash)
        .bind(compressed_size_bytes)
        .bind(error_code)
        .bind(detail)
        .bind(report.map(|report| report.reporter_org_name.as_str()))
        .bind(report.map(|report| report.report_id.as_str()))
        .bind(report.map(|report| report.policy_domain.as_str()))
        .bind(report.map(|report| report.duplicate_key.as_str()))
        .bind(DMARC_AGGREGATE_PARSER_VERSION)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedReportDomain {
    customer_id: CustomerId,
    domain_id: Uuid,
    domain: String,
}

impl DmarcAggregateError {
    fn code(&self) -> &'static str {
        match self {
            Self::CompressedSizeLimit => "compressed_size_limit",
            Self::DecompressedSizeLimit => "decompressed_size_limit",
            Self::UnsupportedCompression => "unsupported_compression",
            Self::MalformedCompression => "malformed_compression",
            Self::ForbiddenXmlConstruct => "forbidden_xml_construct",
            Self::MalformedXml => "malformed_xml",
            Self::XmlDepthLimit => "xml_depth_limit",
            Self::TextSizeLimit => "text_size_limit",
            Self::RecordLimit => "record_limit",
            Self::MissingField(_) => "missing_field",
            Self::InvalidField(_) => "invalid_field",
        }
    }
}

async fn set_report_scope(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &DeploymentId,
    customer_id: &CustomerId,
) -> Result<(), DmarcAggregateIngestError> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
    Ok(())
}

async fn set_deployment_scope(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &DeploymentId,
) -> Result<(), DmarcAggregateIngestError> {
    sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
        .bind(&deployment_id.0)
        .execute(&mut **transaction)
        .await
        .map_err(|_| DmarcAggregateIngestError::Unavailable)?;
    Ok(())
}

fn validate_source(source: &DmarcAggregateSource) -> Result<(), DmarcAggregateIngestError> {
    source_size_to_i64(source.compressed_size_bytes)?;
    if let Some(hash) = &source.artifact_hash {
        if !is_sha256_hex(hash) {
            return Err(DmarcAggregateIngestError::InvalidInput);
        }
    }
    Ok(())
}

fn source_size_to_i64(value: u64) -> Result<i64, DmarcAggregateIngestError> {
    i64::try_from(value).map_err(|_| DmarcAggregateIngestError::InvalidInput)
}

fn record_count_to_i64(value: u64) -> Result<i64, DmarcAggregateIngestError> {
    i64::try_from(value).map_err(|_| DmarcAggregateIngestError::InvalidInput)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn truncate_error_detail(value: &str) -> String {
    value.chars().take(512).collect()
}

pub fn parse_dmarc_aggregate_report(
    input: &[u8],
    compression: DmarcReportCompression,
    limits: &DmarcAggregateLimits,
) -> Result<DmarcAggregateReport, DmarcAggregateError> {
    let xml = decode_report_bytes(input, compression, limits)?;
    reject_forbidden_xml_constructs(&xml)?;
    parse_xml(&xml, limits)
}

pub fn map_policy_domain_exact<'a>(
    policy_domain: &str,
    candidates: &'a [DomainMappingCandidate],
) -> Option<&'a DomainMappingCandidate> {
    let normalized = normalize_domain(policy_domain)?;
    candidates.iter().find(|candidate| {
        normalize_domain(&candidate.domain).as_deref() == Some(normalized.as_str())
    })
}

fn decode_report_bytes(
    input: &[u8],
    compression: DmarcReportCompression,
    limits: &DmarcAggregateLimits,
) -> Result<Vec<u8>, DmarcAggregateError> {
    if input.len() > limits.max_compressed_bytes {
        return Err(DmarcAggregateError::CompressedSizeLimit);
    }
    let resolved = match compression {
        DmarcReportCompression::Auto if input.starts_with(&[0x1f, 0x8b]) => {
            DmarcReportCompression::Gzip
        },
        DmarcReportCompression::Auto if input.starts_with(b"PK\x03\x04") => {
            DmarcReportCompression::Zip
        },
        DmarcReportCompression::Auto => DmarcReportCompression::Xml,
        other => other,
    };
    match resolved {
        DmarcReportCompression::Xml | DmarcReportCompression::Auto => Ok(input.to_vec()),
        DmarcReportCompression::Gzip => gunzip_bounded(input, limits.max_decompressed_bytes),
        DmarcReportCompression::Zip => unzip_single_report_bounded(input, limits),
    }
}

fn gunzip_bounded(input: &[u8], cap: usize) -> Result<Vec<u8>, DmarcAggregateError> {
    let mut decoder = flate2::read::GzDecoder::new(input);
    let mut out = Vec::with_capacity(cap.min(INFLATE_PREALLOC_BYTES));
    let mut chunk = [0_u8; INFLATE_CHUNK_BYTES];
    loop {
        if out.len() >= cap {
            let mut probe = [0_u8; 1];
            return match decoder.read(&mut probe) {
                Ok(0) => Ok(out),
                Ok(_) => Err(DmarcAggregateError::DecompressedSizeLimit),
                Err(_) => Err(DmarcAggregateError::MalformedCompression),
            };
        }
        let want = chunk.len().min(cap - out.len());
        match decoder.read(&mut chunk[..want]) {
            Ok(0) => return Ok(out),
            Ok(read) => out.extend_from_slice(&chunk[..read]),
            Err(_) => return Err(DmarcAggregateError::MalformedCompression),
        }
    }
}

fn unzip_single_report_bounded(
    input: &[u8],
    limits: &DmarcAggregateLimits,
) -> Result<Vec<u8>, DmarcAggregateError> {
    let mut offset = 0usize;
    let mut entries = 0usize;
    let mut report: Option<Vec<u8>> = None;

    while offset < input.len() {
        if input[offset..].starts_with(ZIP_CENTRAL_DIRECTORY_SIGNATURE)
            || input[offset..].starts_with(ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE)
        {
            break;
        }
        if !input[offset..].starts_with(ZIP_LOCAL_FILE_HEADER_SIGNATURE) {
            return Err(DmarcAggregateError::MalformedCompression);
        }
        entries += 1;
        if entries > ZIP_MAX_ENTRIES {
            return Err(DmarcAggregateError::CompressedSizeLimit);
        }
        if input.len().saturating_sub(offset) < 30 {
            return Err(DmarcAggregateError::MalformedCompression);
        }

        let flags = read_le_u16(input, offset + 6)?;
        let method = read_le_u16(input, offset + 8)?;
        let compressed_size = read_le_u32(input, offset + 18)?;
        let uncompressed_size = read_le_u32(input, offset + 22)?;
        let name_len = usize::from(read_le_u16(input, offset + 26)?);
        let extra_len = usize::from(read_le_u16(input, offset + 28)?);
        if flags & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_DATA_DESCRIPTOR) != 0 {
            return Err(DmarcAggregateError::UnsupportedCompression);
        }
        if compressed_size == u32::MAX || uncompressed_size == u32::MAX {
            return Err(DmarcAggregateError::UnsupportedCompression);
        }
        let compressed_size = usize::try_from(compressed_size)
            .map_err(|_| DmarcAggregateError::CompressedSizeLimit)?;
        let uncompressed_size = usize::try_from(uncompressed_size)
            .map_err(|_| DmarcAggregateError::DecompressedSizeLimit)?;
        if compressed_size > limits.max_compressed_bytes {
            return Err(DmarcAggregateError::CompressedSizeLimit);
        }
        if uncompressed_size > limits.max_decompressed_bytes {
            return Err(DmarcAggregateError::DecompressedSizeLimit);
        }

        let name_start = offset + 30;
        let data_start = name_start
            .checked_add(name_len)
            .and_then(|value| value.checked_add(extra_len))
            .ok_or(DmarcAggregateError::MalformedCompression)?;
        let data_end = data_start
            .checked_add(compressed_size)
            .ok_or(DmarcAggregateError::MalformedCompression)?;
        if data_end > input.len() {
            return Err(DmarcAggregateError::MalformedCompression);
        }
        let name = &input[name_start..name_start + name_len];
        let is_directory = name.ends_with(b"/");
        let is_report = is_safe_zip_report_name(name) && name_looks_like_xml_report(name);

        if is_report && !is_directory {
            if report.is_some() {
                return Err(DmarcAggregateError::MalformedCompression);
            }
            let payload = match method {
                ZIP_METHOD_STORED => input[data_start..data_end].to_vec(),
                ZIP_METHOD_DEFLATED => inflate_zip_deflate_bounded(
                    &input[data_start..data_end],
                    limits.max_decompressed_bytes,
                )?,
                _ => return Err(DmarcAggregateError::UnsupportedCompression),
            };
            if payload.len() != uncompressed_size {
                return Err(DmarcAggregateError::MalformedCompression);
            }
            report = Some(payload);
        } else if !is_directory && !matches!(method, ZIP_METHOD_STORED | ZIP_METHOD_DEFLATED) {
            return Err(DmarcAggregateError::UnsupportedCompression);
        }

        offset = data_end;
    }

    report.ok_or(DmarcAggregateError::MalformedCompression)
}

fn inflate_zip_deflate_bounded(input: &[u8], cap: usize) -> Result<Vec<u8>, DmarcAggregateError> {
    let mut decoder = flate2::read::DeflateDecoder::new(input);
    let mut out = Vec::with_capacity(cap.min(INFLATE_PREALLOC_BYTES));
    let mut chunk = [0_u8; INFLATE_CHUNK_BYTES];
    loop {
        if out.len() >= cap {
            let mut probe = [0_u8; 1];
            return match decoder.read(&mut probe) {
                Ok(0) => Ok(out),
                Ok(_) => Err(DmarcAggregateError::DecompressedSizeLimit),
                Err(_) => Err(DmarcAggregateError::MalformedCompression),
            };
        }
        let want = chunk.len().min(cap - out.len());
        match decoder.read(&mut chunk[..want]) {
            Ok(0) => return Ok(out),
            Ok(read) => out.extend_from_slice(&chunk[..read]),
            Err(_) => return Err(DmarcAggregateError::MalformedCompression),
        }
    }
}

fn read_le_u16(input: &[u8], offset: usize) -> Result<u16, DmarcAggregateError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(DmarcAggregateError::MalformedCompression)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_le_u32(input: &[u8], offset: usize) -> Result<u32, DmarcAggregateError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(DmarcAggregateError::MalformedCompression)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn is_safe_zip_report_name(name: &[u8]) -> bool {
    if name.is_empty()
        || name.starts_with(b"/")
        || name.iter().any(|byte| *byte == b'\\' || *byte < 0x20)
    {
        return false;
    }
    name.split(|byte| *byte == b'/')
        .all(|segment| !segment.is_empty() && segment != b"." && segment != b"..")
}

fn name_looks_like_xml_report(name: &[u8]) -> bool {
    std::str::from_utf8(name)
        .map(|value| value.to_ascii_lowercase().ends_with(".xml"))
        .unwrap_or(false)
}

fn reject_forbidden_xml_constructs(xml: &[u8]) -> Result<(), DmarcAggregateError> {
    let lower = xml
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    for forbidden in [b"<!doctype".as_slice(), b"<!entity".as_slice()] {
        if lower
            .windows(forbidden.len())
            .any(|window| window == forbidden)
        {
            return Err(DmarcAggregateError::ForbiddenXmlConstruct);
        }
    }
    Ok(())
}

fn parse_xml(
    xml: &[u8],
    limits: &DmarcAggregateLimits,
) -> Result<DmarcAggregateReport, DmarcAggregateError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();

    let mut report = PartialReport::default();
    let mut records = Vec::new();

    let mut current_record: Option<PartialRecord> = None;
    let mut current_dkim: Option<PartialDkimAuthResult> = None;
    let mut current_spf: Option<PartialSpfAuthResult> = None;

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|_| DmarcAggregateError::MalformedXml)?
        {
            Event::Start(event) => {
                let name = element_name(event.name().as_ref())?;
                path.push(name.clone());
                if path.len() > limits.max_xml_depth {
                    return Err(DmarcAggregateError::XmlDepthLimit);
                }
                if path.as_slice() == ["feedback", "record"] {
                    current_record = Some(PartialRecord {
                        source_ip: None,
                        message_count: None,
                        header_from_domain: None,
                        envelope_from_domain: None,
                        disposition: None,
                        dkim_aligned_result: None,
                        spf_aligned_result: None,
                        dkim_auth_results: Vec::new(),
                        spf_auth_results: Vec::new(),
                    });
                } else if path.ends_with(&[
                    "record".to_string(),
                    "auth_results".to_string(),
                    "dkim".to_string(),
                ]) {
                    current_dkim = Some(PartialDkimAuthResult {
                        domain: None,
                        selector: None,
                        result: None,
                    });
                } else if path.ends_with(&[
                    "record".to_string(),
                    "auth_results".to_string(),
                    "spf".to_string(),
                ]) {
                    current_spf = Some(PartialSpfAuthResult {
                        domain: None,
                        result: None,
                    });
                }
            },
            Event::Text(event) => {
                if event.as_ref().len() > limits.max_text_bytes {
                    return Err(DmarcAggregateError::TextSizeLimit);
                }
                let text = String::from_utf8_lossy(event.as_ref()).trim().to_string();
                if text.is_empty() {
                    buf.clear();
                    continue;
                }
                assign_text(
                    &path,
                    &text,
                    &mut report,
                    current_record.as_mut(),
                    current_dkim.as_mut(),
                    current_spf.as_mut(),
                )?;
            },
            Event::End(event) => {
                let name = element_name(event.name().as_ref())?;
                if path.last().map(String::as_str) != Some(name.as_str()) {
                    return Err(DmarcAggregateError::MalformedXml);
                }
                if path.ends_with(&[
                    "record".to_string(),
                    "auth_results".to_string(),
                    "dkim".to_string(),
                ]) {
                    if let Some(dkim) = current_dkim.take() {
                        if let (Some(domain), Some(result)) = (dkim.domain, dkim.result) {
                            if let Some(record) = current_record.as_mut() {
                                record.dkim_auth_results.push(DkimAuthResult {
                                    domain,
                                    selector: dkim.selector,
                                    result,
                                });
                            }
                        }
                    }
                } else if path.ends_with(&[
                    "record".to_string(),
                    "auth_results".to_string(),
                    "spf".to_string(),
                ]) {
                    if let Some(spf) = current_spf.take() {
                        if let (Some(domain), Some(result)) = (spf.domain, spf.result) {
                            if let Some(record) = current_record.as_mut() {
                                record
                                    .spf_auth_results
                                    .push(SpfAuthResult { domain, result });
                            }
                        }
                    }
                } else if path.as_slice() == ["feedback", "record"] {
                    let record = current_record
                        .take()
                        .ok_or(DmarcAggregateError::MalformedXml)?
                        .finish()?;
                    records.push(record);
                    if records.len() > limits.max_records {
                        return Err(DmarcAggregateError::RecordLimit);
                    }
                }
                path.pop();
            },
            Event::Eof => break,
            Event::DocType(_) | Event::CData(_) => {
                return Err(DmarcAggregateError::ForbiddenXmlConstruct);
            },
            Event::Empty(_) | Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {},
            Event::GeneralRef(_) => return Err(DmarcAggregateError::ForbiddenXmlConstruct),
        }
        buf.clear();
    }

    if !path.is_empty() {
        return Err(DmarcAggregateError::MalformedXml);
    }
    if records.is_empty() {
        return Err(DmarcAggregateError::MissingField("record"));
    }

    let reporter_org_name =
        bounded_required_text(report.reporter_org_name, "report_metadata.org_name")?;
    let report_id = bounded_required_text(report.report_id, "report_metadata.report_id")?;
    let policy_domain = normalize_domain(&bounded_required_text(
        report.policy_domain,
        "policy_published.domain",
    )?)
    .ok_or(DmarcAggregateError::InvalidField("policy_published.domain"))?;
    let policy_p = normalize_enum(
        &bounded_required_text(report.policy_p, "policy_published.p")?,
        &["none", "quarantine", "reject"],
        "policy_published.p",
    )?;
    let policy_adkim = optional_alignment(report.policy_adkim, "policy_published.adkim")?;
    let policy_aspf = optional_alignment(report.policy_aspf, "policy_published.aspf")?;
    let date_range_begin = timestamp_to_utc(report.date_range_begin.ok_or(
        DmarcAggregateError::MissingField("report_metadata.date_range.begin"),
    )?)?;
    let date_range_end = timestamp_to_utc(report.date_range_end.ok_or(
        DmarcAggregateError::MissingField("report_metadata.date_range.end"),
    )?)?;
    if date_range_end < date_range_begin {
        return Err(DmarcAggregateError::InvalidField(
            "report_metadata.date_range",
        ));
    }
    let duplicate_key = duplicate_key(
        &reporter_org_name,
        &report_id,
        &policy_domain,
        date_range_begin,
        date_range_end,
    );

    Ok(DmarcAggregateReport {
        reporter_org_name,
        report_id,
        date_range_begin,
        date_range_end,
        policy_domain,
        policy_adkim,
        policy_aspf,
        policy_p,
        records,
        duplicate_key,
        parser_version: DMARC_AGGREGATE_PARSER_VERSION,
    })
}

fn assign_text(
    path: &[String],
    text: &str,
    report: &mut PartialReport,
    current_record: Option<&mut PartialRecord>,
    current_dkim: Option<&mut PartialDkimAuthResult>,
    current_spf: Option<&mut PartialSpfAuthResult>,
) -> Result<(), DmarcAggregateError> {
    let path_str = path.join("/");
    match path_str.as_str() {
        "feedback/report_metadata/org_name" => report.reporter_org_name = Some(text.to_string()),
        "feedback/report_metadata/report_id" => report.report_id = Some(text.to_string()),
        "feedback/report_metadata/date_range/begin" => {
            report.date_range_begin = Some(parse_i64(text, "report_metadata.date_range.begin")?)
        },
        "feedback/report_metadata/date_range/end" => {
            report.date_range_end = Some(parse_i64(text, "report_metadata.date_range.end")?)
        },
        "feedback/policy_published/domain" => report.policy_domain = Some(text.to_string()),
        "feedback/policy_published/adkim" => report.policy_adkim = Some(text.to_string()),
        "feedback/policy_published/aspf" => report.policy_aspf = Some(text.to_string()),
        "feedback/policy_published/p" => report.policy_p = Some(text.to_string()),
        _ => assign_record_text(path, text, current_record, current_dkim, current_spf)?,
    }
    Ok(())
}

fn assign_record_text(
    path: &[String],
    text: &str,
    current_record: Option<&mut PartialRecord>,
    current_dkim: Option<&mut PartialDkimAuthResult>,
    current_spf: Option<&mut PartialSpfAuthResult>,
) -> Result<(), DmarcAggregateError> {
    let Some(record) = current_record else {
        return Ok(());
    };
    let path_str = path.join("/");
    match path_str.as_str() {
        "feedback/record/row/source_ip" => {
            record.source_ip = Some(
                text.parse::<IpAddr>()
                    .map_err(|_| DmarcAggregateError::InvalidField("record.row.source_ip"))?,
            );
        },
        "feedback/record/row/count" => {
            record.message_count = Some(parse_u64(text, "record.row.count")?);
        },
        "feedback/record/row/policy_evaluated/disposition" => {
            record.disposition = Some(normalize_enum(
                text,
                &["none", "quarantine", "reject"],
                "record.row.policy_evaluated.disposition",
            )?);
        },
        "feedback/record/row/policy_evaluated/dkim" => {
            record.dkim_aligned_result = Some(normalize_enum(
                text,
                &["pass", "fail"],
                "record.row.policy_evaluated.dkim",
            )?);
        },
        "feedback/record/row/policy_evaluated/spf" => {
            record.spf_aligned_result = Some(normalize_enum(
                text,
                &["pass", "fail"],
                "record.row.policy_evaluated.spf",
            )?);
        },
        "feedback/record/identifiers/header_from" => {
            record.header_from_domain = normalize_domain(text);
        },
        "feedback/record/identifiers/envelope_from" => {
            record.envelope_from_domain = normalize_domain(text);
        },
        "feedback/record/auth_results/dkim/domain" => {
            if let Some(dkim) = current_dkim {
                dkim.domain = normalize_domain(text);
            }
        },
        "feedback/record/auth_results/dkim/selector" => {
            if let Some(dkim) = current_dkim {
                dkim.selector = Some(text.to_ascii_lowercase());
            }
        },
        "feedback/record/auth_results/dkim/result" => {
            if let Some(dkim) = current_dkim {
                dkim.result = Some(normalize_auth_result(text));
            }
        },
        "feedback/record/auth_results/spf/domain" => {
            if let Some(spf) = current_spf {
                spf.domain = normalize_domain(text);
            }
        },
        "feedback/record/auth_results/spf/result" => {
            if let Some(spf) = current_spf {
                spf.result = Some(normalize_auth_result(text));
            }
        },
        _ => {},
    }
    Ok(())
}

fn element_name(name: &[u8]) -> Result<String, DmarcAggregateError> {
    std::str::from_utf8(name)
        .map(|value| value.to_ascii_lowercase())
        .map_err(|_| DmarcAggregateError::MalformedXml)
}

fn parse_i64(value: &str, field: &'static str) -> Result<i64, DmarcAggregateError> {
    value
        .parse::<i64>()
        .map_err(|_| DmarcAggregateError::InvalidField(field))
}

fn parse_u64(value: &str, field: &'static str) -> Result<u64, DmarcAggregateError> {
    value
        .parse::<u64>()
        .map_err(|_| DmarcAggregateError::InvalidField(field))
}

fn timestamp_to_utc(value: i64) -> Result<DateTime<Utc>, DmarcAggregateError> {
    Utc.timestamp_opt(value, 0)
        .single()
        .ok_or(DmarcAggregateError::InvalidField(
            "report_metadata.date_range",
        ))
}

fn bounded_required_text(
    value: Option<String>,
    field: &'static str,
) -> Result<String, DmarcAggregateError> {
    let value = value.ok_or(DmarcAggregateError::MissingField(field))?;
    if value.trim().is_empty() {
        return Err(DmarcAggregateError::InvalidField(field));
    }
    Ok(value)
}

fn normalize_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || domain.contains(|c: char| c.is_control() || c.is_whitespace())
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return None;
    }
    let labels_valid = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    labels_valid.then_some(domain)
}

fn normalize_enum(
    value: &str,
    allowed: &[&str],
    field: &'static str,
) -> Result<String, DmarcAggregateError> {
    let normalized = value.trim().to_ascii_lowercase();
    if allowed.iter().any(|allowed| *allowed == normalized) {
        Ok(normalized)
    } else {
        Err(DmarcAggregateError::InvalidField(field))
    }
}

fn optional_alignment(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, DmarcAggregateError> {
    value
        .map(|value| normalize_enum(&value, &["r", "s"], field))
        .transpose()
}

fn normalize_auth_result(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn duplicate_key(
    reporter_org_name: &str,
    report_id: &str,
    policy_domain: &str,
    begin: DateTime<Utc>,
    end: DateTime<Utc>,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        reporter_org_name.to_ascii_lowercase(),
        report_id.to_string(),
        policy_domain.to_ascii_lowercase(),
        begin.timestamp().to_string(),
        end.timestamp().to_string(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    use super::*;

    fn minimal_report() -> &'static [u8] {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>Reporter.example</org_name>
    <report_id>abc-123</report_id>
    <date_range>
      <begin>1761955200</begin>
      <end>1762041600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>Example.COM</domain>
    <adkim>r</adkim>
    <aspf>s</aspf>
    <p>quarantine</p>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.7</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>bounce.example.com</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <selector>s1</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>bounce.example.com</domain>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
</feedback>"#
    }

    #[test]
    fn parses_valid_minimal_aggregate_report() {
        let report = parse_dmarc_aggregate_report(
            minimal_report(),
            DmarcReportCompression::Xml,
            &DmarcAggregateLimits::default(),
        )
        .expect("valid report");
        assert_eq!(report.reporter_org_name, "Reporter.example");
        assert_eq!(report.report_id, "abc-123");
        assert_eq!(report.policy_domain, "example.com");
        assert_eq!(report.policy_adkim.as_deref(), Some("r"));
        assert_eq!(report.policy_aspf.as_deref(), Some("s"));
        assert_eq!(report.policy_p, "quarantine");
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].message_count, 3);
        assert_eq!(report.records[0].header_from_domain, "example.com");
        assert_eq!(
            report.records[0].envelope_from_domain.as_deref(),
            Some("bounce.example.com")
        );
        assert_eq!(report.records[0].dkim_auth_results.len(), 1);
        assert_eq!(report.records[0].spf_auth_results.len(), 1);
        assert_eq!(report.parser_version, DMARC_AGGREGATE_PARSER_VERSION);
    }

    #[test]
    fn parses_gzip_report_under_the_same_limits() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder, minimal_report()).expect("write gzip");
        let compressed = encoder.finish().expect("finish gzip");

        let report = parse_dmarc_aggregate_report(
            &compressed,
            DmarcReportCompression::Auto,
            &DmarcAggregateLimits::default(),
        )
        .expect("gzip report");
        assert_eq!(report.policy_domain, "example.com");
    }

    #[test]
    fn rejects_doctype_and_entity_xml() {
        let xml = br#"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><feedback/>"#;
        let error = parse_dmarc_aggregate_report(
            xml,
            DmarcReportCompression::Xml,
            &DmarcAggregateLimits::default(),
        )
        .expect_err("doctype rejected");
        assert_eq!(error, DmarcAggregateError::ForbiddenXmlConstruct);
    }

    #[test]
    fn rejects_oversize_decompression() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder, minimal_report()).expect("write gzip");
        let compressed = encoder.finish().expect("finish gzip");
        let limits = DmarcAggregateLimits {
            max_decompressed_bytes: 32,
            ..DmarcAggregateLimits::default()
        };
        let error =
            parse_dmarc_aggregate_report(&compressed, DmarcReportCompression::Gzip, &limits)
                .expect_err("overflow rejected");
        assert_eq!(error, DmarcAggregateError::DecompressedSizeLimit);
    }

    #[test]
    fn rejects_too_many_records() {
        let limits = DmarcAggregateLimits {
            max_records: 0,
            ..DmarcAggregateLimits::default()
        };
        let error =
            parse_dmarc_aggregate_report(minimal_report(), DmarcReportCompression::Xml, &limits)
                .expect_err("record limit rejected");
        assert_eq!(error, DmarcAggregateError::RecordLimit);
    }

    #[test]
    fn duplicate_key_is_stable_for_same_report_identity() {
        let first = parse_dmarc_aggregate_report(
            minimal_report(),
            DmarcReportCompression::Xml,
            &DmarcAggregateLimits::default(),
        )
        .expect("first");
        let second = parse_dmarc_aggregate_report(
            minimal_report(),
            DmarcReportCompression::Xml,
            &DmarcAggregateLimits::default(),
        )
        .expect("second");
        assert_eq!(first.duplicate_key, second.duplicate_key);
        assert_eq!(first.duplicate_key.len(), 64);
    }

    #[test]
    fn exact_domain_mapping_does_not_match_suffix_tricks() {
        let expected = DomainMappingCandidate {
            customer_id: "CZA-1".to_string(),
            domain_id: Uuid::new_v4(),
            domain: "example.com".to_string(),
        };
        let attacker = DomainMappingCandidate {
            customer_id: "CZA-2".to_string(),
            domain_id: Uuid::new_v4(),
            domain: "badexample.com".to_string(),
        };
        let candidates = vec![attacker, expected.clone()];
        assert_eq!(
            map_policy_domain_exact("EXAMPLE.com.", &candidates),
            Some(&expected)
        );
        assert_eq!(
            map_policy_domain_exact("sub.example.com", &candidates),
            None
        );
        assert_eq!(
            map_policy_domain_exact("badexample.com", &candidates)
                .unwrap()
                .customer_id,
            "CZA-2"
        );
    }

    fn zip_entry(name: &str, method: u16, payload: &[u8]) -> Vec<u8> {
        let compressed = match method {
            ZIP_METHOD_STORED => payload.to_vec(),
            ZIP_METHOD_DEFLATED => {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
                std::io::Write::write_all(&mut encoder, payload).expect("write deflate");
                encoder.finish().expect("finish deflate")
            },
            _ => payload.to_vec(),
        };
        let mut out = Vec::new();
        out.extend_from_slice(ZIP_LOCAL_FILE_HEADER_SIGNATURE);
        out.extend_from_slice(&20_u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0_u16.to_le_bytes()); // flags
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0_u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0_u32.to_le_bytes()); // crc intentionally ignored
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes()); // extra length
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&compressed);
        out
    }

    #[test]
    fn parses_zip_report_under_the_same_limits() {
        let archive = zip_entry("reports/report.xml", ZIP_METHOD_DEFLATED, minimal_report());
        let report = parse_dmarc_aggregate_report(
            &archive,
            DmarcReportCompression::Auto,
            &DmarcAggregateLimits::default(),
        )
        .expect("zip report");
        assert_eq!(report.policy_domain, "example.com");
    }

    #[test]
    fn zip_report_rejects_unsafe_or_ambiguous_archives() {
        let mut archive = zip_entry("one.xml", ZIP_METHOD_STORED, minimal_report());
        archive.extend(zip_entry("two.xml", ZIP_METHOD_STORED, minimal_report()));
        let error = parse_dmarc_aggregate_report(
            &archive,
            DmarcReportCompression::Zip,
            &DmarcAggregateLimits::default(),
        )
        .expect_err("ambiguous archive rejected");
        assert_eq!(error, DmarcAggregateError::MalformedCompression);

        let error = parse_dmarc_aggregate_report(
            &zip_entry("../report.xml", ZIP_METHOD_STORED, minimal_report()),
            DmarcReportCompression::Zip,
            &DmarcAggregateLimits::default(),
        )
        .expect_err("unsafe name rejected");
        assert_eq!(error, DmarcAggregateError::MalformedCompression);
    }

    #[test]
    fn zip_report_rejects_expansion_past_limit() {
        let archive = zip_entry("report.xml", ZIP_METHOD_DEFLATED, minimal_report());
        let limits = DmarcAggregateLimits {
            max_decompressed_bytes: 32,
            ..DmarcAggregateLimits::default()
        };
        let error = parse_dmarc_aggregate_report(&archive, DmarcReportCompression::Zip, &limits)
            .expect_err("zip expansion rejected");
        assert_eq!(error, DmarcAggregateError::DecompressedSizeLimit);
    }

    #[test]
    fn malformed_zip_is_quarantinable_parser_error() {
        let error = parse_dmarc_aggregate_report(
            b"PK\x03\x04fake",
            DmarcReportCompression::Auto,
            &DmarcAggregateLimits::default(),
        )
        .expect_err("malformed zip rejected");
        assert_eq!(error, DmarcAggregateError::MalformedCompression);
    }
}
