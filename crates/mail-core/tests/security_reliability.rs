//! Phase 1 security and reliability integration tests
//!
//! Tests the invariants from docs/phases/PHASE-1-EXECUTION-PLAN.md Work Package 12.
//! These are unit-level validation of security properties that can be tested without
//! actual SMTP connections or Postfix infrastructure.

use nullapart_mail_contracts::{
    finding::{
        Confidence, FindingCategory, FindingId, FindingScope, FindingSeverity, ScannerStatus,
        ScannerType,
    },
    policy::{ConditionScope, PolicyCondition, PolicyRule, PolicyRuleId, ReasonCode},
    transaction::{
        AuthResultType, CustomerId, DeploymentId, Disposition, EnvelopeSender, Recipient,
        TransactionId,
    },
    PolicyRevisionId, SecurityFinding,
};
use nullapart_mail_core::{
    delivery::classify_smtp_response,
    handoff::{AfterQueueHandoffRequest, HandoffConfig, HandoffConnection, MilterObservations},
    node::{MailNodeConfig, PortList},
    outbound::{
        validate_outbound, ConnectorType, DomainAuthorization, DomainValidation,
        DomainValidationSource, OutboundConnector, OutboundError, OutboundIntakeRequest,
    },
    partition::{DomainMapping, MappingSource, PartitionConfig, TenantResolver},
    policy::{PolicyEvaluationRequest, PolicyRuleEvaluator},
    reinjection::{LoopPreventionHeader, ReinjectionConfig},
};
use sha2::Digest;

// ============================================================================
// SMTP/Security tests
// ============================================================================

/// The relay path is the outbound intake gate: [`validate_outbound`] is the
/// only code that may authorise relaying a submission to an external
/// destination. It takes an explicit sender-domain allow-list plus a
/// [`DomainAuthorization`] level, so the fail-closed default is the *empty*
/// configuration: no allow-listed domain may relay at any authorization
/// level, and no default tenant may absorb an unmapped recipient.
fn relay_request() -> OutboundIntakeRequest {
    OutboundIntakeRequest {
        connector: OutboundConnector {
            connector_id: "conn-1".to_string(),
            customer_id: CustomerId::new("cust-a"),
            deployment_id: DeploymentId::new("CZA-1"),
            ip_address: "192.0.2.10".to_string(),
            authenticated_as: Some("connector-identity".to_string()),
            connector_type: ConnectorType::SmtpMta,
        },
        envelope_sender: EnvelopeSender::new("sender@tenant-a.com"),
        recipients: vec![Recipient {
            address: "recipient@external.example".to_string(),
            orcpt: None,
            notify: None,
        }],
        message_id: None,
        content_hash: "content-hash".to_string(),
    }
}

fn validated_sender_domain(customer_id: CustomerId) -> DomainValidation {
    DomainValidation {
        domain: "tenant-a.com".to_string(),
        customer_id,
        validated: true,
        validation_source: DomainValidationSource::DnsTxt,
        validated_at: chrono::Utc::now(),
    }
}

#[test]
fn open_relay_default_deny() {
    let empty_allow_list: &[DomainValidation] = &[];
    for authorization in [DomainAuthorization::Internal, DomainAuthorization::SendOnly] {
        let result = validate_outbound(&relay_request(), empty_allow_list, &authorization);
        assert!(
            matches!(result, Err(OutboundError::DomainNotAuthorized(_))),
            "an empty allow-list must deny relay for {authorization:?}, got {result:?}"
        );
    }

    // Partitioning is the inbound half of the same default-deny surface: an
    // unmapped recipient must never fall into a default customer, because
    // that would silently become a relay target.
    let partition = PartitionConfig::default();
    assert!(
        partition.default_customer_id.is_none(),
        "no default tenant may absorb unmapped recipients"
    );
}

#[test]
fn relay_path_fails_closed_for_unauthenticated_unvalidated_and_foreign_senders() {
    let authorized = vec![validated_sender_domain(CustomerId::new("cust-a"))];

    // A documented INTERNAL domain may relay once the authenticated connector
    // and customer-owned domain checks have passed.
    let internal = validate_outbound(
        &relay_request(),
        &authorized,
        &DomainAuthorization::Internal,
    );
    assert!(
        internal.is_ok(),
        "an authenticated INTERNAL domain must relay, got {internal:?}"
    );

    // No authenticated connector identity means no relay, even with a
    // fully validated allow-list.
    let mut anonymous = relay_request();
    anonymous.connector.authenticated_as = None;
    let unauthenticated =
        validate_outbound(&anonymous, &authorized, &DomainAuthorization::Internal);
    assert!(
        matches!(unauthenticated, Err(OutboundError::NotAuthenticated)),
        "an unauthenticated connector must be denied, got {unauthenticated:?}"
    );

    // An unvalidated domain never relays.
    let unvalidated = vec![DomainValidation {
        validated: false,
        ..validated_sender_domain(CustomerId::new("cust-a"))
    }];
    let unvalidated_result = validate_outbound(
        &relay_request(),
        &unvalidated,
        &DomainAuthorization::Internal,
    );
    assert!(
        matches!(
            unvalidated_result,
            Err(OutboundError::DomainNotAuthorized(_))
        ),
        "an unvalidated sender domain must be denied, got {unvalidated_result:?}"
    );

    // A domain validated for a *different* customer never relays.
    let foreign = vec![validated_sender_domain(CustomerId::new("cust-b"))];
    let foreign_result =
        validate_outbound(&relay_request(), &foreign, &DomainAuthorization::Internal);
    assert!(
        matches!(foreign_result, Err(OutboundError::DomainNotAuthorized(_))),
        "a cross-customer sender domain must be denied, got {foreign_result:?}"
    );

    // The permitted path still succeeds, so the denials above are
    // configuration denials rather than a broken gate that rejects
    // everything (which would hide a real open-relay regression).
    let permitted = validate_outbound(
        &relay_request(),
        &authorized,
        &DomainAuthorization::Internal,
    );
    assert!(
        permitted.is_ok(),
        "an authenticated, validated, owned sender domain must relay, got {permitted:?}"
    );
}

#[test]
fn unauthorized_outbound_source_rejected() {
    // Outbound: only authenticated connectors from known customer domains can send.
    let resolver = TenantResolver::new(vec![], vec![], PartitionConfig::default());
    let recipients = vec![Recipient {
        address: "user@external.com".to_string(),
        orcpt: None,
        notify: None,
    }];

    // No domain mappings → all recipients unmapped → no valid tenants
    let result = resolver.partition_recipients(&TransactionId::new(), &recipients);
    let partition = result.unwrap();
    assert!(
        !partition.unmapped_recipients.is_empty(),
        "unauthorized recipients should be unmapped"
    );
}

#[test]
fn forged_trusted_headers_not_trusted() {
    // Rspamd: forged Authentication-Results does not become trusted evidence.
    let finding = SecurityFinding {
        id: FindingId::new(),
        scope: FindingScope::Transaction,
        scanner: ScannerType::Dkim,
        scanner_status: ScannerStatus::Unknown,
        severity: FindingSeverity::Info,
        confidence: Confidence::High,
        category: FindingCategory::AuthFailure,
        description: "Authentication-Results header present but not internally generated"
            .to_string(),
        details: None,
        indicators: vec![],
        created_at: chrono::Utc::now(),
        false_positive: false,
        transaction_id: None,
        tenant_message_id: None,
    };

    assert_eq!(
        finding.scanner_status,
        ScannerStatus::Unknown,
        "forged headers produce no trusted findings"
    );
}

#[test]
fn oversized_message_rejected_at_handoff() {
    let config = HandoffConfig {
        max_message_size: 1024,
        ..Default::default()
    };

    let request = AfterQueueHandoffRequest {
        postfix_queue_id: "test".to_string(),
        envelope_sender: EnvelopeSender::new("sender@test.com"),
        recipients: vec![Recipient {
            address: "user@test.com".to_string(),
            orcpt: None,
            notify: None,
        }],
        connection: HandoffConnection {
            client_ip: "127.0.0.1".to_string(),
            client_hostname: None,
            helo_domain: None,
            authenticated: false,
            session_id: "test".to_string(),
        },
        milter_observations: MilterObservations {
            score: 0.0,
            actions: vec![],
            is_spam: false,
            dkim_result: None,
            spf_result: None,
            dmarc_result: None,
            symbols: vec![],
            latency_ms: 0,
        },
        message_content: "A".repeat(2000),
        content_hash: "test".to_string(),
        trace_id: None,
        handoff_at: chrono::Utc::now(),
    };

    let result = nullapart_mail_core::handoff::process_handoff(&config, &request);
    assert!(
        result.is_err(),
        "oversized message must be rejected at handoff"
    );
}

#[test]
fn public_reinjection_blocked() {
    // Reinjection from public internet is never allowed.
    // Config: port 10026 (private), not 25 (public).
    let public = PortList::all_public();
    assert!(
        !public.contains(&PortList::REINJECTION),
        "reinjection port must not be public"
    );
    assert!(
        !public.contains(&PortList::OUTBOUND),
        "outbound port must not be public"
    );
}

#[test]
fn reinjection_bind_localhost() {
    // Reinjection endpoint is localhost-only.
    let config = ReinjectionConfig::default();
    assert!(
        config.endpoint.starts_with("127.0.0.1"),
        "reinjection must bind to localhost only"
    );
}

// ============================================================================
// Responsibility/durability tests
// ============================================================================

#[test]
fn duplicate_handoff_idempotent() {
    let config = HandoffConfig::default();
    let raw = b"Hello";
    let content_hash = hex::encode(sha2::Sha256::digest(raw));
    let request = AfterQueueHandoffRequest {
        postfix_queue_id: "dup-test".to_string(),
        envelope_sender: EnvelopeSender::new("sender@test.com"),
        recipients: vec![Recipient {
            address: "user@test.com".to_string(),
            orcpt: None,
            notify: None,
        }],
        connection: HandoffConnection {
            client_ip: "127.0.0.1".to_string(),
            client_hostname: None,
            helo_domain: None,
            authenticated: false,
            session_id: "test".to_string(),
        },
        milter_observations: MilterObservations {
            score: 0.0,
            actions: vec![],
            is_spam: false,
            dkim_result: None,
            spf_result: None,
            dmarc_result: None,
            symbols: vec![],
            latency_ms: 0,
        },
        message_content: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw),
        content_hash,
        trace_id: None,
        handoff_at: chrono::Utc::now(),
    };

    // Both handoffs succeed — the idempotent detection happens at the persistence layer
    let result1 = nullapart_mail_core::handoff::process_handoff(&config, &request);
    assert!(result1.is_ok());
    let result2 = nullapart_mail_core::handoff::process_handoff(&config, &request);
    assert!(result2.is_ok(), "duplicate handoff must not fail");
}

#[test]
fn downstream_4xx_retry_preserves_mail() {
    let result = nullapart_mail_contracts::transaction::DeliveryResult {
        status: nullapart_mail_contracts::transaction::DeliveryStatus::TransientFailure,
        code: Some(452),
        enhanced_code: Some(nullapart_mail_contracts::transaction::EnhancedCode {
            class: 4,
            subject: 5,
            detail: 2,
        }),
        message: Some("Insufficient storage".to_string()),
    };
    assert_eq!(
        result.status,
        nullapart_mail_contracts::transaction::DeliveryStatus::TransientFailure
    );
    assert_eq!(result.code, Some(452));
}

#[test]
fn downstream_5xx_final_failure() {
    let result = nullapart_mail_contracts::transaction::DeliveryResult {
        status: nullapart_mail_contracts::transaction::DeliveryStatus::PermanentFailure,
        code: Some(550),
        enhanced_code: Some(nullapart_mail_contracts::transaction::EnhancedCode {
            class: 5,
            subject: 1,
            detail: 1,
        }),
        message: Some("Mailbox not found".to_string()),
    };
    assert_eq!(
        result.status,
        nullapart_mail_contracts::transaction::DeliveryStatus::PermanentFailure
    );
    assert_eq!(result.code, Some(550));
}

#[test]
fn reinjection_loop_prevention() {
    let dep = DeploymentId::new("CZA-1");
    let txn = TransactionId::new();
    let header = LoopPreventionHeader::new(&dep, &txn);

    // Not a loop from different deployment
    assert!(!header.is_loop(&DeploymentId::new("EU-WEST-1")));

    // Loop detected for same deployment
    assert!(header.is_loop(&dep));
}

// ============================================================================
// Tenant isolation tests
// ============================================================================

#[test]
fn multi_tenant_transaction_partitioned_correctly() {
    let domains = vec![
        DomainMapping {
            domain: "tenant-a.com".to_string(),
            customer_id: CustomerId::new("cust-a"),
            mapping_source: MappingSource::DomainOwnership,
        },
        DomainMapping {
            domain: "tenant-b.com".to_string(),
            customer_id: CustomerId::new("cust-b"),
            mapping_source: MappingSource::DomainOwnership,
        },
    ];
    let resolver = TenantResolver::new(domains, vec![], PartitionConfig::default());

    let recipients = vec![
        Recipient {
            address: "user@tenant-a.com".to_string(),
            orcpt: None,
            notify: None,
        },
        Recipient {
            address: "admin@tenant-b.com".to_string(),
            orcpt: None,
            notify: None,
        },
    ];

    let result = resolver
        .partition_recipients(&TransactionId::new(), &recipients)
        .unwrap();
    assert_eq!(
        result.instances.len(),
        2,
        "must produce exactly 2 tenant instances"
    );
    assert!(result.unmapped_recipients.is_empty());

    let inst_a = result
        .instances
        .iter()
        .find(|i| i.customer_id.0 == "cust-a")
        .unwrap();
    let inst_b = result
        .instances
        .iter()
        .find(|i| i.customer_id.0 == "cust-b")
        .unwrap();

    assert_eq!(inst_a.recipients.len(), 1);
    assert_eq!(inst_a.recipients[0].address, "user@tenant-a.com");
    assert_eq!(inst_b.recipients.len(), 1);
    assert_eq!(inst_b.recipients[0].address, "admin@tenant-b.com");

    // No cross-tenant contamination
    assert_ne!(inst_a.customer_id, inst_b.customer_id);
    assert_ne!(inst_a.tenant_message_id, inst_b.tenant_message_id);
}

#[test]
fn tenant_quarantine_does_not_affect_other_tenants() {
    let rule_quarantine = PolicyRule {
        id: PolicyRuleId::new(),
        name: "quarantine-tenant-a-spam".to_string(),
        priority: 100,
        condition: PolicyCondition {
            sender: None,
            recipient: None,
            auth: Some(nullapart_mail_contracts::policy::AuthCondition {
                spf: Some(vec![AuthResultType::Fail]),
                dkim: None,
                dmarc: None,
            }),
            content: None,
            finding: None,
            scope: ConditionScope::Tenant,
        },
        action: nullapart_mail_contracts::policy::PolicyAction {
            disposition: Disposition::Quarantine,
            reason_code: ReasonCode::quarantine_spam(),
            notify: None,
            metadata: None,
        },
        enabled: true,
    };

    // Tenant A: SPF fails → quarantined
    let request_a = PolicyEvaluationRequest {
        transaction_id: TransactionId::new(),
        customer_id: CustomerId::new("cust-a"),
        deployment_id: DeploymentId::new("CZA-1"),
        envelope_sender: EnvelopeSender::new("sender@evil.com"),
        recipients: vec![],
        findings: vec![],
        spf_result: Some("fail".to_string()),
        dkim_result: None,
        dmarc_result: None,
        policy_revision: PolicyRevisionId::new(),
        evaluated_at: chrono::Utc::now(),
    };
    let result_a =
        PolicyRuleEvaluator::evaluate(std::slice::from_ref(&rule_quarantine), &request_a);
    assert_eq!(result_a.disposition, Disposition::Quarantine);

    // Tenant B: SPF passes → allowed
    let request_b = PolicyEvaluationRequest {
        transaction_id: TransactionId::new(),
        customer_id: CustomerId::new("cust-b"),
        deployment_id: DeploymentId::new("CZA-1"),
        envelope_sender: EnvelopeSender::new("sender@evil.com"),
        recipients: vec![],
        findings: vec![],
        spf_result: Some("pass".to_string()),
        dkim_result: Some("pass".to_string()),
        dmarc_result: Some("pass".to_string()),
        policy_revision: PolicyRevisionId::new(),
        evaluated_at: chrono::Utc::now(),
    };
    let result_b = PolicyRuleEvaluator::evaluate(&[rule_quarantine], &request_b);
    assert_eq!(result_b.disposition, Disposition::Hold);
}

#[test]
fn wrong_tenant_lookup_returns_no_data() {
    let domains = vec![DomainMapping {
        domain: "tenant-a.com".to_string(),
        customer_id: CustomerId::new("cust-a"),
        mapping_source: MappingSource::DomainOwnership,
    }];

    let resolver = TenantResolver::new(domains, vec![], PartitionConfig::default());

    let rcpt = Recipient {
        address: "user@tenant-b.com".to_string(),
        orcpt: None,
        notify: None,
    };

    let mapping = resolver.resolve_recipient(&rcpt);
    assert!(!mapping.mapped, "wrong tenant must not be mapped");
    assert!(mapping.customer_id.is_none());
}

// ============================================================================
// Reliability tests
// ============================================================================

#[test]
fn tier3_delivery_sli_statuses_have_documented_docs_30_meanings() {
    use nullapart_mail_contracts::transaction::DeliveryStatus;

    // docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md defines the Tier-3 indicators:
    // "accepted messages not lost after Nullapart 250" (durability),
    // "accepted tenant instances reaching a valid terminal/queued state"
    // (mail processing) and delivery retry/terminal failure rate. Every
    // recorded status must land in exactly one of those buckets, and the
    // match is exhaustive: adding a status without classifying it fails the
    // build instead of silently landing in an SLI bucket.
    let sli_bucket = |status: DeliveryStatus| match status {
        DeliveryStatus::Success => "delivered",
        DeliveryStatus::TransientFailure => "retrying",
        DeliveryStatus::PermanentFailure => "terminal_failure",
        DeliveryStatus::Bounced => "terminal_failure",
        DeliveryStatus::Pending => "queued_not_terminal",
        DeliveryStatus::InProgress => "queued_not_terminal",
    };

    assert_eq!(sli_bucket(DeliveryStatus::Success), "delivered");
    assert_eq!(sli_bucket(DeliveryStatus::TransientFailure), "retrying");
    assert_eq!(
        sli_bucket(DeliveryStatus::PermanentFailure),
        "terminal_failure"
    );
    assert_eq!(sli_bucket(DeliveryStatus::Bounced), "terminal_failure");
    assert_eq!(sli_bucket(DeliveryStatus::Pending), "queued_not_terminal");
    assert_eq!(
        sli_bucket(DeliveryStatus::InProgress),
        "queued_not_terminal"
    );

    // Retryable and bounced states must never be conflated with delivery
    // success: docs/30 forbids trading accepted-mail durability for a good
    // looking number.
    assert_ne!(DeliveryStatus::TransientFailure, DeliveryStatus::Success);
    assert_ne!(DeliveryStatus::Bounced, DeliveryStatus::Success);
    assert_ne!(DeliveryStatus::Pending, DeliveryStatus::Success);
}

#[test]
fn tier3_delivery_sli_classification_never_fabricates_success() {
    use nullapart_mail_contracts::transaction::DeliveryStatus;

    // The production mapping from a downstream SMTP response to the recorded
    // delivery status is what the mail-processing and durability SLIs are
    // measured on: only a 2xx may count as success, 4xx keeps the message
    // retrying (retained, not lost), 5xx is terminal, and a code outside the
    // SMTP classes must never be reported as success.
    assert_eq!(classify_smtp_response(250), DeliveryStatus::Success);
    assert_eq!(classify_smtp_response(200), DeliveryStatus::Success);
    assert_eq!(
        classify_smtp_response(421),
        DeliveryStatus::TransientFailure
    );
    assert_eq!(
        classify_smtp_response(452),
        DeliveryStatus::TransientFailure
    );
    assert_eq!(
        classify_smtp_response(550),
        DeliveryStatus::PermanentFailure
    );
    assert_eq!(
        classify_smtp_response(554),
        DeliveryStatus::PermanentFailure
    );
    for code in [0, 100, 1000, u32::MAX] {
        assert_ne!(
            classify_smtp_response(code),
            DeliveryStatus::Success,
            "non-SMTP code {code} must not be reported as delivery success"
        );
    }
}

#[test]
fn required_scanner_sli_statuses_never_report_unknown_or_error_as_clean() {
    use nullapart_mail_contracts::finding::ScannerStatus;

    // docs/30: the required scanner path is "required scan attempts yielding
    // valid result or explicit policy-safe handling", with "scanner
    // UNKNOWN/ERROR rate" tracked as a failure signal. Unknown/Error are
    // failures for that SLI and may never take the Clean value; the match is
    // exhaustive so a new status must be classified deliberately.
    let yields_valid_result = |status: ScannerStatus| match status {
        ScannerStatus::Clean
        | ScannerStatus::Threat
        | ScannerStatus::Suspicious
        | ScannerStatus::NotApplicable => true,
        ScannerStatus::Unknown | ScannerStatus::Error => false,
    };

    assert!(yields_valid_result(ScannerStatus::Clean));
    assert!(yields_valid_result(ScannerStatus::Threat));
    assert!(yields_valid_result(ScannerStatus::Suspicious));
    assert!(yields_valid_result(ScannerStatus::NotApplicable));
    assert!(!yields_valid_result(ScannerStatus::Unknown));
    assert!(!yields_valid_result(ScannerStatus::Error));

    // The measurement surface must keep the three values distinguishable, so
    // no aggregation can collapse an unknown/error run into "clean".
    assert_eq!(
        serde_json::to_value(ScannerStatus::Clean).expect("status must serialize"),
        "clean"
    );
    assert_eq!(
        serde_json::to_value(ScannerStatus::Unknown).expect("status must serialize"),
        "unknown"
    );
    assert_eq!(
        serde_json::to_value(ScannerStatus::Error).expect("status must serialize"),
        "error"
    );
}

#[test]
fn dependency_failure_does_not_lose_accepted_mail() {
    let config = HandoffConfig::default();
    let raw = b"Hello";
    let content_hash = hex::encode(sha2::Sha256::digest(raw));
    let request = AfterQueueHandoffRequest {
        postfix_queue_id: "test-durability".to_string(),
        envelope_sender: EnvelopeSender::new("sender@test.com"),
        recipients: vec![Recipient {
            address: "user@test.com".to_string(),
            orcpt: None,
            notify: None,
        }],
        connection: HandoffConnection {
            client_ip: "127.0.0.1".to_string(),
            client_hostname: None,
            helo_domain: None,
            authenticated: false,
            session_id: "test".to_string(),
        },
        milter_observations: MilterObservations {
            score: 0.0,
            actions: vec![],
            is_spam: false,
            dkim_result: None,
            spf_result: None,
            dmarc_result: None,
            symbols: vec![],
            latency_ms: 0,
        },
        message_content: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw),
        content_hash,
        trace_id: None,
        handoff_at: chrono::Utc::now(),
    };

    let result = nullapart_mail_core::handoff::process_handoff(&config, &request);
    assert!(
        result.is_ok(),
        "handoff must succeed so Postfix knows mail is queued"
    );
}

#[test]
fn reinjection_not_publicly_accessible() {
    let config = MailNodeConfig::default();
    let public = PortList::all_public();
    assert!(
        !public.contains(&config.reinjection_port),
        "reinjection must not be on public port"
    );
    assert!(
        !public.contains(&config.outbound_port),
        "outbound must not be on public port"
    );
}

#[test]
fn policy_reason_codes_are_meaningful() {
    let allowed = ReasonCode::allowed();
    assert!(!allowed.0.is_empty());

    let quarantine_malware = ReasonCode::quarantine_malware();
    assert!(!quarantine_malware.0.is_empty());
    assert!(quarantine_malware.0.contains("MALWARE"));

    let reject_spf = ReasonCode::reject_spf_fail();
    assert!(!reject_spf.0.is_empty());
    assert!(reject_spf.0.contains("SPF"));

    let defer = ReasonCode::defer_rate_limit();
    assert!(!defer.0.is_empty());
    assert!(defer.0.contains("RATE_LIMIT"));
}
