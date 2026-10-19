//! What a published policy revision actually does, family by family.
//!
//! Only four of the twenty-four seeded families have a runtime reader for
//! `policy_revisions.rules`, and the two readers ignore every condition
//! predicate: [`crate::inline_ml::thresholds::thresholds_from_rules`] and
//! [`crate::outbound_intelligence`]
//! (`apply_policy_threshold_rules`) consume only `enabled`, `priority` and
//! `action.metadata`. Until this registry existed the console rendered the same
//! seven condition fieldsets for all twenty-four families, which told operators
//! the delivery path reads predicates it does not read.
//!
//! The profile is derived, not stored: a family is `NotEnforced` unless it is
//! named in [`THRESHOLD_READERS`], so a newly seeded family reports honestly
//! (no reader) instead of inheriting a claim nobody verified. The unit tests
//! pin the wired set to the constants the readers actually match on, which is
//! what stops this file from drifting.

use serde::Serialize;
use serde_json::{Number, Value};

use crate::inline_ml::runtime::INLINE_ML_LABELS;
use crate::inline_ml::thresholds::{
    category_key, label_to_category, ML_THREAT_CLASSIFICATION_FAMILY,
};
use crate::outbound_intelligence::{
    BULK_SENDING_POLICY_FAMILY, OUTBOUND_ABUSE_POLICY_FAMILY, SENDER_REPUTATION_POLICY_FAMILY,
};

/// The families with a runtime reader for their published rules.
const THRESHOLD_READERS: [(&str, EnforcementMode); 4] = [
    (
        ML_THREAT_CLASSIFICATION_FAMILY,
        EnforcementMode::MlThresholds,
    ),
    (
        BULK_SENDING_POLICY_FAMILY,
        EnforcementMode::OutboundThresholds,
    ),
    (
        OUTBOUND_ABUSE_POLICY_FAMILY,
        EnforcementMode::OutboundThresholds,
    ),
    (
        SENDER_REPUTATION_POLICY_FAMILY,
        EnforcementMode::OutboundThresholds,
    ),
];

/// How the delivery path consumes a published revision in one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Enabled rules carry per-class score bands for the inline classifier.
    MlThresholds,
    /// Enabled rules carry numeric operating points for outbound intelligence.
    OutboundThresholds,
    /// Nothing reads this family's revisions, so a revision changes no decision.
    NotEnforced,
}

/// One condition fieldset in the shared [`nullapart_mail_contracts::policy::PolicyCondition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionField {
    Sender,
    Recipient,
    Auth,
    Content,
    Finding,
}

/// How one kind of metadata value is stored and bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataFieldKind {
    /// Positive whole number of messages, recipients or failures.
    Count,
    /// Positive whole number of minutes.
    Minutes,
    /// Fraction greater than zero and at most one.
    Ratio,
    /// The `{low, medium, high}` band triple per classifier class.
    ClassBands,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConditionFieldProfile {
    pub field: ConditionField,
    /// Whether a runtime reader evaluates this predicate for this family.
    pub honoured: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetadataFieldProfile {
    /// The `action.metadata` key the reader looks for.
    pub key: &'static str,
    /// Label for the operator-facing form.
    pub label: &'static str,
    pub kind: MetadataFieldKind,
    /// Smallest accepted value, inclusive, or the exclusive lower bound for a
    /// ratio expressed as `min_exclusive` in the hint.
    pub min: Option<Value>,
    pub max: Option<Value>,
    /// The built-in operating point used when this key is absent. `None` for
    /// the ML bands, which have no built-in per-class default.
    pub default: Option<Value>,
    /// Accepted class keys, for [`MetadataFieldKind::ClassBands`]; empty otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<String>,
    pub hint: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetadataProfile {
    /// Whether `action.metadata` is read at all for this family.
    pub read: bool,
    /// When metadata is present it must contain exactly the listed keys and no
    /// others; a misspelled key is rejected rather than ignored.
    pub exact_keys: bool,
    /// A rule may be published with no metadata.
    pub metadata_optional: bool,
    /// How the reader combines the metadata of several enabled rules, stated in
    /// the reader's own terms.
    pub merge: &'static str,
    pub fields: Vec<MetadataFieldProfile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnforcementProfile {
    pub mode: EnforcementMode,
    pub summary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleProfile {
    pub enforcement: EnforcementProfile,
    pub conditions: Vec<ConditionFieldProfile>,
    pub metadata: MetadataProfile,
}

fn integer(value: u64) -> Option<Value> {
    Some(Value::from(value))
}

fn decimal(value: f64) -> Option<Value> {
    Number::from_f64(value).map(Value::Number)
}

/// The class keys the classifier can band, in taxonomy order, using the same
/// wire names `FindingCondition.category` uses.
fn ml_class_keys() -> Vec<String> {
    INLINE_ML_LABELS
        .iter()
        .filter_map(|label| label_to_category(label))
        .map(category_key)
        .collect()
}

fn count_field(key: &'static str, label: &'static str, default: u64) -> MetadataFieldProfile {
    MetadataFieldProfile {
        key,
        label,
        kind: MetadataFieldKind::Count,
        min: integer(1),
        max: integer(u64::from(u32::MAX)),
        default: integer(default),
        classes: Vec::new(),
        hint: "Whole number above zero. Omit the key to keep the built-in default.",
    }
}

fn outbound_profile(family_key: &str) -> MetadataProfile {
    let fields: Vec<MetadataFieldProfile> = match family_key {
        BULK_SENDING_POLICY_FAMILY => vec![
            count_field("max_messages_per_minute", "Messages per minute", 25),
            count_field("max_messages_per_hour", "Messages per hour", 100),
            count_field("max_recipients_per_message", "Recipients per message", 50),
            count_field(
                "max_unique_recipients_per_hour",
                "Unique recipients per hour",
                250,
            ),
        ],
        OUTBOUND_ABUSE_POLICY_FAMILY => vec![
            count_field(
                "campaign_min_messages_per_hour",
                "Campaign detection floor (messages per hour)",
                40,
            ),
            MetadataFieldProfile {
                key: "rotating_recipient_new_ratio",
                label: "Rotating-recipient new-address share",
                kind: MetadataFieldKind::Ratio,
                min: None,
                max: decimal(1.0),
                default: decimal(0.80),
                classes: Vec::new(),
                hint: "Fraction above 0 and at most 1. Share of hourly recipients that are new.",
            },
            MetadataFieldProfile {
                key: "event_cooldown_minutes",
                label: "Event cooldown (minutes)",
                kind: MetadataFieldKind::Minutes,
                min: integer(1),
                max: None,
                default: integer(30),
                classes: Vec::new(),
                hint: "Whole minutes above zero between repeat events of one kind.",
            },
        ],
        _ => vec![count_field(
            "bounce_failures_per_hour",
            "Bounce failures per hour",
            25,
        )],
    };
    MetadataProfile {
        read: true,
        exact_keys: true,
        metadata_optional: true,
        merge: "Enabled rules apply in revision order and each overwrites the keys it sets, so \
                the last enabled rule to set a key decides it.",
        fields,
    }
}

fn ml_profile() -> MetadataProfile {
    MetadataProfile {
        read: true,
        exact_keys: true,
        metadata_optional: true,
        merge: "Enabled rules are ordered by priority and the first rule that defines a class \
                sets its bands; a later rule cannot change a class an earlier rule already set.",
        fields: vec![MetadataFieldProfile {
            key: "thresholds",
            label: "Per-class score bands",
            kind: MetadataFieldKind::ClassBands,
            min: decimal(0.0),
            max: decimal(1.0),
            default: None,
            classes: ml_class_keys(),
            hint: "Scores run from 0 to 1. A class needs three rising points: the low point where \
                   it becomes a finding, then the Medium and High cutoffs. A class you leave out \
                   gets no band, so the stage reports evidence for it without scoring it.",
        }],
    }
}

fn condition_profiles(mode: EnforcementMode) -> Vec<ConditionFieldProfile> {
    let note = match mode {
        EnforcementMode::NotEnforced => {
            "No stage reads this family's published rules, so nothing here can match or miss."
        },
        _ => {
            "The reader for this family uses only enabled rules and their thresholds, and never \
              evaluates a condition."
        },
    };
    [
        ConditionField::Sender,
        ConditionField::Recipient,
        ConditionField::Auth,
        ConditionField::Content,
        ConditionField::Finding,
    ]
    .into_iter()
    .map(|field| ConditionFieldProfile {
        field,
        honoured: false,
        note,
    })
    .collect()
}

fn enforcement_profile(mode: EnforcementMode) -> EnforcementProfile {
    let summary = match mode {
        EnforcementMode::MlThresholds => {
            "Enabled rules set the inline classifier's per-class score bands. The stage reports \
             an explicit warning when no rule carries a threshold payload."
        },
        EnforcementMode::OutboundThresholds => {
            "Enabled rules override the outbound intelligence operating points. Sender approval \
             state and behaviour still decide which of them is compared."
        },
        EnforcementMode::NotEnforced => {
            "Nothing reads this family's published rules yet. A revision is stored, audited and \
             versioned, but it changes no delivery decision."
        },
    };
    EnforcementProfile { mode, summary }
}

/// The profile for one family. Unknown keys describe the state they are in
/// (no reader), which is the honest default; the family catalog in
/// [`crate::policy_admin`] is what decides a 404.
pub fn rule_profile(family_key: &str) -> RuleProfile {
    let mode = THRESHOLD_READERS
        .iter()
        .find(|(key, _)| *key == family_key)
        .map(|(_, mode)| *mode)
        .unwrap_or(EnforcementMode::NotEnforced);
    let metadata = match mode {
        EnforcementMode::MlThresholds => ml_profile(),
        EnforcementMode::OutboundThresholds => outbound_profile(family_key),
        EnforcementMode::NotEnforced => MetadataProfile {
            read: false,
            exact_keys: false,
            metadata_optional: true,
            merge: "No reader, so metadata is stored but never applied.",
            fields: Vec::new(),
        },
    };
    RuleProfile {
        enforcement: enforcement_profile(mode),
        conditions: condition_profiles(mode),
        metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wired_set_matches_the_readers_constants() {
        let keys: Vec<&str> = THRESHOLD_READERS.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            vec![
                "ml_threat_classification",
                "bulk_sending",
                "outbound_abuse",
                "sender_reputation",
            ]
        );
    }

    #[test]
    fn outbound_metadata_keys_match_the_publish_validators() {
        // has_exact_keys() in outbound_intelligence is the authority; these are
        // the keys it accepts, and the profile must list exactly them.
        let bulk: Vec<&str> = rule_profile(BULK_SENDING_POLICY_FAMILY)
            .metadata
            .fields
            .iter()
            .map(|field| field.key)
            .collect();
        assert_eq!(
            bulk,
            vec![
                "max_messages_per_minute",
                "max_messages_per_hour",
                "max_recipients_per_message",
                "max_unique_recipients_per_hour",
            ]
        );
        let abuse: Vec<&str> = rule_profile(OUTBOUND_ABUSE_POLICY_FAMILY)
            .metadata
            .fields
            .iter()
            .map(|field| field.key)
            .collect();
        assert_eq!(
            abuse,
            vec![
                "campaign_min_messages_per_hour",
                "rotating_recipient_new_ratio",
                "event_cooldown_minutes",
            ]
        );
        let reputation = rule_profile(SENDER_REPUTATION_POLICY_FAMILY).metadata;
        assert_eq!(reputation.fields.len(), 1);
        assert_eq!(reputation.fields[0].key, "bounce_failures_per_hour");
    }

    #[test]
    fn ml_profile_lists_every_classifier_class() {
        let profile = rule_profile(ML_THREAT_CLASSIFICATION_FAMILY);
        assert_eq!(profile.metadata.fields.len(), 1);
        assert_eq!(
            profile.metadata.fields[0].classes.len(),
            INLINE_ML_LABELS.len()
        );
        assert!(profile.metadata.fields[0]
            .classes
            .contains(&"business_email_compromise".to_string()));
    }

    #[test]
    fn unwired_families_are_reported_as_not_enforced() {
        for key in [
            "spam_filtering",
            "quarantine",
            "attachments",
            "url_security",
        ] {
            let profile = rule_profile(key);
            assert_eq!(
                profile.enforcement.mode,
                EnforcementMode::NotEnforced,
                "{key}"
            );
            assert!(!profile.metadata.read, "{key}");
            assert!(profile.conditions.iter().all(|c| !c.honoured), "{key}");
        }
    }

    #[test]
    fn no_family_honours_a_condition_predicate_today() {
        for (key, _) in THRESHOLD_READERS {
            let profile = rule_profile(key);
            assert!(
                profile.conditions.iter().all(|c| !c.honoured),
                "{key} claims an evaluated predicate"
            );
        }
    }

    #[test]
    fn profile_serializes_with_wire_names() {
        let value = serde_json::to_value(rule_profile("bulk_sending")).unwrap();
        assert_eq!(value["enforcement"]["mode"], "outbound_thresholds");
        assert_eq!(value["conditions"][0]["field"], "sender");
        assert_eq!(value["metadata"]["fields"][0]["kind"], "count");
        assert_eq!(value["metadata"]["fields"][0]["min"], 1);
        assert!(value["metadata"]["fields"][0]["classes"].is_null());
        let ml = serde_json::to_value(rule_profile("ml_threat_classification")).unwrap();
        assert_eq!(ml["metadata"]["fields"][0]["kind"], "class_bands");
    }
}
