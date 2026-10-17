//! Privacy & Secret Protection Engine (`PrivacyEngine`). Runs after parse and
//! before persistence. Deterministic: regex, checksum and structure only.

use bower_contracts::{EventRedactor, RedactionResult};
use indexmap::IndexMap;

use crate::applicator::PolicyApplicator;
use crate::detectors::{
    DetectionMatch, FieldNameDetector, ScanText, SensitiveDetector, default_field_name_detector,
    default_value_detectors,
};
use crate::error::PrivacyError;
use crate::ids::{detector_categories as categories, detector_ids as ids};
use crate::json::{self, Node, Object};
use crate::policy::{PrivacyAction, PrivacyFieldRule, PrivacyPolicy};
use crate::text::{compare_ordinal, is_null_or_whitespace, normalize_field_name, truncate_utf16};

pub const MAXIMUM_PAYLOAD_BYTES: usize = 1_048_576;

/// One applied control action. Never carries the original value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedFinding {
    pub detector_id: String,
    pub category: String,
    pub path: String,
    pub action: PrivacyAction,
    pub validated: bool,
    pub sub_kind: Option<String>,
}

/// Sanitisation summary attached to processed events. Never contains originals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivacyMetadata {
    pub detected: Vec<String>,
    pub actions: IndexMap<String, String>,
}

impl PrivacyMetadata {
    pub fn has_findings(&self) -> bool {
        !self.detected.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacyScanResult {
    pub succeeded: bool,
    pub redacted_json: Option<String>,
    pub findings: Vec<AppliedFinding>,
    pub metadata: PrivacyMetadata,
    pub removed_paths: Vec<String>,
    pub masked_paths: Vec<String>,
    pub failure_code: Option<String>,
}

impl PrivacyScanResult {
    pub fn fail(code: &str) -> Self {
        Self {
            succeeded: false,
            redacted_json: None,
            findings: Vec::new(),
            metadata: PrivacyMetadata::default(),
            removed_paths: Vec::new(),
            masked_paths: Vec::new(),
            failure_code: Some(code.to_owned()),
        }
    }

    /// Like C#, privacy lists are always present (empty on failure).
    pub fn to_redaction_result(&self) -> RedactionResult {
        RedactionResult {
            succeeded: self.succeeded,
            redacted_json: self.redacted_json.clone(),
            removed_paths: self.removed_paths.clone(),
            masked_paths: self.masked_paths.clone(),
            failure_code: self.failure_code.clone(),
            privacy_detected: Some(self.metadata.detected.clone()),
            privacy_actions: Some(self.metadata.actions.clone()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacyTextResult {
    pub succeeded: bool,
    pub redacted_text: Option<String>,
    pub findings: Vec<AppliedFinding>,
    pub metadata: PrivacyMetadata,
    pub failure_code: Option<String>,
}

impl PrivacyTextResult {
    fn fail(code: &str) -> Self {
        Self {
            succeeded: false,
            redacted_text: None,
            findings: Vec::new(),
            metadata: PrivacyMetadata::default(),
            failure_code: Some(code.to_owned()),
        }
    }
}

/// A payload that cannot be redacted safely (C# `RegexMatchTimeoutException`,
/// `ArgumentException` or `InvalidOperationException`). Must be quarantined.
struct RedactionFailed;

impl From<PrivacyError> for RedactionFailed {
    fn from(_: PrivacyError) -> Self {
        Self
    }
}

type Step<T = ()> = Result<T, RedactionFailed>;

pub struct PrivacyEngine {
    policy: PrivacyPolicy,
    detectors: Vec<Box<dyn SensitiveDetector>>,
    field_name_detector: Box<dyn FieldNameDetector>,
    applicator: PolicyApplicator,
}

impl std::fmt::Debug for PrivacyEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivacyEngine")
            .field(
                "detectors",
                &self.detectors.iter().map(|d| d.id()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl PrivacyEngine {
    /// Engine with the built-in detector catalogue. Fails when the policy needs an
    /// HMAC key that is not configured.
    pub fn new(policy: PrivacyPolicy) -> Result<Self, PrivacyError> {
        Self::with_detectors(
            policy,
            default_value_detectors(),
            default_field_name_detector(),
        )
    }

    /// Engine with custom detectors (appended or replaced without modifying the engine).
    pub fn with_detectors(
        policy: PrivacyPolicy,
        detectors: Vec<Box<dyn SensitiveDetector>>,
        field_name_detector: Box<dyn FieldNameDetector>,
    ) -> Result<Self, PrivacyError> {
        let applicator = PolicyApplicator::new(&policy)?;
        Ok(Self {
            policy,
            detectors,
            field_name_detector,
            applicator,
        })
    }

    /// Engine with [`PrivacyPolicy::create_default`].
    pub fn with_default_policy() -> Self {
        Self::new(PrivacyPolicy::create_default()).expect("the default policy never uses Hmac")
    }

    pub fn policy(&self) -> &PrivacyPolicy {
        &self.policy
    }

    pub fn detectors(&self) -> &[Box<dyn SensitiveDetector>] {
        &self.detectors
    }

    /// Detector ids that warrant a first-class SOC security event when observed:
    /// high-risk regulated AU identifiers, secrets and crypto — not routine email masks.
    pub fn is_security_event_worthy(detector_id: &str) -> bool {
        // Sub-kind suffixes appear as "secret.api-key:OpenAI" in the detected list.
        let root = match detector_id.find(':') {
            Some(colon) if colon > 0 => &detector_id[..colon],
            _ => detector_id,
        };
        matches!(
            root,
            ids::FIELD_NAME_SECRET
                | ids::TFN
                | ids::CRN
                | ids::MEDICARE
                | ids::IHI
                | ids::PASSPORT
                | ids::DRIVER_LICENCE
                | ids::DVA
                | ids::CREDIT_CARD
                | ids::BSB_ACCOUNT
                | ids::IBAN
                | ids::PAY_ID
                | ids::AWS
                | ids::AZURE
                | ids::ENTRA
                | ids::GCP
                | ids::JWT
                | ids::OAUTH
                | ids::API_KEY
                | ids::KUBERNETES
                | ids::DOCKER
                | ids::DATABASE
                | ids::ENV_VAR
                | ids::CRYPTO_MATERIAL
                | ids::SECURITY_MARKING
        )
    }

    pub fn redact_json(&self, json: &str) -> PrivacyScanResult {
        if is_null_or_whitespace(json) {
            return PrivacyScanResult::fail("empty-payload");
        }

        if json.len() > MAXIMUM_PAYLOAD_BYTES {
            return PrivacyScanResult::fail("payload-too-large");
        }

        let Ok(root) = json::parse(json) else {
            return PrivacyScanResult::fail("invalid-json");
        };
        let Node::Object(mut root) = root else {
            return PrivacyScanResult::fail("root-must-be-object");
        };

        // Detector failures and malformed structures (duplicate keys, unpaired
        // surrogates) are security failures: quarantine, never persist.
        match self.redact_root(&mut root) {
            Ok(result) => result,
            Err(RedactionFailed) => PrivacyScanResult::fail("redaction-failed"),
        }
    }

    fn redact_root(&self, root: &mut Object) -> Step<PrivacyScanResult> {
        let mut findings = Vec::new();
        self.walk_object(root, "$", &mut findings)?;
        self.apply_field_rules(root, &mut findings)?;
        self.enforce_field_length_object(root, "$", &mut findings)?;

        let metadata = build_metadata(&findings);
        if self.policy.emit_metadata && metadata.has_findings() {
            root.map
                .insert("privacy".to_owned(), metadata_to_node(&metadata));
        }

        let removed = distinct_paths(&findings, |action| action == PrivacyAction::Remove);
        let masked = distinct_paths(&findings, |action| {
            matches!(
                action,
                PrivacyAction::Mask
                    | PrivacyAction::Sha256
                    | PrivacyAction::Hmac
                    | PrivacyAction::Encrypt
                    | PrivacyAction::Replace
                    | PrivacyAction::Truncate
            )
        });

        let root = Node::Object(std::mem::take(root));
        let redacted = bower_contracts::json::to_string(&root).map_err(|_| RedactionFailed)?;
        Ok(PrivacyScanResult {
            succeeded: true,
            redacted_json: Some(redacted),
            findings,
            metadata,
            removed_paths: removed,
            masked_paths: masked,
            failure_code: None,
        })
    }

    /// Scans and sanitises a raw text payload (syslog line, CSV cell, …).
    pub fn redact_text(&self, text: &str) -> PrivacyTextResult {
        if text.len() > MAXIMUM_PAYLOAD_BYTES {
            return PrivacyTextResult::fail("payload-too-large");
        }

        let mut findings = Vec::new();
        match self.apply_detectors_to_value(text, "$", &mut findings) {
            Ok(redacted) => PrivacyTextResult {
                succeeded: true,
                redacted_text: Some(redacted),
                metadata: build_metadata(&findings),
                findings,
                failure_code: None,
            },
            Err(RedactionFailed) => PrivacyTextResult::fail("redaction-failed"),
        }
    }

    fn walk_object(
        &self,
        object: &mut Object,
        parent_path: &str,
        findings: &mut Vec<AppliedFinding>,
    ) -> Step {
        if object.poisoned {
            return Err(RedactionFailed);
        }

        let mut redacted_key_index = 0usize;
        let names: Vec<String> = object.map.keys().cloned().collect();
        for original_name in names {
            let mut property_name = original_name;
            let normalized = normalize_field_name(&property_name);
            let field_name_id = self.field_name_detector.id();
            if self.policy.is_detector_enabled(field_name_id)
                && self.field_name_detector.matches_field_name(&normalized)
            {
                let action = self.policy.resolve_action(field_name_id);
                findings.push(AppliedFinding {
                    detector_id: field_name_id.to_owned(),
                    category: self.field_name_detector.category().to_owned(),
                    path: format!("{parent_path}.{property_name}"),
                    action,
                    validated: true,
                    sub_kind: None,
                });
                if !action.keeps_content() {
                    object.map.shift_remove(&property_name);
                }

                continue;
            }

            // Property names are attacker-controlled too: scan them with value detectors
            // and rename the property when a key carries sensitive data.
            let redacted_name = self.apply_detectors_to_value(
                &property_name,
                &format!("{parent_path}.[key]"),
                findings,
            )?;
            if redacted_name != property_name {
                let child = object
                    .map
                    .shift_remove(&property_name)
                    .ok_or(RedactionFailed)?;
                let mut name = redacted_name;
                loop {
                    if name.is_empty() || object.map.contains_key(&name) {
                        redacted_key_index += 1;
                        name = format!("redacted-key-{redacted_key_index}");
                    }
                    if !object.map.contains_key(&name) {
                        break;
                    }
                }

                object.map.insert(name.clone(), child);
                property_name = name;
            }

            let path = format!("{parent_path}.{property_name}");
            let Some(child) = object.map.get_mut(&property_name) else {
                continue;
            };
            match child {
                Node::Object(nested) => self.walk_object(nested, &path, findings)?,
                Node::Array(items) => self.walk_array(items, &path, findings)?,
                scalar => self.redact_scalar(scalar, &path, findings)?,
            }
        }

        Ok(())
    }

    fn walk_array(
        &self,
        items: &mut [Node],
        path: &str,
        findings: &mut Vec<AppliedFinding>,
    ) -> Step {
        for (index, item) in items.iter_mut().enumerate() {
            let item_path = format!("{path}[{index}]");
            match item {
                Node::Object(nested) => self.walk_object(nested, &item_path, findings)?,
                Node::Array(nested) => self.walk_array(nested, &item_path, findings)?,
                scalar => self.redact_scalar(scalar, &item_path, findings)?,
            }
        }

        Ok(())
    }

    /// Strings are scanned as-is; numbers by their exact JSON text so card numbers,
    /// TFNs and account numbers sent as numbers cannot bypass detectors. A redacted
    /// number becomes a string.
    fn redact_scalar(
        &self,
        node: &mut Node,
        path: &str,
        findings: &mut Vec<AppliedFinding>,
    ) -> Step {
        let Some(text) = scannable_text(node)? else {
            return Ok(());
        };
        let redacted = self.apply_detectors_to_value(&text, path, findings)?;
        if redacted != text {
            *node = Node::string(redacted);
        }

        Ok(())
    }

    fn apply_field_rules(&self, root: &mut Object, findings: &mut Vec<AppliedFinding>) -> Step {
        for rule in &self.policy.field_rules {
            // C# indexes Segments[0] unguarded and throws; fail closed instead.
            if rule.segments().is_empty() {
                return Err(RedactionFailed);
            }

            self.apply_field_rule(root, rule, 0, "$", findings)?;
        }

        Ok(())
    }

    fn apply_field_rule(
        &self,
        node: &mut Object,
        rule: &PrivacyFieldRule,
        depth: usize,
        path: &str,
        findings: &mut Vec<AppliedFinding>,
    ) -> Step {
        if node.poisoned {
            return Err(RedactionFailed);
        }

        let segments = rule.segments();
        let segment = &segments[depth];
        let names: Vec<String> = if segment == "*" {
            node.map.keys().cloned().collect()
        } else if node.map.contains_key(segment) {
            vec![segment.clone()]
        } else {
            Vec::new()
        };

        for name in names {
            let child_path = format!("{path}.{name}");
            if depth < segments.len() - 1 {
                if let Some(Node::Object(nested)) = node.map.get_mut(&name) {
                    self.apply_field_rule(nested, rule, depth + 1, &child_path, findings)?;
                }

                continue;
            }

            let Some(child) = node.map.get(&name) else {
                continue;
            };
            let Some(text) = scannable_text(child)? else {
                continue;
            };

            match self
                .applicator
                .apply_to_value(&text, rule.action, rule.max_length)?
            {
                None => {
                    node.map.shift_remove(&name);
                }
                Some(replaced) if replaced != text => {
                    node.map.insert(name.clone(), Node::string(replaced));
                }
                Some(_) => {}
            }

            findings.push(AppliedFinding {
                detector_id: ids::FIELD_RULE.to_owned(),
                category: categories::FIELD_NAME.to_owned(),
                path: child_path,
                action: rule.action,
                validated: true,
                sub_kind: None,
            });
        }

        Ok(())
    }

    fn enforce_field_length_object(
        &self,
        object: &mut Object,
        path: &str,
        findings: &mut Vec<AppliedFinding>,
    ) -> Step {
        if object.poisoned {
            return Err(RedactionFailed);
        }

        for (name, child) in object.map.iter_mut() {
            self.enforce_field_length_node(child, &format!("{path}.{name}"), findings)?;
        }

        Ok(())
    }

    fn enforce_field_length_node(
        &self,
        node: &mut Node,
        path: &str,
        findings: &mut Vec<AppliedFinding>,
    ) -> Step {
        match node {
            Node::String(text) => {
                if text.invalid {
                    return Err(RedactionFailed);
                }

                if let Some(truncated) =
                    truncate_utf16(&text.value, self.policy.maximum_field_length)
                {
                    *node = Node::string(truncated);
                    findings.push(AppliedFinding {
                        detector_id: ids::FIELD_LENGTH.to_owned(),
                        category: categories::FIELD_NAME.to_owned(),
                        path: path.to_owned(),
                        action: PrivacyAction::Truncate,
                        validated: true,
                        sub_kind: None,
                    });
                }
            }
            Node::Object(object) => self.enforce_field_length_object(object, path, findings)?,
            Node::Array(items) => {
                for (index, item) in items.iter_mut().enumerate() {
                    self.enforce_field_length_node(item, &format!("{path}[{index}]"), findings)?;
                }
            }
            Node::Null | Node::Bool(_) | Node::Number(_) => {}
        }

        Ok(())
    }

    fn apply_detectors_to_value(
        &self,
        text: &str,
        path: &str,
        findings: &mut Vec<AppliedFinding>,
    ) -> Step<String> {
        let scan = ScanText::new(text);
        let mut matches: Vec<DetectionMatch> = Vec::new();
        for detector in &self.detectors {
            if self.policy.is_detector_enabled(detector.id()) {
                detector.detect(&scan, path, &mut matches);
            }
        }

        if matches.is_empty() {
            return Ok(text.to_owned());
        }

        // Resolve overlaps: prefer longer matches, then earlier start (stable, like LINQ).
        matches.sort_by(|a, b| {
            b.length_utf16
                .cmp(&a.length_utf16)
                .then(a.start.cmp(&b.start))
        });
        let mut selected: Vec<DetectionMatch> = Vec::new();
        for candidate in matches {
            if !selected
                .iter()
                .any(|existing| overlaps(existing, &candidate))
            {
                selected.push(candidate);
            }
        }

        // Apply right-to-left so offsets remain valid.
        selected.sort_by_key(|found| std::cmp::Reverse(found.start));
        let mut result = text.to_owned();
        for found in selected {
            let action = self.policy.resolve_action(&found.detector_id);
            if !action.keeps_content() {
                let replacement = self.applicator.apply(&result, &found, action)?;
                result.replace_range(found.start..found.end, &replacement);
            }

            findings.push(AppliedFinding {
                detector_id: found.detector_id,
                category: found.category,
                path: path.to_owned(),
                action,
                validated: found.validated,
                sub_kind: found.sub_kind,
            });
        }

        Ok(result)
    }
}

impl EventRedactor for PrivacyEngine {
    fn redact(&self, json: &str) -> RedactionResult {
        self.redact_json(json).to_redaction_result()
    }
}

/// String or number text of a scalar; fails on strings C# cannot read.
fn scannable_text(node: &Node) -> Step<Option<String>> {
    match node {
        Node::String(text) if text.invalid => Err(RedactionFailed),
        Node::String(text) => Ok(Some(text.value.clone())),
        Node::Number(raw) => Ok(Some(raw.get().to_owned())),
        _ => Ok(None),
    }
}

fn overlaps(a: &DetectionMatch, b: &DetectionMatch) -> bool {
    a.start < b.end && b.start < a.end
}

fn distinct_paths(
    findings: &[AppliedFinding],
    include: impl Fn(PrivacyAction) -> bool,
) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for finding in findings.iter().filter(|finding| include(finding.action)) {
        if !paths.contains(&finding.path) {
            paths.push(finding.path.clone());
        }
    }
    paths
}

fn build_metadata(findings: &[AppliedFinding]) -> PrivacyMetadata {
    if findings.is_empty() {
        return PrivacyMetadata::default();
    }

    let mut detected: Vec<String> = Vec::new();
    for finding in findings {
        let id = match &finding.sub_kind {
            Some(sub_kind) => format!("{}:{sub_kind}", finding.detector_id),
            None => finding.detector_id.clone(),
        };
        if !detected.contains(&id) {
            detected.push(id);
        }
    }
    detected.sort_by(|a, b| compare_ordinal(a, b));

    let mut actions = IndexMap::new();
    for finding in findings {
        actions
            .entry(finding.detector_id.clone())
            .or_insert_with(|| finding.action.label().to_owned());
    }

    PrivacyMetadata { detected, actions }
}

fn metadata_to_node(metadata: &PrivacyMetadata) -> Node {
    let detected = metadata
        .detected
        .iter()
        .cloned()
        .map(Node::string)
        .collect();
    let actions = Object {
        map: metadata
            .actions
            .iter()
            .map(|(key, value)| (key.clone(), Node::string(value.clone())))
            .collect(),
        poisoned: false,
    };
    let mut privacy = Object::default();
    privacy
        .map
        .insert("detected".to_owned(), Node::Array(detected));
    privacy
        .map
        .insert("actions".to_owned(), Node::Object(actions));
    Node::Object(privacy)
}

/// Compatibility redactor (`JsonEventRedactor`): delegates to [`PrivacyEngine`].
/// Field-name secrets are removed; emails and other PII are handled by detectors.
#[derive(Debug)]
pub struct JsonEventRedactor {
    engine: PrivacyEngine,
}

impl JsonEventRedactor {
    pub const MAXIMUM_PAYLOAD_BYTES: usize = MAXIMUM_PAYLOAD_BYTES;

    pub fn new() -> Self {
        Self {
            engine: PrivacyEngine::with_default_policy(),
        }
    }

    pub fn with_policy(policy: PrivacyPolicy) -> Result<Self, PrivacyError> {
        Ok(Self {
            engine: PrivacyEngine::new(policy)?,
        })
    }

    pub fn engine(&self) -> &PrivacyEngine {
        &self.engine
    }
}

impl Default for JsonEventRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl EventRedactor for JsonEventRedactor {
    fn redact(&self, json: &str) -> RedactionResult {
        self.engine.redact(json)
    }
}
