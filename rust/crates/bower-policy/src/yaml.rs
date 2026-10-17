//! Strict YAML reader reproducing the `YamlDotNet` deserializer used by
//! `PolicyLoader` (camelCase keys, unknown keys rejected, no required-member
//! enforcement).
//!
//! The model here is nullable exactly where the C# runtime objects can be null,
//! because the policy hash is computed over that object graph. Scalars are read
//! as their source text and converted with `YamlDotNet`'s own rules (octal,
//! hex, binary and base-60 integers, `y`/`on`/`off` booleans), not YAML 1.2
//! core-schema resolution.
//!
//! Errors carry `YamlDotNet`'s messages. serde gives no positions to visitors,
//! so the failing visitor records the message in [`Ctx`] and returns a custom
//! error; `serde_yaml_ng` then attaches the start mark of the node being read,
//! which is the mark `YamlDotNet` reports.

use std::cell::RefCell;
use std::fmt;
use std::marker::PhantomData;

use chrono::NaiveDate;
use serde::Serialize;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

pub(crate) const CONVERSION_FAILED: &str = "Exception during deserialization";
const CORELIB: &str =
    "System.Private.CoreLib, Version=10.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e";
const POLICY_ASSEMBLY: &str =
    "Bower.PolicyEngine, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";

/// A failure detected by a visitor, formatted once the node mark is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Message(String),
    /// `Expected '{expected}', got '{got}' (at Line: _, Col: _, Idx: _).`
    Expected {
        expected: &'static str,
        got: &'static str,
    },
}

#[derive(Default)]
pub(crate) struct Ctx {
    failure: RefCell<Option<Failure>>,
}

impl Ctx {
    fn fail<E: de::Error>(&self, failure: Failure) -> E {
        let text = match &failure {
            Failure::Message(message) => message.clone(),
            Failure::Expected { expected, got } => format!("Expected '{expected}', got '{got}'"),
        };
        // The innermost failure wins; outer visitors only see it propagate.
        self.failure.borrow_mut().get_or_insert(failure);
        E::custom(text)
    }

    /// Records a structural mismatch reported by `serde_yaml_ng` itself
    /// (`invalid type: sequence|map`) when no visitor failure is recorded.
    fn classify(&self, error: &dyn fmt::Display, on_sequence: Failure, on_map: Failure) {
        if self.failure.borrow().is_some() {
            return;
        }
        let text = error.to_string();
        let failure = if text.contains("invalid type: sequence") {
            on_sequence
        } else if text.contains("invalid type: map") {
            on_map
        } else {
            return;
        };
        *self.failure.borrow_mut() = Some(failure);
    }

    pub(crate) fn take(&self) -> Option<Failure> {
        self.failure.borrow_mut().take()
    }
}

fn no_node_deserializer(type_name: &str) -> Failure {
    Failure::Message(format!(
        "No node deserializer was able to deserialize the node into type {type_name}"
    ))
}

fn conversion_failed() -> Failure {
    Failure::Message(CONVERSION_FAILED.to_owned())
}

// ---------------------------------------------------------------------------
// Nullable model mirroring the C# runtime object graph. Serializes like
// `JsonSerializer.Serialize(policy)` with default options (PascalCase names,
// nulls written, `DateOnly` as yyyy-MM-dd).

pub(crate) type RawList = Option<Vec<Option<String>>>;

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawPolicy {
    pub api_version: Option<String>,
    pub kind: Option<String>,
    pub metadata: Option<RawMetadata>,
    pub r#match: Option<RawMatch>,
    pub requirements: Option<RawRequirements>,
    pub decision: Option<RawAction>,
    pub routing: Option<RawRouting>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawMetadata {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub owner: Option<String>,
    #[serde(serialize_with = "serialize_date_only")]
    pub review_date: Option<NaiveDate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawMatch {
    pub event_categories: RawList,
    pub event_types: RawList,
}

impl Default for RawMatch {
    fn default() -> Self {
        Self {
            event_categories: Some(Vec::new()),
            event_types: Some(Vec::new()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawRequirements {
    pub required_fields: RawList,
    pub at_least_one: RawList,
    pub recommended_fields: RawList,
}

impl Default for RawRequirements {
    fn default() -> Self {
        Self {
            required_fields: Some(Vec::new()),
            at_least_one: Some(Vec::new()),
            recommended_fields: Some(Vec::new()),
        }
    }
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawAction {
    pub action: Option<String>,
    pub minimum_value_score: i32,
    pub never_sample: bool,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawRouting {
    pub profile: Option<String>,
    pub destination: Option<String>,
}

fn serialize_date_only<S: serde::Serializer>(
    value: &Option<NaiveDate>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(date) => serializer.serialize_str(&date.format("%Y-%m-%d").to_string()),
        None => serializer.serialize_none(),
    }
}

// ---------------------------------------------------------------------------
// Sections (C# record types read by YamlDotNet's ObjectNodeDeserializer).

trait Section: Default {
    /// CLR type name used in "Property not found" messages.
    const TYPE_NAME: &'static str;
    const FIELDS: &'static [&'static str];

    fn read_field<'de, A: MapAccess<'de>>(
        &mut self,
        index: usize,
        map: &mut A,
        ctx: &Ctx,
    ) -> Result<(), A::Error>;
}

fn string<'de, A: MapAccess<'de>>(map: &mut A, ctx: &Ctx) -> Result<Option<String>, A::Error> {
    map.next_value_seed(ScalarSeed::<StringKind>::new(ctx))
}

fn list<'de, A: MapAccess<'de>>(map: &mut A, ctx: &Ctx) -> Result<RawList, A::Error> {
    map.next_value_seed(ListSeed { ctx })
}

fn section<'de, A: MapAccess<'de>, T: Section>(
    map: &mut A,
    ctx: &Ctx,
) -> Result<Option<T>, A::Error> {
    map.next_value_seed(SectionSeed::<T>::new(ctx))
}

impl Section for RawPolicy {
    const TYPE_NAME: &'static str = "TelemetryPolicy";
    const FIELDS: &'static [&'static str] = &[
        "apiVersion",
        "kind",
        "metadata",
        "match",
        "requirements",
        "decision",
        "routing",
    ];

    fn read_field<'de, A: MapAccess<'de>>(
        &mut self,
        index: usize,
        map: &mut A,
        ctx: &Ctx,
    ) -> Result<(), A::Error> {
        match index {
            0 => self.api_version = string(map, ctx)?,
            1 => self.kind = string(map, ctx)?,
            2 => self.metadata = section(map, ctx)?,
            3 => self.r#match = section(map, ctx)?,
            4 => self.requirements = section(map, ctx)?,
            5 => self.decision = section(map, ctx)?,
            _ => self.routing = section(map, ctx)?,
        }
        Ok(())
    }
}

impl Section for RawMetadata {
    const TYPE_NAME: &'static str = "PolicyMetadata";
    const FIELDS: &'static [&'static str] = &["id", "name", "version", "owner", "reviewDate"];

    fn read_field<'de, A: MapAccess<'de>>(
        &mut self,
        index: usize,
        map: &mut A,
        ctx: &Ctx,
    ) -> Result<(), A::Error> {
        match index {
            0 => self.id = string(map, ctx)?,
            1 => self.name = string(map, ctx)?,
            2 => self.version = string(map, ctx)?,
            3 => self.owner = string(map, ctx)?,
            _ => self.review_date = map.next_value_seed(ScalarSeed::<DateKind>::new(ctx))?,
        }
        Ok(())
    }
}

impl Section for RawMatch {
    const TYPE_NAME: &'static str = "PolicyMatch";
    const FIELDS: &'static [&'static str] = &["eventCategories", "eventTypes"];

    fn read_field<'de, A: MapAccess<'de>>(
        &mut self,
        index: usize,
        map: &mut A,
        ctx: &Ctx,
    ) -> Result<(), A::Error> {
        match index {
            0 => self.event_categories = list(map, ctx)?,
            _ => self.event_types = list(map, ctx)?,
        }
        Ok(())
    }
}

impl Section for RawRequirements {
    const TYPE_NAME: &'static str = "PolicyRequirements";
    const FIELDS: &'static [&'static str] = &["requiredFields", "atLeastOne", "recommendedFields"];

    fn read_field<'de, A: MapAccess<'de>>(
        &mut self,
        index: usize,
        map: &mut A,
        ctx: &Ctx,
    ) -> Result<(), A::Error> {
        match index {
            0 => self.required_fields = list(map, ctx)?,
            1 => self.at_least_one = list(map, ctx)?,
            _ => self.recommended_fields = list(map, ctx)?,
        }
        Ok(())
    }
}

impl Section for RawAction {
    const TYPE_NAME: &'static str = "PolicyAction";
    const FIELDS: &'static [&'static str] = &["action", "minimumValueScore", "neverSample"];

    fn read_field<'de, A: MapAccess<'de>>(
        &mut self,
        index: usize,
        map: &mut A,
        ctx: &Ctx,
    ) -> Result<(), A::Error> {
        // A YAML null for a value type leaves the CLR default.
        match index {
            0 => self.action = string(map, ctx)?,
            1 => {
                self.minimum_value_score = map
                    .next_value_seed(ScalarSeed::<IntKind>::new(ctx))?
                    .unwrap_or_default();
            }
            _ => {
                self.never_sample = map
                    .next_value_seed(ScalarSeed::<BoolKind>::new(ctx))?
                    .unwrap_or_default();
            }
        }
        Ok(())
    }
}

impl Section for RawRouting {
    const TYPE_NAME: &'static str = "PolicyRouting";
    const FIELDS: &'static [&'static str] = &["profile", "destination"];

    fn read_field<'de, A: MapAccess<'de>>(
        &mut self,
        index: usize,
        map: &mut A,
        ctx: &Ctx,
    ) -> Result<(), A::Error> {
        match index {
            0 => self.profile = string(map, ctx)?,
            _ => self.destination = string(map, ctx)?,
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Seeds.

/// Reads a whole document; `None` for an empty or null document.
pub(crate) fn read_policy<'de, D: Deserializer<'de>>(
    deserializer: D,
    ctx: &Ctx,
) -> Result<Option<RawPolicy>, D::Error> {
    SectionSeed::<RawPolicy>::new(ctx).deserialize(deserializer)
}

struct SectionSeed<'a, T> {
    ctx: &'a Ctx,
    marker: PhantomData<T>,
}

impl<'a, T> SectionSeed<'a, T> {
    fn new(ctx: &'a Ctx) -> Self {
        Self {
            ctx,
            marker: PhantomData,
        }
    }
}

impl<'de, T: Section> DeserializeSeed<'de> for SectionSeed<'_, T> {
    type Value = Option<T>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_option(self)
    }
}

impl<'de, T: Section> Visitor<'de> for SectionSeed<'_, T> {
    type Value = Option<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a mapping")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer
            .deserialize_any(SectionVisitor::<T> {
                ctx: self.ctx,
                marker: PhantomData,
            })
            .map(Some)
    }
}

struct SectionVisitor<'a, T> {
    ctx: &'a Ctx,
    marker: PhantomData<T>,
}

macro_rules! scalar_is_conversion_failure {
    ($($method:ident: $type:ty),* $(,)?) => {
        $(fn $method<E: de::Error>(self, _value: $type) -> Result<Self::Value, E> {
            Err(self.ctx.fail(conversion_failed()))
        })*
    };
}

impl<'de, T: Section> Visitor<'de> for SectionVisitor<'_, T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a mapping")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<T, A::Error> {
        let mut value = T::default();
        while let Some(index) = map.next_key_seed(KeySeed::<T> {
            ctx: self.ctx,
            marker: PhantomData,
        })? {
            value.read_field(index, &mut map, self.ctx)?;
        }
        Ok(value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, _seq: A) -> Result<T, A::Error> {
        Err(self.ctx.fail(no_node_deserializer(&format!(
            "Bower.PolicyEngine.Yaml.{}, {POLICY_ASSEMBLY}",
            T::TYPE_NAME
        ))))
    }

    scalar_is_conversion_failure!(
        visit_str: &str,
        visit_bool: bool,
        visit_i64: i64,
        visit_u64: u64,
        visit_i128: i128,
        visit_u128: u128,
        visit_f64: f64,
    );
}

/// Property-name key, matched exactly against camelCase names.
struct KeySeed<'a, T> {
    ctx: &'a Ctx,
    marker: PhantomData<T>,
}

impl<'de, T: Section> DeserializeSeed<'de> for KeySeed<'_, T> {
    type Value = usize;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<usize, D::Error> {
        let ctx = self.ctx;
        deserializer.deserialize_str(self).inspect_err(|error| {
            ctx.classify(
                error,
                Failure::Expected {
                    expected: "Scalar",
                    got: "SequenceStart",
                },
                Failure::Expected {
                    expected: "Scalar",
                    got: "MappingStart",
                },
            );
        })
    }
}

impl<'de, T: Section> Visitor<'de> for KeySeed<'_, T> {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a property name")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<usize, E> {
        T::FIELDS
            .iter()
            .position(|name| *name == value)
            .ok_or_else(|| {
                self.ctx.fail(Failure::Message(format!(
                    "Property '{value}' not found on type 'Bower.PolicyEngine.Yaml.{}'.",
                    T::TYPE_NAME
                )))
            })
    }
}

/// `List<string>`: null, or a sequence of nullable strings.
struct ListSeed<'a> {
    ctx: &'a Ctx,
}

impl<'de> DeserializeSeed<'de> for ListSeed<'_> {
    type Value = RawList;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<RawList, D::Error> {
        deserializer.deserialize_option(self)
    }
}

impl<'de> Visitor<'de> for ListSeed<'_> {
    type Value = RawList;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a sequence")
    }

    fn visit_none<E: de::Error>(self) -> Result<RawList, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<RawList, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<RawList, D::Error> {
        deserializer
            .deserialize_any(ListVisitor { ctx: self.ctx })
            .map(Some)
    }
}

struct ListVisitor<'a> {
    ctx: &'a Ctx,
}

impl<'de> Visitor<'de> for ListVisitor<'_> {
    type Value = Vec<Option<String>>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a sequence")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(ScalarSeed::<StringKind>::new(self.ctx))? {
            items.push(item);
        }
        Ok(items)
    }

    fn visit_map<A: MapAccess<'de>>(self, _map: A) -> Result<Self::Value, A::Error> {
        Err(self.ctx.fail(Failure::Expected {
            expected: "SequenceStart",
            got: "MappingStart",
        }))
    }

    scalar_is_conversion_failure!(
        visit_str: &str,
        visit_bool: bool,
        visit_i64: i64,
        visit_u64: u64,
        visit_i128: i128,
        visit_u128: u128,
        visit_f64: f64,
    );
}

/// `StrictScalarYamlConverter` messages (C# `PolicyYaml.cs`).
pub(crate) const INTEGER_MESSAGE: &str = "Expected a decimal integer such as 70.";
pub(crate) const BOOLEAN_MESSAGE: &str = "Expected true or false.";
pub(crate) const DATE_MESSAGE: &str = "Expected an ISO 8601 date (yyyy-MM-dd).";

/// How a scalar's source text converts to a CLR value.
trait ScalarKind {
    type Output;
    /// Strict value types: the one message for unconvertible text, a mapping
    /// or a sequence. `None` keeps `YamlDotNet`'s own failures (strings).
    const INVALID: Option<&'static str> = None;
    /// Assembly-qualified CLR type for "No node deserializer" messages.
    fn clr_type() -> String;
    fn convert(text: &str) -> Option<Self::Output>;

    fn invalid() -> Failure {
        Self::INVALID.map_or_else(conversion_failed, |message| {
            Failure::Message(message.to_owned())
        })
    }
}

struct StringKind;
struct IntKind;
struct BoolKind;
struct DateKind;

impl ScalarKind for StringKind {
    type Output = String;
    fn clr_type() -> String {
        format!("System.String, {CORELIB}")
    }
    fn convert(text: &str) -> Option<String> {
        Some(text.to_owned())
    }
}

impl ScalarKind for IntKind {
    type Output = i32;
    const INVALID: Option<&'static str> = Some(INTEGER_MESSAGE);
    fn clr_type() -> String {
        format!("System.Int32, {CORELIB}")
    }
    fn convert(text: &str) -> Option<i32> {
        crate::scalar::parse_int32(text)
    }
}

impl ScalarKind for BoolKind {
    type Output = bool;
    const INVALID: Option<&'static str> = Some(BOOLEAN_MESSAGE);
    fn clr_type() -> String {
        format!("System.Boolean, {CORELIB}")
    }
    fn convert(text: &str) -> Option<bool> {
        crate::scalar::parse_bool(text)
    }
}

impl ScalarKind for DateKind {
    type Output = NaiveDate;
    const INVALID: Option<&'static str> = Some(DATE_MESSAGE);
    fn clr_type() -> String {
        format!("System.Nullable`1[[System.DateOnly, {CORELIB}]], {CORELIB}")
    }
    fn convert(text: &str) -> Option<NaiveDate> {
        crate::scalar::parse_date_only(text)
    }
}

/// Nullable scalar read from its exact source text.
struct ScalarSeed<'a, K> {
    ctx: &'a Ctx,
    marker: PhantomData<K>,
}

impl<'a, K> ScalarSeed<'a, K> {
    fn new(ctx: &'a Ctx) -> Self {
        Self {
            ctx,
            marker: PhantomData,
        }
    }
}

impl<'de, K: ScalarKind> DeserializeSeed<'de> for ScalarSeed<'_, K> {
    type Value = Option<K::Output>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_option(self)
    }
}

impl<'de, K: ScalarKind> Visitor<'de> for ScalarSeed<'_, K> {
    type Value = Option<K::Output>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a scalar")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        let ctx = self.ctx;
        deserializer
            .deserialize_str(TextVisitor::<K> {
                ctx,
                marker: PhantomData,
            })
            .map(Some)
            .inspect_err(|error| match K::INVALID {
                // Strict value types reject mappings and sequences with their
                // own message.
                Some(_) => ctx.classify(error, K::invalid(), K::invalid()),
                // Strings: YamlDotNet's node deserializer failures.
                None => ctx.classify(
                    error,
                    no_node_deserializer(&K::clr_type()),
                    conversion_failed(),
                ),
            })
    }
}

struct TextVisitor<'a, K> {
    ctx: &'a Ctx,
    marker: PhantomData<K>,
}

impl<'de, K: ScalarKind> Visitor<'de> for TextVisitor<'_, K> {
    type Value = K::Output;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a scalar")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<K::Output, E> {
        K::convert(value).ok_or_else(|| self.ctx.fail(K::invalid()))
    }
}
