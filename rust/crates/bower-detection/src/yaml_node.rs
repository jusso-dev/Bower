//! A small YAML representation model (YamlDotNet `RepresentationModel` equivalent).
//!
//! Scalars keep their text. Strings and integers round-trip exactly; booleans, floats
//! and nulls are resolved by the YAML parser first, so `True` reads as `true`, `1.10`
//! as `1.1` and `~` as an empty scalar (YamlDotNet keeps the source text).

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum YamlNode {
    Scalar(String),
    Sequence(Vec<YamlNode>),
    Mapping(Vec<(YamlNode, YamlNode)>),
}

impl YamlNode {
    /// `YamlNode.ToString()`: the value for scalars.
    pub fn text(&self) -> String {
        match self {
            Self::Scalar(value) => value.clone(),
            Self::Sequence(items) => {
                format!(
                    "[ {} ]",
                    items.iter().map(Self::text).collect::<Vec<_>>().join(", ")
                )
            }
            Self::Mapping(entries) => format!(
                "{{ {} }}",
                entries
                    .iter()
                    .map(|(key, value)| format!("{{ {}, {} }}", key.text(), value.text()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Mapping lookup by scalar key (exact, case-sensitive). The first match wins.
    pub fn get(&self, key: &str) -> Option<&YamlNode> {
        match self {
            Self::Mapping(entries) => entries
                .iter()
                .find(|(candidate, _)| matches!(candidate, Self::Scalar(text) if text == key))
                .map(|(_, value)| value),
            _ => None,
        }
    }
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = YamlNode;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a YAML node")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value.to_string()))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value.to_string()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value.to_string()))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value.to_string()))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value.to_string()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value.to_string()))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(String::new()))
    }

    fn visit_none<E: de::Error>(self) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(String::new()))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<YamlNode, D::Error> {
        YamlNode::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<YamlNode, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(YamlNode::Sequence(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<YamlNode, A::Error> {
        let mut entries = Vec::new();
        while let Some((key, value)) = map.next_entry()? {
            entries.push((key, value));
        }
        Ok(YamlNode::Mapping(entries))
    }
}

impl<'de> Deserialize<'de> for YamlNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeVisitor)
    }
}
