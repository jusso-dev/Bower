//! A small YAML representation model (YamlDotNet `RepresentationModel` equivalent).
//!
//! Scalars keep their text. Strings and integers round-trip exactly; booleans, floats
//! and nulls are resolved by the YAML parser first, so `True` reads as `true`, `1.10`
//! as `1.1` and `~` as an empty scalar (YamlDotNet keeps the source text).

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum YamlNode {
    Scalar(String),
    TypedScalar(String),
    Sequence(Vec<YamlNode>),
    Mapping(Vec<(YamlNode, YamlNode)>),
}

impl YamlNode {
    /// `YamlNode.ToString()`: the value for scalars.
    pub fn text(&self) -> String {
        match self {
            Self::Scalar(value) => value.clone(),
            Self::TypedScalar(value) => value.get(2..).unwrap_or("").to_owned(),
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

struct NodeVisitor {
    depth: usize,
    remaining: std::rc::Rc<std::cell::Cell<usize>>,
}

impl<'de> serde::de::DeserializeSeed<'de> for NodeVisitor {
    type Value = YamlNode;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<YamlNode, D::Error> {
        if self.depth > 32 || self.remaining.get() == 0 {
            return Err(de::Error::custom("YAML complexity limit exceeded."));
        }
        self.remaining.set(self.remaining.get() - 1);
        deserializer.deserialize_any(self)
    }
}

impl NodeVisitor {
    fn child(&self) -> Self {
        Self {
            depth: self.depth + 1,
            remaining: self.remaining.clone(),
        }
    }
}

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = YamlNode;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a YAML node")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<YamlNode, E> {
        Ok(YamlNode::TypedScalar(format!("b:{value}")))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<YamlNode, E> {
        Ok(YamlNode::TypedScalar(format!("n:{value}")))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<YamlNode, E> {
        Ok(YamlNode::TypedScalar(format!("n:{value}")))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<YamlNode, E> {
        Ok(YamlNode::TypedScalar(format!("n:{value}")))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<YamlNode, E> {
        Ok(YamlNode::TypedScalar(format!("n:{value}")))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<YamlNode, E> {
        Ok(YamlNode::TypedScalar(format!("f:{value}")))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<YamlNode, E> {
        Ok(YamlNode::Scalar(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<YamlNode, E> {
        Ok(YamlNode::TypedScalar(String::new()))
    }

    fn visit_none<E: de::Error>(self) -> Result<YamlNode, E> {
        Ok(YamlNode::TypedScalar(String::new()))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<YamlNode, D::Error> {
        serde::de::DeserializeSeed::deserialize(self.child(), deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<YamlNode, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self.child())? {
            items.push(item);
        }
        Ok(YamlNode::Sequence(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<YamlNode, A::Error> {
        let mut entries = Vec::new();
        while let Some(key) = map.next_key_seed(self.child())? {
            let YamlNode::Scalar(ref text) = key else {
                return Err(de::Error::custom("YAML mapping keys must be strings."));
            };
            if entries.iter().any(|(k, _): &(YamlNode, YamlNode)| {
                crate::ordinal::eq_ignore_case(&k.text(), text)
            }) {
                return Err(de::Error::custom("Duplicate YAML mapping key."));
            }
            let value = map.next_value_seed(self.child())?;
            entries.push((key, value));
        }
        Ok(YamlNode::Mapping(entries))
    }
}

impl<'de> Deserialize<'de> for YamlNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::DeserializeSeed::deserialize(
            NodeVisitor {
                depth: 0,
                remaining: std::rc::Rc::new(std::cell::Cell::new(8192)),
            },
            deserializer,
        )
    }
}
