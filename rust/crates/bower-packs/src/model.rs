//! Pack source (`pack.yaml`) and the signed manifest (`PackModel.cs`).

use bower_contracts::time::{Timestamp, format_json, serde_offset};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// `pack.yaml`: the author-facing description of a pack's source directory.
/// Unknown keys are rejected, as YamlDotNet does by default.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackSource {
    pub api_version: String,
    pub kind: String,
    pub metadata: PackSourceMetadata,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub privacy_profile: Option<String>,
    #[serde(default)]
    pub parsers: Vec<String>,
    #[serde(default)]
    pub detections: Vec<String>,
    #[serde(default)]
    pub samples: Vec<String>,
    /// Include a generated DCR/table ARM template.
    #[serde(default)]
    pub dcr: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackSourceMetadata {
    pub id: String,
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub owner: String,
}

/// `PackRoles`.
pub mod roles {
    pub const POLICY: &str = "policy";
    pub const PRIVACY_PROFILE: &str = "privacy-profile";
    pub const PARSER: &str = "parser";
    pub const DETECTION: &str = "detection";
    pub const SAMPLE: &str = "sample";
    pub const DCR: &str = "dcr";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackFile {
    pub path: String,
    pub role: String,
    pub sha256: String,
    pub bytes: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackPolicyEntry {
    pub id: String,
    pub version: String,
    pub hash: String,
    #[serde(rename = "eventTypes")]
    pub event_types: Vec<String>,
}

/// The signed manifest. Every file in the archive is listed with its hash.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackManifest {
    pub api_version: String,
    pub kind: String,
    pub id: String,
    pub version: String,
    pub name: String,
    pub description: Option<String>,
    pub owner: String,
    #[serde(with = "serde_offset")]
    pub created_at: Timestamp,
    pub files: Vec<PackFile>,
    pub policies: Vec<PackPolicyEntry>,
    pub pack_hash: String,
}

impl PackManifest {
    pub const CURRENT_KIND: &str = "PackManifest";

    /// `JsonSerializer.SerializeToNode(manifest)`: C# property order, nulls written.
    /// Sign and verify its canonical bytes (`bower_integrity::canonical_json`).
    pub fn to_json(&self) -> Value {
        json!({
            "apiVersion": self.api_version,
            "kind": self.kind,
            "id": self.id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "owner": self.owner,
            "createdAt": format_json(&self.created_at),
            "files": self.files.iter().map(|file| json!({
                "path": file.path,
                "role": file.role,
                "sha256": file.sha256,
                "bytes": file.bytes,
            })).collect::<Vec<_>>(),
            "policies": self.policies.iter().map(|policy| json!({
                "id": policy.id,
                "version": policy.version,
                "hash": policy.hash,
                "eventTypes": policy.event_types,
            })).collect::<Vec<_>>(),
            "packHash": self.pack_hash,
        })
    }

    /// Canonical JSON bytes: exactly what is signed and stored as `manifest.json`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        bower_integrity::canonical_json::bytes(&self.to_json())
    }
}
