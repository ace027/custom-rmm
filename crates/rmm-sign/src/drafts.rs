//! Parsing JSON drafts into typed trust documents and rendering decoded
//! payloads back to pretty JSON.

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{ArtifactRevocations, Command, TechnicianList, TrustManifest, decode_doc};
use rmm_trust::envelope::{TYPE_COMMAND, TYPE_MANIFEST, TYPE_REVOCATIONS, TYPE_TECHLIST};
use rmm_trust::error::TrustError;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The document kinds this tool can sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DocType {
    /// Trust manifest.
    Manifest,
    /// Artifact revocation list.
    Revocations,
    /// Technician list.
    Techlist,
    /// Command.
    Command,
}

impl DocType {
    /// The envelope type string bound into signatures.
    pub fn type_string(self) -> &'static str {
        match self {
            Self::Manifest => TYPE_MANIFEST,
            Self::Revocations => TYPE_REVOCATIONS,
            Self::Techlist => TYPE_TECHLIST,
            Self::Command => TYPE_COMMAND,
        }
    }

    /// Inverse of [`Self::type_string`].
    pub fn from_type_string(s: &str) -> Option<Self> {
        [
            Self::Manifest,
            Self::Revocations,
            Self::Techlist,
            Self::Command,
        ]
        .into_iter()
        .find(|t| t.type_string() == s)
    }
}

/// A validated draft in canonical form.
#[derive(Debug, Clone)]
pub struct Draft {
    /// Canonical CBOR payload.
    pub payload: Vec<u8>,
    /// Pretty JSON of the document, as decoded from `payload`.
    pub pretty: String,
}

fn build<T: Serialize + DeserializeOwned>(
    json: &str,
    validate: fn(&T) -> Result<(), TrustError>,
) -> Result<Draft> {
    let doc: T = serde_json::from_str(json).context("invalid draft")?;
    validate(&doc).map_err(|e| anyhow!("draft failed validation: {e}"))?;
    let payload = to_canonical_vec(&doc).map_err(|e| anyhow!("cannot encode draft: {e}"))?;
    let pretty = pretty::<T>(&payload)?;
    Ok(Draft { payload, pretty })
}

fn pretty<T: Serialize + DeserializeOwned>(payload: &[u8]) -> Result<String> {
    let doc: T = decode_doc(payload).map_err(|e| anyhow!("cannot decode payload: {e}"))?;
    Ok(serde_json::to_string_pretty(&doc)?)
}

/// Parse and validate a JSON draft and encode it canonically.
pub fn load_draft(ty: DocType, json: &str) -> Result<Draft> {
    match ty {
        DocType::Manifest => build::<TrustManifest>(json, TrustManifest::validate),
        DocType::Revocations => build::<ArtifactRevocations>(json, ArtifactRevocations::validate),
        DocType::Techlist => build::<TechnicianList>(json, TechnicianList::validate),
        DocType::Command => build::<Command>(json, Command::validate),
    }
}

/// Decode an envelope payload of type `ty` to pretty JSON.
pub fn pretty_payload(ty: DocType, payload: &[u8]) -> Result<String> {
    match ty {
        DocType::Manifest => pretty::<TrustManifest>(payload),
        DocType::Revocations => pretty::<ArtifactRevocations>(payload),
        DocType::Techlist => pretty::<TechnicianList>(payload),
        DocType::Command => pretty::<Command>(payload),
    }
}
