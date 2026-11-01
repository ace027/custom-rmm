//! Parsing JSON drafts into typed trust documents and rendering decoded
//! payloads back to pretty JSON.

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use rmm_proto::canonical::to_canonical_vec;
use rmm_recipe::definition::{Definition, TYPE_DEFINITION};
use rmm_recipe::validate::{BLOCKS, validate_definition};
use rmm_trust::docs::{
    ArtifactRevocations, Command, ReleaseManifest, TechnicianList, TrustManifest, decode_doc,
};
use rmm_trust::envelope::{
    TYPE_COMMAND, TYPE_MANIFEST, TYPE_RELEASE, TYPE_REVOCATIONS, TYPE_TECHLIST,
};
use rmm_trust::error::TrustError;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::aaguid;

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
    /// Catalog action definition.
    Definition,
    /// Release manifest (draft `sha256` values are hex).
    Release,
}

impl DocType {
    /// The envelope type string bound into signatures.
    pub fn type_string(self) -> &'static str {
        match self {
            Self::Manifest => TYPE_MANIFEST,
            Self::Revocations => TYPE_REVOCATIONS,
            Self::Techlist => TYPE_TECHLIST,
            Self::Command => TYPE_COMMAND,
            Self::Definition => TYPE_DEFINITION,
            Self::Release => TYPE_RELEASE,
        }
    }

    /// Inverse of [`Self::type_string`].
    pub fn from_type_string(s: &str) -> Option<Self> {
        [
            Self::Manifest,
            Self::Revocations,
            Self::Techlist,
            Self::Command,
            Self::Definition,
            Self::Release,
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

/// Parse (rejecting unknown fields), statically validate against the block
/// registry and canonically encode an action definition.
fn build_definition(json: &str) -> Result<Draft> {
    let def: Definition = serde_json::from_str(json).context("invalid draft")?;
    validate_definition(&def, BLOCKS).map_err(|e| anyhow!("draft failed validation: {e}"))?;
    let payload = def
        .to_canonical()
        .map_err(|e| anyhow!("cannot encode draft: {e}"))?;
    let pretty = pretty_definition(&payload)?;
    Ok(Draft { payload, pretty })
}

fn pretty_definition(payload: &[u8]) -> Result<String> {
    let def = Definition::from_envelope_payload(payload)
        .map_err(|e| anyhow!("cannot decode payload: {e}"))?;
    Ok(serde_json::to_string_pretty(&def)?)
}

/// Parse and validate a JSON draft and encode it canonically.
pub fn load_draft(ty: DocType, json: &str) -> Result<Draft> {
    match ty {
        DocType::Manifest => build::<TrustManifest>(json, TrustManifest::validate),
        DocType::Revocations => build::<ArtifactRevocations>(json, ArtifactRevocations::validate),
        DocType::Techlist => build::<TechnicianList>(json, TechnicianList::validate),
        DocType::Command => build::<Command>(json, Command::validate),
        DocType::Definition => build_definition(json),
        DocType::Release => build::<ReleaseManifest>(json, ReleaseManifest::validate),
    }
}

/// Decode an envelope payload of type `ty` to pretty JSON.
pub fn pretty_payload(ty: DocType, payload: &[u8]) -> Result<String> {
    match ty {
        DocType::Manifest => pretty::<TrustManifest>(payload),
        DocType::Revocations => pretty::<ArtifactRevocations>(payload),
        DocType::Techlist => pretty::<TechnicianList>(payload),
        DocType::Command => pretty::<Command>(payload),
        DocType::Definition => pretty_definition(payload),
        DocType::Release => pretty::<ReleaseManifest>(payload),
    }
}

/// Hardware-only gate for technician lists: every technician needs at least
/// one credential, and every credential's AAGUID must be 16 bytes and either
/// a compiled YubiKey 5 AAGUID or one of `extra` (`--allow-aaguid`).
pub fn check_techlist_hardware(json: &str, extra: &[[u8; 16]]) -> Result<()> {
    let tl: TechnicianList = serde_json::from_str(json).context("invalid draft")?;
    for tech in &tl.techs {
        if tech.creds.is_empty() {
            bail!(
                "technician {:?} has no credentials; a techlist entry needs a hardware key",
                tech.tech_id
            );
        }
        for cred in &tech.creds {
            let raw = &cred.aaguid.0;
            let Ok(a) = <[u8; 16]>::try_from(raw.as_slice()) else {
                bail!(
                    "technician {:?}: credential aaguid {} is not 16 bytes",
                    tech.tech_id,
                    hex::encode(raw)
                );
            };
            if !aaguid::is_allowed(&a, extra) {
                bail!(
                    "technician {:?}: credential aaguid {} is not an allowlisted hardware \
                     authenticator (YubiKey 5 series, or pass --allow-aaguid {})",
                    tech.tech_id,
                    aaguid::format(&a),
                    hex::encode(a)
                );
            }
        }
    }
    Ok(())
}
