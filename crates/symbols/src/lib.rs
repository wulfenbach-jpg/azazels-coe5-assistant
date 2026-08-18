use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

const COE5_5_39: &str = include_str!("../../../manifests/coe5-5.39.json");

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("invalid embedded symbol manifest: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid RVA '{0}'")]
    InvalidRva(String),
    #[error("invalid signature pattern: {0}")]
    InvalidSignature(String),
    #[error("unknown function symbol '{0}'")]
    UnknownFunction(String),
    #[error("unknown global symbol '{0}'")]
    UnknownGlobal(String),
    #[error("signature mismatch for '{symbol}' at RVA {rva}")]
    SignatureMismatch { symbol: String, rva: Rva },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rva(pub u64);

impl std::fmt::Display for Rva {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "0x{:x}", self.0)
    }
}

impl Serialize for Rva {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Rva {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let digits = value
            .strip_prefix("0x")
            .ok_or_else(|| de::Error::custom(format!("RVA must begin with 0x: {value}")))?;
        u64::from_str_radix(digits, 16)
            .map(Self)
            .map_err(|_| de::Error::custom(format!("invalid RVA: {value}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    pub schema_version: u32,
    pub target: BuildFingerprint,
    pub functions: Vec<FunctionSymbol>,
    pub globals: Vec<GlobalSymbol>,
    pub disabled_capabilities: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildFingerprint {
    pub product: String,
    pub version: String,
    pub architecture: String,
    pub sha256: String,
    pub image_base: Rva,
    pub file_size: u64,
    pub size_of_image: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSymbol {
    pub id: String,
    pub rva: Rva,
    pub size: u64,
    pub subsystem: String,
    pub semantic_tier: SemanticTier,
    pub confidence: Confidence,
    pub signature: SignatureSpec,
    pub capabilities: Vec<String>,
    pub invariants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSymbol {
    pub id: String,
    pub rva: Rva,
    pub data_type: String,
    pub size: Option<u64>,
    pub subsystem: String,
    pub semantic_tier: SemanticTier,
    pub confidence: Confidence,
    pub capabilities: Vec<String>,
    pub invariants: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SemanticTier {
    Inventory,
    Classified,
    Typed,
    Validated,
    Exported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Unknown,
    Provisional,
    High,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSpec {
    pub pattern: String,
    pub mask: String,
    pub section: String,
}

impl BuildManifest {
    pub fn embedded_5_39() -> Result<Self, ManifestError> {
        Ok(serde_json::from_str(COE5_5_39)?)
    }

    pub fn supports_sha256(&self, sha256: &str) -> bool {
        self.target.sha256.eq_ignore_ascii_case(sha256)
    }

    pub fn function(&self, id: &str) -> Result<&FunctionSymbol, ManifestError> {
        self.functions
            .iter()
            .find(|symbol| symbol.id == id)
            .ok_or_else(|| ManifestError::UnknownFunction(id.to_owned()))
    }

    pub fn global(&self, id: &str) -> Result<&GlobalSymbol, ManifestError> {
        self.globals
            .iter()
            .find(|symbol| symbol.id == id)
            .ok_or_else(|| ManifestError::UnknownGlobal(id.to_owned()))
    }

    pub fn capability_disabled_reason(&self, capability: &str) -> Option<&str> {
        self.disabled_capabilities
            .get(capability)
            .map(String::as_str)
    }

    pub fn validate_function_bytes(&self, id: &str, actual: &[u8]) -> Result<(), ManifestError> {
        let symbol = self.function(id)?;
        let signature = ParsedSignature::parse(&symbol.signature)?;
        if signature.matches(actual) {
            Ok(())
        } else {
            Err(ManifestError::SignatureMismatch {
                symbol: id.to_owned(),
                rva: symbol.rva,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignature {
    bytes: Vec<u8>,
    mask: Vec<bool>,
}

impl ParsedSignature {
    pub fn parse(spec: &SignatureSpec) -> Result<Self, ManifestError> {
        let bytes = spec
            .pattern
            .split_ascii_whitespace()
            .map(|byte| {
                u8::from_str_radix(byte, 16)
                    .map_err(|_| ManifestError::InvalidSignature(format!("invalid byte '{byte}'")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if bytes.len() != spec.mask.len() {
            return Err(ManifestError::InvalidSignature(format!(
                "pattern has {} bytes but mask has {} entries",
                bytes.len(),
                spec.mask.len()
            )));
        }
        let mask = spec
            .mask
            .chars()
            .map(|entry| match entry {
                'x' | 'X' => Ok(true),
                '?' => Ok(false),
                other => Err(ManifestError::InvalidSignature(format!(
                    "unsupported mask entry '{other}'"
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { bytes, mask })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn matches(&self, actual: &[u8]) -> bool {
        actual.len() >= self.bytes.len()
            && self
                .bytes
                .iter()
                .zip(&self.mask)
                .zip(actual)
                .all(|((expected, compare), actual)| !compare || expected == actual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_manifest_has_reviewed_symbols() {
        let manifest = BuildManifest::embedded_5_39().unwrap();
        assert_eq!(manifest.target.version, "5.39");
        assert_eq!(manifest.functions.len(), 22);
        assert_eq!(manifest.globals.len(), 44);
        assert!(manifest.function("world_reset_static_state").is_ok());
        assert_eq!(
            manifest.capability_disabled_reason("internal.restart"),
            Some(
                "dynamic teardown, restore-order, RNG, and repeated-cycle invariants are incomplete"
            )
        );
    }

    #[test]
    fn signature_mask_supports_exact_and_wildcard_bytes() {
        let signature = ParsedSignature::parse(&SignatureSpec {
            pattern: "48 8b 00 ff".into(),
            mask: "xx?x".into(),
            section: ".text".into(),
        })
        .unwrap();
        assert!(signature.matches(&[0x48, 0x8b, 0x99, 0xff]));
        assert!(!signature.matches(&[0x48, 0x89, 0x99, 0xff]));
        assert!(!signature.matches(&[0x48, 0x8b]));
    }

    #[test]
    fn rva_round_trips_as_hex() {
        let encoded = serde_json::to_string(&Rva(0x1c6d10)).unwrap();
        assert_eq!(encoded, "\"0x1c6d10\"");
        assert_eq!(
            serde_json::from_str::<Rva>(&encoded).unwrap(),
            Rva(0x1c6d10)
        );
    }
}
