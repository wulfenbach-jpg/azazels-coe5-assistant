use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEnvelope {
    pub signed: SignedUpdate,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedUpdate {
    pub version: Version,
    pub release_notes_url: String,
    pub artifacts: Vec<UpdateArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateArtifact {
    pub target: String,
    pub kind: ArtifactKind,
    pub url: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    PortableZip,
    Msi,
}

impl UpdateEnvelope {
    pub fn verify(&self, public_key_base64: &str) -> Result<()> {
        let public_key = STANDARD
            .decode(public_key_base64)
            .context("decode update public key")?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|value: Vec<u8>| {
            anyhow::anyhow!("public key is {} bytes, expected 32", value.len())
        })?;
        let signature = STANDARD
            .decode(&self.signature_base64)
            .context("decode update signature")?;
        let signature: [u8; 64] = signature.try_into().map_err(|value: Vec<u8>| {
            anyhow::anyhow!("signature is {} bytes, expected 64", value.len())
        })?;
        let key = VerifyingKey::from_bytes(&public_key).context("parse update public key")?;
        if key.is_weak() {
            bail!("update public key is weak");
        }
        let payload = serde_json::to_vec(&self.signed)?;
        key.verify_strict(&payload, &Signature::from_bytes(&signature))
            .context("verify update signature")
    }
}

pub fn verify_artifact(path: &Path, artifact: &UpdateArtifact) -> Result<()> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() != artifact.size {
        bail!(
            "artifact size mismatch: expected {}, found {}",
            artifact.size,
            metadata.len()
        );
    }
    let file = File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !actual.eq_ignore_ascii_case(&artifact.sha256) {
        bail!(
            "artifact SHA-256 mismatch: expected {}, found {actual}",
            artifact.sha256
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[test]
    fn verifies_deterministic_signed_payload() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = SignedUpdate {
            version: Version::new(1, 2, 3),
            release_notes_url: "https://example.invalid/notes".into(),
            artifacts: vec![UpdateArtifact {
                target: "x86_64-pc-windows-msvc".into(),
                kind: ArtifactKind::PortableZip,
                url: "https://example.invalid/assistant.zip".into(),
                size: 42,
                sha256: "00".repeat(32),
            }],
        };
        let payload = serde_json::to_vec(&signed).unwrap();
        let envelope = UpdateEnvelope {
            signature_base64: STANDARD.encode(key.sign(&payload).to_bytes()),
            signed,
        };
        envelope
            .verify(&STANDARD.encode(key.verifying_key().to_bytes()))
            .unwrap();
    }

    #[test]
    fn changed_payload_fails_verification() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let original = SignedUpdate {
            version: Version::new(1, 0, 0),
            release_notes_url: "https://example.invalid/notes".into(),
            artifacts: vec![],
        };
        let signature = key.sign(&serde_json::to_vec(&original).unwrap());
        let mut tampered = original;
        tampered.version = Version::new(2, 0, 0);
        let envelope = UpdateEnvelope {
            signed: tampered,
            signature_base64: STANDARD.encode(signature.to_bytes()),
        };
        assert!(
            envelope
                .verify(&STANDARD.encode(key.verifying_key().to_bytes()))
                .is_err()
        );
    }
}
