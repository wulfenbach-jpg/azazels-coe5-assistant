//! Signs an unsigned update manifest for the Assistant's update channel.
//!
//! The Assistant fetches `update.json` from the latest GitHub release and
//! verifies its Ed25519 signature against the public key stored in the
//! user's `config.toml` (`update.public_key_base64`). This tool signs an
//! unsigned JSON manifest so the release pipeline can publish updates.
//!
//! Usage:
//! ```text
//! update-signer <private-key-base64> <unsigned.json> <signed.json>
//! ```
//!
//! The unsigned manifest is the [`SignedUpdate`] shape serialized by the
//! Assistant:
//! ```json
//! {
//!   "version": "0.1.0",
//!   "release_notes_url": "https://github.com/…/releases/tag/v0.1.0",
//!   "artifacts": [{
//!     "target": "x86_64-pc-windows-msvc",
//!     "kind": "portable_zip",
//!     "url": "https://github.com/…/releases/download/v0.1.0/….zip",
//!     "size": 123456,
//!     "sha256": "…"
//!   }]
//! }
//! ```
//!
//! The private key is the 32-byte Ed25519 seed, base64-encoded. Derive the
//! matching public key for `config.toml` with `--print-public-key`.

use std::{env, fs, path::Path};

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedUpdate {
    version: Version,
    release_notes_url: String,
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Artifact {
    target: String,
    kind: String,
    url: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct Envelope {
    signed: SignedUpdate,
    signature_base64: String,
}

fn main() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 2 && args[0] == "--print-public-key" {
        let key = parse_key(&args[1])?;
        println!(
            "{}",
            STANDARD.encode(VerifyingKey::from(&key).to_bytes())
        );
        return Ok(());
    }
    if args.len() != 3 {
        return Err(format!(
            "usage: {} <private-key-base64> <unsigned.json> <signed.json>",
            env::args().next().unwrap_or_default()
        ));
    }
    let key = parse_key(&args[0])?;
    let source = fs::read_to_string(&args[1]).map_err(|e| format!("read {}: {e}", args[1]))?;
    let signed: SignedUpdate =
        serde_json::from_str(&source).map_err(|e| format!("parse {}: {e}", args[1]))?;
    let payload =
        serde_json::to_vec(&signed).map_err(|e| format!("serialize signed payload: {e}"))?;
    let signature = key.sign(&payload);
    let envelope = Envelope {
        signed,
        signature_base64: STANDARD.encode(signature.to_bytes()),
    };
    let output = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| format!("serialize envelope: {e}"))?;
    fs::write(Path::new(&args[2]), output).map_err(|e| format!("write {}: {e}", args[2]))?;
    println!("signed {} bytes -> {}", payload.len(), args[2]);
    Ok(())
}

fn parse_key(base64: &str) -> Result<SigningKey, String> {
    let bytes = STANDARD
        .decode(base64)
        .map_err(|e| format!("decode private key: {e}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|value: Vec<u8>| format!("private key is {} bytes, expected 32", value.len()))?;
    Ok(SigningKey::from_bytes(&seed))
}
