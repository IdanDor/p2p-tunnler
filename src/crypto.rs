use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::NONCEBYTES;

use std::convert::TryFrom;

use base64::engine::{Engine, general_purpose};

use anyhow::{Result, anyhow};

use bytes::BufMut;

#[derive(Clone)]
pub struct PublicKey(pub box_::PublicKey);
#[derive(Clone)]
pub struct SecretKey(pub box_::SecretKey);

pub struct Sodiumoxide(box_::PrecomputedKey);

impl Sodiumoxide {
    pub fn new(their_pk: &PublicKey, our_sk: &SecretKey) -> Self {
        let precomputed_key = box_::precompute(&their_pk.0, &our_sk.0);
        Self(precomputed_key)
    }
}

pub fn generate_secret_key_base64() -> (SecretKey, String, PublicKey) {
    // Initialize sodiumoxide
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");

    // Generate key pair
    let (pk, sk) = box_::gen_keypair();

    let display = general_purpose::STANDARD.encode(&sk.0);

    // Convert secret key to Base64
    (SecretKey(sk), display, PublicKey(pk))
}

impl Sodiumoxide {
    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<bytes::Bytes> {
        let nonce = box_::gen_nonce();
        Ok(self.encrypt_with_nonce(plaintext, &nonce))
    }

    fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &box_::Nonce) -> bytes::Bytes {
        let ciphertext = box_::seal_precomputed(plaintext, nonce, &self.0);

        let mut buf = bytes::BytesMut::new();
        buf.put(&nonce.0[..]);
        buf.put(&ciphertext[..]);

        buf.freeze()
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < NONCEBYTES {
            dbg!("Decryption failed");
            return None;
        }
        let (nonce, ciphertext) = ciphertext.split_at(NONCEBYTES);

        if let Some(nonce) = box_::Nonce::from_slice(nonce) {
            let r = box_::open_precomputed(ciphertext, &nonce, &self.0);
            if r.is_err() {
                dbg!("Decryption failed");
            }
            r.ok()
        } else {
            None
        }
    }
}

impl PublicKey {
    pub fn new(buf: [u8; 32]) -> Self {
        Self(box_::PublicKey(buf))
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        // Decode Base64
        let bytes = general_purpose::STANDARD
            .decode(value)
            .map_err(|e| anyhow!("Base64 decode error: {}", e))?;

        if bytes.len() != 32 {
            return Err(anyhow!("Invalid length: expected 32, got {}", bytes.len()));
        }

        // Convert Vec<u8> -> [u8; 32], panic on bad length
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(PublicKey::new(array))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "{}", general_purpose::STANDARD.encode(self.0.0))
    }
}

impl SecretKey {
    pub fn new(buf: [u8; 32]) -> Self {
        Self(box_::SecretKey(buf))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }
}

impl TryFrom<&str> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        // Decode Base64
        let bytes = general_purpose::STANDARD
            .decode(value)
            .map_err(|e| anyhow!("Base64 decode error: {}", e))?;

        if bytes.len() != 32 {
            return Err(anyhow!("Invalid length: expected 32, got {}", bytes.len()));
        }

        // Convert Vec<u8> -> [u8; 32], panic on bad length
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(SecretKey::new(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_CRYPTO_BOX_FIXTURE: &str =
        "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzpWED4HGlH8yRoxt9BCfpllp5qfjdkM0Y6OY7RfCMsjCPcg==";

    #[test]
    fn matches_the_legacy_crypto_box_fixture() {
        sodiumoxide::init().unwrap();
        let our_secret = SecretKey::new([0x11; 32]);
        let their_secret = SecretKey::new([0x22; 32]);
        let their_public = their_secret.public_key();
        let crypto = Sodiumoxide::new(&their_public, &our_secret);
        let nonce = box_::Nonce([0x33; NONCEBYTES]);

        let encrypted = crypto.encrypt_with_nonce(b"legacy DHT fixture", &nonce);
        assert_eq!(
            general_purpose::STANDARD.encode(&encrypted),
            LEGACY_CRYPTO_BOX_FIXTURE
        );

        let fixture = general_purpose::STANDARD
            .decode(LEGACY_CRYPTO_BOX_FIXTURE)
            .unwrap();
        assert_eq!(
            crypto.decrypt(&fixture).as_deref(),
            Some(b"legacy DHT fixture".as_slice())
        );
    }
}
