use std::convert::TryFrom;

use anyhow::{Result, anyhow};
use base64::engine::{Engine, general_purpose};
use bytes::BufMut;
use crypto_box::{
    Nonce, PublicKey as CryptoBoxPublicKey, SalsaBox, SecretKey as CryptoBoxSecretKey,
    aead::{Aead, AeadCore, OsRng},
};

const NONCE_BYTES: usize = 24;

#[derive(Clone)]
pub struct PublicKey(CryptoBoxPublicKey);

#[derive(Clone)]
pub struct SecretKey(CryptoBoxSecretKey);

pub struct CryptoBox(SalsaBox);

impl CryptoBox {
    pub fn new(their_public_key: &PublicKey, our_secret_key: &SecretKey) -> Self {
        Self(SalsaBox::new(&their_public_key.0, &our_secret_key.0))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<bytes::Bytes> {
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        self.encrypt_with_nonce(plaintext, &nonce)
    }

    fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &Nonce) -> Result<bytes::Bytes> {
        let ciphertext = self
            .0
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("crypto_box encryption failed"))?;

        let mut value = bytes::BytesMut::with_capacity(NONCE_BYTES + ciphertext.len());
        value.put_slice(nonce.as_slice());
        value.put_slice(&ciphertext);
        Ok(value.freeze())
    }

    pub fn decrypt(&self, encrypted_value: &[u8]) -> Option<Vec<u8>> {
        if encrypted_value.len() < NONCE_BYTES {
            return None;
        }

        let (nonce, ciphertext) = encrypted_value.split_at(NONCE_BYTES);
        self.0.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
    }
}

pub fn generate_secret_key_base64() -> (SecretKey, String, PublicKey) {
    let secret_key = CryptoBoxSecretKey::generate(&mut OsRng);
    let encoded_secret_key = general_purpose::STANDARD.encode(secret_key.to_bytes());
    let public_key = PublicKey(secret_key.public_key());

    (SecretKey(secret_key), encoded_secret_key, public_key)
}

impl PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(CryptoBoxPublicKey::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

fn decode_base64_key(value: &str) -> Result<[u8; 32]> {
    let bytes = general_purpose::STANDARD
        .decode(value)
        .map_err(|error| anyhow!("Base64 decode error: {error}"))?;
    let length = bytes.len();

    bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid length: expected 32, got {length}"))
}

impl TryFrom<&str> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        Ok(Self::new(decode_base64_key(value)?))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}",
            general_purpose::STANDARD.encode(self.as_bytes())
        )
    }
}

impl SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(CryptoBoxSecretKey::from(bytes))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }
}

impl TryFrom<&str> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        Ok(Self::new(decode_base64_key(value)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_CRYPTO_BOX_FIXTURE: &str =
        "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzpWED4HGlH8yRoxt9BCfpllp5qfjdkM0Y6OY7RfCMsjCPcg==";

    #[test]
    fn matches_the_legacy_crypto_box_fixture() {
        let our_secret = SecretKey::new([0x11; 32]);
        let their_secret = SecretKey::new([0x22; 32]);
        let crypto = CryptoBox::new(&their_secret.public_key(), &our_secret);
        let mut nonce = Nonce::default();
        nonce.copy_from_slice(&[0x33; NONCE_BYTES]);

        let encrypted = crypto
            .encrypt_with_nonce(b"legacy DHT fixture", &nonce)
            .unwrap();
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
