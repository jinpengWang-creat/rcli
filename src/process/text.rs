use std::{fs, io::Read, path::Path};

use crate::{
    cli::{TextEncryptDecryptFormat, TextSignVerifyFormat},
    get_reader, process, TextKeyGenerateFormat,
};
use anyhow::{Ok, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead},
    AeadCore, ChaCha20Poly1305, KeyInit,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

pub trait TextSign {
    /// Sign the data from the reader and return the signature
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerify {
    /// Verify the data from the reader with the signature
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub trait KeyLoader {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized;
}

pub trait KeyGenerator {
    fn generate() -> Result<Vec<Vec<u8>>>;
}

pub struct Blake3 {
    key: [u8; 32],
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Blake3 { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into()?;
        let signer = Blake3::new(key);
        Ok(signer)
    }
}

impl KeyLoader for Blake3 {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl TextSign for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buff = Vec::new();
        reader.read_to_end(&mut buff)?;
        let hash = blake3::keyed_hash(&self.key, &buff);
        Ok(hash.as_bytes().to_vec())
    }
}

impl TextVerify for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buff = Vec::new();
        reader.read_to_end(&mut buff)?;
        let hash = blake3::keyed_hash(&self.key, &buff);
        let hash = hash.as_bytes();
        Ok(hash == sig)
    }
}

impl KeyGenerator for Blake3 {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = process::process_genpass(32, false, false, false, false)?;
        let key = key.as_bytes().to_vec();
        Ok(vec![key])
    }
}
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Ed25519Signer { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = SigningKey::from_bytes(key.try_into()?);
        let signer = Ed25519Signer::new(key);
        Ok(signer)
    }
}

impl KeyLoader for Ed25519Signer {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl TextSign for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buff = Vec::new();
        reader.read_to_end(&mut buff)?;
        let signature = self.key.sign(&buff);
        Ok(signature.to_bytes().to_vec())
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let mut cspring = OsRng;
        let sk = SigningKey::generate(&mut cspring);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.as_bytes().to_vec();
        Ok(vec![sk, pk])
    }
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    pub fn new(key: VerifyingKey) -> Self {
        Ed25519Verifier { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(key.try_into()?)?;
        let signer = Ed25519Verifier::new(key);
        Ok(signer)
    }
}

impl KeyLoader for Ed25519Verifier {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl TextVerify for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buff = Vec::new();
        reader.read_to_end(&mut buff)?;
        let sig = Signature::from_bytes(sig.try_into()?);
        let ret = self.key.verify(&buff, &sig).is_ok();
        Ok(ret)
    }
}
pub struct Chacha20poly1305 {
    key: [u8; 32],
}

impl Chacha20poly1305 {
    pub fn new(key: [u8; 32]) -> Self {
        Chacha20poly1305 { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = key.try_into()?;
        let signer = Chacha20poly1305::new(key);
        Ok(signer)
    }
}

impl KeyLoader for Chacha20poly1305 {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyGenerator for Chacha20poly1305 {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let mut merge_key = Vec::with_capacity(32);
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        merge_key.extend_from_slice(key.as_slice());
        Ok(vec![merge_key])
    }
}

pub fn process_text_sign(input: &str, key: &str, format: TextSignVerifyFormat) -> Result<Vec<u8>> {
    let mut reader = get_reader(input)?;

    let signed = match format {
        TextSignVerifyFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignVerifyFormat::Ed25519 => {
            let singer = Ed25519Signer::load(key)?;
            singer.sign(&mut reader)?
        }
    };
    Ok(signed)
}

pub fn process_text_verify(
    input: &str,
    key: &str,
    format: TextSignVerifyFormat,
    sign: &[u8],
) -> Result<bool> {
    let mut reader = get_reader(input)?;
    let signed = match format {
        TextSignVerifyFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.verify(&mut reader, sign)?
        }
        TextSignVerifyFormat::Ed25519 => {
            let singer = Ed25519Verifier::load(key)?;
            singer.verify(&mut reader, sign)?
        }
    };
    Ok(signed)
}

pub fn process_text_generate(format: TextKeyGenerateFormat) -> Result<Vec<Vec<u8>>> {
    match format {
        TextKeyGenerateFormat::Blake3 => Blake3::generate(),
        TextKeyGenerateFormat::Ed25519 => Ed25519Signer::generate(),
        TextKeyGenerateFormat::Chacha20poly1305 => Chacha20poly1305::generate(),
    }
}

pub fn process_text_encrypt(
    input: &str,
    key: &str,
    format: TextEncryptDecryptFormat,
) -> Result<Vec<u8>> {
    let mut reader = get_reader(input)?;
    let result = match format {
        TextEncryptDecryptFormat::Chacha20poly1305 => {
            let mut result = Vec::new();
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            result.extend_from_slice(nonce.as_slice());

            let chacha = Chacha20poly1305::load(key)?;
            let mut buff = Vec::new();
            reader.read_to_end(&mut buff)?;

            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&chacha.key));
            let ciphertext = cipher
                .encrypt(&nonce, buff.as_ref())
                .expect("Error to encrypt text!");
            result.extend_from_slice(&ciphertext);
            result
        }
    };

    Ok(result)
}

pub fn process_text_decrypt(
    input: &str,
    key: &str,
    format: TextEncryptDecryptFormat,
) -> Result<Vec<u8>> {
    let mut reader = get_reader(input)?;
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;
    let ciphertext = URL_SAFE_NO_PAD.decode(ciphertext)?;
    let plaintext = match format {
        TextEncryptDecryptFormat::Chacha20poly1305 => {
            let chacha = Chacha20poly1305::load(key)?;
            let key = GenericArray::from_slice(&chacha.key);
            let nonce = GenericArray::from_slice(&ciphertext[..12]);
            let cipher = ChaCha20Poly1305::new(key);
            cipher
                .decrypt(nonce, &ciphertext[12..])
                .expect("Error to decrypt text!")
        }
    };
    Ok(plaintext)
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_ed25519_sign_verify() -> Result<()> {
        let sk = Ed25519Signer::load("fixtures/ed25519.sk")?;
        let pk = Ed25519Verifier::load("fixtures/ed25519.pk")?;

        let data = b"hello world";
        let sig = sk.sign(&mut &data[..])?;
        assert!(pk.verify(&mut &data[..], &sig)?);
        Ok(())
    }

    #[test]
    fn test_chacha20poly1305_quick() {
        use chacha20poly1305::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            ChaCha20Poly1305,
        };
        use std::result::Result::Ok;

        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, b"plaintext message".as_ref())
            .unwrap();
        println!("{:?}", ciphertext);
        let cipher = ChaCha20Poly1305::new(&key);
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref());
        println!("{:?}", plaintext);
        if let Ok(msg) = plaintext {
            println!("{:?}", String::from_utf8_lossy(&msg));
        }
    }
}
