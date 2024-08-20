use std::{fs, io::Read, path::Path};

use anyhow::anyhow;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    AeadCore, ChaCha20Poly1305,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::{get_reader, process_genpass, standard_decode, standard_encode, TextSignFormat};

pub trait TextEncrypt {
    fn encrypt(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>>;
}

pub trait TextDecrypt {
    fn decrypt(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>>;
}

pub trait TextSign {
    /// sign the data from the reader and return the signature
    fn sign(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>>;
}

pub trait TextVerify {
    /// verify the data from the reader with the signature
    fn verify(&self, reader: impl Read, sig: &[u8]) -> anyhow::Result<bool>;
}
pub trait KeyLoader {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self>
    where
        Self: Sized;
}

pub trait KeyGenerator {
    fn generate() -> anyhow::Result<Vec<Vec<u8>>>;
}
pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

#[derive(Debug)]
pub struct Encryptor {
    key: [u8; 32],
}

pub fn process_text_decrypt(input: &str, key: &str) -> anyhow::Result<String> {
    let mut reader = get_reader(input)?;
    let designature = {
        let signer = Encryptor::load(key)?;
        signer.decrypt(&mut reader)?
    };
    Ok(String::from_utf8_lossy(&designature).to_string())
}

pub fn process_text_encrypt(input: &str, key: &str) -> anyhow::Result<String> {
    let mut reader = get_reader(input)?;
    let signature = {
        let signer = Encryptor::load(key)?;
        signer.encrypt(&mut reader)?
    };
    standard_encode(signature)
}
pub fn process_text_sign(input: &str, key: &str, format: TextSignFormat) -> anyhow::Result<String> {
    let mut reader = get_reader(input)?;
    let signature = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Signer::load(key)?;
            signer.sign(&mut reader)?
        }
    };
    let signed = URL_SAFE_NO_PAD.encode(signature);
    Ok(signed)
}

pub fn process_text_verify(
    input: &str,
    key: &str,
    format: TextSignFormat,
    sig: &str,
) -> anyhow::Result<bool> {
    let mut reader = get_reader(input)?;
    let signature = URL_SAFE_NO_PAD.decode(sig.trim())?;
    let verified = match format {
        TextSignFormat::Blake3 => {
            let verifier = Blake3::load(key)?;
            verifier.verify(&mut reader, &signature)?
        }
        TextSignFormat::Ed25519 => {
            let verifier = Ed25519Verifier::load(key)?;
            verifier.verify(&mut reader, &signature)?
        }
    };

    Ok(verified)
}

pub fn process_text_generate(format: TextSignFormat) -> anyhow::Result<Vec<Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

impl TextEncrypt for Encryptor {
    fn encrypt(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let key = GenericArray::from_slice(&self.key);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut nonce_vec = nonce.clone().to_vec();
        let mut ciphertext = cipher
            .encrypt(&nonce, &*buf)
            .map_err(|e| anyhow!("{}", e))?;
        nonce_vec.append(&mut ciphertext);
        Ok(nonce_vec)
    }
}

impl TextDecrypt for Encryptor {
    fn decrypt(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>> {
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        let buf = standard_decode(&buf)?;
        let nonce_vec = buf[0..12].to_vec();
        let buf_text = &buf[12..];
        let key = GenericArray::from_slice(&self.key);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);
        let nonce = GenericArray::from_slice(&nonce_vec);
        let plaintext = cipher
            .decrypt(nonce, buf_text)
            .map_err(|e| anyhow!("decrypt error: {}", e))?;
        Ok(plaintext)
    }
}

impl TextSign for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes().to_vec())
    }
}

impl TextSign for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerify for Blake3 {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> anyhow::Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let hash = blake3::keyed_hash(&self.key, &buf);
        let hash = hash.as_bytes();
        Ok(hash == sig)
    }
}

impl TextVerify for Ed25519Verifier {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> anyhow::Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let signature = ed25519_dalek::Signature::from_bytes(sig.try_into()?);
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}

impl KeyLoader for Blake3 {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Signer {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Verifier {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Encryptor {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyGenerator for Blake3 {
    fn generate() -> anyhow::Result<Vec<Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let key = key.as_bytes().to_vec();
        Ok(vec![key])
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generate() -> anyhow::Result<Vec<Vec<u8>>> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.to_bytes().to_vec();
        Ok(vec![sk, pk])
    }
}

impl Encryptor {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    pub fn try_new(key: &[u8]) -> anyhow::Result<Self> {
        let key = &key[..32];
        let key = key.try_into()?;
        let encryptor = Encryptor::new(key);
        Ok(encryptor)
    }
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    pub fn try_new(key: &[u8]) -> anyhow::Result<Self> {
        let key = &key[..32];
        let key = key.try_into()?;
        let signer = Blake3::new(key);
        Ok(signer)
    }
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
    pub fn try_new(key: &[u8]) -> anyhow::Result<Self> {
        let key = SigningKey::from_bytes(key.try_into()?);
        let signer = Ed25519Signer::new(key);
        Ok(signer)
    }
}

impl Ed25519Verifier {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }
    pub fn try_new(key: &[u8]) -> anyhow::Result<Self> {
        let key = VerifyingKey::from_bytes(key.try_into()?)?;
        let verifier = Ed25519Verifier::new(key);
        Ok(verifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_sign_verify() -> anyhow::Result<()> {
        let blake3 = Blake3::load("fixtures/blake3.txt")?;
        let data = b"hello world";
        let signature = blake3.sign(&mut &data[..]).unwrap();
        assert!(blake3.verify(&mut &data[..], &signature).unwrap());
        Ok(())
    }

    #[test]
    fn test_ed25519_sign_verify() -> anyhow::Result<()> {
        let sk = Ed25519Signer::load("fixtures/ed25519.sk")?;
        let pk = Ed25519Verifier::load("fixtures/ed25519.pk")?;
        let data = b"hello world";
        let signature = sk.sign(&mut &data[..]).unwrap();
        assert!(pk.verify(&mut &data[..], &signature).unwrap());
        Ok(())
    }
    #[test]
    fn test_encrypt_decrypt() -> anyhow::Result<()> {
        let key = Encryptor::load("fixtures/b64.txt")?;
        let data = b"hello world";
        let encrypt_text = key.encrypt(&mut &data[..])?;
        let encrypt_texts = standard_encode(encrypt_text)?.as_bytes().to_vec();
        let decrypt_text = key.decrypt(&mut &encrypt_texts[..])?;
        assert_eq!(data, &decrypt_text[..]);
        Ok(())
    }
    // #[test]
    // fn test_process_encrypt_decrypt() -> anyhow::Result<()> {
    //     let res = process_text_encrypt("test.txt", "fixtures/b64.txt")?;
    //     let res2 = process_text_decrypt("test2.txt", "fixtures/b64.txt")?;
    //     println!("{}: {}", res, res2);
    //     Ok(())
    // }
}
