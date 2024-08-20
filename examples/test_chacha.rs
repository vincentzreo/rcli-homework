use anyhow::anyhow;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};

fn main() -> anyhow::Result<()> {
    // let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    // let key = key.to_vec();
    let key_text = "u&7#EetAwa@q6FKS@%2$K18ym6UJn^R1".to_string();
    let key = key_text.as_bytes();
    let key = GenericArray::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    // let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let nonce = GenericArray::from_slice(&key[..12]);
    let texts = "hello".to_string();
    let ciphertext = cipher
        .encrypt(nonce, texts.as_bytes())
        .map_err(|e| anyhow!("{}", e))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow!("{}", e))?;
    assert_eq!(&plaintext, texts.as_bytes());
    Ok(())
}
