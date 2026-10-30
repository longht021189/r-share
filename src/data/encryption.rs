use super::crypto_ffi;

const PUBLIC_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Generates a new random X25519 keypair, returned as `(private_key, public_key)`.
pub fn generate_encryption_keypair() -> ([u8; 32], [u8; 32]) {
    crypto_ffi::x25519_generate_keypair()
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    crypto_ffi::random_bytes(&mut nonce);
    nonce
}

/// Encrypts `plaintext` so that only the holder of the private key matching
/// `recipient_public_key` can decrypt it.
///
/// Uses an ephemeral X25519 keypair (anonymous sender, "sealed box" style) +
/// HKDF-SHA256 + XChaCha20-Poly1305. The returned bytes are
/// `ephemeral_public_key (32) || nonce (24) || ciphertext`.
pub fn encrypt(plaintext: &[u8], recipient_public_key: [u8; 32]) -> Vec<u8> {
    let (ephemeral_private, ephemeral_public) = crypto_ffi::x25519_generate_keypair();
    let shared_secret = crypto_ffi::x25519_diffie_hellman(&ephemeral_private, &recipient_public_key);

    let key = derive_key(&shared_secret, &ephemeral_public, &recipient_public_key);
    let nonce = random_nonce();
    let ciphertext = crypto_ffi::xchacha20poly1305_encrypt(&key, &nonce, plaintext);

    let mut out = Vec::with_capacity(PUBLIC_KEY_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts a bundle produced by `encrypt` using `private_key`.
///
/// Returns `None` if the bundle is malformed or the ciphertext doesn't
/// authenticate (wrong key, or the data was tampered with).
pub fn decrypt(bundle: &[u8], private_key: [u8; 32]) -> Option<Vec<u8>> {
    if bundle.len() < PUBLIC_KEY_LEN + NONCE_LEN {
        return None;
    }
    let (ephemeral_public_bytes, rest) = bundle.split_at(PUBLIC_KEY_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let ephemeral_public: [u8; PUBLIC_KEY_LEN] = ephemeral_public_bytes.try_into().ok()?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().ok()?;

    let recipient_public = crypto_ffi::x25519_public_from_private(&private_key);
    let shared_secret = crypto_ffi::x25519_diffie_hellman(&private_key, &ephemeral_public);

    let key = derive_key(&shared_secret, &ephemeral_public, &recipient_public);
    crypto_ffi::xchacha20poly1305_decrypt(&key, &nonce, ciphertext)
}

/// Expands the raw X25519 shared secret into a symmetric key via HKDF-SHA256.
///
/// The raw ECDH output must never be used directly as a symmetric key; HKDF
/// also binds the key to both public keys involved in the exchange.
fn derive_key(
    shared_secret: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> [u8; 32] {
    let mut info = Vec::with_capacity(ephemeral_public.len() + recipient_public.len());
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);

    let mut key = [0u8; 32];
    crypto_ffi::hkdf_sha256(shared_secret, &info, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_with_generated_keypair() {
        let (private_key, public_key) = generate_encryption_keypair();

        let bundle = encrypt(b"hello world", public_key);
        let plaintext = decrypt(&bundle, private_key).unwrap();

        assert_eq!(plaintext, b"hello world");
    }

    #[test]
    fn rejects_wrong_private_key() {
        let (_, public_key) = generate_encryption_keypair();
        let (other_private_key, _) = generate_encryption_keypair();

        let bundle = encrypt(b"hello world", public_key);

        assert!(decrypt(&bundle, other_private_key).is_none());
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let (private_key, public_key) = generate_encryption_keypair();

        let mut bundle = encrypt(b"hello world", public_key);
        let last = bundle.len() - 1;
        bundle[last] ^= 0xFF;

        assert!(decrypt(&bundle, private_key).is_none());
    }

    #[test]
    fn rejects_truncated_bundle() {
        let (private_key, _) = generate_encryption_keypair();
        assert!(decrypt(&[0u8; 10], private_key).is_none());
    }
}
