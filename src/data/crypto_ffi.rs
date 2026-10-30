//! Safe wrappers around c-share's `crypto.h` C API (see `build.rs` and
//! `c-share/modules/crypto/README.md`). Every wolfSSL-backed primitive
//! `data::encryption`/`data::signing` need lives here so `unsafe` stays in
//! one place; those modules only ever see safe functions.

mod raw {
    #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
    include!(concat!(env!("OUT_DIR"), "/crypto_bindings.rs"));
}

/// Fills `out` with cryptographically secure random bytes.
pub fn random_bytes(out: &mut [u8]) {
    let ret = unsafe { raw::c_share_crypto_random_bytes(out.as_mut_ptr(), out.len()) };
    assert_eq!(ret, 0, "c_share_crypto_random_bytes failed");
}

/// Generates a new random X25519 keypair, returned as `(private_key, public_key)`.
pub fn x25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; 32];
    let ret = unsafe {
        raw::c_share_crypto_x25519_generate_keypair(private_key.as_mut_ptr(), public_key.as_mut_ptr())
    };
    assert_eq!(ret, 0, "c_share_crypto_x25519_generate_keypair failed");
    (private_key, public_key)
}

/// Derives the X25519 public key matching `private_key`.
pub fn x25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let mut public_key = [0u8; 32];
    let ret = unsafe {
        raw::c_share_crypto_x25519_public_from_private(private_key.as_ptr(), public_key.as_mut_ptr())
    };
    assert_eq!(ret, 0, "c_share_crypto_x25519_public_from_private failed");
    public_key
}

/// Computes the X25519 Diffie-Hellman shared secret. The raw output must
/// never be used directly as a symmetric key -- see [`hkdf_sha256`].
pub fn x25519_diffie_hellman(private_key: &[u8; 32], their_public_key: &[u8; 32]) -> [u8; 32] {
    let mut shared_secret = [0u8; 32];
    let ret = unsafe {
        raw::c_share_crypto_x25519_diffie_hellman(
            private_key.as_ptr(),
            their_public_key.as_ptr(),
            shared_secret.as_mut_ptr(),
        )
    };
    assert_eq!(ret, 0, "c_share_crypto_x25519_diffie_hellman failed");
    shared_secret
}

/// Generates a new random Ed25519 keypair, returned as `(private_key, public_key)`.
pub fn ed25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; 32];
    let ret = unsafe {
        raw::c_share_crypto_ed25519_generate_keypair(private_key.as_mut_ptr(), public_key.as_mut_ptr())
    };
    assert_eq!(ret, 0, "c_share_crypto_ed25519_generate_keypair failed");
    (private_key, public_key)
}

/// Derives the Ed25519 public key matching a 32-byte private key (seed).
/// Only exercised by tests today (`generate_keypair` returns both halves
/// already), kept for API symmetry with [`x25519_public_from_private`].
#[allow(dead_code)]
pub fn ed25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let mut public_key = [0u8; 32];
    let ret = unsafe {
        raw::c_share_crypto_ed25519_public_from_private(private_key.as_ptr(), public_key.as_mut_ptr())
    };
    assert_eq!(ret, 0, "c_share_crypto_ed25519_public_from_private failed");
    public_key
}

/// Signs `message` with `private_key` (a 32-byte Ed25519 seed).
pub fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut signature = [0u8; 64];
    let ret = unsafe {
        raw::c_share_crypto_ed25519_sign(
            private_key.as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
        )
    };
    assert_eq!(ret, 0, "c_share_crypto_ed25519_sign failed");
    signature
}

/// Verifies `signature` over `message` against `public_key`.
#[must_use]
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let ret = unsafe {
        raw::c_share_crypto_ed25519_verify(
            public_key.as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
        )
    };
    ret == 0
}

/// Derives `out.len()` bytes of key material from `ikm` via HKDF-SHA256, with
/// no salt and `info` as the context string.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let ret = unsafe {
        raw::c_share_crypto_hkdf_sha256(
            ikm.as_ptr(),
            ikm.len(),
            info.as_ptr(),
            info.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, 0, "c_share_crypto_hkdf_sha256 failed");
}

/// Encrypts `plaintext` with XChaCha20-Poly1305 (no additional authenticated
/// data). Returns `ciphertext || tag`.
pub fn xchacha20poly1305_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; plaintext.len() + 16];
    let ret = unsafe {
        raw::c_share_crypto_xchacha20poly1305_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            out.as_mut_ptr(),
        )
    };
    assert_eq!(ret, 0, "c_share_crypto_xchacha20poly1305_encrypt failed");
    out
}

/// Decrypts a bundle produced by [`xchacha20poly1305_encrypt`] (`ciphertext`
/// includes the trailing tag). Returns `None` if authentication fails or
/// `ciphertext` is too short.
#[must_use]
pub fn xchacha20poly1305_decrypt(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 16 {
        return None;
    }
    let mut out = vec![0u8; ciphertext.len() - 16];
    let ret = unsafe {
        raw::c_share_crypto_xchacha20poly1305_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            out.as_mut_ptr(),
        )
    };
    (ret == 0).then_some(out)
}
