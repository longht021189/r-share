use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;

use super::crypto_ffi;
use crate::data::proto::SignedData;

/// Generates a new random Ed25519 keypair, returned as `(private_key, public_key)`.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    crypto_ffi::ed25519_generate_keypair()
}

/// Signs `data` with `private_key` (a 32-byte Ed25519 seed).
///
/// `data.signature` is reset to `None` before signing, since the signature
/// itself must never be part of what gets signed.
pub fn sign_signed_data(mut data: SignedData, private_key: [u8; 32]) -> SignedData {
    data.signature = None;
    let signature = crypto_ffi::ed25519_sign(&private_key, &data.encode_to_vec());
    data.signature = Some(signature.to_vec());
    data
}

/// Verifies `data.signature` against `data.content` + `data.timestamp` using
/// `public_key` (a 32-byte Ed25519 public key), and rejects if `data.timestamp`
/// is older than `max_age` relative to `now`, or is in the future.
pub fn verify_signed_data(
    data: &SignedData,
    public_key: [u8; 32],
    now: SystemTime,
    max_age: Duration,
) -> bool {
    let Some(timestamp) = &data.timestamp else {
        return false;
    };
    let Ok(now_secs) = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64) else {
        return false;
    };
    let age_secs = now_secs - timestamp.seconds;
    if age_secs < 0 || age_secs > max_age.as_secs() as i64 {
        return false;
    }
    let Some(signature_bytes) = data.signature.as_deref() else {
        return false;
    };
    let Ok(signature): Result<[u8; 64], _> = signature_bytes.try_into() else {
        return false;
    };

    let mut unsigned = data.clone();
    unsigned.signature = None;
    let message = unsigned.encode_to_vec();

    crypto_ffi::ed25519_verify(&public_key, &message, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::Timestamp;

    const PRIVATE_KEY: [u8; 32] = [7u8; 32];
    const TIMESTAMP_SECS: i64 = 1_700_000_000;
    const MAX_AGE: Duration = Duration::from_secs(300);

    fn public_key() -> [u8; 32] {
        crypto_ffi::ed25519_public_from_private(&PRIVATE_KEY)
    }

    fn now_at(offset: Duration) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(TIMESTAMP_SECS as u64) + offset
    }

    fn unsigned_data() -> SignedData {
        SignedData {
            content: b"hello world".to_vec(),
            signature: None,
            timestamp: Some(Timestamp {
                seconds: TIMESTAMP_SECS,
                nanos: 0,
            }),
        }
    }

    #[test]
    fn verifies_untampered_data() {
        let data = sign_signed_data(unsigned_data(), PRIVATE_KEY);

        assert!(verify_signed_data(
            &data,
            public_key(),
            now_at(Duration::ZERO),
            MAX_AGE
        ));
    }

    #[test]
    fn rejects_tampered_content() {
        let mut data = sign_signed_data(unsigned_data(), PRIVATE_KEY);

        data.content = b"tampered".to_vec();
        assert!(!verify_signed_data(
            &data,
            public_key(),
            now_at(Duration::ZERO),
            MAX_AGE
        ));
    }

    #[test]
    fn rejects_missing_signature() {
        let data = unsigned_data();

        assert!(!verify_signed_data(
            &data,
            public_key(),
            now_at(Duration::ZERO),
            MAX_AGE
        ));
    }

    #[test]
    fn rejects_missing_timestamp() {
        let mut data = sign_signed_data(unsigned_data(), PRIVATE_KEY);
        data.timestamp = None;

        assert!(!verify_signed_data(
            &data,
            public_key(),
            now_at(Duration::ZERO),
            MAX_AGE
        ));
    }

    #[test]
    fn rejects_wrong_public_key() {
        let data = sign_signed_data(unsigned_data(), PRIVATE_KEY);

        assert!(!verify_signed_data(
            &data,
            [9u8; 32],
            now_at(Duration::ZERO),
            MAX_AGE
        ));
    }

    #[test]
    fn rejects_timestamp_older_than_max_age() {
        let data = sign_signed_data(unsigned_data(), PRIVATE_KEY);

        assert!(!verify_signed_data(
            &data,
            public_key(),
            now_at(MAX_AGE + Duration::from_secs(1)),
            MAX_AGE
        ));
    }

    #[test]
    fn accepts_timestamp_within_max_age() {
        let data = sign_signed_data(unsigned_data(), PRIVATE_KEY);

        assert!(verify_signed_data(
            &data,
            public_key(),
            now_at(MAX_AGE),
            MAX_AGE
        ));
    }

    #[test]
    fn rejects_timestamp_in_the_future() {
        let data = sign_signed_data(unsigned_data(), PRIVATE_KEY);

        // `now` is one second before the timestamp itself.
        let now = UNIX_EPOCH + Duration::from_secs(TIMESTAMP_SECS as u64 - 1);
        assert!(!verify_signed_data(&data, public_key(), now, MAX_AGE));
    }

    #[test]
    fn generated_keypair_roundtrips() {
        let (private_key, public_key) = generate_keypair();
        let data = sign_signed_data(unsigned_data(), private_key);

        assert!(verify_signed_data(
            &data,
            public_key,
            now_at(Duration::ZERO),
            MAX_AGE
        ));
    }
}
