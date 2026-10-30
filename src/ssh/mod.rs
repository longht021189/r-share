use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::public::Ed25519PublicKey;
use ssh_key::{LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// Encodes an Ed25519 `private_key` (32-byte seed, as returned by
/// [`crate::data::signing::generate_keypair`]) as the contents of an OpenSSH
/// private key file such as `~/.ssh/id_ed25519`.
///
/// The key is not passphrase-protected. When writing it to disk, restrict the
/// file to `0600`, otherwise `ssh` refuses to use it.
pub fn private_key_to_openssh(private_key: [u8; 32], comment: &str) -> Zeroizing<String> {
    let keypair = Ed25519Keypair::from_seed(&private_key);
    let key = PrivateKey::new(KeypairData::Ed25519(keypair), comment)
        .expect("an Ed25519 keypair is always a valid OpenSSH private key");
    key.to_openssh(LineEnding::LF)
        .expect("an Ed25519 private key always encodes to OpenSSH format")
}

/// Encodes an Ed25519 `public_key` (32 bytes) as the contents of an OpenSSH
/// public key file such as `~/.ssh/id_ed25519.pub`: a single line of the form
/// `ssh-ed25519 <base64> <comment>`, ending in a newline.
pub fn public_key_to_openssh(public_key: [u8; 32], comment: &str) -> String {
    let mut key = PublicKey::from(Ed25519PublicKey(public_key));
    key.set_comment(comment);
    let line = key
        .to_openssh()
        .expect("an Ed25519 public key always encodes to OpenSSH format");
    format!("{line}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::signing::generate_keypair;

    #[test]
    fn private_key_has_openssh_format() {
        let (private_key, _) = generate_keypair();

        let text = private_key_to_openssh(private_key, "g-bot");

        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(text.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
    }

    #[test]
    fn public_key_has_openssh_format() {
        let (_, public_key) = generate_keypair();

        let text = public_key_to_openssh(public_key, "g-bot");

        assert!(text.starts_with("ssh-ed25519 AAAA"));
        assert!(text.ends_with(" g-bot\n"));
    }

    #[test]
    fn private_key_round_trips_through_openssh_parser() {
        let (private_key, public_key) = generate_keypair();

        let text = private_key_to_openssh(private_key, "g-bot");
        let parsed = PrivateKey::from_openssh(text.as_str()).unwrap();

        assert_eq!(parsed.comment(), "g-bot");
        let parsed_keypair = parsed.key_data().ed25519().unwrap();
        assert_eq!(parsed_keypair.private.to_bytes(), private_key);
        assert_eq!(parsed_keypair.public.0, public_key);
    }

    #[test]
    fn private_and_public_files_match_according_to_ssh_keygen() {
        let (private_key, public_key) = generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        let private_path = dir.path().join("id_ed25519");
        std::fs::write(&private_path, private_key_to_openssh(private_key, "g-bot").as_str()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let output = std::process::Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&private_path)
            .output();
        let Ok(output) = output else {
            return; // ssh-keygen is not installed; skip.
        };

        assert!(output.status.success(), "{output:?}");
        let derived = String::from_utf8(output.stdout).unwrap();
        let expected = public_key_to_openssh(public_key, "g-bot");
        assert_eq!(derived.trim(), expected.trim());
    }
}
