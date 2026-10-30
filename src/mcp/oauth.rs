//! OAuth 2.1 with PKCE for an upstream: the authorization URL, the token
//! request bodies, and the tokens they return. Nothing here touches the disk:
//! tokens live in memory for as long as the gateway does.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The OAuth settings of an upstream. A public client: PKCE, no client secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuth {
    pub authorization_url: String,
    pub token_url: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// The tokens of one login.
#[derive(Clone, Debug)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<Instant>,
}

impl Credentials {
    /// Expired, or expiring within a minute.
    pub fn is_stale(&self) -> bool {
        self.expires_at
            .is_some_and(|at| Instant::now() + Duration::from_secs(60) >= at)
    }

    /// Reads a token response. A response without a new refresh token keeps
    /// `previous_refresh`.
    pub fn from_response(body: &[u8], previous_refresh: Option<&str>) -> Result<Credentials, String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
        }
        let response: TokenResponse =
            serde_json::from_slice(body).map_err(|err| format!("invalid token response: {err}"))?;
        Ok(Credentials {
            access_token: response.access_token,
            refresh_token: response
                .refresh_token
                .or_else(|| previous_refresh.map(str::to_owned)),
            expires_at: response
                .expires_in
                .map(|seconds| Instant::now() + Duration::from_secs(seconds)),
        })
    }
}

/// `bytes` random bytes, base64url-encoded without padding.
pub fn random_token(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("the OS random source is available");
    URL_SAFE_NO_PAD.encode(buffer)
}

/// The S256 code challenge of a PKCE verifier.
pub fn challenge_of(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn authorization_url(oauth: &OAuth, state: &str, verifier: &str) -> Result<String, String> {
    let mut url = url::Url::parse(&oauth.authorization_url)
        .map_err(|err| format!("invalid authorization_url: {err}"))?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &oauth.client_id)
            .append_pair("redirect_uri", &oauth.redirect_uri)
            .append_pair("state", state)
            .append_pair("code_challenge", &challenge_of(verifier))
            .append_pair("code_challenge_method", "S256");
        if !oauth.scopes.is_empty() {
            query.append_pair("scope", &oauth.scopes.join(" "));
        }
    }
    Ok(url.to_string())
}

/// A form-encoded body.
pub fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth() -> OAuth {
        OAuth {
            authorization_url: "https://auth.example/authorize".into(),
            token_url: "https://auth.example/token".into(),
            client_id: "client".into(),
            redirect_uri: "https://app.example/callback".into(),
            scopes: vec!["read".into(), "write".into()],
        }
    }

    #[test]
    fn the_challenge_matches_rfc_7636() {
        assert_eq!(
            challenge_of("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_authorization_url_carries_pkce_and_state() {
        let url = authorization_url(&oauth(), "state-1", "verifier").unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "state-1");
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["code_challenge"], challenge_of("verifier"));
        assert_eq!(query["scope"], "read write");
    }

    #[test]
    fn a_refresh_response_keeps_the_old_refresh_token() {
        let body = br#"{"access_token":"a2","expires_in":3600}"#;
        let credentials = Credentials::from_response(body, Some("r1")).unwrap();
        assert_eq!(credentials.access_token, "a2");
        assert_eq!(credentials.refresh_token.as_deref(), Some("r1"));
        assert!(!credentials.is_stale());
    }
}
