use std::sync::Mutex;

use super::oauth::Credentials;
use super::upstream::Upstream;

pub(super) struct Session {
    pub(super) upstream: Upstream,
    pub(super) session_id: Mutex<Option<String>>,
    pub(super) credentials: Mutex<Option<Credentials>>,
}

impl Session {
    pub(super) fn name(&self) -> &str {
        &self.upstream.name
    }

    pub(super) fn session_id(&self) -> Option<String> {
        self.session_id.lock().unwrap().clone()
    }

    pub(super) fn set_session_id(&self, id: Option<String>) {
        *self.session_id.lock().unwrap() = id;
    }

    pub(super) fn credentials(&self) -> Option<Credentials> {
        self.credentials.lock().unwrap().clone()
    }

    pub(super) fn set_credentials(&self, credentials: Option<Credentials>) {
        *self.credentials.lock().unwrap() = credentials;
    }
}

pub(super) struct PendingLogin {
    pub(super) name: String,
    pub(super) verifier: String,
}

pub(super) enum Failure {
    /// The upstream no longer knows the session.
    Expired,
    /// The upstream rejected the token.
    Unauthorized,
    /// The upstream needs a login, and there is no usable token.
    LoginRequired,
    Failed(String),
}

impl Failure {
    pub(super) fn describe(self, name: &str) -> String {
        let message = match self {
            Failure::Expired => "session expired".to_owned(),
            Failure::Unauthorized => "HTTP 401".to_owned(),
            Failure::LoginRequired => "login required".to_owned(),
            Failure::Failed(message) => message,
        };
        format!("{name}: {message}")
    }
}

pub(super) struct RpcError {
    pub(super) code: i64,
    pub(super) message: String,
}

impl RpcError {
    pub(super) fn new(code: i64, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}
