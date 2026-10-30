use std::any::Any;
use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

use super::oauth::OAuth;

/// One upstream MCP server. Its `name` is the prefix of its tools' names.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Upstream {
    /// Non-empty, and without `__`.
    pub name: String,
    pub url: String,
    /// Sent with every request to the upstream. With `oauth`, an
    /// `Authorization` here is replaced by the login's token.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub oauth: Option<OAuth>,
    /// Keep the refresh token in the gateway's [`TokenStore`], so a restart does
    /// not need a new login. Off, the login lives in memory only.
    #[serde(default)]
    pub persist: bool,
    /// Prefixed onto this upstream's tools' descriptions, so a client sees
    /// which one to pick when two share a template (e.g. two logins to the
    /// same service) and so cannot tell them apart by tool name alone.
    #[serde(default)]
    pub note: Option<String>,
}

/// Where refresh tokens of `persist` upstreams are kept between runs. The
/// gateway only ever gives it the refresh token; access tokens are never stored.
pub trait TokenStore: Send + Sync {
    fn load(&self, name: &str) -> Option<String>;
    fn save(&self, name: &str, refresh_token: &str);
    fn delete(&self, name: &str);

    /// Held for the whole of a refresh, so that gateways sharing the store
    /// never rotate the same refresh token twice. Dropping the guard releases
    /// it. The default holds nothing, which suits a store used by one gateway.
    fn lock(&self) -> io::Result<Box<dyn Any>> {
        Ok(Box::new(()))
    }
}
