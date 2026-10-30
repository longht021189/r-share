use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::AtomicU64;

use serde::Serialize;
use serde_json::{Value, json};

use super::session::{Failure, PendingLogin, RpcError, Session};
use super::upstream::{TokenStore, Upstream};
use super::{INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND, PROTOCOL_VERSION, SEPARATOR, oauth};
use crate::http_client::{HttpClient, Method};

/// The default store: keeps nothing.
struct NoStore;

impl TokenStore for NoStore {
    fn load(&self, _: &str) -> Option<String> {
        None
    }

    fn save(&self, _: &str, _: &str) {}

    fn delete(&self, _: &str) {}
}

/// An upstream's login state, as reported by [`Gateway::list_upstreams`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStatus {
    /// No `oauth` settings: every call just carries its static headers, if any.
    NoAuthNeeded,
    LoggedIn,
    LoggedOut,
    /// [`Gateway::begin_login`] was called and the redirect has not completed
    /// the login yet.
    LoginPending,
}

/// One upstream's name, url, note, and current [`UpstreamStatus`].
#[derive(Clone, Debug, Serialize)]
pub struct UpstreamInfo {
    pub name: String,
    pub url: String,
    pub note: Option<String>,
    pub status: UpstreamStatus,
}

pub struct Gateway {
    pub(super) http: HttpClient,
    pub(super) sessions: RwLock<Vec<Arc<Session>>>,
    pub(super) pending: Mutex<HashMap<String, PendingLogin>>,
    pub(super) login_handler: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    pub(super) upstream_added_handler: Option<Box<dyn Fn(&Upstream) + Send + Sync>>,
    pub(super) store: Box<dyn TokenStore>,
    pub(super) next_id: AtomicU64,
}

impl Gateway {
    pub fn new(http: HttpClient, upstreams: Vec<Upstream>) -> Result<Gateway, String> {
        let mut names = BTreeSet::new();
        for upstream in &upstreams {
            check_name(&upstream.name)?;
            if !names.insert(upstream.name.as_str()) {
                return Err(format!("upstream {:?} is listed twice", upstream.name));
            }
        }
        let sessions = upstreams.into_iter().map(|upstream| Arc::new(new_session(upstream))).collect();
        Ok(Gateway {
            http,
            sessions: RwLock::new(sessions),
            pending: Mutex::new(HashMap::new()),
            login_handler: None,
            upstream_added_handler: None,
            store: Box::new(NoStore),
            next_id: AtomicU64::new(1),
        })
    }

    /// Called with the upstream's name and the authorization URL when it needs a
    /// login, e.g. to open the URL in a browser and serve the redirect.
    pub fn on_login_required(mut self, handler: impl Fn(&str, &str) + Send + Sync + 'static) -> Self {
        self.login_handler = Some(Box::new(handler));
        self
    }

    /// Called with an upstream just added through [`Gateway::add_upstream`],
    /// so it can be kept somewhere that outlives this process (e.g. appended
    /// to the config file a restart reads).
    pub fn on_upstream_added(mut self, handler: impl Fn(&Upstream) + Send + Sync + 'static) -> Self {
        self.upstream_added_handler = Some(Box::new(handler));
        self
    }

    /// Keeps refresh tokens of `persist` upstreams in `store`. Without this,
    /// nothing is kept.
    pub fn with_token_store(mut self, store: impl TokenStore + 'static) -> Self {
        self.store = Box::new(store);
        self
    }

    /// Adds `upstream` to the running gateway: it is immediately usable, the
    /// same as one passed to [`Gateway::new`]. An `oauth` upstream is always
    /// persisted, like the config loader forces at start-up. Calls the
    /// [`Gateway::on_upstream_added`] handler, if any, before it takes effect.
    pub fn add_upstream(&self, mut upstream: Upstream) -> Result<(), String> {
        check_name(&upstream.name)?;
        if upstream.oauth.is_some() {
            upstream.persist = true;
        }
        let mut sessions = self.sessions.write().unwrap();
        if sessions.iter().any(|session| session.name() == upstream.name) {
            return Err(format!("upstream {:?} is listed twice", upstream.name));
        }
        if let Some(handler) = &self.upstream_added_handler {
            handler(&upstream);
        }
        sessions.push(Arc::new(new_session(upstream)));
        Ok(())
    }

    /// A snapshot of every upstream's name, url, note, and login status.
    pub fn list_upstreams(&self) -> Vec<UpstreamInfo> {
        let pending = self.pending.lock().unwrap();
        self.sessions
            .read()
            .unwrap()
            .iter()
            .map(|session| {
                let status = if session.upstream.oauth.is_none() {
                    UpstreamStatus::NoAuthNeeded
                } else if session.credentials().is_some() {
                    UpstreamStatus::LoggedIn
                } else if pending.values().any(|login| login.name == session.name()) {
                    UpstreamStatus::LoginPending
                } else {
                    UpstreamStatus::LoggedOut
                };
                UpstreamInfo {
                    name: session.name().to_owned(),
                    url: session.upstream.url.clone(),
                    note: session.upstream.note.clone(),
                    status,
                }
            })
            .collect()
    }

    /// The authorization URL that logs `name` in. Finish the login with the
    /// `code` and `state` the redirect carries, through [`Gateway::complete_login`].
    pub fn begin_login(&self, name: &str) -> Result<String, String> {
        let session = self.session(name)?;
        let oauth = session
            .upstream
            .oauth
            .as_ref()
            .ok_or_else(|| format!("{name} has no OAuth settings"))?;
        let verifier = oauth::random_token(32);
        let state = oauth::random_token(16);
        let url = oauth::authorization_url(oauth, &state, &verifier)?;
        self.pending
            .lock()
            .unwrap()
            .insert(state, PendingLogin { name: name.to_owned(), verifier });
        Ok(url)
    }

    /// Exchanges the `code` of a login started by [`Gateway::begin_login`] for
    /// tokens. Returns the name of the upstream logged in.
    pub async fn complete_login(&self, state: &str, code: &str) -> Result<String, String> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .remove(state)
            .ok_or("unknown or already used login state")?;
        let session = self.session(&pending.name)?;
        let oauth = session
            .upstream
            .oauth
            .as_ref()
            .ok_or_else(|| format!("{} has no OAuth settings", pending.name))?;
        let credentials = self
            .token_request(
                oauth,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", oauth.redirect_uri.as_str()),
                    ("client_id", oauth.client_id.as_str()),
                    ("code_verifier", pending.verifier.as_str()),
                ],
                None,
            )
            .await?;
        if session.upstream.persist {
            if let Some(refresh_token) = &credentials.refresh_token {
                self.store.save(&pending.name, refresh_token);
            }
        }
        session.set_credentials(Some(credentials));
        session.set_session_id(None);
        Ok(pending.name)
    }

    /// Logs `name` out: ends its session, if it has one, and forgets its tokens
    /// and any login in progress, in memory and in the store. Ending the session
    /// is best effort; the upstream may not support it.
    pub async fn terminate(&self, name: &str) -> Result<(), String> {
        let session = self.session(name)?;
        if session.session_id().is_some() {
            let _ = self.send(&session, Method::Delete, None).await;
        }
        session.set_session_id(None);
        session.set_credentials(None);
        self.store.delete(name);
        self.pending.lock().unwrap().retain(|_, login| login.name != name);
        Ok(())
    }

    /// Answers one message from the client. Notifications get no answer.
    pub async fn handle(&self, message: Value) -> Option<Value> {
        let method = message.get("method")?.as_str()?.to_owned();
        let id = message.get("id")?.clone();
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let outcome = match method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mcp-gateway", "version": env!("CARGO_PKG_VERSION") },
            })),
            "ping" => Ok(json!({})),
            "tools/list" => self.list_tools().await.map(|tools| json!({ "tools": tools })),
            "tools/call" => self.call_tool(&params).await,
            _ => Err(RpcError::new(METHOD_NOT_FOUND, format!("unknown method {method}"))),
        };
        Some(match outcome {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(err) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": err.code, "message": err.message },
            }),
        })
    }

    fn session(&self, name: &str) -> Result<Arc<Session>, String> {
        self.sessions
            .read()
            .unwrap()
            .iter()
            .find(|session| session.name() == name)
            .cloned()
            .ok_or_else(|| format!("unknown upstream {name}"))
    }

    /// Upstreams that need a login are left out of the list, and the handler
    /// is asked to start one.
    async fn list_tools(&self) -> Result<Vec<Value>, RpcError> {
        let mut tools = Vec::new();
        // Cloning the `Arc`s out of the lock, rather than holding it across
        // the `.await`s below, keeps a slow upstream from blocking
        // `add_upstream`/`list_upstreams` meanwhile.
        let sessions = self.sessions.read().unwrap().clone();
        for session in &sessions {
            let mut cursor: Option<String> = None;
            loop {
                let params = cursor.as_ref().map_or_else(|| json!({}), |c| json!({ "cursor": c }));
                let page = match self.rpc(session, "tools/list", params).await {
                    Ok(page) => page,
                    Err(Failure::LoginRequired) => {
                        self.request_login(session);
                        break;
                    }
                    Err(failure) => {
                        return Err(RpcError::new(INTERNAL_ERROR, failure.describe(session.name())));
                    }
                };
                for tool in page.get("tools").and_then(Value::as_array).into_iter().flatten() {
                    let Some(name) = tool.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    let full = format!("{}{SEPARATOR}{name}", session.name());
                    let mut tool = tool.clone();
                    tool["name"] = json!(full);
                    if let Some(note) = &session.upstream.note {
                        let description = tool.get("description").and_then(Value::as_str).unwrap_or_default();
                        tool["description"] = json!(format!("[{note}] {description}"));
                    }
                    tools.push(tool);
                }
                cursor = page.get("nextCursor").and_then(Value::as_str).map(str::to_owned);
                if cursor.is_none() {
                    break;
                }
            }
        }
        Ok(tools)
    }

    async fn call_tool(&self, params: &Value) -> Result<Value, RpcError> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "missing tool name"))?;
        let unknown = || RpcError::new(INVALID_PARAMS, format!("unknown tool {name}"));
        let (upstream, tool) = name.split_once(SEPARATOR).ok_or_else(unknown)?;
        let session = self.session(upstream).map_err(|_| unknown())?;

        let mut forwarded = json!({ "name": tool });
        if let Some(arguments) = params.get("arguments") {
            forwarded["arguments"] = arguments.clone();
        }
        match self.rpc(&session, "tools/call", forwarded).await {
            Ok(result) => Ok(result),
            Err(Failure::LoginRequired) => {
                self.request_login(&session);
                Err(RpcError::new(INTERNAL_ERROR, format!("{upstream}: login required")))
            }
            Err(failure) => Err(RpcError::new(INTERNAL_ERROR, failure.describe(upstream))),
        }
    }

    /// Starts a login for `session`, unless one is already in progress.
    fn request_login(&self, session: &Session) {
        let Some(handler) = &self.login_handler else {
            return;
        };
        let name = session.name();
        if self.pending.lock().unwrap().values().any(|login| login.name == name) {
            return;
        }
        if let Ok(url) = self.begin_login(name) {
            handler(name, &url);
        }
    }
}

fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.contains(SEPARATOR) {
        return Err(format!("upstream name {name:?} must be non-empty and must not contain {SEPARATOR:?}"));
    }
    Ok(())
}

fn new_session(upstream: Upstream) -> Session {
    Session { upstream, session_id: Mutex::new(None), credentials: Mutex::new(None) }
}
