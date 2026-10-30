use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::gateway::Gateway;
use super::oauth::{self, Credentials, OAuth};
use super::session::{Failure, Session};
use super::PROTOCOL_VERSION;
use crate::http_client::{Method, Request, Response};

const TIMEOUT: Duration = Duration::from_secs(120);

impl Gateway {
    /// Calls `method` on one upstream. A stale token is refreshed first; a
    /// rejected one is refreshed and the call retried once, and an expired
    /// session is started again.
    pub(super) async fn rpc(&self, session: &Session, method: &str, params: Value) -> Result<Value, Failure> {
        let mut retried = false;
        loop {
            let outcome = match self.ensure_fresh(session).await {
                Ok(()) => self.attempt(session, method, params.clone()).await,
                Err(failure) => Err(failure),
            };
            match outcome {
                Err(Failure::Expired) if !retried => session.set_session_id(None),
                Err(Failure::Unauthorized) if !retried => match &session.upstream.oauth {
                    Some(oauth) => self.refresh(session, oauth).await?,
                    None => return Err(Failure::Unauthorized),
                },
                other => return other,
            }
            retried = true;
        }
    }

    async fn attempt(&self, session: &Session, method: &str, params: Value) -> Result<Value, Failure> {
        if session.session_id().is_none() {
            self.initialize(session).await?;
        }
        let (result, _) = self.request(session, Method::Post, method, params).await?;
        Ok(result)
    }

    async fn ensure_fresh(&self, session: &Session) -> Result<(), Failure> {
        let Some(oauth) = &session.upstream.oauth else {
            return Ok(());
        };
        match session.credentials() {
            // No stored login either: some upstreams answer unauthenticated
            // requests just fine (OAuth only raises a quota, say), so the
            // call is still attempted without a token. A genuinely protected
            // one answers 401, and `rpc` turns that into `LoginRequired`.
            None if session.upstream.persist => match self.store.load(session.name()) {
                Some(refresh_token) => {
                    session.set_credentials(Some(Credentials {
                        access_token: String::new(),
                        refresh_token: Some(refresh_token),
                        expires_at: Some(Instant::now()),
                    }));
                    self.refresh(session, oauth).await
                }
                None => Ok(()),
            },
            None => Ok(()),
            Some(credentials) if credentials.is_stale() => self.refresh(session, oauth).await,
            Some(_) => Ok(()),
        }
    }

    /// Replaces the tokens of `session` with fresh ones. Without a refresh token,
    /// or if the refresh fails, the login is over.
    async fn refresh(&self, session: &Session, oauth: &OAuth) -> Result<(), Failure> {
        // With `persist`, another gateway sharing the store may have rotated the
        // refresh token since this one read it. The lock is taken first, and the
        // stored token is read under it.
        let _guard = if session.upstream.persist {
            Some(self.store.lock().map_err(|err| Failure::Failed(format!("token store: {err}")))?)
        } else {
            None
        };
        let stored = session.upstream.persist.then(|| self.store.load(session.name())).flatten();
        let refresh_token = stored.or_else(|| session.credentials().and_then(|credentials| credentials.refresh_token));
        let Some(refresh_token) = refresh_token else {
            session.set_credentials(None);
            return Err(Failure::LoginRequired);
        };
        let pairs = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", oauth.client_id.as_str()),
        ];
        match self.token_request(oauth, &pairs, Some(refresh_token.as_str())).await {
            Ok(credentials) => {
                if session.upstream.persist {
                    if let Some(rotated) = &credentials.refresh_token {
                        self.store.save(session.name(), rotated);
                    }
                }
                session.set_credentials(Some(credentials));
                Ok(())
            }
            Err(_) => {
                self.store.delete(session.name());
                session.set_credentials(None);
                Err(Failure::LoginRequired)
            }
        }
    }

    pub(super) async fn token_request(
        &self,
        oauth: &OAuth,
        pairs: &[(&str, &str)],
        previous_refresh: Option<&str>,
    ) -> Result<Credentials, String> {
        let mut request = Request::new(Method::Post, oauth.token_url.as_str());
        request.body = oauth::form(pairs);
        request.timeout = TIMEOUT;
        let request = request
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json");
        let response = self.http.send(request).await.map_err(|err| err.to_string())?;
        if !(200..300).contains(&response.status) {
            return Err(format!("token endpoint answered HTTP {}", response.status));
        }
        Credentials::from_response(&response.body, previous_refresh)
    }

    async fn initialize(&self, session: &Session) -> Result<(), Failure> {
        session.set_session_id(None);
        let params = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "mcp-gateway", "version": env!("CARGO_PKG_VERSION") },
        });
        let (_, session_id) = self.request(session, Method::Post, "initialize", params).await?;
        session.set_session_id(session_id);

        let body = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let response = self.send(session, Method::Post, Some(&body)).await?;
        if !(200..300).contains(&response.status) {
            return Err(Failure::Failed(format!("HTTP {}", response.status)));
        }
        Ok(())
    }

    async fn request(
        &self,
        session: &Session,
        http_method: Method,
        method: &str,
        params: Value,
    ) -> Result<(Value, Option<String>), Failure> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self.send(session, http_method, Some(&body)).await?;
        if response.status == 401 {
            return Err(Failure::Unauthorized);
        }
        if response.status == 404 && session.session_id().is_some() {
            return Err(Failure::Expired);
        }
        let session_id = response.header_values("mcp-session-id").next().map(str::to_owned);
        let result = reply_for(&response, id).map_err(Failure::Failed)?;
        Ok((result, session_id))
    }

    pub(super) async fn send(&self, session: &Session, method: Method, body: Option<&Value>) -> Result<Response, Failure> {
        let mut request = Request::new(method, session.upstream.url.as_str());
        request.timeout = TIMEOUT;
        if let Some(body) = body {
            request.body = serde_json::to_vec(body).expect("a JSON value serializes");
            request = request.header("content-type", "application/json");
        }
        request = request
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION);

        let credentials = session.credentials();
        let token = credentials.as_ref().map(|credentials| credentials.access_token.as_str());
        for (name, value) in &session.upstream.headers {
            if token.is_some() && name.eq_ignore_ascii_case("authorization") {
                continue;
            }
            request = request.header(name.as_str(), value.as_str());
        }
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(session_id) = session.session_id() {
            request = request.header("mcp-session-id", session_id);
        }
        self.http
            .send(request)
            .await
            .map_err(|err| Failure::Failed(err.to_string()))
    }
}

/// The `result` of the reply to request `id`, from a JSON or an SSE body.
fn reply_for(response: &Response, id: u64) -> Result<Value, String> {
    let text = String::from_utf8_lossy(&response.body);
    if !(200..300).contains(&response.status) {
        let excerpt: String = text.chars().take(200).collect();
        return Err(format!("HTTP {}: {excerpt}", response.status));
    }
    let is_sse = response
        .header_values("content-type")
        .any(|value| value.starts_with("text/event-stream"));
    let messages = if is_sse {
        sse_messages(&text)
    } else {
        vec![serde_json::from_str::<Value>(&text).map_err(|err| err.to_string())?]
    };
    let reply = messages
        .into_iter()
        .find(|message| message.get("id") == Some(&json!(id)))
        .ok_or_else(|| "no reply to the request".to_owned())?;
    if let Some(error) = reply.get("error") {
        let message = error.get("message").and_then(Value::as_str).unwrap_or("error");
        return Err(message.to_owned());
    }
    reply.get("result").cloned().ok_or_else(|| "reply has no result".to_owned())
}

/// The JSON messages carried by the `data:` lines of an SSE body.
pub(super) fn sse_messages(body: &str) -> Vec<Value> {
    body.replace("\r\n", "\n")
        .split("\n\n")
        .filter_map(|event| {
            let data: Vec<&str> = event
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(|data| data.strip_prefix(' ').unwrap_or(data))
                .collect();
            if data.is_empty() {
                return None;
            }
            serde_json::from_str(&data.join("\n")).ok()
        })
        .collect()
}
