use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::oauth::OAuth;
use super::transport::sse_messages;
use super::*;
use crate::http_client::HttpClient;

fn upstream(name: &str) -> Upstream {
    Upstream {
        name: name.into(),
        url: "https://unused.invalid/mcp".into(),
        headers: BTreeMap::new(),
        oauth: None,
        persist: false,
        note: None,
    }
}

#[derive(Clone, Default)]
struct SharedStore(Arc<Mutex<HashMap<String, String>>>);

impl TokenStore for SharedStore {
    fn load(&self, name: &str) -> Option<String> {
        self.0.lock().unwrap().get(name).cloned()
    }

    fn save(&self, name: &str, refresh_token: &str) {
        self.0.lock().unwrap().insert(name.to_owned(), refresh_token.to_owned());
    }

    fn delete(&self, name: &str) {
        self.0.lock().unwrap().remove(name);
    }
}

fn oauth_upstream(name: &str) -> Upstream {
    Upstream {
        oauth: Some(OAuth {
            authorization_url: "https://auth.invalid/authorize".into(),
            token_url: "https://auth.invalid/token".into(),
            client_id: "client".into(),
            redirect_uri: "https://app.invalid/callback".into(),
            scopes: Vec::new(),
        }),
        ..upstream(name)
    }
}

/// Binds a server that answers every connection `401 Unauthorized`, and
/// returns its URL. A call without a login goes out unauthenticated (some
/// upstreams answer those just fine), so a test of what happens once one is
/// actually rejected needs an upstream that rejects it.
fn unauthorized_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    format!("http://{addr}/mcp")
}

/// Like [`oauth_upstream`], but its `url` actually rejects an unauthenticated
/// request, rather than being unreachable.
fn rejecting_oauth_upstream(name: &str) -> Upstream {
    Upstream {
        url: unauthorized_server(),
        ..oauth_upstream(name)
    }
}

fn gateway() -> Gateway {
    Gateway::new(HttpClient::start().unwrap(), vec![upstream("figma")]).unwrap()
}

#[test]
fn upstream_names_are_prefixes_that_cannot_clash() {
    let http = HttpClient::start().unwrap();
    assert!(Gateway::new(http.clone(), vec![upstream("a__b")]).is_err());
    assert!(Gateway::new(http.clone(), vec![upstream("")]).is_err());
    assert!(Gateway::new(http.clone(), vec![upstream("figma"), upstream("figma")]).is_err());
    assert!(Gateway::new(http, vec![upstream("figma"), upstream("jira")]).is_ok());
}

#[test]
fn add_upstream_rejects_a_bad_name_or_one_already_taken() {
    let gateway = gateway();
    assert!(gateway.add_upstream(upstream("a__b")).is_err());
    assert!(gateway.add_upstream(upstream("figma")).is_err());
    assert!(gateway.add_upstream(upstream("jira")).is_ok());
}

#[tokio::test]
async fn an_added_upstream_is_usable_right_away() {
    let gateway = gateway();
    gateway
        .add_upstream(Upstream { url: unauthorized_server(), ..upstream("jira") })
        .unwrap();
    let reply = gateway
        .handle(json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": { "name": "jira__search" } }))
        .await
        .unwrap();
    // Reaches the upstream (and gets an HTTP-level failure) rather than
    // "unknown tool": the newly added upstream is recognized right away.
    assert_eq!(reply["error"]["code"], INTERNAL_ERROR);
}

#[test]
fn list_upstreams_reports_each_ones_status() {
    let gateway = Gateway::new(HttpClient::start().unwrap(), vec![upstream("figma"), oauth_upstream("work")]).unwrap();

    let info = gateway.list_upstreams();
    assert_eq!(info.iter().find(|i| i.name == "figma").unwrap().status, UpstreamStatus::NoAuthNeeded);
    assert_eq!(info.iter().find(|i| i.name == "work").unwrap().status, UpstreamStatus::LoggedOut);

    gateway.begin_login("work").unwrap();
    let info = gateway.list_upstreams();
    assert_eq!(info.iter().find(|i| i.name == "work").unwrap().status, UpstreamStatus::LoginPending);
}

#[test]
fn a_login_gives_an_authorization_url_and_is_pending() {
    let gateway = Gateway::new(HttpClient::start().unwrap(), vec![oauth_upstream("work")]).unwrap();
    let url = gateway.begin_login("work").unwrap();
    let parsed = url::Url::parse(&url).unwrap();
    let query: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    let pending = gateway.pending.lock().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending.contains_key(&query["state"]));
}

#[test]
fn logging_in_an_upstream_without_oauth_is_refused() {
    assert!(gateway().begin_login("figma").is_err());
    assert!(gateway().begin_login("nope").is_err());
}

#[tokio::test]
async fn an_unknown_login_state_is_refused() {
    let gateway = Gateway::new(HttpClient::start().unwrap(), vec![oauth_upstream("work")]).unwrap();
    assert!(gateway.complete_login("never-issued", "code").await.is_err());
}

#[tokio::test]
async fn terminate_forgets_a_pending_login() {
    let gateway = Gateway::new(HttpClient::start().unwrap(), vec![oauth_upstream("work")]).unwrap();
    gateway.begin_login("work").unwrap();
    gateway.terminate("work").await.unwrap();
    assert!(gateway.pending.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_call_without_a_login_asks_for_one_and_is_refused() {
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = asked.clone();
    let gateway = Gateway::new(HttpClient::start().unwrap(), vec![rejecting_oauth_upstream("work")])
        .unwrap()
        .on_login_required(move |_, url| seen.lock().unwrap().push(url.to_owned()));

    let reply = gateway
        .handle(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "work__search" },
        }))
        .await
        .unwrap();
    assert_eq!(reply["error"]["code"], INTERNAL_ERROR);
    let asked = asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].starts_with("https://auth.invalid/authorize?"));
}

fn asking_gateway(upstream: Upstream, store: SharedStore) -> (Gateway, Arc<Mutex<Vec<String>>>) {
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = asked.clone();
    let gateway = Gateway::new(HttpClient::start().unwrap(), vec![upstream])
        .unwrap()
        .with_token_store(store)
        .on_login_required(move |_, url| seen.lock().unwrap().push(url.to_owned()));
    (gateway, asked)
}

fn search_call() -> Value {
    json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": { "name": "work__search" } })
}

#[tokio::test]
async fn a_stored_refresh_token_is_dropped_once_refused() {
    let store = SharedStore::default();
    store.save("work", "stored-refresh");
    let upstream = Upstream {
        persist: true,
        ..oauth_upstream("work")
    };
    let (gateway, asked) = asking_gateway(upstream, store.clone());

    let reply = gateway.handle(search_call()).await.unwrap();
    assert_eq!(reply["error"]["code"], INTERNAL_ERROR);
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert!(store.load("work").is_none());
}

#[tokio::test]
async fn a_login_without_persist_never_reads_the_store() {
    let store = SharedStore::default();
    store.save("work", "stored-refresh");
    let (gateway, asked) = asking_gateway(rejecting_oauth_upstream("work"), store.clone());

    gateway.handle(search_call()).await.unwrap();
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert_eq!(store.load("work").as_deref(), Some("stored-refresh"));
}

#[tokio::test]
async fn initialize_is_answered_without_the_network() {
    let reply = gateway()
        .handle(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }))
        .await
        .unwrap();
    assert_eq!(reply["id"], 1);
    assert_eq!(reply["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert!(reply["result"]["capabilities"]["tools"].is_object());
}

#[tokio::test]
async fn notifications_get_no_reply() {
    let reply = gateway()
        .handle(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await;
    assert!(reply.is_none());
}

#[tokio::test]
async fn an_unknown_method_is_an_error_reply() {
    let reply = gateway()
        .handle(json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/list" }))
        .await
        .unwrap();
    assert_eq!(reply["error"]["code"], METHOD_NOT_FOUND);
}

#[tokio::test]
async fn a_tool_of_no_upstream_is_refused_without_the_network() {
    let reply = gateway()
        .handle(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "jira__search" },
        }))
        .await
        .unwrap();
    assert_eq!(reply["error"]["code"], INVALID_PARAMS);
}

#[test]
fn sse_bodies_yield_their_data_messages() {
    let body = ": keep-alive\r\n\r\nevent: message\r\ndata: {\"id\":1,\"result\":{}}\r\n\r\ndata: {\"id\":2}\n\n";
    let messages = sse_messages(body);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["id"], 1);
    assert_eq!(messages[1]["id"], 2);
}
