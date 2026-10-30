//! A tiny local HTTP server for the redirect leg of one OAuth login, to pair
//! with [`Gateway::begin_login`] and [`Gateway::complete_login`].

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use super::gateway::Gateway;

/// The `host:port` and path of a `redirect_uri`, parsed once so a typo is an
/// error at startup rather than when a login is actually attempted.
#[derive(Clone, Debug)]
pub struct Redirect {
    authority: String,
    path: String,
}

impl Redirect {
    /// Parses `uri`, which must be a `http://127.0.0.1:<port>/...` or
    /// `http://localhost:<port>/...` address -- the only kind this listens for.
    pub fn parse(uri: &str) -> Result<Redirect, String> {
        let invalid = || format!("redirect_uri {uri} must be an http://127.0.0.1 or http://localhost address");
        let rest = uri.strip_prefix("http://").ok_or_else(invalid)?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].split('?').next().unwrap_or("/")),
            None => (rest, "/"),
        };
        if !(authority.starts_with("127.0.0.1:") || authority.starts_with("localhost:")) {
            return Err(invalid());
        }
        Ok(Redirect { authority: authority.to_owned(), path: path.to_owned() })
    }

    /// Binds the redirect's address, ready to [`RedirectListener::wait`] on it.
    pub fn listen(&self) -> Result<RedirectListener, String> {
        let listener = TcpListener::bind(&self.authority)
            .map_err(|err| format!("cannot listen on {} for the login: {err}", self.authority))?;
        Ok(RedirectListener { listener, path: self.path.clone() })
    }
}

/// Bound and ready to receive one OAuth redirect.
pub struct RedirectListener {
    listener: TcpListener,
    path: String,
}

impl RedirectListener {
    /// Blocks until the browser's redirect arrives, completes the pending
    /// login it carries through `gateway`, and returns the logged-in
    /// upstream's name. A request for any other path is refused and does not
    /// end the wait.
    pub fn wait(self, gateway: &Gateway, runtime: &tokio::runtime::Runtime) -> Result<String, String> {
        for stream in self.listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(&stream);
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let mut header = String::new();
            while reader.read_line(&mut header).is_ok_and(|read| read > 2) {
                header.clear();
            }
            let target = request_line.split_whitespace().nth(1).unwrap_or_default();
            let (target_path, query) = target.split_once('?').unwrap_or((target, ""));
            if target_path != self.path {
                respond(&mut stream, "404 Not Found", "not the login callback");
                continue;
            }
            let params = parse_query(query);
            let outcome = match (params.get("code"), params.get("state")) {
                (Some(code), Some(state)) => runtime.block_on(gateway.complete_login(state, code)),
                _ => Err(params.get("error").cloned().unwrap_or_else(|| "no code".to_owned())),
            };
            let (status, body) = match &outcome {
                Ok(name) => ("200 OK", format!("Logged in to {name}. You can close this window.")),
                Err(err) => ("400 Bad Request", format!("Login failed: {err}")),
            };
            respond(&mut stream, status, &body);
            return outcome;
        }
        Err("the listener closed before a login arrived".to_owned())
    }
}

fn respond(stream: &mut impl Write, status: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
}

pub(super) fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (percent_decode(key), percent_decode(value)))
        .collect()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|hex| u8::from_str_radix(hex, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
