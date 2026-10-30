//! An MCP gateway: several upstream MCP servers, served as one.
//!
//! Each upstream is a remote MCP server speaking Streamable HTTP (one JSON-RPC
//! POST per message, the reply as JSON or as an SSE stream). Its tools are
//! listed as `<upstream>__<tool>`, and a call to such a name is forwarded to
//! that upstream under its own name. [`Gateway::handle`] answers one message
//! from the client; [`serve_stdio`] runs the gateway over stdin/stdout.
//!
//! A `Gateway` is meant to be split across two processes, typically two
//! machines: [`serve_admin`] runs the `service` half (the real upstreams,
//! their tokens, and `/mcp` itself) wherever it can stay up and keep a
//! stable public address for OAuth redirects (a cloud VM, say); [`Relay`]
//! runs the `stdio` half, wherever an MCP client like Claude Code actually
//! spawns a process (so, typically, a developer's own machine), forwarding
//! each message to the service's `/mcp` over plain HTTP. [`serve_stdio`] and
//! [`Gateway`] directly, without a `Relay`, still works for a single
//! unsplit process -- there is just nothing left in this codebase that
//! starts one that way.
//!
//! An upstream either carries static `headers`, or has `oauth` settings: then
//! the gateway logs it in with PKCE ([`Gateway::begin_login`] and
//! [`Gateway::complete_login`]), refreshes its tokens, and calls the
//! [`Gateway::on_login_required`] handler when a login is needed. Tokens are
//! kept in memory only, and [`Gateway::terminate`] drops them.
//!
//! The upstream's session is started on first use, and started again if the
//! upstream forgets it (a `404` on a session it issued).
//!
//! - `upstream`: the configuration of an upstream and the [`TokenStore`] trait.
//! - `gateway`: the public [`Gateway`] API and tool routing, including
//!   [`Gateway::add_upstream`] and [`Gateway::list_upstreams`].
//! - `session`: per-upstream state and the internal failure types.
//! - `transport`: HTTP requests, SSE replies, session start and token refresh.
//! - `stdio`: the stdin/stdout loop.
//! - `admin`: the `service` half of a split gateway -- a plain HTTP API over
//!   `add_upstream`/`list_upstreams`/`begin_login`, the OAuth redirect
//!   (`/callback`), and MCP itself (`/mcp`, [`Gateway::handle`]) for
//!   [`Relay`] (the `stdio` half, typically on a different machine) to call.
//! - `relay`: [`Relay`], the `stdio` half: forwards whatever it reads from
//!   stdin to one remote `/mcp` verbatim, trusting the remote end to already
//!   speak full MCP, rather than merging upstreams itself like [`Gateway`].
//! - `file_store`: a [`TokenStore`] that keeps refresh tokens in a JSON file.
//! - `login_server`: a local HTTP server for one OAuth login's redirect.
//! - `env`: [`expand_env`], `$VAR` expansion for a config value that
//!   shouldn't sit in plaintext (a header, a shared secret).

pub mod oauth;

mod admin;
mod env;
mod file_store;
mod gateway;
mod login_server;
mod relay;
mod session;
mod stdio;
mod transport;
mod upstream;

#[cfg(test)]
mod tests;

pub use admin::serve as serve_admin;
pub use env::expand_env;
pub use file_store::FileStore;
pub use gateway::{Gateway, UpstreamInfo, UpstreamStatus};
pub use login_server::{Redirect, RedirectListener};
pub use relay::{Relay, serve_stdio as serve_stdio_relay};
pub use stdio::serve_stdio;
pub use upstream::{TokenStore, Upstream};

const PROTOCOL_VERSION: &str = "2025-06-18";
const SEPARATOR: &str = "__";

const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;
const PARSE_ERROR: i64 = -32700;
