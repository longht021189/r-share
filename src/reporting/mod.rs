//! Crash/error reporting, confined to this one module.
//!
//! The concrete backend (Sentry, for now) is named in exactly two places
//! here — [`init`] and the [`report_error!`] macro — never at a call site.
//! Swapping it for something else later means editing this module only.
//!
//! The DSN is deliberately not defined here: it identifies one project's
//! Sentry project, so each project passes its own to [`init`].

#[cfg(feature = "c_share_http")]
mod transport;

/// Re-exported only so [`report_error!`] can name the backend through
/// `$crate`, without the calling crate depending on it.
#[doc(hidden)]
pub use sentry_anyhow;

/// Held for the reporter's lifetime: dropping it flushes anything queued.
/// Never `std::process::exit` while one of these is alive — that skips
/// destructors (including this one's) and would silently drop in-flight
/// reports.
#[must_use]
pub struct Guard(
    #[allow(dead_code, reason = "held only for its Drop side effect")] sentry::ClientInitGuard,
);

/// Initializes crash/error reporting for the process, sending to `dsn`.
/// Panics are captured automatically from here on (via the backend's global
/// panic hook); ordinary errors need an explicit [`report_error!`] call.
///
/// An empty `dsn` disables reporting entirely. A malformed one is reported
/// as a warning and reporting is likewise left disabled, rather than
/// panicking the whole process over a bad config value.
#[cfg(not(feature = "c_share_http"))]
pub fn init(dsn: &str) -> Guard {
    if !dsn.is_empty() {
        eprintln!("warning: built without the c_share_http feature; error reports are not sent");
    }
    start(dsn, None)
}

/// Like [`init`], but sends through `http` (see the `transport` module)
/// instead of sentry's own reqwest transport. `http` must outlive the guard:
/// sentry keeps sending through it until the guard is dropped.
#[cfg(feature = "c_share_http")]
pub fn init(dsn: &str, http: &crate::http_client::HttpClient) -> Guard {
    start(dsn, Some(std::sync::Arc::new(transport::HttpTransportFactory::new(http.clone()))))
}

fn start(dsn: &str, transport: Option<std::sync::Arc<dyn sentry::TransportFactory>>) -> Guard {
    let dsn = if dsn.is_empty() {
        None
    } else {
        match dsn.parse() {
            Ok(dsn) => Some(dsn),
            Err(e) => {
                eprintln!("warning: invalid Sentry DSN ({e}); error reporting is disabled");
                None
            }
        }
    };

    // `ClientOptions` is `#[non_exhaustive]`, so it can't be built with
    // struct-literal syntax (even `..Default::default()`) from outside
    // the `sentry` crate.
    let mut options = sentry::ClientOptions::default();
    options.dsn = dsn;
    options.release = sentry::release_name!();
    options.attach_stacktrace = true;
    options.transport = transport;
    Guard(sentry::init(options))
}

/// Reports an [`anyhow::Error`] to the configured backend. Not for panics —
/// those are already captured by the panic hook installed in [`init`] at the
/// moment they happen, with a real stack trace; calling this on one too would
/// just double-report it.
///
/// A macro instead of a function so the backend crate (`sentry_anyhow`) is
/// named in exactly one place — this expansion — rather than needing a
/// wrapper function call at every call site for what would otherwise be a
/// single pass-through line.
#[macro_export]
macro_rules! report_error {
    ($err:expr) => {
        $crate::reporting::sentry_anyhow::capture_anyhow($err)
    };
}
