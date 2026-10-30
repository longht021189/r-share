//! A cookie jar that survives restarts.
//!
//! Cookies live in memory and are mirrored to a JSON file, so state that a
//! server hands out through `Set-Cookie` (a device id, a session token, ...)
//! is still there on the next launch. Useful wherever the platform keeps no
//! cookies for you, e.g. a webview on a custom URL scheme.
//!
//! The jar knows nothing about HTTP clients: feed it `Set-Cookie` values with
//! [`PersistentJar::set_cookies`] and ask it for the `Cookie` header of a URL
//! with [`PersistentJar::request_header`]. That keeps it usable with whichever
//! client (and client version) a project has, and confines the backing
//! `cookie_store` crate to this module.
//!
//! Most callers want the one process-wide jar: point it at a file with
//! [`init`] once at startup, then reach it from anywhere with [`shared`]. The
//! [`proxy`](crate::proxy) module uses that jar for its own requests, so
//! cookies written through [`shared`] are sent by it.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use cookie_store::CookieStore;
use url::Url;

static SHARED: OnceLock<PersistentJar> = OnceLock::new();

/// A write happens once the jar has not changed for this long...
const QUIET: Duration = Duration::from_secs(2);
/// ...or at the latest this long after the first change, however busy it is.
const MAX_WAIT: Duration = Duration::from_secs(5);

/// Makes the process-wide jar persistent: it is loaded from `path` now and
/// written back there in the background. Call it once at startup, before
/// anything uses [`shared`]. Call [`PersistentJar::flush`] on exit, so the last
/// changes reach the file.
///
/// Returns `false`, and ignores `path`, when the jar already exists because of
/// an earlier `init` or because [`shared`] was used first.
pub fn init(path: PathBuf) -> bool {
    SHARED.set(PersistentJar::load(Some(path))).is_ok()
}

/// The process-wide jar. Held in memory only unless [`init`] ran first.
pub fn shared() -> &'static PersistentJar {
    SHARED.get_or_init(|| PersistentJar::load(None))
}

/// A cookie jar backed by an optional JSON file.
///
/// Only cookies that are persistent (have an expiry) and not yet expired are
/// written; session cookies stay in memory, like in a browser.
///
/// Writes are debounced: a change schedules a write on a background thread,
/// which waits for the jar to go quiet (see [`QUIET`] and [`MAX_WAIT`]). Reads
/// and changes never wait for the disk.
pub struct PersistentJar {
    inner: Arc<Inner>,
    commands: Option<Sender<Command>>,
}

/// What the writer thread is asked to do.
enum Command {
    /// The jar changed: write once it has settled.
    Changed,
    /// Write now, then signal the sender.
    Flush(SyncSender<()>),
}

/// The state shared with the writer thread.
struct Inner {
    store: Mutex<CookieStore>,
    /// Set when the jar changed since it was last written.
    dirty: AtomicBool,
    path: Option<PathBuf>,
}

impl PersistentJar {
    /// Creates a jar, loading it from `path` when given. The jar is written
    /// back to the same file in the background, see [`save`](Self::save). With
    /// `None` it is held in memory only.
    ///
    /// A missing or unreadable file yields an empty jar: losing cookies is
    /// better than refusing to start.
    pub fn load(path: Option<PathBuf>) -> Self {
        let store = path
            .as_ref()
            .and_then(|path| File::open(path).ok())
            .and_then(|file| cookie_store::serde::json::load(BufReader::new(file)).ok())
            .unwrap_or_default();
        let inner = Arc::new(Inner {
            store: Mutex::new(store),
            dirty: AtomicBool::new(false),
            path,
        });
        let commands = inner.path.is_some().then(|| {
            let (sender, receiver) = mpsc::channel();
            let writer = Arc::clone(&inner);
            thread::Builder::new()
                .name("cookie-writer".into())
                .spawn(move || write_in_background(&writer, &receiver))
                .expect("failed to spawn the cookie writer thread");
            sender
        });
        Self { inner, commands }
    }

    /// Number of cookies that have not expired.
    pub fn len(&self) -> usize {
        self.store().iter_unexpired().count()
    }

    /// Whether the jar holds no unexpired cookie.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Stores the cookies from the `Set-Cookie` header values of a response to
    /// `url`. Values that do not parse are skipped, as browsers do. The change
    /// is written to disk in the background.
    pub fn set_cookies<'a>(&self, headers: impl IntoIterator<Item = &'a str>, url: &Url) {
        {
            let mut store = self.store();
            for header in headers {
                let _ = store.parse(header, url);
            }
        }
        self.mark_changed();
    }

    /// The value of the `Cookie` header to send with a request to `url`, or
    /// `None` when no cookie applies.
    pub fn request_header(&self, url: &Url) -> Option<String> {
        let store = self.store();
        let header = store
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        (!header.is_empty()).then_some(header)
    }

    /// Stores one cookie given as a `Set-Cookie` style string, as page script
    /// would write it through `document.cookie`. The change is written to disk
    /// in the background.
    ///
    /// Fails if the cookie does not parse or is not valid for `url`, e.g. its
    /// `Domain` does not match the host; the jar is unchanged then.
    pub fn add(&self, cookie: &str, url: &Url) -> anyhow::Result<()> {
        self.store()
            .parse(cookie, url)
            .map_err(|err| anyhow!("invalid cookie: {err}"))?;
        self.mark_changed();
        Ok(())
    }

    /// Asks for the jar to be written soon. Returns at once; the write happens
    /// in the background once the jar has settled. Does nothing when the jar
    /// has no file, or when nothing changed since the last write.
    pub fn save(&self) {
        if let Some(commands) = &self.commands {
            let _ = commands.send(Command::Changed);
        }
    }

    /// Writes the jar now if it changed, and returns once the file is up to
    /// date. Call it on exit: a change still waiting for its debounce would
    /// otherwise be lost with the process.
    pub fn flush(&self) {
        let Some(commands) = &self.commands else {
            return;
        };
        let (ack, done) = mpsc::sync_channel(1);
        if commands.send(Command::Flush(ack)).is_ok() {
            let _ = done.recv();
        } else {
            // The writer is gone; write from here.
            self.inner.save();
        }
    }

    fn mark_changed(&self) {
        self.inner.dirty.store(true, Ordering::Relaxed);
        self.save();
    }

    fn store(&self) -> MutexGuard<'_, CookieStore> {
        self.inner.store()
    }
}

impl Inner {
    /// Writes the jar to its file if it changed since the last write. The file
    /// is replaced atomically, so a crash never leaves a half-written jar.
    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        if let Err(err) = self.write(path) {
            // Nothing reached the disk, so try again on the next change.
            self.dirty.store(true, Ordering::Relaxed);
            eprintln!("[cookie] cannot save: {err:#}");
        }
    }

    fn write(&self, path: &Path) -> anyhow::Result<()> {
        let mut json = Vec::new();
        cookie_store::serde::json::save(&self.store(), &mut json)
            .map_err(|err| anyhow!("cannot serialize cookies: {err}"))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, json).with_context(|| format!("cannot write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
    }

    fn store(&self) -> MutexGuard<'_, CookieStore> {
        // A panic while holding the lock cannot leave the store half-updated in
        // a way that matters here, so keep going with what is there.
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The writer thread: runs until every jar handle is gone, writing when asked.
fn write_in_background(inner: &Inner, commands: &mpsc::Receiver<Command>) {
    while let Ok(command) = commands.recv() {
        match command {
            Command::Flush(ack) => {
                inner.save();
                let _ = ack.send(());
            }
            Command::Changed => {
                // Debounce: keep collecting changes until the jar is quiet for
                // QUIET, but never hold a change back for longer than MAX_WAIT.
                let started = Instant::now();
                loop {
                    let remaining = MAX_WAIT.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        break;
                    }
                    match commands.recv_timeout(QUIET.min(remaining)) {
                        Ok(Command::Changed) => {}
                        Ok(Command::Flush(ack)) => {
                            inner.save();
                            let _ = ack.send(());
                        }
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => {
                            inner.save();
                            return;
                        }
                    }
                }
                inner.save();
            }
        }
    }
    // Every handle is gone: keep what has not been written yet.
    inner.save();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn cookies_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookies.json");
        let site = url("https://www.example.com/");

        let jar = PersistentJar::load(Some(path.clone()));
        jar.add("id=abc; Max-Age=3600; Domain=example.com", &site)
            .unwrap();
        jar.add("session=xyz; Domain=example.com", &site).unwrap();
        jar.flush();

        let reloaded = PersistentJar::load(Some(path));
        let header = reloaded.request_header(&site).unwrap();
        assert!(header.contains("id=abc"), "{header}");
        // Session cookies are not persisted.
        assert!(!header.contains("session"), "{header}");
        assert_eq!(reloaded.len(), 1);
    }

    #[test]
    fn request_header_matches_domain() {
        let jar = PersistentJar::load(None);
        jar.set_cookies(
            ["a=1; Domain=example.com", "b=2; Domain=example.com"],
            &url("https://www.example.com/"),
        );

        let header = jar
            .request_header(&url("https://api.example.com/x"))
            .unwrap();
        assert!(header.contains("a=1") && header.contains("b=2"), "{header}");
        assert_eq!(header.matches("; ").count(), 1, "{header}");
        assert_eq!(jar.request_header(&url("https://other.org/")), None);
    }

    #[test]
    fn invalid_set_cookie_values_are_skipped() {
        let jar = PersistentJar::load(None);
        jar.set_cookies(["", "no-equals-sign", "ok=1"], &url("https://example.com/"));
        assert_eq!(jar.len(), 1);
        assert!(jar.add("", &url("https://example.com/")).is_err());
        // A domain that does not match the host is refused, as in a browser.
        let other = "a=1; Domain=other.org";
        assert!(jar.add(other, &url("https://example.com/")).is_err());
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn save_only_writes_after_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("cookies.json");

        let jar = PersistentJar::load(Some(path.clone()));
        jar.flush();
        assert!(!path.exists());

        jar.set_cookies(["a=1; Max-Age=60"], &url("https://example.com/"));
        jar.flush();
        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn a_broken_file_yields_an_empty_jar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookies.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(PersistentJar::load(Some(path)).is_empty());
    }

    #[test]
    fn a_change_is_written_once_the_jar_settles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookies.json");
        let jar = PersistentJar::load(Some(path.clone()));

        jar.set_cookies(["a=1; Max-Age=60"], &url("https://example.com/"));
        assert!(!path.exists(), "written before the debounce");

        thread::sleep(QUIET + Duration::from_millis(500));
        assert!(path.exists(), "not written after the jar settled");
    }

    #[test]
    fn flush_writes_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookies.json");
        let jar = PersistentJar::load(Some(path.clone()));

        jar.set_cookies(["a=1; Max-Age=60"], &url("https://example.com/"));
        jar.flush();
        assert!(path.exists());
    }
}
