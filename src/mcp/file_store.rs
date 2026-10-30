//! A [`TokenStore`] that keeps refresh tokens in one JSON file:
//! `{ "<upstream>": "<refresh token>" }`, readable and writable by its owner only.
//!
//! Several gateways may share the file. [`TokenStore::lock`] takes an advisory
//! lock on a sibling `.lock` file, and writes go through a temporary file that
//! is renamed over the old one, so a reader never sees half a file.

use std::any::Any;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::upstream::TokenStore;

pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> FileStore {
        FileStore { path: path.into() }
    }

    fn read(&self) -> BTreeMap<String, String> {
        match fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|err| {
                eprintln!("token store {}: cannot parse, ignoring it: {err}", self.path.display());
                BTreeMap::new()
            }),
            Err(err) if err.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(err) => {
                eprintln!("token store {}: cannot read: {err}", self.path.display());
                BTreeMap::new()
            }
        }
    }

    fn write(&self, tokens: &BTreeMap<String, String>) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = sibling(&self.path, "tmp");
        let _ = fs::remove_file(&tmp);
        let mut file = OpenOptions::new().write(true).create_new(true).open_private(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(tokens).expect("a map of strings serializes"))?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &self.path)
    }

    fn update(&self, change: impl FnOnce(&mut BTreeMap<String, String>)) {
        let mut tokens = self.read();
        change(&mut tokens);
        if let Err(err) = self.write(&tokens) {
            eprintln!("token store {}: cannot write: {err}", self.path.display());
        }
    }
}

impl TokenStore for FileStore {
    fn load(&self, name: &str) -> Option<String> {
        self.read().remove(name)
    }

    fn save(&self, name: &str, refresh_token: &str) {
        self.update(|tokens| {
            tokens.insert(name.to_owned(), refresh_token.to_owned());
        });
    }

    fn delete(&self, name: &str) {
        self.update(|tokens| {
            tokens.remove(name);
        });
    }

    fn lock(&self) -> io::Result<Box<dyn Any>> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open_private(&sibling(&self.path, "lock"))?;
        file.lock()?;
        Ok(Box::new(file))
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// Opens files for the owner only (`0600`), on Unix.
trait OpenPrivate {
    fn open_private(&mut self, path: &Path) -> io::Result<File>;
}

impl OpenPrivate for OpenOptions {
    fn open_private(&mut self, path: &Path) -> io::Result<File> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600);
        }
        self.open(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, FileStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path().join("tokens.json"));
        (dir, store)
    }

    #[test]
    fn tokens_round_trip_per_upstream() {
        let (_dir, store) = store();
        assert!(store.load("work").is_none());
        store.save("work", "r1");
        store.save("home", "r2");
        store.save("work", "r3");
        assert_eq!(store.load("work").as_deref(), Some("r3"));
        assert_eq!(store.load("home").as_deref(), Some("r2"));
        store.delete("work");
        assert!(store.load("work").is_none());
        assert_eq!(store.load("home").as_deref(), Some("r2"));
    }

    #[test]
    fn the_file_is_json_and_owner_only() {
        let (dir, store) = store();
        store.save("work", "r1");
        let text = fs::read_to_string(dir.path().join("tokens.json")).unwrap();
        let parsed: BTreeMap<String, String> = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.get("work").map(String::as_str), Some("r1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("tokens.json")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!dir.path().join("tokens.json.tmp").exists());
    }

    #[test]
    fn a_second_lock_waits_for_the_first() {
        let (_dir, store) = store();
        let held = store.lock().unwrap();
        let other = FileStore::new(store.path.clone());
        let waiter = std::thread::spawn(move || other.lock().map(drop).is_ok());
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!waiter.is_finished());
        drop(held);
        assert!(waiter.join().unwrap());
    }
}
