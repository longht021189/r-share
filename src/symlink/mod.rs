use std::io;
use std::path::Path;

/// Creates a symbolic link at `link` pointing to `target`.
///
/// A relative `target` is stored as is and resolved relative to the directory
/// containing `link`, like `ln -s`. Fails with [`io::ErrorKind::AlreadyExists`]
/// if something already exists at `link`. The target itself does not have to
/// exist (a dangling link is created).
///
/// On Windows, the kind of link (file or directory) is chosen by looking at
/// `target`; if it does not exist, a file link is created. Creating symlinks
/// there requires Developer Mode or the "create symbolic links" privilege.
pub fn create(target: &Path, link: &Path) -> io::Result<()> {
    create_impl(target, link)
}

/// Like [`create`], but idempotent: creates `link`'s parent directories, and
/// if `link` already exists as a symlink, replaces it.
///
/// If `link` exists as anything else (a real file or directory), this still
/// fails with [`io::ErrorKind::AlreadyExists`] rather than clobbering it.
pub fn replace(target: &Path, link: &Path) -> io::Result<()> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match link.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => remove_symlink(link)?,
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    create(target, link)
}

/// Removes the symlink at `link`. On Windows, a link to a directory is
/// removed like a directory, not like a file.
fn remove_symlink(link: &Path) -> io::Result<()> {
    if cfg!(windows) && link.is_dir() {
        return std::fs::remove_dir(link);
    }
    std::fs::remove_file(link)
}

#[cfg(unix)]
fn create_impl(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_impl(target: &Path, link: &Path) -> io::Result<()> {
    let resolved = match link.parent() {
        Some(parent) => parent.join(target),
        None => target.to_path_buf(),
    };
    if resolved.is_dir() {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_to_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("file.txt");
        let link = tmp.path().join("link.txt");
        std::fs::write(&target, "hello").unwrap();

        create(&target, &link).unwrap();

        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_link(&link).unwrap(), target);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "hello");
    }

    #[test]
    fn links_to_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("dir");
        let link = tmp.path().join("link");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("file.txt"), "hello").unwrap();

        create(&target, &link).unwrap();

        assert!(link.is_dir());
        assert_eq!(std::fs::read_to_string(link.join("file.txt")).unwrap(), "hello");
    }

    #[test]
    fn resolves_relative_target_from_the_link_directory() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        std::fs::write(tmp.path().join("file.txt"), "hello").unwrap();
        let link = tmp.path().join("sub").join("link.txt");

        create(Path::new("../file.txt"), &link).unwrap();

        assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("../file.txt"));
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "hello");
    }

    #[test]
    fn creates_a_dangling_link_when_target_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("link");

        create(&tmp.path().join("missing"), &link).unwrap();

        assert!(link.symlink_metadata().is_ok());
        assert!(!link.exists());
    }

    #[test]
    fn fails_if_link_already_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("file.txt");
        let link = tmp.path().join("link.txt");
        std::fs::write(&target, "hello").unwrap();
        std::fs::write(&link, "occupied").unwrap();

        let err = create(&target, &link).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "occupied");
    }

    #[test]
    fn replace_creates_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("file.txt");
        let link = tmp.path().join("a/b/link.txt");
        std::fs::write(&target, "hello").unwrap();

        replace(&target, &link).unwrap();

        assert_eq!(std::fs::read_to_string(&link).unwrap(), "hello");
    }

    #[test]
    fn replace_swaps_an_existing_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        let link = tmp.path().join("link");
        std::fs::write(&a, "a").unwrap();
        std::fs::write(&b, "b").unwrap();

        replace(&a, &link).unwrap();
        replace(&b, &link).unwrap();

        assert_eq!(std::fs::read_to_string(&link).unwrap(), "b");
    }

    #[test]
    fn replace_refuses_to_clobber_a_real_file() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        let link = tmp.path().join("link");
        std::fs::write(&target, "hi").unwrap();
        std::fs::write(&link, "real file").unwrap();

        let err = replace(&target, &link).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "real file");
    }
}
