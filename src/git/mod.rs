use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::io::Write;
use std::process::Command;

use tempfile::NamedTempFile;

use crate::ssh::private_key_to_openssh;

/// Error returned by the git CLI wrappers in this module.
#[derive(Debug)]
pub enum GitError {
    /// The `git` executable could not be started (e.g. it is not installed).
    Spawn(std::io::Error),
    /// The temporary SSH key file could not be written.
    KeyFile(std::io::Error),
    /// [`checkout`]'s revision is neither a branch nor a tag of the remote,
    /// nor a full commit hash.
    UnknownRevision(String),
    /// `git` ran but exited unsuccessfully.
    Failed {
        /// The arguments passed to `git`.
        args: Vec<String>,
        /// The exit code, or `None` if the process was killed by a signal.
        code: Option<i32>,
        /// Trimmed contents of git's stderr.
        stderr: String,
    },
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::Spawn(err) => write!(f, "failed to run git: {err}"),
            GitError::KeyFile(err) => write!(f, "failed to write temporary SSH key file: {err}"),
            GitError::UnknownRevision(rev) => {
                write!(f, "{rev:?} is neither a branch nor a tag of the remote, nor a full commit hash")
            }
            GitError::Failed { args, code, stderr } => {
                write!(f, "git {} failed", args.join(" "))?;
                if let Some(code) = code {
                    write!(f, " (exit code {code})")?;
                }
                if !stderr.is_empty() {
                    write!(f, ": {stderr}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for GitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GitError::Spawn(err) | GitError::KeyFile(err) => Some(err),
            GitError::UnknownRevision(_) | GitError::Failed { .. } => None,
        }
    }
}

/// What a new worktree should check out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorktreeBranch<'a> {
    /// Create a new branch `name`, starting at `start_point` (default: `HEAD`).
    New {
        name: &'a str,
        start_point: Option<&'a str>,
    },
    /// Check out an existing branch. It must not be checked out in another worktree.
    Existing(&'a str),
    /// Check out `HEAD` as a detached HEAD, with no branch. For throwaway work copies.
    Detached,
}

/// Runs `git` with `args` and the extra environment `envs`, never prompting
/// for credentials on the terminal. Returns what git wrote to stdout.
fn run_git_output<I, S>(args: I, envs: &[(&str, &str)]) -> Result<Vec<u8>, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<S> = args.into_iter().collect();
    let output = Command::new("git")
        .args(&args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .envs(envs.iter().copied())
        .output()
        .map_err(GitError::Spawn)?;

    if output.status.success() {
        return Ok(output.stdout);
    }
    Err(GitError::Failed {
        args: args
            .iter()
            .map(|arg| arg.as_ref().to_string_lossy().into_owned())
            .collect(),
        code: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// Like [`run_git_output`], for commands whose output is not needed.
fn run_git<I, S>(args: I, envs: &[(&str, &str)]) -> Result<(), GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_git_output(args, envs).map(drop)
}

/// Builds the `GIT_SSH_COMMAND` that makes `ssh` authenticate with only the
/// key file at `key_path`, and never prompt. Unknown hosts are added to
/// `known_hosts` on first connect; a changed host key is still rejected.
///
/// On Windows, git runs the command through its bundled `sh`, so the path is
/// written with forward slashes (`C:/Users/...`), which both Win32 OpenSSH and
/// Git for Windows' `ssh` accept, instead of backslashes.
fn ssh_command(key_path: &Path) -> String {
    let path = key_path.to_string_lossy();
    let path = if cfg!(windows) { path.replace('\\', "/") } else { path.into_owned() };
    let quoted = path.replace('\'', "'\\''");
    format!("ssh -i '{quoted}' -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new")
}

/// Clones the repository at `url` into `dest` using the git CLI.
///
/// `dest` must not exist or must be an empty directory.
///
/// If `ssh_key` is given (an Ed25519 private key, i.e. a 32-byte seed as
/// returned by [`crate::data::signing::generate_keypair`]), git authenticates
/// over SSH with only that key, ignoring keys from `~/.ssh` and the SSH agent.
/// The key is written to a temporary file (mode `0600` on Unix, the user's
/// private temp directory on Windows) that is deleted when this function
/// returns. Unknown hosts are trusted on first use
/// (`StrictHostKeyChecking=accept-new`), while a changed host key is rejected.
pub fn clone(url: &str, dest: &Path, ssh_key: Option<[u8; 32]>) -> Result<(), GitError> {
    let args = [OsStr::new("clone"), OsStr::new("--"), url.as_ref(), dest.as_os_str()];

    let Some(private_key) = ssh_key else {
        return run_git(args, &[]);
    };

    let mut key_file = NamedTempFile::new().map_err(GitError::KeyFile)?;
    key_file
        .write_all(private_key_to_openssh(private_key, "").as_bytes())
        .and_then(|()| key_file.flush())
        .map_err(GitError::KeyFile)?;

    // Close our handle before ssh opens the file (Windows refuses to share it
    // otherwise); the file is still deleted when `key_path` is dropped.
    let key_path = key_file.into_temp_path();

    let command = ssh_command(&key_path);
    run_git(args, &[("GIT_SSH_COMMAND", &command)])
}

/// Creates a worktree at `path` for the repository at `repo`, using
/// `git worktree add`. `path` must not exist or must be an empty directory.
pub fn worktree_add(repo: &Path, path: &Path, branch: WorktreeBranch<'_>) -> Result<(), GitError> {
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("-C"),
        repo.as_os_str(),
        OsStr::new("worktree"),
        OsStr::new("add"),
    ];
    match branch {
        WorktreeBranch::New { name, start_point } => {
            args.extend([OsStr::new("-b"), OsStr::new(name), OsStr::new("--"), path.as_os_str()]);
            args.extend(start_point.map(OsStr::new));
        }
        WorktreeBranch::Existing(name) => {
            args.extend([OsStr::new("--"), path.as_os_str(), OsStr::new(name)]);
        }
        WorktreeBranch::Detached => {
            args.extend([OsStr::new("--detach"), OsStr::new("--"), path.as_os_str()]);
        }
    }
    run_git(args, &[])
}

/// Lists the paths of all worktrees of the repository at `repo`, using
/// `git worktree list --porcelain`. The first entry is the repository's own
/// primary working tree.
pub fn worktree_list(repo: &Path) -> Result<Vec<PathBuf>, GitError> {
    let args = [
        OsStr::new("-C"),
        repo.as_os_str(),
        OsStr::new("worktree"),
        OsStr::new("list"),
        OsStr::new("--porcelain"),
    ];
    let stdout = run_git_output(args, &[])?;
    Ok(String::from_utf8_lossy(&stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .map(PathBuf::from)
        .collect())
}

/// What [`checkout`] checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedOut {
    /// The commit `HEAD` is now at.
    pub commit: String,
    /// The local branch now checked out, tracking the remote's; `None` for a
    /// detached `HEAD` (a tag or a commit).
    pub branch: Option<String>,
}

/// What a [`checkout`] revision turned out to be on the remote.
enum Target {
    Branch(String),
    Tag(String),
    Commit(String),
}

/// Checks out one revision of the repository at `url` into a new repository
/// at `dest` (which must not exist or must be an empty directory), fetching
/// only that revision rather than cloning everything -- what GitHub's
/// `actions/checkout` does.
///
/// `rev` is a branch name, a tag name (either optionally spelled out as
/// `refs/heads/...`/`refs/tags/...`), or a full 40- or 64-character commit
/// hash (a short one cannot be fetched); `None` means the remote's default
/// branch. A branch is checked out as a local branch of the same name
/// tracking `origin/<branch>`; a tag or a commit as a detached `HEAD`.
/// `depth` limits the fetch to that many commits (`None`: full history).
///
/// If `ssh_key_file` is given (an OpenSSH private key file, e.g. written
/// from [`crate::ssh::private_key_to_openssh`]), git authenticates over SSH
/// with only that key, the same way as [`clone`] -- but the setting is kept
/// in the new repository's own config (`core.sshCommand`), so later git
/// commands there (a push, say) authenticate the same way for as long as the
/// file exists. [`unset_ssh_command`] removes it again.
pub fn checkout(
    url: &str,
    dest: &Path,
    rev: Option<&str>,
    depth: Option<u32>,
    ssh_key_file: Option<&Path>,
) -> Result<CheckedOut, GitError> {
    run_git([OsStr::new("init"), OsStr::new("-q"), dest.as_os_str()], &[])?;
    let git_in = |args: &[&str]| {
        let mut all: Vec<&OsStr> = vec![OsStr::new("-C"), dest.as_os_str()];
        all.extend(args.iter().map(OsStr::new));
        run_git_output(all, &[])
    };
    git_in(&["remote", "add", "origin", url])?;
    if let Some(key) = ssh_key_file {
        git_in(&["config", "core.sshCommand", &ssh_command(key)])?;
    }

    let target = resolve_revision(dest, rev)?;
    let refspec = match &target {
        Target::Branch(branch) => format!("+refs/heads/{branch}:refs/remotes/origin/{branch}"),
        Target::Tag(tag) => format!("+refs/tags/{tag}:refs/tags/{tag}"),
        Target::Commit(commit) => commit.clone(),
    };
    let depth = depth.map(|depth| format!("--depth={depth}"));
    let mut fetch = vec!["fetch", "-q", "--no-tags"];
    fetch.extend(depth.as_deref());
    fetch.extend(["origin", &refspec]);
    git_in(&fetch)?;

    let branch = match target {
        Target::Branch(branch) => {
            let upstream = format!("origin/{branch}");
            git_in(&["checkout", "-q", "-B", &branch, "--track", &upstream])?;
            Some(branch)
        }
        Target::Tag(tag) => {
            git_in(&["checkout", "-q", "--detach", &format!("refs/tags/{tag}")])?;
            None
        }
        Target::Commit(_) => {
            git_in(&["checkout", "-q", "--detach", "FETCH_HEAD"])?;
            None
        }
    };
    let commit = git_in(&["rev-parse", "HEAD"])?;
    Ok(CheckedOut { commit: String::from_utf8_lossy(&commit).trim().to_owned(), branch })
}

/// Asks the remote `origin` of the repository at `repo` what `rev` is (see
/// [`checkout`]), without fetching anything.
fn resolve_revision(repo: &Path, rev: Option<&str>) -> Result<Target, GitError> {
    let ls_remote = |args: &[&str]| -> Result<String, GitError> {
        let mut all: Vec<&OsStr> = vec![OsStr::new("-C"), repo.as_os_str(), OsStr::new("ls-remote")];
        all.extend(args.iter().map(OsStr::new));
        run_git_output(all, &[]).map(|out| String::from_utf8_lossy(&out).into_owned())
    };

    let Some(rev) = rev else {
        // `ref: refs/heads/main\tHEAD`, then `<hash>\tHEAD`.
        let listed = ls_remote(&["--symref", "origin", "HEAD"])?;
        let branch = listed
            .lines()
            .find_map(|line| line.strip_prefix("ref: refs/heads/")?.strip_suffix("\tHEAD"));
        return Ok(match branch {
            Some(branch) => Target::Branch(branch.to_owned()),
            None => Target::Commit("HEAD".to_owned()),
        });
    };

    let is_hash = matches!(rev.len(), 40 | 64) && rev.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hash {
        return Ok(Target::Commit(rev.to_owned()));
    }
    if let Some(branch) = rev.strip_prefix("refs/heads/") {
        return Ok(Target::Branch(branch.to_owned()));
    }
    if let Some(tag) = rev.strip_prefix("refs/tags/") {
        return Ok(Target::Tag(tag.to_owned()));
    }

    let (head, tag) = (format!("refs/heads/{rev}"), format!("refs/tags/{rev}"));
    let listed = ls_remote(&["origin", &head, &tag])?;
    let refs: Vec<&str> = listed.lines().filter_map(|line| line.split('\t').nth(1)).collect();
    if refs.contains(&head.as_str()) {
        Ok(Target::Branch(rev.to_owned()))
    } else if refs.contains(&tag.as_str()) {
        Ok(Target::Tag(rev.to_owned()))
    } else {
        Err(GitError::UnknownRevision(rev.to_owned()))
    }
}

/// Removes the `core.sshCommand` a [`checkout`] with an SSH key left in the
/// repository at `repo`'s config.
pub fn unset_ssh_command(repo: &Path) -> Result<(), GitError> {
    let args = [
        OsStr::new("-C"),
        repo.as_os_str(),
        OsStr::new("config"),
        OsStr::new("--unset"),
        OsStr::new("core.sshCommand"),
    ];
    run_git(args, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// Creates a repo with one commit on `main`, plus an extra branch `feature`.
    fn init_repo(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-b", "main"]);
        std::fs::write(dir.join("file.txt"), "hello").unwrap();
        git(dir, &["add", "."]);
        git(dir, &["commit", "-m", "init"]);
        git(dir, &["branch", "feature"]);
    }

    /// [`init_repo`], plus a second commit on `feature` and a tag `v1` on
    /// `main`'s commit. Returns its `file://` URL (a plain path would make
    /// git ignore `--depth`).
    fn init_checkout_source(dir: &Path) -> String {
        init_repo(dir);
        git(dir, &["tag", "v1"]);
        git(dir, &["checkout", "-q", "feature"]);
        std::fs::write(dir.join("file.txt"), "feature").unwrap();
        git(dir, &["commit", "-qam", "feature"]);
        git(dir, &["checkout", "-q", "main"]);
        format!("file://{}", dir.display())
    }

    #[test]
    fn checks_out_the_default_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        let url = init_checkout_source(&source);

        let checked_out = checkout(&url, &dest, None, Some(1), None).unwrap();

        assert_eq!(checked_out.branch.as_deref(), Some("main"));
        assert_eq!(checked_out.commit, git(&source, &["rev-parse", "main"]));
        assert_eq!(git(&dest, &["branch", "--show-current"]), "main");
        assert_eq!(git(&dest, &["rev-parse", "--abbrev-ref", "@{upstream}"]), "origin/main");
        assert_eq!(git(&dest, &["rev-parse", "--is-shallow-repository"]), "true");
    }

    #[test]
    fn checks_out_a_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        let url = init_checkout_source(&source);

        let checked_out = checkout(&url, &dest, Some("feature"), None, None).unwrap();

        assert_eq!(checked_out.branch.as_deref(), Some("feature"));
        assert_eq!(std::fs::read_to_string(dest.join("file.txt")).unwrap(), "feature");
        assert_eq!(git(&dest, &["rev-parse", "--is-shallow-repository"]), "false");
    }

    #[test]
    fn checks_out_a_tag_detached() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        let url = init_checkout_source(&source);

        let checked_out = checkout(&url, &dest, Some("v1"), Some(1), None).unwrap();

        assert_eq!(checked_out.branch, None);
        assert_eq!(checked_out.commit, git(&source, &["rev-parse", "v1"]));
        assert_eq!(git(&dest, &["branch", "--show-current"]), "");
    }

    #[test]
    fn checks_out_a_commit_detached() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        let url = init_checkout_source(&source);
        let commit = git(&source, &["rev-parse", "feature"]);

        let checked_out = checkout(&url, &dest, Some(&commit), Some(1), None).unwrap();

        assert_eq!(checked_out, CheckedOut { commit, branch: None });
        assert_eq!(std::fs::read_to_string(dest.join("file.txt")).unwrap(), "feature");
    }

    #[test]
    fn checkout_refuses_an_unknown_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let url = init_checkout_source(&source);

        let err = checkout(&url, &tmp.path().join("dest"), Some("nope"), None, None).unwrap_err();

        assert!(matches!(err, GitError::UnknownRevision(_)), "{err}");
    }

    #[test]
    fn checkout_with_a_key_keeps_then_unsets_ssh_command() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        let url = init_checkout_source(&source);
        let key = tmp.path().join("key");

        // A file:// URL does not use SSH, so the key itself is never read.
        checkout(&url, &dest, None, None, Some(&key)).unwrap();
        assert_eq!(git(&dest, &["config", "core.sshCommand"]), ssh_command(&key));

        unset_ssh_command(&dest).unwrap();
        assert!(run_git(["-C", dest.to_str().unwrap(), "config", "core.sshCommand"], &[]).is_err());
    }

    #[test]
    fn clones_a_repository() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        init_repo(&source);

        clone(source.to_str().unwrap(), &dest, None).unwrap();

        assert_eq!(std::fs::read_to_string(dest.join("file.txt")).unwrap(), "hello");
    }

    #[test]
    fn clones_a_repository_with_ssh_key_set() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        init_repo(&source);

        // A local path does not use SSH, so this only checks that passing a key is harmless.
        clone(source.to_str().unwrap(), &dest, Some([7; 32])).unwrap();

        assert!(dest.join("file.txt").exists());
    }

    #[test]
    fn ssh_command_uses_only_the_given_key() {
        let command = ssh_command(Path::new("/tmp/key"));

        assert_eq!(command, "ssh -i '/tmp/key' -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new");
    }

    #[cfg(windows)]
    #[test]
    fn ssh_command_uses_forward_slashes_on_windows() {
        let command = ssh_command(Path::new(r"C:\Users\me\AppData\Local\Temp\.tmpAbC"));

        assert!(command.starts_with("ssh -i 'C:/Users/me/AppData/Local/Temp/.tmpAbC' "), "{command}");
    }

    #[test]
    fn ssh_command_escapes_single_quotes_in_path() {
        let command = ssh_command(Path::new("/tmp/it's a key"));

        assert!(command.starts_with(r"ssh -i '/tmp/it'\''s a key' "), "{command}");
    }

    #[test]
    fn clone_fails_for_missing_repository() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");

        let err = clone(missing.to_str().unwrap(), &tmp.path().join("dest"), None).unwrap_err();

        assert!(matches!(err, GitError::Failed { .. }), "{err}");
    }

    #[test]
    fn adds_worktree_on_new_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let worktree = tmp.path().join("wt");
        init_repo(&repo);

        worktree_add(
            &repo,
            &worktree,
            WorktreeBranch::New { name: "topic", start_point: None },
        )
        .unwrap();

        assert_eq!(git(&worktree, &["branch", "--show-current"]), "topic");
        assert!(worktree.join("file.txt").exists());
    }

    #[test]
    fn adds_worktree_on_new_branch_from_start_point() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let worktree = tmp.path().join("wt");
        init_repo(&repo);

        worktree_add(
            &repo,
            &worktree,
            WorktreeBranch::New { name: "topic", start_point: Some("feature") },
        )
        .unwrap();

        assert_eq!(
            git(&worktree, &["rev-parse", "HEAD"]),
            git(&repo, &["rev-parse", "feature"])
        );
    }

    #[test]
    fn adds_worktree_on_existing_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let worktree = tmp.path().join("wt");
        init_repo(&repo);

        worktree_add(&repo, &worktree, WorktreeBranch::Existing("feature")).unwrap();

        assert_eq!(git(&worktree, &["branch", "--show-current"]), "feature");
    }

    #[test]
    fn adds_detached_worktree_creating_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let worktree = tmp.path().join("nested/dirs/wt");
        init_repo(&repo);

        worktree_add(&repo, &worktree, WorktreeBranch::Detached).unwrap();

        assert_eq!(git(&worktree, &["branch", "--show-current"]), "");
        assert_eq!(git(&worktree, &["rev-parse", "HEAD"]), git(&repo, &["rev-parse", "HEAD"]));
    }

    #[test]
    fn lists_worktrees_starting_with_the_primary_one() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let worktree = tmp.path().join("wt");
        init_repo(&repo);

        assert_eq!(worktree_list(&repo).unwrap().len(), 1);

        worktree_add(&repo, &worktree, WorktreeBranch::Detached).unwrap();

        let listed = worktree_list(&repo).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].canonicalize().unwrap(), repo.canonicalize().unwrap());
        assert_eq!(listed[1].canonicalize().unwrap(), worktree.canonicalize().unwrap());
    }

    #[test]
    fn worktree_list_fails_for_a_non_repository() {
        let tmp = tempfile::tempdir().unwrap();

        let err = worktree_list(tmp.path()).unwrap_err();

        assert!(matches!(err, GitError::Failed { .. }), "{err}");
    }

    #[test]
    fn worktree_add_fails_when_branch_is_already_checked_out() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        init_repo(&repo);

        let err =
            worktree_add(&repo, &tmp.path().join("wt"), WorktreeBranch::Existing("main")).unwrap_err();

        assert!(matches!(err, GitError::Failed { .. }), "{err}");
    }
}
