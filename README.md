# r-share

Holds the Rust mods that are shared across projects.

## Using it in another project

The dependency is declared once, as a git dependency, and a local checkout is swapped in per machine. Never put a `path` in the committed `Cargo.toml`: it only holds on your machine and breaks the build for anyone who clones the project on its own.

### 1. Declare a git dependency

In the project's `Cargo.toml` (committed), use a git dependency so anyone who clones the project on its own can still build it:

```toml
[dependencies]
r-share = { git = "https://github.com/longht021189/r-share" }
```

### 2. Local development: use the `r-share` checkout next to your project

During development, to use the `r-share` code on your machine instead of the GitHub version, create `.cargo/config.toml` and point a `[patch]` at your checkout:

```toml
[patch."https://github.com/longht021189/r-share"]
r-share = { path = "../r-share" }
```

Where to put the file:

- Cargo looks for `.cargo/config.toml` in the directory it is run from and in every parent directory. Put it in the **repository root**, even when `Cargo.toml` lives in a subdirectory (for a Tauri app that is `src-tauri/`), so it is found however cargo gets started.
- The `path` is resolved from the directory that contains `.cargo`. With the file in the repository root and the two repos side by side, that is `../r-share`. Adjust it to match your machine.

Add the file to the project's `.gitignore` so it is not committed:

```gitignore
/.cargo/config.toml
```

Without this file, cargo fetches `r-share` from GitHub.

To check that the local copy is the one in use, run `cargo tree -p r-share`: it should print the local path, not the git URL.

### Notes

- Cargo does not allow `path` and `git` in the same dependency, so the setup is split between `Cargo.toml` (git) and `.cargo/config.toml` (path) as shown above.
- The `[patch]` does not replace the GitHub repository, it overrides what cargo finds in it. When cargo has to resolve `r-share` from scratch, i.e. the first time the dependency is added or when `Cargo.lock` has no entry for it, it still fetches the GitHub repository and needs to find the crate (a `Cargo.toml`) there. So push `r-share` to GitHub before adding it to a project for the first time. After that, builds with the local override do not need the network for `r-share`, and new code only has to be pushed for people who do not have the override.
- A lockfile generated during development with `[patch]` does not record the git source. Before committing `Cargo.lock`, temporarily rename `.cargo/config.toml` and run `cargo update -p r-share` so the lockfile records the git commit of `r-share`.

### Troubleshooting

- `could not find Cargo.toml in .../.cargo/git/checkouts/r-share-...`: cargo had to resolve `r-share` and the commit it fetched from GitHub has no `r-share` crate, usually because the local commits were never pushed. Push `r-share` first. Do not work around it by putting a `path` in `Cargo.toml`.
- Local changes to `r-share` have no effect: the `.cargo/config.toml` is missing, in the wrong directory, or its `path` does not point at the checkout. Check with `cargo tree -p r-share`.

## Building c-share

`build.rs` builds [c-share](https://github.com/longht021189/c-share) (a CMake/vcpkg
C++ project, not a crate) and links its static libraries in. c-share isn't a Rust
dependency, so it isn't declared in `Cargo.toml` -- `build.rs` finds it on disk:

- `C_SHARE_PATH` env var, if set, or
- `../c-share`, next to this checkout, otherwise.

`c_share::waker` and `c_share::crypto` are always built -- `crypto` backs
`data::encryption`/`data::signing` (X25519, Ed25519, HKDF-SHA256,
XChaCha20-Poly1305, and secure random, all via wolfSSL -- see
`c-share/modules/crypto/README.md`) and needs wolfSSL, resolved via vcpkg, so
**`VCPKG_ROOT` must always be set to build r-share**:

```sh
VCPKG_ROOT=/path/to/vcpkg cargo build
```

`c_share::http` additionally needs libcurl (on top of the wolfSSL every build
already resolves), so it stays behind the `c_share_http` feature, which also
builds the `http_client` module (an async wrapper -- see its own doc comment):

```sh
VCPKG_ROOT=/path/to/vcpkg cargo build --features c_share_http
```

The first build compiles wolfSSL from source through vcpkg, which is slow
(the `c_share_http` feature additionally compiles curl); see c-share's own
README for the full vcpkg/NDK prerequisites. On macOS this also needs Xcode's
command line tools for `SystemConfiguration.framework`, which libcurl uses
for proxy auto-detection.

Both modules' Rust bindings are generated at build time by `bindgen` straight
from their plain-C header (`crypto.h`, `client_c.h` -- see
`src/data/crypto_ffi.rs` and `src/http_client/ffi.rs`); neither module's C++
API (`client.hpp`) is bindgen-able directly, which is why each has a C shim.
