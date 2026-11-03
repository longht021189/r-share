use std::env;
use std::path::{Path, PathBuf};

fn main() -> std::io::Result<()> {
    let protoc_path = protoc_bin_vendored::protoc_bin_path()
        .expect("failed to locate vendored protoc binary");
    unsafe {
        std::env::set_var("PROTOC", protoc_path);
    }

    prost_build::compile_protos(&["proto/data.proto"], &["proto/"])?;

    let c_share_dir = c_share_path();
    build_c_share(&c_share_dir);
    generate_crypto_bindings(&c_share_dir);
    if c_share_http_enabled() {
        generate_http_bindings(&c_share_dir);
    }

    Ok(())
}

fn c_share_http_enabled() -> bool {
    env::var_os("CARGO_FEATURE_C_SHARE_HTTP").is_some()
}

// Same idea as generate_crypto_bindings, for client_c.h -- the plain C shim
// around c-share's C++ `http::Client` (whose own client.hpp can't go through
// bindgen: std::string/std::vector/classes have no stable C ABI). Enums are
// emitted as Rust enums so the wrapper matches on variants instead of magic
// numbers.
fn generate_http_bindings(c_share_dir: &Path) {
    let header = c_share_dir.join("modules/http/include/c_share/http/client_c.h");
    println!("cargo:rerun-if-changed={}", header.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen_builder(&header)
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .generate()
        .expect("failed to generate bindings for c-share's client_c.h")
        .write_to_file(out_dir.join("http_bindings.rs"))
        .expect("failed to write http_bindings.rs");
}

// Generates Rust FFI declarations for c-share's crypto.h (a plain C API --
// see that module's README for why) straight from the header in the
// checkout build_c_share() also builds, so the two never drift apart.
fn generate_crypto_bindings(c_share_dir: &Path) {
    let header = c_share_dir.join("modules/crypto/include/c_share/crypto/crypto.h");
    println!("cargo:rerun-if-changed={}", header.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen_builder(&header)
        .generate()
        .expect("failed to generate bindings for c-share's crypto.h")
        .write_to_file(out_dir.join("crypto_bindings.rs"))
        .expect("failed to write crypto_bindings.rs");
}

// Builds c-share (a sibling CMake project, not a crate) and links its static
// libraries into r-share. `waker` and `crypto` are always built (crypto backs
// data::encryption/signing, and always needs wolfSSL); `http` additionally
// needs libcurl, so it stays behind the `c_share_http` feature (it backs the
// `http` module).
//
// c-share's dependencies (wolfSSL, curl, ...) come from vcpkg-share, either:
// - prebuilt: VCPKG_SHARE_PREFIX names an install prefix (include/, lib/,
//   share/) for the target, as g-bot's vcpkg-share workflow pushes to
//   vcpkg-share's deps/<hash> branch (or its build.js builds locally); no
//   vcpkg is run, or
// - built here: through vcpkg's toolchain (VCPKG_ROOT), with vcpkg-share's
//   manifest (c-share's CMakeLists.txt finds vcpkg-share next to it, or at
//   VCPKG_SHARE_PATH).
fn build_c_share(c_share_dir: &Path) {
    println!("cargo:rerun-if-env-changed=C_SHARE_PATH");
    println!("cargo:rerun-if-env-changed=VCPKG_SHARE_PREFIX");
    println!("cargo:rerun-if-env-changed=VCPKG_SHARE_PATH");
    println!("cargo:rerun-if-env-changed=VCPKG_ROOT");
    println!("cargo:rerun-if-changed={}", c_share_dir.display());

    let build_http = c_share_http_enabled();
    let prefix = env::var_os("VCPKG_SHARE_PREFIX").map(PathBuf::from);
    let triplet = vcpkg_triplet();

    let mut config = cmake::Config::new(&c_share_dir);
    config
        .define("CMAKE_BUILD_TYPE", "RelWithDebInfo")
        .define("C_SHARE_BUILD_EXAMPLES", "OFF")
        .define("C_SHARE_BUILD_TESTS", "OFF")
        .define("C_SHARE_BUILD_HTTP", if build_http { "ON" } else { "OFF" })
        .define("C_SHARE_BUILD_CRYPTO", "ON")
        .build_target("all");
    if let Some(prefix) = &prefix {
        println!("cargo:rerun-if-changed={}", prefix.join("lib").display());
        // CMake's own find modules where it has one, as under vcpkg's
        // toolchain: zlib's config defines only ZLIB::ZLIBSTATIC, so curl's
        // config and c-share's http module need FindZLIB for ZLIB::ZLIB
        // (vcpkg's zlib wrapper forces it too). FindCURL still prefers
        // curl's config, and CMAKE_PREFIX_PATH comes before the system's
        // paths, so everything is found in the prefix.
        config.define("CMAKE_PREFIX_PATH", prefix);
    } else {
        let vcpkg_root = env::var("VCPKG_ROOT").expect(
            "set VCPKG_SHARE_PREFIX (vcpkg-share's prebuilt dependencies for this target) \
             or VCPKG_ROOT (to build them with vcpkg): r-share builds c-share's `crypto` \
             module (wolfSSL) unconditionally, and `http` (additionally libcurl) when the \
             `c_share_http` feature is enabled -- see r-share's README",
        );
        config
            .define(
                "CMAKE_TOOLCHAIN_FILE",
                Path::new(&vcpkg_root).join("scripts/buildsystems/vcpkg.cmake"),
            )
            // Always explicit, not just for windows/android: left unset, vcpkg's
            // toolchain file falls back to auto-detecting the *building*
            // machine's own platform, which is wrong when that's a Linux-to-
            // Linux cross-compile (e.g. an arm64 host targeting x64-linux) --
            // `vcpkg_triplet()` already computes the right value for a native
            // build too, so setting it unconditionally is never wrong.
            .define("VCPKG_TARGET_TRIPLET", triplet);
    }
    if target_os() == "android" {
        // Mirrors c-share's android-* CMake presets: the NDK's toolchain file
        // (chain-loaded by vcpkg's, without a prefix), which needs the ABI and
        // API level.
        let ndk = android_ndk();
        let ndk_toolchain = ndk.join("build/cmake/android.toolchain.cmake");
        config
            // vcpkg's own Android toolchain (scripts/toolchains/android.cmake,
            // used for every port it builds) finds the NDK through
            // ANDROID_NDK_HOME alone, whichever of the variables above named
            // it (Tauri's CLI sets NDK_HOME).
            .env("ANDROID_NDK_HOME", &ndk)
            .define(
                if prefix.is_some() {
                    "CMAKE_TOOLCHAIN_FILE"
                } else {
                    "VCPKG_CHAINLOAD_TOOLCHAIN_FILE"
                },
                ndk_toolchain,
            )
            .define("ANDROID_ABI", android_abi())
            .define("ANDROID_PLATFORM", format!("android-{ANDROID_API_LEVEL}"));
        if let Some(prefix) = &prefix {
            // The NDK's toolchain confines find_package to its sysroot unless
            // a path is under CMAKE_FIND_ROOT_PATH.
            config.define("CMAKE_FIND_ROOT_PATH", prefix);
        }
    } else {
        // Other cross-compiles (e.g. a Linux host building for a different
        // Linux arch) have no chainloaded toolchain file to pick the right
        // compiler for us, and the `cmake` crate doesn't set one either --
        // it only ever adds flags like `-m64`/`-m32`, which silently fail
        // against whatever the host's plain `cc`/`c++` happens to be.
        // `CC_<target>`/`CXX_<target>`/`AR_<target>` are the same
        // convention the `cc` crate (and bindgen's `BINDGEN_EXTRA_CLANG_ARGS_
        // <target>`) already use for this, so honor them here too instead of
        // inventing a separate variable.
        if let Some(cc) = cross_compiler_env_var("CC") {
            config.define("CMAKE_C_COMPILER", cc);
        }
        if let Some(cxx) = cross_compiler_env_var("CXX") {
            config.define("CMAKE_CXX_COMPILER", cxx);
        }
        if let Some(ar) = cross_compiler_env_var("AR") {
            config.define("CMAKE_AR", ar);
        }
    }

    let dst = config.build();
    let build_dir = dst.join("build");

    println!(
        "cargo:rustc-link-search=native={}",
        build_dir.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=waker");
    println!("cargo:rustc-link-lib=static=crypto");
    if build_http {
        println!("cargo:rustc-link-lib=static=http");
    }

    if target_os() == "windows" {
        println!("cargo:rustc-link-lib=dylib=ws2_32");
    }

    // c-share's static libs are C++ (even crypto's plain-C-facing crypto.cpp
    // pulls in exception-unwinding stubs for its RAII types, e.g.
    // ScopedRng's destructor), so the final link needs the C++ runtime --
    // rustc doesn't add it automatically since a Rust binary doesn't
    // otherwise imply one.
    match target_os().as_str() {
        "macos" => println!("cargo:rustc-link-lib=dylib=c++"),
        "linux" => println!("cargo:rustc-link-lib=dylib=stdc++"),
        // Static, so the app's .so doesn't need libc++_shared.so packaged
        // alongside it.
        "android" => {
            // Copy just the C++ runtime somewhere private: that sysroot
            // directory also holds a static libc.a, which `-lc` would then pick
            // over the API-level libc.so stub and break the link (32-bit ARM).
            let src = android_sysroot().join("usr/lib").join(android_lib_dir());
            let dst = PathBuf::from(env::var("OUT_DIR").unwrap()).join("android-cxx");
            std::fs::create_dir_all(&dst).unwrap();
            for lib in ["libc++_static.a", "libc++abi.a"] {
                std::fs::copy(src.join(lib), dst.join(lib))
                    .unwrap_or_else(|e| panic!("copying {lib} from the NDK sysroot: {e}"));
            }
            println!("cargo:rustc-link-search=native={}", dst.display());
            println!("cargo:rustc-link-lib=static=c++_static");
            println!("cargo:rustc-link-lib=static=c++abi");
        }
        _ => {}
    }

    match &prefix {
        Some(prefix) => link_vcpkg_static_libs(&prefix.join("lib")),
        None => link_vcpkg_static_libs(&build_dir.join(format!("vcpkg_installed/{triplet}/lib"))),
    }
}

// Neither c-share module has a CMake install/export config to hand us an
// authoritative transitive link line, so instead of hardcoding wolfSSL's (and,
// with `c_share_http`, curl's) own dependency graph -- which shifts with
// vcpkg's resolved features -- link every static lib vcpkg actually produced
// for this build. Harmless when a lib (e.g. curl, without `c_share_http`)
// isn't referenced by anything: the linker only pulls in archive members
// actual unresolved symbols need.
fn link_vcpkg_static_libs(lib_dir: &Path) {
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    let static_ext = if target_os() == "windows" {
        "lib"
    } else {
        "a"
    };

    let mut libs: Vec<String> = std::fs::read_dir(lib_dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", lib_dir.display()))
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension()?.to_str()? != static_ext {
                return None;
            }
            let stem = path.file_stem()?.to_str()?;
            Some(stem.strip_prefix("lib").unwrap_or(stem).to_string())
        })
        .collect();
    libs.sort();
    libs.dedup();

    for lib in libs {
        println!("cargo:rustc-link-lib=static={lib}");
    }

    if target_os() == "macos" {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        // libcurl's macos.c (proxy auto-detection via SCDynamicStoreCopyProxies)
        // needs this; harmless to link when `c_share_http` is off too.
        println!("cargo:rustc-link-lib=framework=SystemConfiguration");
    }
}

// Reads `<prefix>_<target-with-underscores>` (e.g. `CC_x86_64_unknown_linux_gnu`),
// the convention the `cc` crate and bindgen's `BINDGEN_EXTRA_CLANG_ARGS_*`
// already use to name a cross-compiler for a specific Rust target triple.
fn cross_compiler_env_var(prefix: &str) -> Option<String> {
    let target = env::var("TARGET").expect("TARGET is set by Cargo").replace('-', "_");
    env::var(format!("{prefix}_{target}")).ok()
}

fn c_share_path() -> PathBuf {
    if let Some(path) = env::var_os("C_SHARE_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../c-share")
}

// `cfg!(target_os = ...)` in a build script describes the host, not the
// target being compiled for, so cross-compiling (e.g. Android from macOS)
// must go through the CARGO_CFG_TARGET_* variables Cargo sets instead.
fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS is set by Cargo")
}

fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH is set by Cargo")
}

// Matches ANDROID_PLATFORM in c-share's android-* CMake presets.
const ANDROID_API_LEVEL: &str = "24";

fn android_ndk() -> PathBuf {
    for var in ["ANDROID_NDK_HOME", "NDK_HOME", "ANDROID_NDK_ROOT"] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    ["ANDROID_NDK_HOME", "NDK_HOME", "ANDROID_NDK_ROOT"]
        .iter()
        .find_map(|var| env::var_os(var))
        .map(PathBuf::from)
        .expect(
            "ANDROID_NDK_HOME (or NDK_HOME / ANDROID_NDK_ROOT) must point at the Android \
             NDK when building for Android",
        )
}

fn android_abi() -> &'static str {
    match target_arch().as_str() {
        "aarch64" => "arm64-v8a",
        "arm" => "armeabi-v7a",
        "x86_64" => "x86_64",
        "x86" => "x86",
        arch => panic!("unsupported Android architecture: {arch}"),
    }
}

// Directory name under the sysroot's usr/lib, which differs from the Rust
// target triple for 32-bit ARM (arm-linux-androideabi vs armv7-...).
fn android_lib_dir() -> &'static str {
    match target_arch().as_str() {
        "aarch64" => "aarch64-linux-android",
        "arm" => "arm-linux-androideabi",
        "x86_64" => "x86_64-linux-android",
        "x86" => "i686-linux-android",
        arch => panic!("unsupported Android architecture: {arch}"),
    }
}

fn android_sysroot() -> PathBuf {
    android_ndk()
        .join("toolchains/llvm/prebuilt")
        .join(android_host_tag())
        .join("sysroot")
}

fn android_host_tag() -> &'static str {
    // The NDK ships x86_64 host toolchains only; Apple Silicon runs them
    // through Rosetta.
    if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else if cfg!(target_os = "windows") {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    }
}

// bindgen parses the headers with the host's libclang, so a cross build must
// tell it the real target and, for Android, where the NDK's sysroot lives.
fn bindgen_builder(header: &Path) -> bindgen::Builder {
    let mut builder = bindgen::Builder::default()
        .header(header.to_str().expect("c-share path must be valid UTF-8"));
    if target_os() == "android" {
        let sysroot = android_sysroot();
        let target = env::var("TARGET").expect("TARGET is set by Cargo");
        builder = builder
            .clang_arg(format!("--target={target}{ANDROID_API_LEVEL}"))
            .clang_arg(format!("--sysroot={}", sysroot.display()));
    }
    builder
}

fn vcpkg_triplet() -> &'static str {
    match (target_os().as_str(), target_arch().as_str()) {
        ("windows", _) => "x64-windows-static",
        ("macos", "aarch64") => "arm64-osx",
        ("macos", _) => "x64-osx",
        ("android", "aarch64") => "arm64-android",
        ("android", "arm") => "arm-neon-android",
        ("android", "x86_64") => "x64-android",
        ("android", "x86") => "x86-android",
        ("linux", "aarch64") => "arm64-linux",
        _ => "x64-linux",
    }
}
