#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("./README.md")]
#![deny(missing_docs)]

use core::{str::FromStr as _, fmt::Write as _};
use std::{
  sync::OnceLock,
  io::Write as _,
  collections::HashSet,
  path::{Component, PathBuf},
  env, fs,
  process::Command,
};

mod config;
use config::*;

mod rerun_if_changed;
use rerun_if_changed::rerun_if_changed;

/// A marker that this command was invoked from the build script.
const BUILD_SCRIPT_MARKER: &str = "SERAI_RUNTIME_BUILD_RS";

#[rustfmt::skip]
/// Fetch an environment variable which `cargo` sets when building crates.
///
/// https://doc.rust-lang.org/1.94.0/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates
/// provides the full list of these.
fn cargo_env(var: &str) -> String {
  #[expect(clippy::disallowed_methods)]
  env::var(var).unwrap_or_else(|_| {
    panic!("`build.rs` invoked without the `cargo`-provided `{var}` env var set")
  })
}

/// Locate the workspace's directory.
///
/// This will return the workspace for the _current_ crate being compiled, not the original.
fn workspace_dir() -> PathBuf {
  let workspace = Command::new(cargo_env("CARGO"))
    .arg("locate-project")
    .arg("--workspace")
    .arg("--message-format")
    .arg("plain")
    .output()
    .unwrap();
  assert!(workspace.status.success());
  let mut workspace = PathBuf::from(String::from_utf8(workspace.stdout).unwrap().trim());
  assert_eq!(workspace.file_name().unwrap(), "Cargo.toml");
  assert!(workspace.pop(), "failed to pop item we know exists");
  // We require the workspace be absolute because we use it as the basis for relative paths later
  assert!(workspace.is_absolute());
  workspace
}

/// The home directory which will be used for the nested invocation of `cargo`.
fn cargo_home() -> PathBuf {
  PathBuf::from(cargo_env("OUT_DIR")).join("cargo")
}

/// The configuration to use for vendored sources.
fn vendor_configuration(vendored_sources: &str) -> String {
  let mut vendored_sources = format!(
    r#"
[source.vendored-sources]
directory = "{}"

[sources.crates-io]
replace-with = "vendored-sources"
"#,
    vendored_sources.replace('"', "\\\"")
  );

  // Also replace all of the Git sources we use with the vendored sources
  {
    let mut git_sources = HashSet::new();

    // Identify the in-use Git sources via parsing the `Cargo.lock` (a TOML file)
    {
      let lockfile = fs::read_to_string(workspace_dir().join("Cargo.lock"))
        .expect("couldn't read workspace's `Cargo.lock`");
      let lockfile = toml::Table::from_str(&lockfile).expect("`Cargo.lock` was not valid toml");

      for package in lockfile["package"].as_array().expect("`package` wasn't an array") {
        let Some(source) = package.get("source") else { continue };
        let source = source.as_str().expect("package `source` wasn't a string");
        if !source.starts_with("git+") {
          continue;
        }
        let source_without_current_revision = source.split('#').next().unwrap();
        git_sources.insert(source_without_current_revision.to_owned());
      }
    }

    for source in git_sources {
      write!(
        &mut vendored_sources,
        r#"
[sources."{}"]
git = "{}"
replace-with = "vendored-sources"
"#,
        source.replace('"', "\\\""),
        source.split('?').next().unwrap().replace('"', "\\\"")
      )
      .unwrap();

      // If this was the source for a specific revision, add that field now
      if let Some(rev) = source.split("?rev=").nth(1) {
        write!(
          &mut vendored_sources,
          r#"
rev = "{rev}"
"#
        )
        .unwrap();
      }
    }
  }

  vendored_sources
}

/// A [`Command`] for the specified binary.
///
/// This will erase the host environment and provide a consistent current working
/// directory/environment.
fn command(bin: &str) -> Command {
  let mut command = Command::new(bin);

  /*
    If this is a nested invocation, we have already sanitized the environment and do not do so
    again (where any new sanitization may overwrite values set by `cargo` as part of the build
    process).
  */
  #[expect(clippy::disallowed_methods)]
  match env::var(BUILD_SCRIPT_MARKER) {
    Ok(_) => return command,
    Err(env::VarError::NotPresent) => {}
    Err(env::VarError::NotUnicode(_)) => panic!("`BUILD_SCRIPT_MARKER` we set wasn't UTF-8"),
  }

  // Run this command from the location of the crate's `Cargo.toml`
  command.current_dir(cargo_env("CARGO_MANIFEST_DIR"));
  // Do not arbitrarily propagate the environment from the host to ensure this is uncontaminated
  command.env_clear();

  // Mark this is invoked from the build script
  command.env(BUILD_SCRIPT_MARKER, "1");

  // Propagate Window's `SystemRoot` environment variable as required for basic functioning
  // Notably, `git` for Windows won't function at all if this isn't set
  #[cfg(target_family = "windows")]
  #[expect(clippy::disallowed_methods)]
  if let Ok(root) = env::var("SystemRoot") {
    command.env("SystemRoot", root);
  }

  // Propagate macOS's `DYLD_FALLBACK_LIBRARY_PATH` environment variable, which `rust-lld` requires
  // to find `libLLVM` since https://github.com/rust-lang/rust/pull/157205
  #[cfg(target_os = "macos")]
  #[expect(clippy::disallowed_methods)]
  if let Ok(fallback_libraries) = env::var("DYLD_FALLBACK_LIBRARY_PATH") {
    command.env("DYLD_FALLBACK_LIBRARY_PATH", fallback_libraries);
  }

  /*
    Normalize the locale, in case any tooling attempts to take it into consideration.

    This is likely redundant, but could matter if any tooling performed a string sort by deferring
    to a locale-respecting string sort function (such as by using `strcoll`).

    https://www.gnu.org/software/libc/manual/html_node/Collation-Functions.html
  */
  command.env("LC_ALL", "C");

  // Propagate the Rust toolchain
  for key in ["CARGO", "RUSTC", "RUSTDOC"] {
    command.env(key, cargo_env(key));
  }

  /*
    We also propagate `RUSTUP_HOME` and `RUSTUP_TOOLCHAIN` so that when we create a fresh
    `CARGO_HOME` later in this build script, `rustup` can still resolve its toolchain.

    This wasn't observed as necessary on an `x86_64-unknown-linux-gnu` host. It was reported as
    necessary on an `aarch64-apple-darwin` host however. It _shouldn't_ be necessary as this script
    should _solely_ use the _already resolved_ `rustc`, `cargo`, as identified by the
    `RUSTC`, `CARGO` environment variables. It isn't observed to be problematic
    (re: reproducibility) to include here however, and solves a practical issue of this not working
    otherwise. Ideally, a cleaner solution would overall.
  */
  for key in ["RUSTUP_HOME", "RUSTUP_TOOLCHAIN"] {
    #[expect(clippy::disallowed_methods)]
    if let Ok(value) = env::var(key) {
      command.env(key, value);
    }
  }

  /*
    We use our own `cargo` directory to ensure we know where the `cargo` directory is.

    This does limit the host's ability to have a differing `cargo` configuration, potentially
    limiting contamination yet also potentially breaking systems for which `cargo` doesn't work
    out-of-the-box and _must_ be configured.
  */
  {
    let cargo_home = cargo_home();
    command.env("CARGO_HOME", &cargo_home);

    /*
      This is declared as a static so it's only run once, as we don't need to create the
      configuration file multiple times.
    */
    static CARGO_CONFIG: OnceLock<()> = OnceLock::new();
    CARGO_CONFIG.get_or_init(|| {
      if !fs::exists(&cargo_home).expect("couldn't check if our own `CARGO_HOME` already exists") {
        fs::create_dir_all(&cargo_home).expect("couldn't create our own `CARGO_HOME`");
      }

      let config_path = cargo_home.join("config.toml");
      // If there's an existing config, remove it so we can create the definitively correct one now
      if fs::exists(&config_path)
        .expect("couldn't check if `CARGO_HOME/config.toml` already exists")
      {
        fs::remove_file(&config_path).expect("couldn't remove existing `CARGO_HOME/config.toml`");
      }

      // If vendored sources were declared, ensure our `CARGO_HOME` has such configuration now
      #[expect(clippy::disallowed_methods)]
      if let Ok(vendor) = env::var("SERAI_RUNTIME_VENDOR") {
        fs::write(config_path, vendor_configuration(&vendor).as_bytes())
          .expect("couldn't write config to use vendored sources");
      }
    });
  }

  /*
    Finally, we propagate the host's `PATH`, as the Rust toolchain requires the host's C compiler,
    even when using the self-contained linker, in order to drive it and provide the
    platform-specific libraries.

    While we could build a `PATH` from the Rust toolchain, and then append the value of
    `RUSTC_LINKER` (to have a `PATH` deterministic to the Rust toolchain with the sole exception of
    the host's linker), `RUSTC_LINKER` is the linker for the _target_, not the host, when we would
    want to set the linker for the host specifically. There also isn't a trivial way to query the
    _resolved_ linker after all the possible configuration methods are taken into consideration.
  */
  #[expect(clippy::disallowed_methods)]
  if let Ok(path) = env::var("PATH") {
    command.env("PATH", path);
  }

  /*
    Propagate toolchain configuration which are _optional_ and may not be set.

    The propagation of the `clippy`-specific environment variables is unfortunately very fragile.
    https://github.com/rust-lang/rust-clippy/blob/0f17b47529fcde29fde44343e8f35e5cd2f21b89
      /src/main.rs#L123-L124
  */
  for key in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CLIPPY_ARGS", "CLIPPY_TERMINAL_WIDTH"] {
    #[expect(clippy::disallowed_methods)]
    if let Ok(value) = env::var(key) {
      command.env(key, value);
    }
  }

  /*
    If this `rustc` was built from source, with a version string which declares itself as so,
    normalize the version string to the one from the release build.

    This is required as the version impacts how symbols are mangled, and symbol mangling, even when
    symbols are stripped, effect the resulting binary. While we expect a consistent Rust toolchain
    to perform this build process, we want to support a consistent Rust toolchain built from source
    _or_ downloaded as a pre-built release.

    This won't effect how the symbols within the standard library themselves are mangled, due to
    `rustc` expecting it to be pre-compiled and therefore literally defined, so there's still
    _some_ non-determinism here. Thankfully, normalizing how _most_ symbols are mangled is
    sufficient.
  */
  {
    let version = Command::new(cargo_env("RUSTC"))
      .arg("--version")
      .output()
      .expect("couldn't invoke `rustc` to get the version");
    assert!(version.status.success());
    let version = String::from_utf8(version.stdout).expect("`rustc` version wasn't UTF-8");

    #[expect(clippy::get_first)]
    if version.contains("built from a source tarball") {
      let version = version.split(' ').collect::<Vec<_>>();
      assert_eq!(version.get(0).copied(), Some("rustc"));
      let version = version
        .get(1)
        .copied()
        .expect("`rustc --version` didn't contain its version in the expected position");

      const CANONICAL_RUSTC_VERSION: &str = "1.94.0";
      if version != CANONICAL_RUSTC_VERSION {
        eprintln!(
          "
          `rustc` version ({version}) was different from {CANONICAL_RUSTC_VERSION} (canonical).
          this will not be a canonical build
        "
        );
      }
      if let Some(version) = match version {
        "1.91.1" => Some("1.91.1 (ed61e7d7e 2025-11-07)"),
        "1.92.0" => Some("1.92.0 (ded5c06cf 2025-12-08)"),
        "1.93.0" => Some("1.93.0 (254b59607 2026-01-19)"),
        "1.93.1" => Some("1.93.1 (01f6ddf75 2026-02-11)"),
        "1.94.0" => Some("1.94.0 (4a4ef493e 2026-03-02)"),
        "1.94.1" => Some("1.94.1 (e408947bf 2026-03-25)"),
        "1.95.0" => Some("1.95.0 (59807616e 2026-04-14)"),
        _ => {
          eprintln!(
            "
            unrecognized `rustc` version.
            this may not be a canonical build, even within this version of the Rust toolchain
          "
          );
          None
        }
      } {
        command.env("RUSTC_FORCE_RUSTC_VERSION", version);
      }
    }
  }

  /*
    Set `RUSTC_BOOTSTRAP` to be able to use unstable options.

    We use a few of these, and each must be carefully reviewed. We MUST NOT use any unstable issues
    which may have problematic side effects. We MUST only use unstable options which have yet to be
    stablized (such as due to their recency or due to ongoing discussion on what API to stablize
    them with).

    This means our risk is limited to breaking when upgrading our toolchain, not miscompiles.

    One use-case for this is `build-std`, a famous and widely-used unstable option (even used by
    `substrate-wasm-builder` for the `wasm32-unknown-unknown` target), which hopefully will be
    stablized within the next year (https://github.com/rust-lang/rust-project-goals/issues/274).
  */
  command.env("RUSTC_BOOTSTRAP", "1");

  // Set the Rust flags we'll use for the WASM
  command.env(
    format!("CARGO_TARGET_{}_RUSTFLAGS", "wasm32v1-none".replace('-', "_").to_uppercase()),
    wasm_rustflags(),
  );

  if release_wasm() {
    /*
      `incremental` is recommended to be disabled for release builds.

      https://doc.rust-lang.org/1.94.0/rustc/codegen-options/index.html#incremental
      https://doc.rust-lang.org/1.94.0/cargo/reference/profiles.html#incremental

      Note that if `rustc` considers the `incremental` option as non-`None`, it will sample a
      32-bit integer to prevent conflicts with.

      https://github.com/rust-lang/rust/blob/655a7d20fefe23757ca9ecbbea01e4fe80208aaf
        /compiler/rustc_session/src/session.rs#L1071-L1074

      That would suggest this environment variable is required to achieve determinism, but while
      this has been observed to impact static archives, it has yet to be observed to impact the
      WASM blobs (the only item we require to be deterministic).

      We also do set this on a release build (when we require determinism), and don't set it on a
      debug build (when we don't guarantee determinism and practically need incremental builds for
      the developer experience).
    */
    command.env("CARGO_INCREMENTAL", "false");
  }

  /*
    Propagate a variety of (optional) configurations which won't affect our determinism.

    Specifically, we propagte the network settings, the terminal display settings, and any
    configured logging.
  */
  #[expect(clippy::disallowed_methods)]
  let vars = env::vars();
  for (key, value) in vars {
    if matches!(
      key.as_str(),
      "CARGO_LOG" | "HTTPS_PROXY" | "https_proxy" | "http_proxy" | "HTTP_TIMEOUT" | "TERM" |
      _ if key.starts_with("CARGO_HTTP_") ||
           key.starts_with("CARGO_NET_") ||
           key.starts_with("CARGO_TERM_")
    ) {
      command.env(key, value);
    }
  }

  // Propagate the `SERAI_PROTOCOL_ID` environment variable, as documented
  #[expect(clippy::disallowed_methods)]
  if let Ok(protocol_id) = env::var("SERAI_PROTOCOL_ID") {
    command.env("SERAI_PROTOCOL_ID", protocol_id);
  }

  command
}

#[expect(dead_code)]
fn rustc_command() -> Command {
  // Use the `rustc` we were invoked with
  command(&cargo_env("RUSTC"))
}

fn cargo_command() -> Command {
  // Use the `cargo` we were invoked with
  command(&cargo_env("CARGO"))
}

/// Normalize a file within a crate's path to a host-independent definition.
///
/// This will normalize the path for the crate to `/{name}-{version}`, regardless of actual
/// location. This identifies the crate as the parent of the relevant `Cargo.toml`, as determined
/// with `cargo locate-project`.
fn normalize_crate_path(file: PathBuf) -> PathBuf {
  let file = fs::canonicalize(file).unwrap();
  let directory = file.parent().expect("file was outside of any directory");

  let package_toml = cargo_command()
    .current_dir(directory)
    .arg("locate-project")
    .args(["--message-format", "plain"])
    .args(["--color", "never"])
    .output()
    .unwrap();
  assert!(package_toml.status.success());
  let package_toml =
    String::from_utf8(package_toml.stdout).expect("path to crate's `Cargo.toml` wasn't UTF-8");
  let package_toml = PathBuf::from(package_toml.trim());
  let package_toml = fs::canonicalize(package_toml).unwrap();

  let (name, version) = {
    let toml = fs::read_to_string(&package_toml).expect("couldn't read `Cargo.toml` to string");
    let toml = toml::Table::from_str(&toml).expect("`Cargo.toml` was not valid toml");
    (
      toml["package"]["name"].as_str().expect("package `name` wasn't a string").to_owned(),
      toml["package"]["version"].as_str().expect("package `version` wasn't a string").to_owned(),
    )
  };

  let actual_crate_path = package_toml.parent().expect("`Cargo.toml` was outside of a directory");
  let file_path_within_crate = file.strip_prefix(actual_crate_path).unwrap();
  PathBuf::from(format!("/{name}-{version}")).join(file_path_within_crate)
}

/*
  Later on, we declare ourselves as the `RUSTC_WRAPPER`, letting us manually configure `rustc`
  invocations. We do this to (manually) resolve https://github.com/rust-lang/cargo/issues/8140.

  This means we have to strip all `-C metadata=*` arguments passed to `rustc`. We can assume this
  is safe as `rustc` will error if two items ever share a hash, as is inherently feasible with
  how small the hash size is (only 64 bits).

  However, because `cargo` assumes this `metadata` will be present (to enable building multiple
  crates with the same name), we must also provide our own metadata definition. We derive
  additional metadata from the path to the crate, which will be unique, and is independent of the
  host once normalized with our `normalize_crate_path` function.
*/
fn rustc_wrapper(mut args: impl Iterator<Item = String>) {
  // The first argument will be the `rustc` we are expected to wrap
  let rustc = args.next().expect("missing argument for the `rustc` path");
  let mut command = Command::new(&rustc);

  // If there's yet another wrapper, proxy the actual `rustc` for it now
  #[expect(clippy::disallowed_methods)]
  if let Ok(wrapper) = env::var("RUSTC_WORKSPACE_WRAPPER") {
    if rustc == wrapper {
      command.arg(args.next().unwrap());
    }
  }

  // If we're within a split argument or not
  let mut within_split_arg = false;
  // The file being compiled
  let mut file = None;
  // If this command added metadata
  let mut added_metadata = false;
  while let Some(arg) = args.next() {
    // Detect if this the file being compiled by checking it's not (part of) an argument
    if (!within_split_arg) && (!arg.starts_with('-')) {
      assert!(file.is_none(), "found file {arg} when we have file {}", file.unwrap());
      file = Some(arg.clone());
    }

    if let Some(codegen_arg) = arg.strip_prefix("-C") {
      let mut codegen_arg = codegen_arg.to_owned();
      // If this is `-C option`, which is parsed as two separate arguments, fetch `option` now
      if codegen_arg.is_empty() {
        codegen_arg = args.next().unwrap();
      }

      // Even if this was split, we've already handled it in its entirety
      within_split_arg = false;

      // If this is `metadata`, drop it entirely
      if codegen_arg.starts_with("metadata") {
        added_metadata = true;
        continue;
      }

      // Else, propagate it to the underlying `rustc`
      command.arg("-C");
      command.arg(codegen_arg);
      continue;
    }

    command.arg(&arg);

    /*
      Update if we're within a split argument or not.

      This methodology is incomplete, as it assumes every argument is followed by a single
      value. It fails to consider options without values, and options with multiple values.

      It works at this time, simply by the layout `rustc` happens to be invoked with, but this
      could be improved in the future.
    */
    let arg_is_split_option = arg.starts_with('-') && (arg != "-") && (!arg.contains('='));
    // If we're already in a split argument, then while this could have been one, it isn't
    let arg_is_split_option = (!within_split_arg) && arg_is_split_option;
    within_split_arg = arg_is_split_option;
  }

  /*
    If this invocation had added metadata, add our own metadata of the (normalized) file path.

    _Some_ metadata is necessary to differentiate crates with the same name within our tree, such
    as crates with multiple versions present. We derive the metadata from the file path, after
    trimming host-dependent context.
  */
  if added_metadata {
    let file = file.expect("`rustc` given metadata when it wasn't given a file to compile?");
    let normalized = normalize_crate_path(PathBuf::from(file));

    // Instead of using the platform-dependent `normalized.to_str()`, we impl our own `to_string`
    let mut path_str = String::new();
    for component in normalized.components() {
      match component {
        Component::RootDir => {}
        Component::Normal(folder) => write!(path_str, "/{}", folder.to_str().unwrap()).unwrap(),
        Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
          panic!("unrecognized component in normalized path")
        }
      }
    }

    command.arg(format!("-Cmetadata={path_str}"));
  }

  // Become `rustc`, invoking it, propagating its `stdout`, `stderr`, and exit code
  let output = command.output().unwrap();
  std::io::stdout().write_all(&output.stdout).unwrap();
  std::io::stderr().write_all(&output.stderr).unwrap();
  std::process::exit(output.status.code().unwrap());
}

fn main() {
  {
    #[expect(clippy::disallowed_methods)]
    let invoked_by_self = env::var(BUILD_SCRIPT_MARKER).is_ok();
    let mut args = env::args().peekable();
    {
      // This is needed as on Windows, one may have `.exe` while the other may not
      let no_extension = |mut path: PathBuf| {
        assert!(path.set_extension(""));
        path
      };
      assert_eq!(
        args.next().map(|arg| no_extension(PathBuf::from(arg))),
        Some(no_extension(std::env::current_exe().unwrap())),
        "first argument wasn't our invocation"
      );
    }
    let has_arguments = args.peek().is_some();
    /*
      If we're invoked as a build script, we wouldn't have had arguments provided.

      If we're invoked as `rustc`'s wrapper, `cargo` guarantees an argument of the `rustc` which
      should be used.

      https://doc.rust-lang.org/1.94.0/cargo/reference/config.html#buildrustc-wrapper

      This lets us determine which context we're being called in by if there are arguments.
    */
    if invoked_by_self && has_arguments {
      rustc_wrapper(args);
    }
  }

  // Check this is being called correctly and we should move forward
  {
    let target = cargo_env("TARGET");
    if target == "wasm32v1-none" {
      let direct_build_error = format!(
        r#"`serai-runtime` is being built for WASM directly. Do not do this. Run:

`cargo build --{} --no-default-features -p serai-runtime`

which will build the WASM as part of its build process, with the necessary configuration."#,
        cargo_env("PROFILE")
      );
      #[expect(clippy::disallowed_methods)]
      {
        assert!(env::var(BUILD_SCRIPT_MARKER).is_ok(), "{}", direct_build_error);
      }

      // If we're building the WASM blob, the build would've been configured by the parent process
      // and we have nothing to do here other than return.
      return;
    }
    #[expect(clippy::disallowed_methods)]
    {
      assert!(
        env::var(BUILD_SCRIPT_MARKER).is_err(),
        "build script called from build script for non-WASM target?"
      );
    }
  }

  // Resolve the features we'll build `serai-runtime` with
  let features_flag = {
    #[allow(unused_mut)]
    let mut features_flag = "--features=".to_owned();
    #[cfg(feature = "try-runtime")]
    write!(features_flag, "try-runtime,").unwrap();
    #[cfg(feature = "runtime-benchmarks")]
    write!(features_flag, "runtime-benchmarks,").unwrap();
    features_flag
  };

  rerun_if_changed(&features_flag);

  let mut build_command = cargo_command();

  /*
    Install ourselves as the `rustc` wrapper for the reasons described above.

    This would overwrite any system-provided `RUSTC_WRAPPER`, but that shouldn't be a problem here.
    Tooling such as `clippy` override `RUSTC_WORKSPACE_WRAPPER`, which we respect.
  */
  #[expect(clippy::disallowed_methods)]
  {
    assert!(
      matches!(env::var("RUSTC_WRAPPER"), Err(env::VarError::NotPresent)),
      "`RUSTC_WRAPPER` set when this build script sets it itself",
    );
  }
  build_command.env("RUSTC_WRAPPER", env::current_exe().unwrap());

  {
    /*
      We use a nested `target` directory for building the WASM as the existing `target` directory
      will be locked by the build process we're currently running.
    */
    let target_dir = PathBuf::from(cargo_env("OUT_DIR")).join("target");
    if release_wasm() {
      /*
        Remove the directory if it already exists, as this will be a non-incremental build so at
        best it does nothing, and at worst it accumulates due to `cargo`'s lack-luster garbage
        collection.
      */
      let _ = fs::remove_dir_all(&target_dir);
    }
    build_command.env("CARGO_TARGET_DIR", &target_dir);
  }

  /*
    `trim-paths` is an unstable flag to strip the build environment's paths, as would otherwise
    prevent reproducible builds without an exactly-matching filesystem layout.

    https://doc.rust-lang.org/1.94.0/cargo/reference/unstable.html#profile-trim-paths-option

    This would be part of `DETERMINISM` except for how it's a `cargo` argument, not a `rustc` flag.
  */
  build_command.arg("-Ztrim-paths=all");

  build_command.arg("rustc");
  build_command.arg("--locked");
  build_command.args(["--package", &cargo_env("CARGO_PKG_NAME")]);
  build_command.args(["--target", "wasm32v1-none"]);
  build_command.args(["--crate-type", "cdylib"]);
  build_command.arg("--no-default-features");
  build_command.arg(features_flag);

  if release_wasm() {
    build_command.arg("--release");
  }

  /*
    We use `build-std` for performance reasons and to ensure all of our configuration is respected.
    It also allows us to not explicitly add the `wasm32v1-none` target, and the pre-compiled
    `rust-std`, instead solely adding the `rust-src` component (as necessary to build `rust-std`
    here and now). This improves the ability to reproduce Serai from a bootstrapped environment.

    https://doc.rust-lang.org/1.94.0/cargo/reference/unstable.html#build-std
  */
  build_command.arg("-Zbuild-std=compiler_builtins,panic_abort,core,alloc");
  /*
    We set this to an empty value to override the default values which enable unwinding.

    https://doc.rust-lang.org/1.94.0/cargo/reference/unstable.html#build-std-features
  */
  build_command.arg("-Zbuild-std-features=");

  // Invoke the build command and ensure it succeeds
  assert!(build_command.status().unwrap().success());

  /*
    Now that we know the build command works, rerun it with structured output.

    We don't do this initially as if the crate has an error, the developer wants to be yielded the
    error, and yielding the JSON-structured output is a mess for the developer to deal with.
  */
  build_command.arg("--message-format=json");
  let build_output = build_command.output().unwrap();
  assert!(build_output.status.success());

  /*
    We now find the location of the build artifact within our nested `target` directory and copy it
    to the current `out` directory.

    Ideally, we would use `--artifact-dir` for this
    (https://doc.rust-lang.org/1.94.0/cargo/reference/unstable.html#artifact-dir), but it's only
    available for `cargo build` (when we use `cargo rustc` due to needing `--crate-type`).

    Since the target directory format is unstable, we have to parse the build command's output to
    locate the artifact (hence why we required a structured output).

    Reference: https://doc.rust-lang.org/1.94.0/cargo/reference/external-tools.html#json-messages
  */
  {
    let wasm_filename = cargo_env("CARGO_PKG_NAME").replace('-', "_") + ".wasm";
    let mut wasm_path = None;
    {
      use core_json::{ConstStack, Deserializer};

      for json_object in String::from_utf8(build_output.stdout).unwrap().lines() {
        let mut deserializer = Deserializer::<_, ConstStack<32>>::new(json_object.as_bytes())
          .expect("couldn't begin deserializing `cargo`'s JSON output as JSON");
        let message = deserializer.value().unwrap();

        let mut message = message.fields().expect("message wasn't a JSON object");
        while let Some(field) = message.next() {
          let mut field = field.unwrap();
          let key = field.key().map(|char| char.unwrap()).collect::<String>();
          if key == "filenames" {
            let mut filenames = field.value().iterate().expect("`filenames` wasn't an array");
            while let Some(filename) = filenames.next() {
              let filename = filename
                .unwrap()
                .to_str()
                .expect("entry of `filenames` wasn't a string")
                .map(|char| char.unwrap())
                .collect::<String>();
              let filename = PathBuf::from(filename);

              if filename.file_name().unwrap() == wasm_filename.as_str() {
                assert!(
                  wasm_path.is_none(),
                  "multiple `{wasm_filename}` found within `cargo`'s JSON output"
                );
                wasm_path = Some(filename);
              }
            }
          }
        }
      }
    }
    let wasm_path = wasm_path.expect("couldn't find WASM artifact within `cargo`'s JSON output");

    fs::copy(wasm_path, PathBuf::from(cargo_env("OUT_DIR")).join(&wasm_filename))
      .expect("couldn't copy artifact to our directory");
  }
}
