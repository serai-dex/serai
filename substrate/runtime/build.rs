//! # `serai-runtime` `build.rs`
//!
//! This file serves as an alternative to the infrastructure which would traditionally be provided
//! by `substrate-wasm-builder`. It is not itself configurable and is tailored for Serai
//! specifically.
//!
//! ### Why not `substrate-wasm-builder`?
//!
//! `substrate-wasm-builder` leaves what happens under the hood as opaque to the developer.
//! Locally defining a build script is feasible, even if it's enough work there _should_ be a
//! library for it. For Serai, that work should be undertaken to ensure clarity and propriety.
//!
//! `substrate-wasm-builder` has accumulated cruft over the years however and is not sufficiently
//! configurable to our needs. Additionally, on Alpine Linux, it'd fail to detect `wasm32v1-none`
//! was installed and fall back to `wasm32-unknown-unknown`. Serai does not want to _ever_
//! fallback (`wasm32-unknown-unknown` being a legacy choice which should have been already
//! removed) _and_ wanted to fix such compilations. Using `wasm32v1-none` outright, without
//! attempting to detect if it's installed, removes any possible bugs that would happen during
//! detection.
//!
//! `substrate-wasm-builer` also _propagated_ the host environment when building the target. This
//! methodology was incompatible with `cfg_aliases` as `--cfg` values from the outer compilation
//! would propagate to the inner compilation. While so overloading `--cfg` may be argued faulty
//! design by `cfg_aliases`, and propagation of `--cfg` may be argued correct by
//! `substrate-wasm-builder`, this was problematic for Serai.
//!
//! ### What does this do?
//!
//! This build script defines a build script as expected for a Substrate runtime. It compiles the
//! current crate to a WASM blob itself exported by the current crate.
//!
//! This build script _attempts_ to _better enable_ reproducible builds. It does not guarantee
//! that the output will be reproducible or that if it is reproducible, it will be reproducible by
//! any other environment than the exact same operating system, toolchain, and even file
//! hierarchy. Serai intends to build the runtime from within a hash-pinned OCI container
//! (`orchestration/runtime/Containerfile`) to ensure this, defining a test suite to verify its
//! methodology (`tests/reproducible-runtime`) which the CI runs
//! (`.github/workflows/reproducible-runtime`). Despite using an OCI container to pin an exact
//! environment, this build script attempts to minimize how much the environment effects the
//! output. This is via a few methods such as not propagating the host environment and setting
//! build flags which intended to make the output (more) deterministic.
//!
//! This build script also applies a variety of optimizations, both to the output itself and the
//! time to compile, as desirable. It should be noted `substrate-wasm-builder` applies a pass with
//! `wasm-opt`. This used to be somewhat required, as `wasm-opt` was invoked to reduce the
//! functionality within the output WASM to the desired WASM MVP (now available as
//! `wasm32v1-none`), but isn't necessary today. While `wasm-opt` could still be used as a general
//! optimization pass, Serai doesn't employ it as:
//!
//!   - The included optimizations should achieve the desired performance.
//!   - While `wasm-opt` was being used to reduce the WASM blob's _size_, Serai does not mind
//!     large WASM blobs. This is as it does not employ _on-chain WASM blob distribution_ as
//!     Substrate frequently does for on-chain upgrades.
//!   - It'd add an external dependency of `wasm-opt`, requiring it be bootstrapped.
//!
//! ### Usage
//!
//! This crate _MUST_ be built for a non-`wasm32v1-none` target. It will then spawn a nested
//! `cargo build` command to build this for `wasm32v1-none`, with the desired configuration and
//! options. As part of this, `cargo build` will be invoked with a _fresh_ `CARGO_HOME`. This means
//! any host-specific `cargo` configuration will _NOT_ be propagated.
//!
//! Exceptionally, networking configuration from the host environment is propagated as it isn't
//! expected to impact the result and may be necessary to download dependencies.
//!
//! ### Caveats
//!
//! This is not expected to produce reproducible builds when compiled in a non-`release` profile.
//! `location-detail` includes the host-formatted file path by default, which will be dependent on
//! the host (even with our usage of `-Z trim-paths`). While we could set
//! `location-detail=line,column` to omit the file path, this would so adversely harm debugging it
//! isn't valued when the intent is to enable verifying _published_ builds (not in-development
//! builds).
//!
//! The included methodology is specific to WASM which means this build script will not
//! immediately work to produce a PolkaVM runtime, a feature which can be assumed if one instead
//! used `substrate-wasm-builder`.

use core::fmt::Write as _;
use std::{
  io::Write as _,
  path::{Component, PathBuf},
  env, fs,
  process::Command,
  collections::HashSet,
};

#[rustfmt::skip]
/// Fetch an environment variable which `cargo` sets when building crates.
///
/// https://doc.rust-lang.org/1.93.0/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates
/// provides the full list of these.
fn cargo_env(var: &str) -> String {
  env::var(var).unwrap_or_else(|_| {
    panic!("`build.rs` invoked without the `cargo`-provided `{var}` env var set")
  })
}

/// Whether or not the WASM should be built in a `release` configuration.
fn release_wasm() -> bool {
  let profile = cargo_env("PROFILE");
  match profile.as_str() {
    "debug" | "test" => false,
    "bench" | "release" => true,
    _ => panic!("unexpected profile: {profile}"),
  }
}

/// The `RUSTFLAGS` to set when building the WASM.
fn wasm_rustflags() -> String {
  /// Compiler arguments required for a Substrate runtime making use of FRAME.
  ///
  /// Substrate's primitives, pallets make use of this `cfg` value to determine what context
  /// they're being built within.
  const REQUIRED_BY_SUBSTRATE: &str = "--cfg substrate_runtime";

  /// Compiler arguments for WASM.
  ///
  /// `--export-table` causes the linker to export the function table from our artifact, allowing
  /// out VM to identify what function we want to call by its name.
  const WASM: &str = "-C link-arg=--export-table";
  /// The compilation arguments required due to <https://github.com/rust-lang/rust/issues/145491>.
  const ONE_45491: &str =
    "-C link-arg=--mllvm=-mcpu=mvp -C link-arg=--mllvm=-mattr=+mutable-globals";

  /// Compiler arguments employed for safety purpose.
  ///
  /// `panic=abort` is used as `unwind` is very difficult to be used safely, and any panic within
  /// the runtime should propagate, causing the entire execution to panic, and the
  /// transaction/block to be rejected. Note that
  /// [`polkadot-sdk` itself builds runtimes with `abort`](
  ///   https://github.com/paritytech/polkadot-sdk/issues/10533#issuecomment-3681125280
  /// ) so this specification here is intended to be explicit and redundant for what should
  /// _already_ be the build configuration.
  ///
  /// We set `overflow-checks=on` to ensure overflows do not silently occur.
  const SAFETY: &str = "-C panic=abort -C overflow-checks=on";

  /// Compiler arguments to increase the result's determinism.
  ///
  /// We explicitly set `symbol-mangling-version` to achieve a canonical definition of mangled
  /// symbols.
  ///
  /// Instead of sorting [`codegen-source-order`](https://github.com/rust-lang/rust/pull/144722) as
  /// it's inherently ordered, which may vary when the parallel frontend is invoked, we explicitly
  /// sort it by the order the source code itself was defined in. This should be unnecessary, as we
  /// simply do not use the parallel frontend, but it will become on-by-default in the future.
  const DETERMINISM: &str = "-C symbol-mangling-version=v0 -Z codegen-source-order";

  /// Compiler arguments regarding the compilation process itself.
  ///
  /// `embed-bitcode=false` is set as the bitcode is unnecessary yet takes notable time to compile.
  ///
  /// `linker-plugin-lto` is used as Rust's LTO requires bitcode, forcing us to defer to the
  /// linker's LTO. While this would suggest we _should_ set `embed-bitcode=true`,
  /// [Rust's documentation](
  ///   https://doc.rust-lang.org/1.93.0/rustc/codegen-options/index.html#embed-bitcode
  /// ) suggests that's likely not desired and should solely be done when compiling one library
  /// with mixed methods of linking. When compiling and linking just once (as seen here), it's
  /// suggested to use the linker's LTO instead.
  const COMPILATION: &str = "-C embed-bitcode=false -C linker-plugin-lto=true";

  /// Compilation arguments for optimizations.
  ///
  /// Reducing the amount of `codegen-units` allows more optimized code, which we maximize here by
  /// using a minimal amount of codegen units (1). Potentially surprisingly, this is
  /// [expected to be unrelated to determinism](https://github.com/rust-lang/rust/issues/128675)
  /// and is solely here for the optimizations made possible.
  const OPTIMIZE: &str = "-C debug-assertions=false -C opt-level=3 -C codegen-units=1";
  /// Compilation arguments to strip the debug information.
  ///
  /// `strip=symbols` should have the pleasant effect of stripping mangled symbols. While we define
  /// a canonical symbol mangling scheme, it's one less thing to have to consider.
  ///
  /// `force-unwind-tables=no` is used to disable `unwind` tables, which are still present with
  /// `panic=abort` in order to provide the backtrace functionality.
  ///
  /// [`location-detail`](
  ///   https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/location-detail.html
  /// ) is used to strip information about the source code's location, as used for debug messages
  /// when panicking.
  const STRIP_DEBUG: &str =
    "-C debuginfo=none -C strip=symbols -C force-unwind-tables=no -Z location-detail=none";

  let mut rustflags =
    format!("{REQUIRED_BY_SUBSTRATE} {WASM} {ONE_45491} {SAFETY} {DETERMINISM} {COMPILATION}");
  if release_wasm() {
    write!(rustflags, " {OPTIMIZE} {STRIP_DEBUG}").unwrap();
  }
  rustflags
}

/// A marker that this command was invoked from the build script.
const BUILD_SCRIPT_MARKER: &str = "SERAI_RUNTIME_BUILD_RS";

/// A [`Command`] for the specified binary.
///
/// This will erase the host environment and provide a consistent current working
/// directory/environment.
fn command(bin: &str) -> Command {
  let mut command = Command::new(bin);

  // Run this command from the location of the crate's `Cargo.toml`
  command.current_dir(cargo_env("CARGO_MANIFEST_DIR"));
  // Do not arbitrarily propagate the environment from the host to ensure this is uncontaminated
  command.env_clear();

  // Propagate Window's `SystemRoot` environment variable as required for basic functioning
  // Notably, `git` for Windows won't function at all if this isn't set
  #[cfg(target_family = "windows")]
  if let Ok(root) = env::var("SystemRoot") {
    command.env("SystemRoot", root);
  }

  // Mark this is invoked from the build script
  command.env(BUILD_SCRIPT_MARKER, "1");

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
    if let Ok(value) = env::var(key) {
      command.env(key, value);
    }
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
    if let Ok(value) = env::var(key) {
      command.env(key, value);
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

      https://doc.rust-lang.org/1.93.0/rustc/codegen-options/index.html#incremental
      https://doc.rust-lang.org/1.93.0/cargo/reference/profiles.html#incremental
    */
    command.env("CARGO_INCREMENTAL", "false");
  }

  /*
    Propagate a variety of (optional) configurations which won't affect our determinism.

    Specifically, we propagte the network settings, the terminal display settings, and any
    configured logging.
  */
  for (key, value) in env::vars() {
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

/// Locate the workspace's directory.
fn workspace_dir() -> PathBuf {
  // Short-circuit to the explicitly-declared directory when recursively invoked
  if env::var(BUILD_SCRIPT_MARKER).is_ok() {
    return PathBuf::from(env::var("WORKSPACE_DIR").unwrap());
  }

  let workspace = cargo_command()
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

/// Normalize a crate's path to a host-independent definition.
///
/// We detect if the crate is from the Rust sysroot (`std`), `git`, a registry, or a workspace,
/// before replacing _where_ each of these folders were located with the folder alone.
///
/// Specifically,
///   - The Rust sysroot is replaced with `/rust`.
///   - `cargo`-managed dependencies have `CARGO_HOME` replaced with `/cargo`.
///   - The workspace is replaced with `/workspace`.
fn normalize_crate_path(rustc: &str, file: PathBuf) -> PathBuf {
  let file = fs::canonicalize(file).unwrap();

  let sysroot = {
    let sysroot = Command::new(rustc).arg("--print").arg("sysroot").output().unwrap();
    assert!(sysroot.status.success());
    fs::canonicalize(PathBuf::from(String::from_utf8(sysroot.stdout).unwrap().trim())).unwrap()
  };
  let cargo = fs::canonicalize(PathBuf::from(
    env::var("CARGO_HOME").expect("`CARGO_HOME` wasn't explicitly set, when we set it ourselves?"),
  ))
  .unwrap();
  let workspace: PathBuf = workspace_dir();

  /*
    Make sure for the order we test these in, they won't be detected as one another.

    Note we assume the sysroot to be in a separate directory, but we solely assume the workspace
    is not under `cargo`'s directory (which it shouldn't be, as we create a fresh directory for
    it). This is because we do assume `cargo` is under our workspace (in the form of
    `workspace/target/cargo` or so), which we ensure is safe by testing for `cargo` (the more
    specific case) before testing for the workspace (the more general case).
  */
  assert!(!workspace.starts_with(&sysroot), "workspace was under the `rustc` sysroot");
  assert!(
    !cargo.starts_with(&sysroot),
    "`cargo` (part of the target directory) was under the `rustc` sysroot"
  );
  assert!(
    !workspace.starts_with(&cargo),
    "workspace was under the freshly created `cargo` directory?"
  );

  if let Ok(in_sysroot) = file.strip_prefix(sysroot) {
    PathBuf::from("/rust").join(in_sysroot)
  } else if let Ok(in_cargo) = file.strip_prefix(cargo) {
    PathBuf::from("/cargo").join(in_cargo)
  } else if let Ok(in_workspace) = file.strip_prefix(workspace) {
    PathBuf::from("/workspace").join(in_workspace)
  } else {
    panic!("unrecognized origin for crate. not in workspace, sysroot, or `CARGO_HOME`");
  }
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
    let normalized = normalize_crate_path(&rustc, PathBuf::from(file));

    // Instead of using the platform-dependent `normalized.display()`, we impl our own `to_string`
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

      https://doc.rust-lang.org/1.93.0/cargo/reference/config.html#buildrustc-wrapper

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
      assert!(env::var(BUILD_SCRIPT_MARKER).is_ok(), "{}", direct_build_error);

      // If we're building the WASM blob, the build would've been configured by the parent process
      // and we have nothing to do here other than return.
      return;
    }
    assert!(
      env::var(BUILD_SCRIPT_MARKER).is_err(),
      "build script called from build script for non-WASM target?"
    );
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

  /*
    Re-run anytime the dependencies change.

    We detect if the dependencies change by using if the `Cargo.lock` changed. This isn't
    fine-grained, as it covers the entire Serai workspace, but there isn't another way to check if
    the dependencies changed we can't tell `cargo` to rerun if the output of
    `cargo tree -p serai-runtime` changes. We could implement such detection ourselves, but it
    isn't worth the complexity at this time.

    TODO(never): If reran yet everything is the same except the `Cargo.lock`, compare the subtree
    for `serai-runtime` specifically ourselves. This would avoid rebuilds because a
    not-in-`serai-runtime`-tree dependency was updated.

    Then, for all crates specified by file path, we re-run if their directories change.

    The usage of `cargo tree` is sub-optimal in that `cargo tree` is intended for human consumption
    and may? not have a stable definition. We accept this here. Alternatively, we could use
    `cargo metadata` (with a defined, stable format), but the complexity of parsing its JSON isn't
    worth the benefit when `cargo tree` performs the exact filtering we want and its format is
    simple enough to parse (solely unstable).
  */
  {
    let mut rerun_if_changed = HashSet::new();
    rerun_if_changed.insert(workspace_dir().join("Cargo.lock"));

    let tree_command = || {
      let mut command = cargo_command();
      command.arg("tree").args(["--prefix", "none", "--color", "never", "--charset", "utf8"]);
      command
    };

    // Note this subtree includes `serai-runtime` itself, so this will be reran if this changes
    let runtime_subtree = tree_command()
      .args(["-p", "serai-runtime"])
      .args(["--edges", "no-dev"])
      .args(["--target", "wasm32v1-none"])
      .args(["--no-default-features", &features_flag])
      .output()
      .expect("failed to get dependency tree for `serai-runtime`");
    assert!(runtime_subtree.status.success());
    let runtime_subtree = String::from_utf8(runtime_subtree.stdout)
      .expect("`cargo tree` with UTF-8 charset wasn't UTF-8");

    for dep in runtime_subtree.lines() {
      let mut parts = dep.split(' ');

      let crate_name = parts.next().expect("line in `cargo tree` output omitted crate name");
      let crate_version = parts.next().expect("line in `cargo tree` output omitted crate name");

      /*
        `cargo tree`, as configured above, will output any subtype next (such `proc-macro`). It
        will then proceed to output the source, if not crates.io, before outputting if a wildcard
        version specification was used.

        Unfortunately, it doesn't let us distinguish what the text was intended to be, forcing us
        to detect it ad-hoc. We iterate all remaining parts and if any are paths on our filesystem,
        we check if they correspond to the crate we're looking for using a `cargo tree` command.
      */
      for part in parts {
        /*
          If this 'crate' doesn't exist, or we can't access it, this isn't what we're looking for.
          This shouldn't be necessary as we proceed to check this path with an invocation of
          `cargo`, but it's better to check this is a path before we start calling an executable
          with it as input.
        */
        let (folder, would_be_manifest) = {
          let mut possible_folder = PathBuf::from(
            part
              .strip_prefix('(')
              .expect("contextual part of `cargo tree` omitted opening parentheses")
              .strip_suffix(')')
              .expect("contextual part of `cargo tree` omitted closing parentheses"),
          );

          // `cargo tree` was invoked from `workspace_dir()`, so ensure that context is respected
          if possible_folder.is_relative() {
            possible_folder = workspace_dir().join(possible_folder);
          }
          assert!(possible_folder.is_absolute());

          let would_be_manifest = possible_folder.join("Cargo.toml");
          let manifest_exists_and_is_accessible =
            matches!(fs::exists(&would_be_manifest), Ok(true));
          if !manifest_exists_and_is_accessible {
            continue;
          }
          (possible_folder, would_be_manifest)
        };
        let would_be_manifest = would_be_manifest
          .into_os_string()
          .into_string()
          .expect("UTF-8 string -> path -> string failed");

        // Get the ID of the corresponding crate for this (would-be) manifest via `cargo`
        let possible_crate = tree_command()
          .args(["--manifest-path", &would_be_manifest])
          .args(["--depth", "0"])
          .output()
          .expect("failed to spawn `cargo tree` command for possible path of dependency");
        // If `cargo` didn't succeed, this obviously wasn't a properly-defined crate
        if !possible_crate.status.success() {
          continue;
        }

        // The first line, and only line due to `--depth 0`, should be this crate's ID
        let this_crate = String::from_utf8(possible_crate.stdout)
          .expect("`cargo tree` with UTF-8 charset wasn't UTF-8");
        let mut this_crate_parts = this_crate.split(' ');
        let this_crate_name = this_crate_parts.next().expect("`cargo tree` omitted name of dep");
        let this_crate_version =
          this_crate_parts.next().expect("`cargo tree` omitted version of dep");
        if (this_crate_name == crate_name) && (this_crate_version == crate_version) {
          // Re-run if this directory changes
          rerun_if_changed.insert(folder);
          break;
        }
      }
    }

    for path in rerun_if_changed {
      // We require this path be absolute so we aren't concerned about the working directory
      // `cargo` applies to `rerun-if-changed` directives (the crate itself's root)
      assert!(path.is_absolute());
      println!("cargo::rerun-if-changed={}", path.display());
    }
  }

  let mut build_command = cargo_command();

  /*
    Propagate the workspace directory.

    When invoked as a `rustc` wrapper, we check if we're compiling a crate within our workspace,
    requiring knowing the workspace's path. However, when invoked as a `rustc` wrapper, the
    directory we're invoked from changes and prevents resolving the workspace.

    To solve this, we explicitly declare the original workspace for our future calls.
  */
  build_command.env("WORKSPACE_DIR", workspace_dir());

  /*
    Install ourselves as the `rustc` wrapper for the reasons described above.

    This would overwrite any system-provided `RUSTC_WRAPPER`, but that shouldn't be a problem here.
    Tooling such as `clippy` override `RUSTC_WORKSPACE_WRAPPER`, which we respect.
  */
  assert!(
    matches!(env::var("RUSTC_WRAPPER"), Err(env::VarError::NotPresent)),
    "`RUSTC_WRAPPER` set when this build script sets it itself",
  );
  build_command.env("RUSTC_WRAPPER", std::env::current_exe().unwrap());

  /*
    We use a nested `cargo` directory to ensure we know where the `cargo` directory is.

    This does limit the host's ability to have a differing `cargo` configuration, potentially
    limiting contamination yet also potentially breaking systems for which `cargo` doesn't work
    out-of-the-box and _must_ be configured.
  */
  build_command.env("CARGO_HOME", PathBuf::from(cargo_env("OUT_DIR")).join("cargo"));

  /*
    We use a nested `target` directory for building the WASM as the existing `target` directory
    will be locked by the build process we're currently running.
  */
  let target_dir = PathBuf::from(cargo_env("OUT_DIR")).join("target");
  if release_wasm() {
    /*
      Remove the directory if it already exists, as this will be a non-incremental build so at best
      it does nothing, and at worst it accumulates due to `cargo`'s lack-luster garbage collection.
    */
    let _ = fs::remove_dir_all(&target_dir);
  }
  build_command.env("CARGO_TARGET_DIR", &target_dir);

  /*
    `trim-paths` is an unstable flag to strip the build environment's paths, as would otherwise
    prevent reproducible builds without an exactly-matching filesystem layout.

    https://doc.rust-lang.org/1.93.0/cargo/reference/unstable.html#profile-trim-paths-option

    This would be part of `DETERMINISM` except for how it's a `cargo` argument, not a `rustc` flag.
  */
  build_command.arg("-Ztrim-paths=all");

  build_command.arg("rustc");
  build_command.arg("--package").arg(cargo_env("CARGO_PKG_NAME"));
  build_command.arg("--target").arg("wasm32v1-none");
  build_command.arg("--crate-type").arg("cdylib");
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

    https://doc.rust-lang.org/1.93.0/cargo/reference/unstable.html#build-std
  */
  build_command.arg("-Zbuild-std=compiler_builtins,panic_abort,core,alloc");
  /*
    We set this to an empty value to override the default values which enable unwinding.

    https://doc.rust-lang.org/1.93.0/cargo/reference/unstable.html#build-std-features
  */
  build_command.arg("-Zbuild-std-features=");

  // Invoke the build command and ensure it succeeds
  assert!(build_command.status().unwrap().success());

  /*
    We now find the location of the build artifact within our nested `target` directory and copy it
    to the current `out` directory.

    Ideally, we would use `--artifact-dir` for this
    (https://doc.rust-lang.org/1.93.0/cargo/reference/unstable.html#artifact-dir), but it's only
    available for `cargo build` (when we use `cargo rustc` due to needing `--crate-type`).

    Since the target directory format is unstable, we either have to:
    - Hardcode a path
    - Parse the compiler's standard output
    - Implement such a search (anooying but less so)

    The first is fragile. The second requires a JSON library or would be quite hacky. The third is
    quite simple to implement, just slow as it's a recursive file search and doesn't immediately
    have the path of the artifact (either via knowing it or being told it).

    This search isn't optimized, and doesn't respect symbolic links/understand cycles, but we can
    reasonably assume the `target` directory to not have such arcane structure.
  */
  {
    let file = cargo_env("CARGO_PKG_NAME").replace('-', "_") + ".wasm";
    let mut search_dir = vec![target_dir];
    let mut done = false;
    while let Some(next) = search_dir.pop() {
      for entry in fs::read_dir(next).expect("couldn't read files in target directory") {
        let entry = entry.expect("couldn't access entry in target directory");
        if entry
          .file_type()
          .expect("couldn't learn file type of entry in target directory")
          .is_dir()
        {
          search_dir.push(entry.path());
          continue;
        }
        if entry.file_name().as_encoded_bytes() == file.as_bytes() {
          fs::copy(entry.path(), PathBuf::from(cargo_env("OUT_DIR")).join(&file))
            .expect("couldn't copy artifact to our directory");
          done = true;
          break;
        }
      }
    }
    assert!(done, "failed to locate the `{file}` artifact");
  }
}
