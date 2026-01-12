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
//! This build script _attempts_ to better enable _reproducible builds_. It does not guarantee
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
//! This build script also applies a variety of optimizations, both to the time to compile and the
//! output itself, as desirable. It should be noted `substrate-wasm-builder` applies a pass with
//! `wasm-opt`. This used to be somewhat required, as `wasm-opt` was invoked to reduce the
//! functionality within the output WASM to the desired WASM MVP (now available as `wasmv1-none`),
//! but isn't necessary today. While `wasm-opt` could still be used as a general optimization
//! pass, Serai doesn't employ it as:
//!
//!   - The included optimizations should achieve the desired performance.
//!   - While `wasm-opt` was being used to reduce the WASM blob's _size_, Serai does not mind
//!     large WASM blobs. This is as it does not employ _on-chain WASM blob distribution_ as
//!     Substrate frequently does for on-chain upgrades.
//!
//! The included methodology is specific to WASM which means this build script will not
//! immediately work to produce a PolkaVM runtime, a feature which can be assumed if one instead
//! used `substrate-wasm-builder`.

use core::fmt::Write as _;
use std::{path::PathBuf, env, fs, process::Command};

#[rustfmt::skip]
/// Fetch an environment variable which `cargo` sets when building crates.
///
/// https://doc.rust-lang.org/1.92.0/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates
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
  ///   https://doc.rust-lang.org/1.92.0/rustc/codegen-options/index.html#embed-bitcode
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

  // Mark this is invoked from the build script
  command.env(BUILD_SCRIPT_MARKER, "1");

  // Normalize the locale
  command.env("LC_ALL", "C");

  // Propagate the Rust toolchain
  command.env("CARGO", cargo_env("CARGO")).env("RUSTC", cargo_env("RUSTC"));

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

      https://doc.rust-lang.org/1.92.0/rustc/codegen-options/index.html#incremental
      https://doc.rust-lang.org/1.92.0/cargo/reference/profiles.html#incremental
    */
    command.env("CARGO_INCREMENTAL", "false");
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
  assert!(workspace.pop());
  workspace
}

fn main() {
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

  // Re-run anytime the workspace changes
  // TODO: Re-run anytime `Cargo.lock` or specifically the `src` folders change
  println!("cargo::rerun-if-changed={}", workspace_dir().display());

  let mut build_command = cargo_command();

  /*
    We do propagate the host's `PATH`, as the Rust toolchain requires the host's C compiler, even
    when using the self-contained linker, in order to drive it and provide the platform-specific
    libraries.

    While we could build a `PATH` from the Rust toolchain, and then append the value of
    `RUSTC_LINKER` (to have a `PATH` deterministic to the Rust toolchain with the sole exception of
    the host's linker), `RUSTC_LINKER` is the linker for the _target_, not the host, when we would
    want to set the linker for the host specifically. There also isn't a trivial way to query the
    _resolved_ linker after all the possible configuration methods are taken into consideration
  */
  if let Ok(path) = env::var("PATH") {
    build_command.env("PATH", path);
  }

  /*
    We use a nested `target` directory for building the WASM as the existing `target` directory
    will be locked by the build process we're currently running.
  */
  let target_dir = PathBuf::from(cargo_env("OUT_DIR")).join("target");
  // Remove the directory if it already exists
  let _ = fs::remove_dir_all(&target_dir);
  build_command.env("CARGO_TARGET_DIR", &target_dir);

  /*
    `trim-paths` is an unstable flag to strip the build environment's paths, as would otherwise
    prevent reproducible builds without an exactly-matching filesystem layout.

    https://doc.rust-lang.org/1.92.0/cargo/reference/unstable.html#profile-trim-paths-option

    This would be part of `DETERMINISM` except for how it's a `cargo` argument, not a `rustc` flag.
  */
  build_command.arg("-Ztrim-paths=all");

  build_command.arg("rustc");
  build_command.arg("--package").arg(cargo_env("CARGO_PKG_NAME"));
  build_command.arg("--target").arg("wasm32v1-none");
  build_command.arg("--crate-type").arg("cdylib");
  build_command.arg("--no-default-features");

  if release_wasm() {
    build_command.arg("--release");
  }

  /*
    We use `build-std` for performance reasons and to ensure all of our configuration is respected.
    It also allows us to not explicitly add the `wasm32v1-none` target, and the pre-compiled
    `rust-std`, instead solely adding the `rust-src` component (as necessary to build `rust-std`
    here and now). This improves the ability to reproduce Serai from a bootstrapped environment.

    https://doc.rust-lang.org/1.92.0/cargo/reference/unstable.html#build-std
  */
  build_command.arg("-Zbuild-std=compiler_builtins,panic_abort,core,alloc");
  /*
    We set this to an empty value to override the default values which enable unwinding.

    https://doc.rust-lang.org/1.92.0/cargo/reference/unstable.html#build-std-features
  */
  build_command.arg("-Zbuild-std-features=");

  // Invoke the build command and ensure it succeeds
  assert!(build_command.status().unwrap().success());

  /*
    We now find the location of the build artifact within our nested `target` directory and copy it
    to the current `out` directory.

    Ideally, we would use `--artifact-dir` for this
    (https://doc.rust-lang.org/1.92.0/cargo/reference/unstable.html#artifact-dir), but it's only
    available for `cargo build` (when we use `cargo rustc` due to needing `--crate-type`).

    Since the target directory format is unstable, we either have to:
    - Hardcode a path
    - Parse the compiler's standard output
    - Implement such a search (anooying but less so)

    The first is fragile. The second requires a JSON library or would be quite hacky. The third is
    quite simple to implement, just slow as it's a recursive file search and doesn't immediately
    have the path of the artifact (either via knowing it or being told it).
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
