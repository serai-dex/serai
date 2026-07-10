use core::fmt::Write as _;

use super::cargo_env;

/// Whether or not the WASM should be built in a `release` configuration.
pub(super) fn release_wasm() -> bool {
  let profile = cargo_env("PROFILE");
  match profile.as_str() {
    "debug" | "test" => false,
    "bench" | "release" => true,
    _ => panic!("unexpected profile: {profile}"),
  }
}

/// The `RUSTFLAGS` to set when building the WASM.
pub(super) fn wasm_rustflags() -> String {
  /// Compiler arguments required for a Substrate runtime making use of FRAME.
  ///
  /// Substrate's primitives, pallets make use of this `cfg` value to determine what context
  /// they're being built within.
  const REQUIRED_BY_SUBSTRATE: &str = "--cfg substrate_runtime";

  /// Compiler arguments for WASM.
  ///
  /// `--export-table` causes the linker to export the function table from our artifact, allowing
  /// our VM to identify what function we want to call by its name.
  ///
  /// `--export=__heap_base` is needed for Substrate's `FreeingBumpHeapAllocator` which expects to
  /// be able to find this constant. This was inherently exported historically but became explicit
  /// with <https://github.com/rust-lang/rust/pull/156174>.
  const WASM: &str = "-C link-arg=--export-table -C link-arg=--export=__heap_base";
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
  ///   https://doc.rust-lang.org/1.94.0/rustc/codegen-options/index.html#embed-bitcode
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
