#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unexpected_cfgs)]

#[cfg(any(feature = "std", target_family = "wasm"))]
extern crate alloc;

#[cfg(any(feature = "std", target_family = "wasm"))]
mod common;
#[cfg(any(feature = "std", target_family = "wasm"))]
pub use common::*;

// If this is WASM, or `native_runtime` was set, we build the runtime proper
#[cfg(any(target_family = "wasm", native_runtime))]
mod wasm;

/*
  If this is `std`, and `native_runtime` wasn't set, we solely stub `impl_runtime_apis` for the
  `RuntimeApi` the node requires. This satisfies the type contract, as Substrate will use to call
  into the WASM blob with certain assumptions, without doubling compilation times for what will
  never actually be called by the node (due to always using the WASM, as desired).
*/
#[cfg(all(feature = "std", not(native_runtime)))]
mod std_runtime_api;
#[cfg(all(feature = "std", not(native_runtime)))]
pub use std_runtime_api::RuntimeApi;

// If this isn't WASM, regardless of what it is, we include the WASM blob from the build script
#[cfg(all(not(target_family = "wasm"), debug_assertions))]
pub const WASM: &[u8] =
  include_bytes!(concat!(env!("OUT_DIR"), "/target/wasm32v1-none/debug/serai_runtime.wasm"));
#[cfg(all(not(target_family = "wasm"), not(debug_assertions)))]
pub const WASM: &[u8] =
  include_bytes!(concat!(env!("OUT_DIR"), "/target/wasm32v1-none/release/serai_runtime.wasm"));
