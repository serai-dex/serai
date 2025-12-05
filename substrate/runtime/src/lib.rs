#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(feature = "std", target_family = "wasm"))]
extern crate alloc;

#[cfg(any(feature = "std", target_family = "wasm"))]
mod common;
#[cfg(any(feature = "std", target_family = "wasm"))]
pub use common::*;

// If this is WASM, we build the runtime proper
#[cfg(target_family = "wasm")]
mod wasm;

// If this is `std`, we solely stub with `impl_runtime_apis` for the `RuntimeApi` the node requires
#[cfg(feature = "std")]
mod std_runtime_api;
#[cfg(feature = "std")]
pub use std_runtime_api::RuntimeApi;

// If this isn't WASM, regardless of what it is, we include the WASM blob from the build script
#[cfg(all(not(target_family = "wasm"), debug_assertions))]
pub const WASM: &[u8] =
  include_bytes!(concat!(env!("OUT_DIR"), "/target/wasm32v1-none/debug/serai_runtime.wasm"));
#[cfg(all(not(target_family = "wasm"), not(debug_assertions)))]
pub const WASM: &[u8] =
  include_bytes!(concat!(env!("OUT_DIR"), "/target/wasm32v1-none/release/serai_runtime.wasm"));
