#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![allow(unexpected_cfgs)] // We use `native_runtime` as a config to force building the runtime

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

/// The current crate as compiled to WASM.
#[cfg(not(target_family = "wasm"))]
pub const WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/serai_runtime.wasm"));
