#![cfg_attr(docsrs, feature(doc_cfg))]

/// Re-export of `log` for direct access (e.g. `serai_env::log::Level`).
pub use log;

use std::sync::Once;
static INIT: Once = Once::new();

/// Test helpers.
#[cfg(any(test, feature = "test-helpers"))]
#[doc(hidden)]
pub mod test_helpers;

/// Lazily initialize the logger (safe to call multiple times).
pub fn ensure_logger() {
  INIT.call_once(init_logger);
}

// Obtain a variable from the Serai environment/secret store.
pub fn var(variable: &str) -> Option<String> {
  // TODO: Move this to a proper secret store
  // TODO: Unset this variable
  std::env::var(variable).ok()
}

pub fn init_logger() {
  // TODO: Implement `env_logger::Env` for this library instead of using `env_logger::Env`?
  let _ =
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).try_init();
}

/// Extract the message from a `catch_unwind` payload, covering both
/// `&'static str` (e.g. `panic!("literal")`) and `String` (e.g. `panic!("fmt {}", v)`).
pub fn panic_message(payload: &Box<dyn core::any::Any + Send>) -> &str {
  payload
    .downcast_ref::<&str>()
    .copied()
    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
    .unwrap_or("<non-string panic payload>")
}

/// Coverage-gated `trace!`. Compiles to nothing under `cfg(coverage)`.
#[cfg(not(coverage))]
#[macro_export]
macro_rules! trace {
  ($($arg:tt)+) => { $crate::log::trace!($($arg)+) };
}
#[cfg(coverage)]
#[macro_export]
macro_rules! trace {
  ($($arg:tt)+) => {};
}

/// Coverage-gated `debug!`. Compiles to nothing under `cfg(coverage)`.
#[cfg(not(coverage))]
#[macro_export]
macro_rules! debug {
  ($($arg:tt)+) => { $crate::log::debug!($($arg)+) };
}
#[cfg(coverage)]
#[macro_export]
macro_rules! debug {
  ($($arg:tt)+) => {};
}

/// Coverage-gated `info!`. Compiles to nothing under `cfg(coverage)`.
#[cfg(not(coverage))]
#[macro_export]
macro_rules! info {
  ($($arg:tt)+) => { $crate::log::info!($($arg)+) };
}
#[cfg(coverage)]
#[macro_export]
macro_rules! info {
  ($($arg:tt)+) => {};
}

/// Coverage-gated `warn!`. Compiles to nothing under `cfg(coverage)`.
#[cfg(not(coverage))]
#[macro_export]
macro_rules! warn {
  ($($arg:tt)+) => { $crate::log::warn!($($arg)+) };
}
#[cfg(coverage)]
#[macro_export]
macro_rules! warn {
  ($($arg:tt)+) => {};
}

/// Coverage-gated `error!`. Compiles to nothing under `cfg(coverage)`.
#[cfg(not(coverage))]
#[macro_export]
macro_rules! error {
  ($($arg:tt)+) => { $crate::log::error!($($arg)+) };
}
#[cfg(coverage)]
#[macro_export]
macro_rules! error {
  ($($arg:tt)+) => {};
}
