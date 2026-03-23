#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Re-export of `log` for direct access (e.g. `serai_env::log::Level`).
pub use log;

// Obtain a variable from the Serai environment/secret store.
pub fn var(variable: &str) -> Option<String> {
  // TODO: Move this to a proper secret store
  // TODO: Unset this variable
  std::env::var(variable).ok()
}

pub fn init_logger() {
  env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
    .try_init()
    .ok();
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

/// `info!` in production, `debug!` in tests.
/// Use for operational logging that is useful in production but noisy during testing.
#[macro_export]
macro_rules! prod_info {
  ($($arg:tt)+) => {{
    #[cfg(not(test))]
    { $crate::log::info!($($arg)+) }
    #[cfg(test)]
    { $crate::log::debug!($($arg)+) }
  }};
}
