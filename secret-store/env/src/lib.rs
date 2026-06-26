#![cfg_attr(docsrs, feature(doc_cfg))]

use std::collections::HashMap;

use zeroize::Zeroizing;

/// Re-export of `log` for direct access (e.g. `serai_env::log::Level`).
pub use log;

mod encryption;

/// The environment, as received from the Serai Secret Store.
pub struct Environment(HashMap<String, Zeroizing<String>>);

impl Environment {
  /// Receive the environment from the Secret Store.
  pub async fn from_secret_store() -> Self {
    let server = tokio::net::TcpListener::bind("0.0.0.0:59119".to_owned())
      .await
      .expect("couldn't bind to the expected port for the secret store");
    'invalid_socket: loop {
      /*
        TODO: Check the origin. Right now, a service other than the secret-store can provide
        secrets, though this is accepted as working with incorrect secrets does not reveal/impact
        the actual secrets.
      */
      let Ok((socket, _origin)) = server.accept().await else { continue 'invalid_socket };
      let Ok(socket) = encryption::EncryptedSocket::new(socket).await else {
        continue 'invalid_socket;
      };
      let Ok(secrets) = socket.read_all().await else { continue 'invalid_socket };
      let secrets = Zeroizing::new(secrets);

      // TODO: Support Unicode
      for c in secrets.iter().copied() {
        if c > 0x7f {
          continue 'invalid_socket;
        }
      }
      let mut chars = secrets.iter().copied().map(char::from);

      let mut result = HashMap::new();
      {
        match chars.next() {
          Some('"') => {
            let mut key = String::new();
            loop {
              match chars.next() {
                Some('"') => break,
                Some(c) => key.push(c),
                None => continue 'invalid_socket,
              }
            }

            match chars.next() {
              Some('=') => {}
              _ => continue 'invalid_socket,
            }
            match chars.next() {
              Some('"') => {}
              _ => continue 'invalid_socket,
            }

            let mut value = Zeroizing::new(String::new());
            loop {
              match chars.next() {
                Some('"') => break,
                Some(c) => value.push(c),
                None => continue 'invalid_socket,
              }
            }

            result.insert(key, value);
          }
          Some(_) => continue 'invalid_socket,
          None => return Environment(result),
        }
      }
    }
  }

  /// Fetch a variable from the environment.
  pub fn var(&self, variable: &str) -> Option<&Zeroizing<String>> {
    self.0.get(variable)
  }
}

pub fn init_logger() {
  // TODO: Implement `env_logger::Env` for this library instead of using `env_logger::Env`?
  env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
    .try_init()
    .unwrap();
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
