#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::time::Duration;

/// Sleep for the specified duration.
pub fn sleep(duration: Duration) -> impl core::future::Future<Output = ()> {
  tokio::time::sleep(duration)
}
