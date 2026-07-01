//! Provides [`TestRng`] and [`new_test_rng`]. When a test panics the seed is printed to stderr
//! so you can reproduce the exact same test run.

use rand::{RngCore as _, SeedableRng as _};

/// Environment variable to set a specific 32-byte hex seed for reproducible fuzz tests.
const MOCK_TEST_SEED_ENV: &str = "MOCK_TEST_SEED";

/// A wrapper around [`StdRng`] that prints the `MOCK_TEST_SEED` on [`Drop`]
/// only when the current thread is panicking.
#[derive(Clone)]
pub struct TestRng(rand::rngs::StdRng, [u8; 32]);

impl TestRng {
  /// Create a new `TestRng` from a 32-byte seed.
  fn new(seed: [u8; 32]) -> Self {
    Self(rand::rngs::StdRng::from_seed(seed), seed)
  }
}

impl rand_core::RngCore for TestRng {
  fn next_u32(&mut self) -> u32 {
    self.0.next_u32()
  }
  fn next_u64(&mut self) -> u64 {
    self.0.next_u64()
  }
  fn fill_bytes(&mut self, dest: &mut [u8]) {
    self.0.fill_bytes(dest);
  }
  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
    self.0.try_fill_bytes(dest)
  }
}

impl rand_core::CryptoRng for TestRng {}

impl Drop for TestRng {
  fn drop(&mut self) {
    if std::thread::panicking() {
      eprintln!(
        "MOCK_TEST_SEED={}  (set this env var to reproduce this exact test run)",
        hex::encode(self.1),
      );
    }
  }
}

/// One-line test scaffolding: initialises the env logger and returns a
/// deterministic [`TestRng`] whose seed is printed on [`Drop`] only if the
/// test panics.
pub fn new_test_rng() -> TestRng {
  crate::ensure_logger();

  let seed: [u8; 32] = match crate::var(MOCK_TEST_SEED_ENV) {
    Some(hex_str) => hex::decode(&hex_str)
      .expect("MOCK_TEST_SEED must be a valid hex string")
      .try_into()
      .expect("MOCK_TEST_SEED must decode to exactly 32 bytes (64 hex chars)"),
    None => {
      let mut seed = [0u8; 32];
      rand::rngs::OsRng.fill_bytes(&mut seed);
      seed
    }
  };

  TestRng::new(seed)
}
