//! Test helper utilities

use rand::Rng as _;
use rand_core::{CryptoRng, RngCore};
use serai_primitives::{network_id::NetworkId, test_helpers::all_networks};

/// Pick a random element from a slice.
pub fn pick<'a, T, R: RngCore + CryptoRng>(rng: &mut R, slice: &'a [T]) -> &'a T {
  let i = rng.next_u64() % u64::try_from(slice.len()).unwrap();
  &slice[usize::try_from(i).unwrap()]
}

/// Get a random amount using a weighted distribution.
/// Never goes to u64::MAX, uses saner mainnet values instead
pub fn random_amount<R: RngCore + CryptoRng>(rng: &mut R) -> u64 {
  match rng.next_u64() % 100 {
    0 ..= 24 => (rng.next_u64() % 10) + 1,
    25 ..= 59 => (rng.next_u64() % 990) + 11,
    60 ..= 84 => (rng.next_u64() % 99_000) + 1_001,
    _ => (rng.next_u64() % 9_900_000) + 100_001,
  }
}

/// Get a random network (Serai or external).
pub fn random_network_id<R: RngCore + CryptoRng>(rng: &mut R) -> NetworkId {
  *pick(rng, &all_networks())
}

/// Randomly select a non-empty subset of items from the vector, in random order.
pub fn random_subset<T, R: RngCore + CryptoRng>(rng: &mut R, items: &mut Vec<T>) {
  let num = rng.gen_range(1usize ..= items.len());
  for i in 0 .. num {
    let j = rng.gen_range(i .. items.len());
    items.swap(i, j);
  }
  items.truncate(num);
}
