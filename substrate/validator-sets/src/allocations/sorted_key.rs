//! The key type for the `SortedAllocations` map.
//!
//! This premises itself on lexicographic trickery similar to what's used in `substrate-median`.
//! There is the argument they should share a lexicography library (such as a module within
//! `serai-primitives`), yet `substrate-median` was intended to not rely on any Serai-specific
//! dependencies and `substrate-validator-sets-pallet` doesn't need to rely on `substrate-median`.

use scale::{Encode, Decode, MaxEncodedLen};

use serai_abi::primitives::{network_id::NetworkId, balance::Amount, address::SeraiAddress};

/// The key to use for the sorted allocations map.
///
/// This has a specific layout to cause a specific order within the corresponding map.
/// Specifically, validators should be grouped by network before being ordered by who has allocated
/// the most stake. This results in an approximation of a
/// `StorageDoubleMap<Identity, NetworkId, Blake2_128Concat, SeraiAddress>`, with a sort applied to
/// the latter keys. It wouldn't be an issue to use a non-`Identity` hasher for the first key
/// (`NetworkId`), it's just considered unnecessary due to how `NetworkId` is small and
/// statically-defined.
///
/// So encoding the amount does allow an adversary to create layers within the Merkle trie over a
/// non-trivial domain (the `u64` space). As the underlying trie operates over nibbles, and a `u64`
/// is represented with `8` bytes, at worst this would allow creating `16` layers. This is
/// acceptable, especially as Serai doesn't have to worry about Proof of Validity costs as most
/// Substrate-based runtimes would. In practice, it isn't quite so easy for the adversary as these
/// amounts correspond to literal amounts of allocated stake (for which there's a minimum).
#[derive(Clone, Copy, Encode, Decode, MaxEncodedLen)]
pub(crate) struct SortedAllocationsKey {
  network: NetworkId,
  lexicographic_amount: [u8; 8],
  storage_hash: [u8; 16],
  validator: SeraiAddress,
}

/// Reverse the lexicographic order of a given byte array.
///
/// This is a bijective mapping. Calling reverse twice is equivalent to the identity function.
fn reverse_lexicographic_order<const N: usize>(bytes: [u8; N]) -> [u8; N] {
  let mut res = [0u8; N];
  for (i, byte) in bytes.iter().enumerate() {
    res[i] = !*byte;
  }
  res
}

impl SortedAllocationsKey {
  pub(super) fn new(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> SortedAllocationsKey {
    /*
      We want the accounts with the highest allocations to be first. Since the DB iterates from
      low to high, we take the big-endian bytes of the amount (meaning the lowest-value allocations
      have the lowest lexicographic order and will be first), then reverse their order.
    */
    let lexicographic_amount = reverse_lexicographic_order(amount.0.to_be_bytes());
    // Hash all of the keys to best defend against layer-spam attacks
    let storage_hash = sp_io::hashing::blake2_128(&(network, amount, validator).encode());
    SortedAllocationsKey { network, lexicographic_amount, storage_hash, validator }
  }

  pub(super) fn network(&self) -> NetworkId {
    self.network
  }

  pub(super) fn validator(&self) -> SeraiAddress {
    self.validator
  }

  pub(super) fn amount(&self) -> Amount {
    // This relies on how `reverse_lexicographic_order` is a bijective mapping
    Amount(u64::from_be_bytes(reverse_lexicographic_order(self.lexicographic_amount)))
  }
}

#[test]
fn test_reverse_lexicographic_order() {
  use rand_core::{RngCore as _, OsRng};

  use sp_io::TestExternalities;
  use frame_support::{pallet_prelude::*, Identity, traits::StorageInstance};

  TestExternalities::default().execute_with(|| {
    struct Storage;
    impl StorageInstance for Storage {
      fn pallet_prefix() -> &'static str {
        "LexicographicOrder"
      }

      const STORAGE_PREFIX: &'static str = "storage";
    }
    type Map = StorageMap<Storage, Identity, [u8; 8], (), OptionQuery>;

    struct StorageReverse;
    impl StorageInstance for StorageReverse {
      fn pallet_prefix() -> &'static str {
        "LexicographicOrder"
      }

      const STORAGE_PREFIX: &'static str = "storagereverse";
    }
    type MapReverse = StorageMap<StorageReverse, Identity, [u8; 8], (), OptionQuery>;

    // populate the maps
    let mut amounts = vec![];
    // Push the `u16` range, and the first value requiring more than two bytes to represent
    for i in 0 ..= u64::from(u16::MAX) + 1 {
      amounts.push(i);
    }
    // Push a variety of random values
    for _ in 0 .. 100 {
      amounts.push(OsRng.next_u64());
    }

    for a in &amounts {
      Map::set(a.to_be_bytes(), Some(()));
      MapReverse::set(reverse_lexicographic_order(a.to_be_bytes()), Some(()));
    }

    amounts.sort_unstable();

    // retrive back and check whether they are sorted as expected
    let total_size = amounts.len();
    let mut map_iter = Map::iter_keys();
    let mut reverse_map_iter = MapReverse::iter_keys();
    for i in 0 .. amounts.len() {
      let first = map_iter.next().unwrap();
      let second = reverse_map_iter.next().unwrap();

      // The next value in the in-order map should be the next value in the sorted amounts
      assert_eq!(u64::from_be_bytes(first), amounts[i]);
      // And then if we again apply the bijective mapping, the next value in the reversed map
      // should be the next value from the end in the sorted amounts
      assert_eq!(
        u64::from_be_bytes(reverse_lexicographic_order(second)),
        amounts[total_size - (i + 1)]
      );
    }
  });
}

#[test]
fn sorted_allocations_key() {
  use rand_core::{RngCore as _, OsRng};

  let mut address = [0; 32];
  OsRng.fill_bytes(&mut address);
  let address = SeraiAddress(address);

  let amount = Amount(OsRng.next_u64());
  let key = SortedAllocationsKey::new(NetworkId::Serai, address, amount);
  assert_eq!(key.validator(), address);
  assert_eq!(key.amount(), amount);

  let other_amount = Amount(OsRng.next_u64());
  let other_key = SortedAllocationsKey::new(NetworkId::Serai, address, other_amount);
  assert_eq!(key.encode().cmp(&other_key.encode()), amount.cmp(&other_amount).reverse());
}
