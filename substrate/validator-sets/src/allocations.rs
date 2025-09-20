use sp_core::{Encode, sr25519::Public};

use serai_abi::primitives::{network_id::NetworkId, balance::Amount, validator_sets::KeyShares};

use frame_support::storage::{StorageMap, StoragePrefixedMap};

/// The key to use for the allocations map.
pub(crate) type AllocationsKey = (NetworkId, Public);
/// The key to use for the sorted allocations map.
pub(crate) type SortedAllocationsKey = (NetworkId, [u8; 8], [u8; 16], Public);

/// The storage underlying `Allocations`.
///
/// This storage is expected to be owned by the `Allocations` interface and not directly read/write
/// to.
pub(crate) trait AllocationsStorage {
  /// An opaque map storing allocations.
  type Allocations: StorageMap<AllocationsKey, Amount, Query = Option<Amount>>;
  /// An opaque map storing allocations in a sorted manner.
  ///
  /// This MUST be instantiated with a map using `Identity` for its hasher.
  /*
    This is premised on the underlying trie iterating from keys with low-bytes to keys with
    high-bytes.

    We use Identity so we don't have a hasher add pseudorandom bytes to the start of the keys. This
    does remove the protection using a hash algorithm here offers against spam attacks (by flooding
    the DB with layers, increasing lookup time and Merkle proof sizes, not that we use Merkle
    proofs as Polkadot does).

    Since amounts are represented with just 8 bytes, only 16 nibbles are present. This caps the
    potential depth caused by spam at 16 layers (as the underlying DB operates on nibbles). While
    there is an entire 32-byte public key after this, a Blake hash of the key is inserted after the
    amount to prevent the key from also being used to cause layer spam. We use a `[u8; 16]` to
    represent this, and not a explicit `Blake2_128Concat` hasher, to ensure all prior keys are part
    part of the hash. A Substrate-hasher would only hash the immediately following key.

    There's also a minimum stake requirement, which further reduces the potential for spam.
  */
  type SortedAllocations: StorageMap<SortedAllocationsKey, (), Query = Option<()>>
    + StoragePrefixedMap<()>;
}

/// An interface for managing validators' allocations.
pub(crate) trait Allocations {
  /// Set an allocation.
  ///
  /// Returns the validator's prior allocation.
  fn set_allocation(network: NetworkId, key: Public, amount: Amount) -> Option<Amount>;

  /// Get an allocation.
  fn get_allocation(network: NetworkId, key: Public) -> Option<Amount>;

  /// Iterate over allocations for a network, yielding the highest-valued allocations.
  ///
  /// This will yield all validators present whose allocation is greater than or equal to the
  /// specified minimum.
  ///
  /// If two validators share an allocation, the order is deterministic yet otherwise undefined.
  fn iter_allocations(
    network: NetworkId,
    minimum_allocation: Amount,
  ) -> impl Iterator<Item = (Public, Amount)>;

  /// Calculate the expected key shares for a network, per the current allocations.
  fn expected_key_shares(network: NetworkId, allocation_per_key_share: Amount) -> KeyShares;
}

/// Reverses the lexicographic order of a given byte array.
///
/// This is a bijective mapping. Calling reverse twice is equivalent to the identity function.
fn reverse_lexicographic_order<const N: usize>(bytes: [u8; N]) -> [u8; N] {
  let mut res = [0u8; N];
  for (i, byte) in bytes.iter().enumerate() {
    res[i] = !*byte;
  }
  res
}

/// The storage key to use with the sorted allocations map.
#[inline]
fn sorted_allocation_storage_key(
  network: NetworkId,
  key: Public,
  amount: Amount,
) -> (NetworkId, [u8; 8], [u8; 16], Public) {
  // We want the accounts with the highest allocations to be first. Since the DB iterates from
  // low to high, we take the BE bytes of the amount (meaning the lowest-value allocations have
  // the lowest lexicographic order and will be first), then reverse their order.
  let amount = reverse_lexicographic_order(amount.0.to_be_bytes());
  // Hash all of the keys to best defend against layer-spam attacks
  let hash = sp_io::hashing::blake2_128(&(network, amount, key).encode());
  (network, amount, hash, key)
}

// Recover the user's public key from a storage key.
fn recover_key_from_sorted_allocation_storage_key(key: &[u8]) -> Public {
  <Public as From<[u8; 32]>>::from(key[(key.len() - 32) ..].try_into().unwrap())
}

// Recover the amount allocated from a storage key.
fn recover_amount_from_sorted_allocation_storage_key(key: &[u8]) -> Amount {
  // We read the amount from the end of the key as everything after the amount is fixed-length
  let distance_from_end = 8 + 16 + 32;
  let start_pos = key.len() - distance_from_end;
  let raw: [u8; 8] = key[start_pos .. (start_pos + 8)].try_into().unwrap();
  // Take advantage of how this is a bijective mapping
  let raw = reverse_lexicographic_order(raw);
  Amount(u64::from_be_bytes(raw))
}

impl<Storage: AllocationsStorage> Allocations for Storage {
  fn set_allocation(network: NetworkId, key: Public, amount: Amount) -> Option<Amount> {
    // Remove their existing allocation, if one exists
    let prior = Storage::Allocations::take((network, key));
    if let Some(amount) = prior {
      Storage::SortedAllocations::remove(sorted_allocation_storage_key(network, key, amount));
    }
    // If we're setting a non-zero allocation, add it back to the maps
    if amount.0 != 0 {
      Storage::Allocations::set((network, key), Some(amount));
      Storage::SortedAllocations::set(
        sorted_allocation_storage_key(network, key, amount),
        Some(()),
      );
    }
    prior
  }

  fn get_allocation(network: NetworkId, key: Public) -> Option<Amount> {
    Storage::Allocations::get((network, key))
  }

  fn iter_allocations(
    network: NetworkId,
    minimum_allocation: Amount,
  ) -> impl Iterator<Item = (Public, Amount)> {
    // Iterate over the sorted allocations for this network
    let mut prefix = Storage::SortedAllocations::final_prefix().to_vec();
    prefix.extend(&network.encode());
    // Decode the read keys into (key, amount) tuples
    frame_support::storage::PrefixIterator::<_, ()>::new(prefix.clone(), prefix, |key, _value| {
      Ok((
        recover_key_from_sorted_allocation_storage_key(key),
        recover_amount_from_sorted_allocation_storage_key(key),
      ))
    })
    // Filter by the specified minimum allocation
    .filter(move |(_key, allocation)| *allocation >= minimum_allocation)
  }

  fn expected_key_shares(network: NetworkId, allocation_per_key_share: Amount) -> KeyShares {
    let mut total_key_shares = 0;
    for (_, amount) in Self::iter_allocations(network, allocation_per_key_share) {
      total_key_shares += KeyShares::from_allocation(amount, allocation_per_key_share).0;

      if total_key_shares >= KeyShares::MAX_PER_SET {
        break;
      }
    }
    KeyShares::saturating_from(total_key_shares)
  }
}

#[test]
fn test_reverse_lexicographic_order() {
  use rand_core::{RngCore, OsRng};

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
    for _ in 0 .. 100 {
      amounts.push(OsRng.next_u64());
    }

    let mut amounts_sorted = amounts.clone();
    amounts_sorted.sort();
    for a in amounts {
      Map::set(a.to_be_bytes(), Some(()));
      MapReverse::set(reverse_lexicographic_order(a.to_be_bytes()), Some(()));
    }

    // retrive back and check whether they are sorted as expected
    let total_size = amounts_sorted.len();
    let mut map_iter = Map::iter_keys();
    let mut reverse_map_iter = MapReverse::iter_keys();
    for i in 0 .. amounts_sorted.len() {
      let first = map_iter.next().unwrap();
      let second = reverse_map_iter.next().unwrap();

      // The next value in the in-order map should be the next value in the sorted amounts
      assert_eq!(u64::from_be_bytes(first), amounts_sorted[i]);
      // And then if we again apply the bijective mapping, the next value in the reversed map
      // should be the next value from the end in the sorted amounts
      assert_eq!(
        u64::from_be_bytes(reverse_lexicographic_order(second)),
        amounts_sorted[total_size - (i + 1)]
      );
    }
  });
}

#[test]
fn test_allocations() {
  use rand_core::{RngCore, OsRng};

  use borsh::BorshDeserialize;

  use sp_io::TestExternalities;
  use frame_support::{pallet_prelude::*, Identity, traits::StorageInstance};

  TestExternalities::default().execute_with(|| {
    struct Storage;
    impl StorageInstance for Storage {
      fn pallet_prefix() -> &'static str {
        "Allocations"
      }

      const STORAGE_PREFIX: &'static str = "Storage::Allocations";
    }
    type AllocationsMap =
      StorageMap<Storage, Blake2_128Concat, AllocationsKey, Amount, OptionQuery>;

    struct StorageSorted;
    impl StorageInstance for StorageSorted {
      fn pallet_prefix() -> &'static str {
        "Allocations"
      }

      const STORAGE_PREFIX: &'static str = "Storage::SortedAllocations";
    }
    type SortedAllocationsMap =
      StorageMap<StorageSorted, Identity, SortedAllocationsKey, (), OptionQuery>;

    struct Allocations;
    impl AllocationsStorage for Allocations {
      type Allocations = AllocationsMap;
      type SortedAllocations = SortedAllocationsMap;
    }

    let before = NetworkId::deserialize_reader(&mut [0].as_slice()).unwrap();
    let network = NetworkId::deserialize_reader(&mut [1].as_slice()).unwrap();
    let after = NetworkId::deserialize_reader(&mut [2].as_slice()).unwrap();

    // Create allocations
    let rand_allocation = || {
      let mut key = [0; 32];
      OsRng.fill_bytes(&mut key);
      let key = Public::from(key);
      let amount = Amount(OsRng.next_u64());
      (key, amount)
    };
    const ALLOCATIONS: usize = 100;
    let mut allocations = vec![];
    for _ in 0 .. ALLOCATIONS {
      let (key, amount) = rand_allocation();
      allocations.push((key, amount));
      assert_eq!(Allocations::set_allocation(network, key, amount), None);
    }
    // Sort them from highest amount to lowest
    allocations.sort_by_key(|item| item.1);
    allocations.reverse();

    // Set allocations for the previous and next network, by byte, to ensure the map isn't solely
    // these allocations. This ensures we don't read from another network accidentally
    {
      let (key, amount) = rand_allocation();
      assert_eq!(Allocations::set_allocation(before, key, amount), None);
      assert_eq!(Allocations::set_allocation(after, key, amount), None);
    }

    // Check the iterator works
    {
      let mut a = Allocations::iter_allocations(network, Amount(0));
      let mut b = allocations.clone().into_iter();
      for _ in 0 .. ALLOCATIONS {
        assert_eq!(a.next(), b.next());
      }
      assert!(a.next().is_none());
      assert!(b.next().is_none());
    }

    // Check the minimum works
    {
      assert_eq!(
        Allocations::iter_allocations(network, allocations[0].1).next(),
        Some(allocations[0])
      );
      assert_eq!(
        Allocations::iter_allocations(
          network,
          // Fails with probability ~1/2**57
          (allocations[0].1 + Amount(1)).unwrap()
        )
        .next(),
        None,
      );
    }
  });
}
