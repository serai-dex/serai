use core::marker::PhantomData;

use sp_core::{Encode, sr25519::Public};

use serai_primitives::{constants::MAX_KEY_SHARES_PER_SET, network_id::NetworkId, balance::Amount};

use frame_support::storage::{StorageMap, StoragePrefixedMap as Spm};

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

/// The key to use for the allocations map.
type AllocationsKey = (NetworkId, Public);
/// The key to use for the sorted allocations map.
type SortedAllocationsKey = (NetworkId, [u8; 8], [u8; 16], Public);

/// An interface for managing validators' allocations.
///
/// `SortedAllocationsMap` MUST be instantiated with a map using `Identity` for its hasher.
/*
  This is premised on the underlying trie iterating from keys with low-bytes to keys with
  high-bytes.

  We use Identity so we don't have a hasher add pseudorandom bytes to the start of the keys. This
  does remove the protection using a hash algorithm here offers against spam attacks (by flooding
  the DB with layers, increasing lookup time and Merkle proof sizes, not that we use Merkle proofs
  proofs as Polkadot does).

  Since amounts are represented with just 8 bytes, only 16 nibbles are present. This caps the
  potential depth caused by spam at 16 layers (as the underlying DB operates on nibbles). While
  there is an entire 32-byte public key after this, a Blake hash of the key is inserted after the
  amount to prevent the key from also being used to cause layer spam. We use a `[u8; 16]` to
  represent this, and not a explicit `Blake2_128Concat` hasher, to ensure all prior keys are part
  part of the hash. A Substrate-hasher would only hash the immediately following key.

  There's also a minimum stake requirement, which further reduces the potential for spam.
*/
pub(crate) struct Allocations<
  AllocationsMap: StorageMap<AllocationsKey, Amount, Query = Option<Amount>>,
  SortedAllocationsMap: StorageMap<SortedAllocationsKey, (), Query = Option<()>> + Spm<()>,
>(PhantomData<(AllocationsMap, SortedAllocationsMap)>);
impl<
    AllocationsMap: StorageMap<AllocationsKey, Amount, Query = Option<Amount>>,
    SortedAllocationsMap: StorageMap<SortedAllocationsKey, (), Query = Option<()>> + Spm<()>,
  > Allocations<AllocationsMap, SortedAllocationsMap>
{
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

  /// Set an allocation.
  ///
  /// Returns the validator's prior allocation.
  pub(crate) fn set(network: NetworkId, key: Public, amount: Amount) -> Option<Amount> {
    let prior = AllocationsMap::take((network, key));
    if let Some(amount) = prior {
      SortedAllocationsMap::remove(Self::sorted_allocation_storage_key(network, key, amount));
    }
    if amount.0 != 0 {
      AllocationsMap::set((network, key), Some(amount));
      SortedAllocationsMap::set(
        Self::sorted_allocation_storage_key(network, key, amount),
        Some(()),
      );
    }
    prior
  }

  /// Get an allocation.
  pub(crate) fn get(network: NetworkId, key: Public) -> Option<Amount> {
    AllocationsMap::get((network, key))
  }

  /// Iterate over allocations for a network, yielding the highest-valued allocations.
  ///
  /// This will yield all validators present whose allocation is greater than or equal to the
  /// specified minimum.
  ///
  /// If two validators share an allocation, the order is deterministic yet otherwise undefined.
  pub(crate) fn iter(
    network: NetworkId,
    minimum_allocation: Amount,
  ) -> impl Iterator<Item = (Public, Amount)> {
    let mut prefix = SortedAllocationsMap::final_prefix().to_vec();
    prefix.extend(&network.encode());
    frame_support::storage::PrefixIterator::<_, ()>::new(prefix.clone(), prefix, |key, _value| {
      Ok((
        Self::recover_key_from_sorted_allocation_storage_key(key),
        Self::recover_amount_from_sorted_allocation_storage_key(key),
      ))
    })
    .filter(move |(_key, allocation)| *allocation >= minimum_allocation)
  }

  /// Check if a fresh sample will be BFT for f > 0.
  pub(crate) fn will_be_bft_for_any_nonzero_f(
    network: NetworkId,
    allocation_per_key_share: Amount,
  ) -> bool {
    let mut validators_len = 0;
    let mut top_validator_key_shares = None;
    let mut total_key_shares = 0;
    for (_, amount) in Self::iter(network, allocation_per_key_share) {
      validators_len += 1;

      let key_shares = amount.0 / allocation_per_key_share.0;
      total_key_shares += key_shares;
      // If this is the first validator, they're the top validator, due to this being sorted
      if top_validator_key_shares.is_none() {
        top_validator_key_shares = Some(key_shares);
      }

      if total_key_shares > u64::from(MAX_KEY_SHARES_PER_SET) {
        break;
      }
    }

    let Some(top_validator_key_shares) = top_validator_key_shares else {
      // This network has n = 0 so f = 0
      return false;
    };

    // `total_key_shares` may exceed `MAX_KEY_SHARES_PER_SET`, which will cause a round robin
    // reduction of each validator's key shares until their sum is `MAX_KEY_SHARES_PER_SET`.
    // `post_amortization_key_shares_for_top_validator` yields what the top validator's key shares
    // would be after such a reduction, letting us evaluate this correctly
    let top_validator_key_shares =
      serai_primitives::validator_sets::post_amortization_key_shares_for_top_validator(
        validators_len,
        top_validator_key_shares,
        total_key_shares,
      );
    let total_key_shares = total_key_shares.min(MAX_KEY_SHARES_PER_SET.into());
    // We achieve BFT under n=3f+1. Accordingly, for the top validator's key shares to be `f`, and
    // still have `3f < n`, we tolerate the top validator being faulty
    (top_validator_key_shares * 3) < total_key_shares
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

      const STORAGE_PREFIX: &'static str = "AllocationsMap";
    }
    type AllocationsMap =
      StorageMap<Storage, Blake2_128Concat, AllocationsKey, Amount, OptionQuery>;

    struct StorageSorted;
    impl StorageInstance for StorageSorted {
      fn pallet_prefix() -> &'static str {
        "Allocations"
      }

      const STORAGE_PREFIX: &'static str = "SortedAllocationsMap";
    }
    type SortedAllocationsMap =
      StorageMap<StorageSorted, Identity, SortedAllocationsKey, (), OptionQuery>;

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
      assert_eq!(
        Allocations::<AllocationsMap, SortedAllocationsMap>::set(network, key, amount),
        None
      );
    }
    // Sort them from highest amount to lowest
    allocations.sort_by_key(|item| item.1);
    allocations.reverse();

    // Set allocations for the previous and next network, by byte, to ensure the map isn't solely
    // these allocations. This ensures we don't read from another network accidentally
    {
      let (key, amount) = rand_allocation();
      assert_eq!(
        Allocations::<AllocationsMap, SortedAllocationsMap>::set(before, key, amount),
        None
      );
      assert_eq!(
        Allocations::<AllocationsMap, SortedAllocationsMap>::set(after, key, amount),
        None
      );
    }

    // Check the iterator works
    {
      let mut a = Allocations::<AllocationsMap, SortedAllocationsMap>::iter(network, Amount(0));
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
        Allocations::<AllocationsMap, SortedAllocationsMap>::iter(network, allocations[0].1).next(),
        Some(allocations[0])
      );
      assert_eq!(
        Allocations::<AllocationsMap, SortedAllocationsMap>::iter(
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
