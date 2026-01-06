use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::{address::SeraiAddress, balance::Amount};

/// The representation for an amount of key shares.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct KeyShares(u16);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(KeyShares);

impl KeyShares {
  /// Zero key shares.
  pub const ZERO: KeyShares = KeyShares(0);
  /// One key share.
  pub const ONE: KeyShares = KeyShares(1);
  /// The maximum amount of key shares per set.
  ///
  /// While this may increase in the future, it was currently chosen to fit within a `u7`. It also
  /// should be more than adequate for years to come.
  pub const MAX_PER_SET: u16 = 127;
  /// The maximum amount of key shares per set, represented as a `u32`.
  #[expect(clippy::as_conversions)]
  pub const MAX_PER_SET_U32: u32 = Self::MAX_PER_SET as u32;
  /// The maximum amount of key shares per set, represented as a `u64`.
  #[expect(clippy::as_conversions)]
  pub const MAX_PER_SET_U64: u64 = Self::MAX_PER_SET as u64;

  /// Create key shares from a `u16`.
  ///
  /// This will saturate the value if the `u16` exceeds the maximum amount of key shares.
  pub fn saturating_from(key_shares: u16) -> KeyShares {
    KeyShares(key_shares.min(Self::MAX_PER_SET))
  }

  /// Calculate the amount of key shares for an allocation.
  ///
  /// Presumably panics if `allocation_per_key_share` is zero.
  pub fn from_allocation(allocation: Amount, allocation_per_key_share: Amount) -> Self {
    Self::saturating_from(
      u16::try_from(allocation.0 / allocation_per_key_share.0).unwrap_or(u16::MAX),
    )
  }

  /// For a set of validators whose key shares may exceed the maximum, reduce their key shares
  /// until they are less than or equal to the maximum.
  ///
  /// This assumes the input is sorted and all validators have at least one key share. This
  /// function has undefined behavior otherwise.
  ///
  /// Returns the new amount of validators with a non-zero amount of key shares. The caller MUST
  /// truncate their container accordingly.
  ///
  /// This runs in time linear to the excess key shares and may panic if:
  ///   - The total amount of key shares exceeds `u16::MAX`.
  ///   - The list of validators is absurdly long
  ///   - The list of validators includes validators without key shares
  ///
  /// Reduction occurs by reducing each validator in a reverse round-robin. This means the
  /// validators with the least key shares are evicted first.
  #[must_use]
  pub fn amortize_excess(validators: &mut [(SeraiAddress, KeyShares)]) -> usize {
    let total_key_shares = validators.iter().map(|(_key, shares)| shares.0).sum::<u16>();
    let mut actual_len = validators.len();
    let mut offset = 1;
    for _ in 0 .. usize::from(total_key_shares.saturating_sub(Self::MAX_PER_SET)) {
      // If the offset exceeds the new length, reset it
      if offset > actual_len {
        offset = 1;
      }

      // Take one key share from this validator
      let index = actual_len - offset;
      validators[index].1 .0 -= 1;
      // If they now have zero key shares, shrink the length and continue
      if validators[index].1 .0 == 0 {
        actual_len -= 1;
        continue;
      }

      // Increment the offset to take from the next validator on the next iteration
      offset += 1;
    }
    actual_len
  }
}

impl From<KeyShares> for u16 {
  fn from(key_shares: KeyShares) -> u16 {
    key_shares.0
  }
}

impl TryFrom<u16> for KeyShares {
  type Error = ();
  fn try_from(value: u16) -> Result<Self, ()> {
    if value > Self::MAX_PER_SET {
      Err(())
    } else {
      Ok(Self(value))
    }
  }
}

#[test]
fn key_shares() {
  assert_eq!(KeyShares::ZERO, KeyShares(0));
  assert_eq!(KeyShares::ONE, KeyShares(1));
  assert!(KeyShares::ZERO != KeyShares::ONE);

  assert_eq!(u32::from(KeyShares::MAX_PER_SET), KeyShares::MAX_PER_SET_U32);
  assert_eq!(u64::from(KeyShares::MAX_PER_SET), KeyShares::MAX_PER_SET_U64);

  assert_eq!(KeyShares::from_allocation(Amount(0), Amount(1)), KeyShares(0));
  assert_eq!(KeyShares::from_allocation(Amount(100), Amount(10)), KeyShares(10));
  assert_eq!(KeyShares::from_allocation(Amount(100), Amount(51)), KeyShares(1));
  assert_eq!(
    KeyShares::from_allocation(Amount(KeyShares::MAX_PER_SET_U64), Amount(1)),
    KeyShares(KeyShares::MAX_PER_SET)
  );
  assert_eq!(
    KeyShares::from_allocation(Amount(KeyShares::MAX_PER_SET_U64 + 1), Amount(1)),
    KeyShares(KeyShares::MAX_PER_SET)
  );

  for key_shares_u16 in u16::MIN ..= u16::MAX {
    let Ok(key_shares) = KeyShares::try_from(key_shares_u16) else {
      assert_eq!(KeyShares::saturating_from(key_shares_u16), KeyShares(KeyShares::MAX_PER_SET));
      continue;
    };
    assert_eq!(u16::from(key_shares), key_shares_u16);
    assert_eq!(key_shares, KeyShares::saturating_from(key_shares_u16));

    assert_eq!(
      KeyShares::deserialize_reader(&mut borsh::to_vec(&key_shares).unwrap().as_slice()).unwrap(),
      key_shares
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};
      assert_eq!(key_shares.encode(), borsh::to_vec(&key_shares).unwrap());
      assert_eq!(KeyShares::decode_all(&mut key_shares.encode().as_slice()).unwrap(), key_shares);
      assert_eq!(key_shares.encode().len(), KeyShares::max_encoded_len());
    }
  }
}

#[test]
fn amortize_excess() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};
  let address = || {
    let mut address = [0; 32];
    OsRng.fill_bytes(&mut address);
    SeraiAddress(address)
  };
  let alice = address();
  let bob = address();
  let charlie = address();
  for (mut input, output) in [
    (vec![], [].as_slice()),
    (vec![(alice, KeyShares::ONE)], [(alice, KeyShares::ONE)].as_slice()),
    (
      vec![(alice, KeyShares(KeyShares::MAX_PER_SET))],
      [(alice, KeyShares(KeyShares::MAX_PER_SET))].as_slice(),
    ),
    (
      vec![(alice, KeyShares(KeyShares::MAX_PER_SET)), (bob, KeyShares::ONE)],
      [(alice, KeyShares(KeyShares::MAX_PER_SET))].as_slice(),
    ),
    (
      vec![
        (alice, KeyShares(KeyShares::MAX_PER_SET)),
        (bob, KeyShares::ONE),
        (charlie, KeyShares::ONE),
      ],
      [(alice, KeyShares(KeyShares::MAX_PER_SET))].as_slice(),
    ),
    (
      vec![
        (alice, KeyShares(KeyShares::MAX_PER_SET)),
        (bob, KeyShares(2)),
        (charlie, KeyShares::ONE),
      ],
      [(alice, KeyShares(KeyShares::MAX_PER_SET - 1)), (bob, KeyShares::ONE)].as_slice(),
    ),
    (
      vec![(alice, KeyShares(KeyShares::MAX_PER_SET)), (bob, KeyShares(KeyShares::MAX_PER_SET))],
      [
        (alice, KeyShares(KeyShares::MAX_PER_SET.div_ceil(2))),
        (bob, KeyShares(KeyShares::MAX_PER_SET / 2)),
      ]
      .as_slice(),
    ),
  ] {
    let length = KeyShares::amortize_excess(&mut input);
    assert_eq!(&input[.. length], output);
  }
}
