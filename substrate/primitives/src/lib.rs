#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(test)]
use sp_io::TestExternalities;

#[cfg(test)]
use frame_support::{pallet_prelude::*, Identity, traits::StorageInstance};

use sp_core::{ConstU32, bounded::BoundedVec};
pub use sp_application_crypto as crypto;

mod amount;
pub use amount::*;

mod block;
pub use block::*;

mod networks;
pub use networks::*;

mod balance;
pub use balance::*;

mod account;
pub use account::*;

mod tx;
pub use tx::*;

#[cfg(feature = "borsh")]
pub fn borsh_serialize_bounded_vec<W: borsh::io::Write, T: BorshSerialize, const B: u32>(
  bounded: &BoundedVec<T, ConstU32<B>>,
  writer: &mut W,
) -> Result<(), borsh::io::Error> {
  borsh::BorshSerialize::serialize(bounded.as_slice(), writer)
}

#[cfg(feature = "borsh")]
pub fn borsh_deserialize_bounded_vec<R: borsh::io::Read, T: BorshDeserialize, const B: u32>(
  reader: &mut R,
) -> Result<BoundedVec<T, ConstU32<B>>, borsh::io::Error> {
  let vec: Vec<T> = borsh::BorshDeserialize::deserialize_reader(reader)?;
  vec.try_into().map_err(|_| borsh::io::Error::other("bound exceeded"))
}

// Monero, our current longest address candidate, has a longest address of featured
// 1 (enum) + 1 (flags) + 64 (two keys) = 66
// When JAMTIS arrives, it'll become 112 or potentially even 142 bytes
pub const MAX_ADDRESS_LEN: u32 = 196;

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExternalAddress(
  #[cfg_attr(
    feature = "borsh",
    borsh(
      serialize_with = "borsh_serialize_bounded_vec",
      deserialize_with = "borsh_deserialize_bounded_vec"
    )
  )]
  BoundedVec<u8, ConstU32<{ MAX_ADDRESS_LEN }>>,
);
#[cfg(feature = "std")]
impl Zeroize for ExternalAddress {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize()
  }
}

impl ExternalAddress {
  #[cfg(feature = "std")]
  pub fn new(address: Vec<u8>) -> Result<ExternalAddress, &'static str> {
    Ok(ExternalAddress(address.try_into().map_err(|_| "address length exceeds {MAX_ADDRESS_LEN}")?))
  }

  pub fn address(&self) -> &[u8] {
    self.0.as_ref()
  }

  #[cfg(feature = "std")]
  pub fn consume(self) -> Vec<u8> {
    self.0.into_inner()
  }
}

impl AsRef<[u8]> for ExternalAddress {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

// Should be enough for a Uniswap v3 call
pub const MAX_DATA_LEN: u32 = 512;
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Data(
  #[cfg_attr(
    feature = "borsh",
    borsh(
      serialize_with = "borsh_serialize_bounded_vec",
      deserialize_with = "borsh_deserialize_bounded_vec"
    )
  )]
  BoundedVec<u8, ConstU32<{ MAX_DATA_LEN }>>,
);

#[cfg(feature = "std")]
impl Zeroize for Data {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize()
  }
}

impl Data {
  #[cfg(feature = "std")]
  pub fn new(data: Vec<u8>) -> Result<Data, &'static str> {
    Ok(Data(data.try_into().map_err(|_| "data length exceeds {MAX_DATA_LEN}")?))
  }

  pub fn data(&self) -> &[u8] {
    self.0.as_ref()
  }

  #[cfg(feature = "std")]
  pub fn consume(self) -> Vec<u8> {
    self.0.into_inner()
  }
}

impl AsRef<[u8]> for Data {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

/// Lexicographically reverses a given byte array.
pub fn reverse_lexicographic_order<const N: usize>(bytes: [u8; N]) -> [u8; N] {
  let mut res = [0u8; N];
  for (i, byte) in bytes.iter().enumerate() {
    res[i] = !*byte;
  }
  res
}

#[test]
fn test_reverse_lexicographic_order() {
  TestExternalities::default().execute_with(|| {
    // Set up Storage
    struct Storage;
    impl StorageInstance for Storage {
      fn pallet_prefix() -> &'static str {
        "LexicographicOrder"
      }

      const STORAGE_PREFIX: &'static str = "storaage";
    }
    struct StorageReverse;
    impl StorageInstance for StorageReverse {
      fn pallet_prefix() -> &'static str {
        "LexicographicOrder"
      }

      const STORAGE_PREFIX: &'static str = "storaagereverse";
    }

    // Maps
    type Map = StorageMap<Storage, Identity, [u8; 8], u16, OptionQuery>;
    type MapReverse = StorageMap<StorageReverse, Identity, [u8; 8], u16, OptionQuery>;

    // populate the maps
    let amounts: Vec<u64> = vec![
      89094597672602079,
      9812545476752143188,
      735020655991311,
      9285083041886385685,
      53762221139194,
      13946534802749779967,
      109372747683,
      11819301306422986078,
      737471142364463,
      5198787146240868890,
      12664490967510575660,
      17980533125308,
      13875105403707512416,
      8588894095664203595,
      4339496150923070988,
      4231647914743370582,
      10647602703415832559,
      14880694170381462414,
      6096962179554666106,
      6659285945129437525,
      16456564335889698351,
      13845959324357347,
      1648569167474441524,
      13133695496521888158,
      7616461337984068322,
      12726729663511294792,
      8000797058089650061,
      15005828517346690662,
      1793588,
      7220477668898016104,
      16181904040794627088,
      14797634045215342682,
      19639150764444,
      8177870148422964533,
      581491679308004752,
      4314801822544279657,
      94651700756056691,
      96186224808132,
      8410150218145059327,
      14985557922391323432,
      11352279857984687689,
      34328309207209,
      5611615379596223089,
      18125943563248874553,
      17533195941173182568,
      18169879009154892725,
      6008387172344065013,
      2998266057356919988,
      2644053484132935149,
      11547298436182772089,
      4586345667609119481,
      6172439446948403799,
      10626959711571315184,
      12907610780314711856,
      17196831155500322373,
      15974476473205372690,
      14655680501878891324,
      6726170126210474968,
      57886895824576419,
      4617815046373141865,
      17316901742166242228,
      13898507508355951049,
      10252715777491496804,
      8757446702634329168,
      3825982926411780397,
      5429203804114305693,
      14146937173155582346,
      4166019698606353622,
      11249167927606315147,
      18015207767097956850,
      13660375940391754802,
      564863094733853289,
      9530638362187710906,
      3188632306609925749,
      18113494183422781593,
      1835777136545799569,
      6632144245864749829,
      8626951292883317778,
      8029065522637372030,
      5223975568957781514,
      8948791824790231783,
      8608930334805227719,
      4018500067378149536,
      3096559742628404701,
      12236725434494870905,
      1073499773668488616,
      10723113063135353762,
      13242954556652696261,
      13691823023000210372,
      12624898660330224628,
      3250859179908177396,
      13075208133426449118,
      18011040994576979536,
      1915235854583868831,
      12468256923643148798,
      95752683624580217,
      1724650070088393290,
      8239892706949648329,
      7652806705326215966,
      82960,
    ];

    let mut amounts_sorted: Vec<u64> = amounts.clone();
    amounts_sorted.sort();
    for a in amounts {
      Map::set(a.to_be_bytes(), Some(1));
      MapReverse::set(reverse_lexicographic_order(a.to_be_bytes()), Some(1));
    }

    // retrive back and check whether they are sorted as expected
    let total_size = amounts_sorted.len();
    let mut map_iter = Map::iter_keys();
    let mut reverse_map_iter = MapReverse::iter_keys();
    for i in 0 .. amounts_sorted.len() {
      let first = map_iter.next().unwrap();
      let second = reverse_map_iter.next().unwrap();

      assert_eq!(u64::from_be_bytes(first), amounts_sorted[i]);
      assert_eq!(
        u64::from_be_bytes(reverse_lexicographic_order(second)),
        amounts_sorted[total_size - (i + 1)]
      );
    }
  });
}

pub type BlockNumber = u64;
pub type Header = sp_runtime::generic::Header<BlockNumber, sp_runtime::traits::BlakeTwo256>;
