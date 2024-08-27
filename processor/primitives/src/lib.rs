#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{hash::Hash, fmt::Debug};

use group::GroupEncoding;

use scale::{Encode, Decode};
use borsh::{BorshSerialize, BorshDeserialize};

/// A module for task-related structs and functionality.
pub mod task;

mod output;
pub use output::*;

mod eventuality;
pub use eventuality::*;

mod block;
pub use block::*;

/// An ID for an output/transaction/block/etc.
///
/// IDs don't need to implement `Copy`, enabling `[u8; 33]`, `[u8; 64]` to be used. IDs are still
/// bound to being of a constant-size, where `Default::default()` returns an instance of such size
/// (making `Vec<u8>` invalid as an `Id`).
pub trait Id:
  Send
  + Sync
  + Clone
  + Default
  + PartialEq
  + Eq
  + Hash
  + AsRef<[u8]>
  + AsMut<[u8]>
  + Debug
  + Encode
  + Decode
  + BorshSerialize
  + BorshDeserialize
{
}
impl<const N: usize> Id for [u8; N] where [u8; N]: Default {}

/// A wrapper for a group element which implements the borsh traits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BorshG<G: GroupEncoding>(pub G);
impl<G: GroupEncoding> BorshSerialize for BorshG<G> {
  fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
    writer.write_all(self.0.to_bytes().as_ref())
  }
}
impl<G: GroupEncoding> BorshDeserialize for BorshG<G> {
  fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
    let mut repr = G::Repr::default();
    reader.read_exact(repr.as_mut())?;
    Ok(Self(
      Option::<G>::from(G::from_bytes(&repr)).ok_or(borsh::io::Error::other("invalid point"))?,
    ))
  }
}
