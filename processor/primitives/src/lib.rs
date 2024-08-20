#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::fmt::Debug;
use std::io;

use group::{Group, GroupEncoding};

use serai_primitives::Balance;

use scale::{Encode, Decode};
use borsh::{BorshSerialize, BorshDeserialize};

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

/// The type of the output.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OutputType {
  /// An output received to the address external payments use.
  ///
  /// This is reported to Substrate in a `Batch`.
  External,

  /// A branch output.
  ///
  /// Given a known output set, and a known series of outbound transactions, we should be able to
  /// form a completely deterministic schedule S. The issue is when S has TXs which spend prior TXs
  /// in S (which is needed for our logarithmic scheduling). In order to have the descendant TX,
  /// say S[1], build off S[0], we need to observe when S[0] is included on-chain.
  ///
  /// We cannot.
  ///
  /// Monero (and other privacy coins) do not expose their UTXO graphs. Even if we know how to
  /// create S[0], and the actual payment info behind it, we cannot observe it on the blockchain
  /// unless we participated in creating it. Locking the entire schedule, when we cannot sign for
  /// the entire schedule at once, to a single signing set isn't feasible.
  ///
  /// While any member of the active signing set can provide data enabling other signers to
  /// participate, it's several KB of data which we then have to code communication for.
  /// The other option is to simply not observe S[0]. Instead, observe a TX with an identical
  /// output to the one in S[0] we intended to use for S[1]. It's either from S[0], or Eve, a
  /// malicious actor, has sent us a forged TX which is... equally as usable? So who cares?
  ///
  /// The only issue is if we have multiple outputs on-chain with identical amounts and purposes.
  /// Accordingly, when the scheduler makes a plan for when a specific output is available, it
  /// shouldn't set that plan. It should *push* that plan to a queue of plans to perform when
  /// instances of that output occur.
  Branch,

  /// A change output.
  ///
  /// This should be added to the available UTXO pool with no further action taken. It does not
  /// need to be reported (though we do still need synchrony on the block it's in). There's no
  /// explicit expectation for the usage of this output at time of recipience.
  Change,

  /// A forwarded output from the prior multisig.
  ///
  /// This is distinguished for technical reasons around detecting when a multisig should be
  /// retired.
  Forwarded,
}

impl OutputType {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&[match self {
      OutputType::External => 0,
      OutputType::Branch => 1,
      OutputType::Change => 2,
      OutputType::Forwarded => 3,
    }])
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut byte = [0; 1];
    reader.read_exact(&mut byte)?;
    Ok(match byte[0] {
      0 => OutputType::External,
      1 => OutputType::Branch,
      2 => OutputType::Change,
      3 => OutputType::Forwarded,
      _ => Err(io::Error::other("invalid OutputType"))?,
    })
  }
}

/// A received output.
pub trait ReceivedOutput<K: GroupEncoding, A>:
  Send + Sync + Sized + Clone + PartialEq + Eq + Debug
{
  /// The type used to identify this output.
  type Id: 'static + Id;

  /// The type of this output.
  fn kind(&self) -> OutputType;

  /// The ID of this output.
  fn id(&self) -> Self::Id;
  /// The key this output was received by.
  fn key(&self) -> K;

  /// The presumed origin for this output.
  ///
  /// This is used as the address to refund coins to if we can't handle the output as desired
  /// (unless overridden).
  fn presumed_origin(&self) -> Option<A>;

  /// The balance associated with this output.
  fn balance(&self) -> Balance;
  /// The arbitrary data (presumably an InInstruction) associated with this output.
  fn data(&self) -> &[u8];

  /// Write this output.
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;
  /// Read an output.
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
}

/// A block header from an external network.
pub trait BlockHeader: Send + Sync + Sized + Clone + Debug {
  /// The type used to identify blocks.
  type Id: 'static + Id;
  /// The ID of this block.
  fn id(&self) -> Self::Id;
  /// The ID of the parent block.
  fn parent(&self) -> Self::Id;
}

/// A block from an external network.
///
/// A block is defined as a consensus event associated with a set of transactions. It is not
/// necessary to literally define it as whatever the external network defines as a block. For
/// external networks which finalize block(s), this block type should be a representation of all
/// transactions within a period finalization (whether block or epoch).
#[async_trait::async_trait]
pub trait Block: Send + Sync + Sized + Clone + Debug {
  /// The type used for this block's header.
  type Header: BlockHeader;

  /// The type used to represent keys on this external network.
  type Key: Group + GroupEncoding;
  /// The type used to represent addresses on this external network.
  type Address;
  /// The type used to represent received outputs on this external network.
  type Output: ReceivedOutput<Self::Key, Self::Address>;

  /// The ID of this block.
  fn id(&self) -> <Self::Header as BlockHeader>::Id;

  /// Scan all outputs within this block to find the outputs spendable by this key.
  fn scan_for_outputs(&self, key: Self::Key) -> Vec<Self::Output>;
}
