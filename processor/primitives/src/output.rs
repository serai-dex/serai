use core::fmt::Debug;
use std::io;

use group::GroupEncoding;

use serai_primitives::{ExternalAddress, Balance};

use crate::Id;

/// An address on the external network.
pub trait Address: Send + Sync + TryFrom<ExternalAddress> {}

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
  /// Write the OutputType.
  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&[match self {
      OutputType::External => 0,
      OutputType::Branch => 1,
      OutputType::Change => 2,
      OutputType::Forwarded => 3,
    }])
  }

  /// Read an OutputType.
  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
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
pub trait ReceivedOutput<K: GroupEncoding, A: Address>:
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
