use alloc::{vec, vec::Vec};

use zeroize::Zeroize;

use borsh::{io, BorshSerialize, BorshDeserialize};

use crate::{
  BlockHash, crypto::Signature, network_id::ExternalNetworkId,
  instructions::InInstructionWithBalance,
};

/*
  `Batch`s have a size limit we enforce upon deserialization.

  The naive solution would be to deserialize, then serialize, and check the serialized length is
  less than the maximum. This performs a redundant allocation and is computationally non-trivial.

  The next solution would be to wrap the deserialization with a `Cursor` so one can check the
  amount read, yet `Cursor` isn't available under no-std.

  We solve this by manually implementing a `Cursor`-equivalent (for our purposes) which let us
  check the total amount read is `<=` the maximum size.

  The issue is we need every call to `BorshDeserialize::deserialize_reader` to use our custom
  reader, which requires manually implementing it, which means we can't use the derive macro and
  can't ensure it follows the borsh specification. We solve this by generating two identical
  structs, one internal with a derived `BorshDeserialize::deserialize_reader`, one public with a
  manually implemented `BorshDeserialize::deserialize_reader` wrapping the internal struct's. This
  lets us ensure the correct reader is used and error if the size limit is hit, while still using
  a derived `BorshDeserialize` which will definitively be compliant.
*/
macro_rules! batch_struct {
  (#[$derive: meta] $pub: vis $name: ident) => {
    /// A batch of `InInstruction`s to publish onto Serai.
    #[$derive]
    $pub struct $name {
      /// The size this will be once encoded.
      #[allow(dead_code)] // This is unused for the `BatchDeserialize` instance
      #[borsh(skip)]
      encoded_size: usize,

      /// The network this batch of instructions is coming from.
      network: ExternalNetworkId,
      /// The ID of this `Batch`.
      id: u32,
      /// The hash of the external network's block which produced this `Batch`.
      external_network_block_hash: BlockHash,
      /// The instructions to execute.
      instructions: Vec<InInstructionWithBalance>,
    }
  }
}

batch_struct!(
  #[derive(BorshDeserialize)]
  BatchDeserialize
);
batch_struct!(#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize)] pub Batch);

impl BorshDeserialize for Batch {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    // A custom reader which enforces the `Batch`'s max size limit
    struct SizeLimitReader<'a, R: io::Read> {
      reader: &'a mut R,
      read: usize,
    }
    impl<R: io::Read> io::Read for SizeLimitReader<'_, R> {
      fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.reader.read(buf)?;
        self.read = self.read.saturating_add(read);
        if self.read > Batch::MAX_SIZE {
          #[cfg_attr(feature = "std", expect(clippy::io_other_error))]
          Err(io::Error::new(io::ErrorKind::Other, "Batch size exceeded maximum"))?;
        }
        Ok(read)
      }
    }

    let mut size_limit_reader = SizeLimitReader { reader, read: 0 };
    let BatchDeserialize {
      encoded_size: _,
      network,
      id,
      external_network_block_hash,
      instructions,
    } = <_>::deserialize_reader(&mut size_limit_reader)?;
    Ok(Batch {
      encoded_size: size_limit_reader.read,
      network,
      id,
      external_network_block_hash,
      instructions,
    })
  }
}

/// An error incurred while pushing an instruction onto a `Batch`.
#[derive(Debug)]
pub enum PushInstructionError {
  /// The Batch's max size was exceeded.
  MaxSizeExceeded,
}

impl Batch {
  /// The maximum size of a valid `Batch`'s encoding.
  const MAX_SIZE: usize = 32_768;

  /// Create a new Batch.
  pub fn new(network: ExternalNetworkId, id: u32, external_network_block_hash: BlockHash) -> Self {
    let mut batch =
      Batch { encoded_size: 0, network, id, external_network_block_hash, instructions: vec![] };
    batch.encoded_size = borsh::to_vec(&batch).unwrap().len();
    batch
  }

  /// Push an `InInstructionWithBalance` onto this `Batch`.
  pub fn push_instruction(
    &mut self,
    instruction: InInstructionWithBalance,
  ) -> Result<(), PushInstructionError> {
    if (self.encoded_size.saturating_add(borsh::to_vec(&instruction).unwrap().len())) >
      Self::MAX_SIZE
    {
      Err(PushInstructionError::MaxSizeExceeded)?;
    }
    self.instructions.push(instruction);
    Ok(())
  }

  /// The message to sign when publishing this Batch.
  pub fn publish_batch_message(&self) -> Vec<u8> {
    const DST: &[u8] = b"InInstructions-publish_batch";
    // We don't estimate the size of this Batch, we just reserve a small constant capacity
    let mut buf = Vec::with_capacity(1024);
    (DST, self).serialize(&mut buf).unwrap();
    buf
  }

  /// The network this batch of instructions is coming from.
  pub fn network(&self) -> ExternalNetworkId {
    self.network
  }

  /// The ID of this `Batch`.
  pub fn id(&self) -> u32 {
    self.id
  }

  /// The hash of the external network's block which produced this `Batch`.
  pub fn external_network_block_hash(&self) -> BlockHash {
    self.external_network_block_hash
  }

  /// The instructions within this `Batch`.
  pub fn instructions(&self) -> &[InInstructionWithBalance] {
    &self.instructions
  }
}

/// A signed batch.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct SignedBatch {
  /// The signed batch.
  pub batch: Batch,
  /// The signature.
  pub signature: Signature,
}

#[cfg(feature = "std")]
impl Zeroize for SignedBatch {
  fn zeroize(&mut self) {
    self.batch.zeroize();
    self.signature.0.as_mut().zeroize();
  }
}

#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::Encode for SignedBatch {
  fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
    f(&borsh::to_vec(self).unwrap())
  }
}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::MaxEncodedLen for SignedBatch {
  fn max_encoded_len() -> usize {
    Batch::MAX_SIZE + 64
  }
}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::EncodeLike<SignedBatch> for SignedBatch {}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::Decode for SignedBatch {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    crate::read_scale_as_borsh(input)
  }
}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::DecodeWithMemTracking for SignedBatch {}
