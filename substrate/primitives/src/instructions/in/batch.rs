use alloc::{vec, vec::Vec};

use zeroize::Zeroize;

use borsh::{io, BorshSerialize, BorshDeserialize};

use crate::{
  BlockHash, crypto::Signature, network_id::ExternalNetworkId,
  instructions::InInstructionWithBalance,
};

/*
  `Batch`es have a size limit we enforce upon deserialization.

  The naive solution would be to deserialize, then serialize, and check the serialized length is
  less than the maximum. This performs a redundant allocation and is computationally non-trivial.

  The next solution would be to wrap the deserialization with a `Cursor` so one can check the
  amount read, yet `Cursor` isn't available under no-`std`.

  We solve this by manually implementing a `Cursor`-equivalent (for our purposes) which lets us
  check the total amount read is `<=` the maximum size.

  The issue is we need every call to `BorshDeserialize::deserialize_reader` to use our custom
  reader, which requires manually implementing it, which means we can't use the derive macro and
  can't ensure it follows the Borsh specification. We solve this by generating two identical
  structs, one internal with a derived `BorshDeserialize::deserialize_reader`, one public with a
  manually implemented `BorshDeserialize::deserialize_reader` wrapping the internal `struct`'s.
  This lets us ensure the correct reader is used and error if the size limit is hit, while still
  using a derived `BorshDeserialize` which will definitively be compliant.
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

// The internal `Batch` which derives `BorshDeserialize`.
batch_struct!(
  #[derive(BorshDeserialize)]
  BatchDeserialize
);

// The public `Batch` which wraps `BatchDeserialize`'s `BorshDeserialize`.
batch_struct!(#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize)] pub Batch);

impl BorshDeserialize for Batch {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    // A custom reader which enforces the `Batch`'s max size limit
    struct SizeLimitReader<'reader, R: io::Read> {
      reader: &'reader mut R,
      read: usize,
    }
    impl<R: io::Read> io::Read for SizeLimitReader<'_, R> {
      fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.reader.read(buf)?;
        self.read = self.read.saturating_add(read);
        if self.read > Batch::MAX_SIZE {
          Err(io::Error::other("`Batch` size exceeded maximum"))?;
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
  pub const MAX_SIZE: usize = 32_768;

  /// Create a new Batch.
  pub fn new(network: ExternalNetworkId, id: u32, external_network_block_hash: BlockHash) -> Self {
    let mut batch =
      Batch { encoded_size: 0, network, id, external_network_block_hash, instructions: vec![] };
    batch.encoded_size = borsh::object_length(&batch).unwrap();
    batch
  }

  /// Push an `InInstructionWithBalance` onto this `Batch`.
  pub fn push_instruction(
    &mut self,
    instruction: InInstructionWithBalance,
  ) -> Result<(), PushInstructionError> {
    let new_size = self.encoded_size.saturating_add(borsh::object_length(&instruction).unwrap());
    if new_size > Self::MAX_SIZE {
      Err(PushInstructionError::MaxSizeExceeded)?;
    }
    self.encoded_size = new_size;
    self.instructions.push(instruction);
    Ok(())
  }

  /// The message to sign when publishing this Batch.
  pub fn publish_batch_message(&self) -> Vec<u8> {
    const DST: &[u8] = b"InInstructions-publish_batch";
    let mut buf = Vec::with_capacity(DST.len().saturating_add(self.encoded_size));
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
#[cfg(feature = "scale")]
crate::borsh_as_scale!(SignedBatch);
#[cfg(feature = "scale")]
impl scale::MaxEncodedLen for SignedBatch {
  fn max_encoded_len() -> usize {
    Batch::MAX_SIZE + 64
  }
}

impl Zeroize for SignedBatch {
  fn zeroize(&mut self) {
    self.batch.zeroize();
    self.signature.0.as_mut().zeroize();
  }
}

#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
#[test]
fn batch() {
  use rand_core::{RngCore as _, OsRng};

  use crate::prelude::*;

  let coins = Coin::all().collect::<Vec<_>>();
  let external_coins = ExternalCoin::all().collect::<Vec<_>>();

  for network in ExternalNetworkId::all() {
    let id = OsRng.next_u64() as u32;

    let mut external_network_block_hash = [0; 32];
    OsRng.fill_bytes(&mut external_network_block_hash);
    let external_network_block_hash = BlockHash(external_network_block_hash);

    // Check `Batch`es can be constructed as expected
    let mut batch = Batch::new(network, id, external_network_block_hash);
    assert_eq!(borsh::to_vec(&batch).unwrap().len(), batch.encoded_size);
    assert_eq!(batch.network(), network);
    assert_eq!(batch.id(), id);
    assert_eq!(batch.external_network_block_hash(), external_network_block_hash);
    assert!(batch.instructions().is_empty());

    // Check they can be serialized and the `encoded_size` is maintained
    assert_eq!(borsh::to_vec(&batch).unwrap().len(), batch.encoded_size);
    assert_eq!(
      Batch::deserialize_reader(&mut borsh::to_vec(&batch).unwrap().as_slice()).unwrap(),
      batch
    );

    // Push randomly-sampled instructions as a fuzz test
    let mut instructions = vec![];
    let mut instruction;
    while {
      instruction = {
        let mut address = [0; 32];
        OsRng.fill_bytes(&mut address);
        let address = SeraiAddress(address);
        let instruction = match OsRng.next_u64() % 7 {
          0 => InInstruction::GenesisLiquidity(address),
          1 => {
            InInstruction::SwapToStakedSri { validator: address, minimum: Amount(OsRng.next_u64()) }
          }
          2 => InInstruction::TransferWithSwap {
            to: address,
            maximum_to_swap: Amount(OsRng.next_u64()),
            sri: Amount(OsRng.next_u64()),
          },
          3 => InInstruction::Transfer { to: address },
          4 => InInstruction::SwapAndAddLiquidity {
            address,
            coin: Amount(OsRng.next_u64()),
            sri_minimum: Amount(OsRng.next_u64()),
            sri_for_fees: Amount(OsRng.next_u64()),
          },
          5 => InInstruction::Swap {
            address,
            minimum_to_receive: Balance {
              coin: coins[(OsRng.next_u64() as usize) % coins.len()],
              amount: Amount(OsRng.next_u64()),
            },
          },
          6 => {
            let mut address =
              vec![0; ((OsRng.next_u64() as u32) % ExternalAddress::MAX_LEN) as usize];
            OsRng.fill_bytes(&mut address);
            InInstruction::SwapOut {
              instruction: OutInstruction::Transfer(address.try_into().unwrap()),
              minimum_to_receive: ExternalBalance {
                coin: external_coins[(OsRng.next_u64() as usize) % external_coins.len()],
                amount: Amount(OsRng.next_u64()),
              },
            }
          }
          _ => unreachable!(),
        };
        let balance = ExternalBalance {
          coin: external_coins[(OsRng.next_u64() as usize) % external_coins.len()],
          amount: Amount(OsRng.next_u64()),
        };
        InInstructionWithBalance { instruction, balance }
      };
      batch.push_instruction(instruction.clone()).is_ok()
    } {
      instructions.push(instruction.clone());
      // `instructions`, `encoded_size` should have been updated
      assert_eq!(batch.instructions(), &instructions);
      assert_eq!(borsh::to_vec(&batch).unwrap().len(), batch.encoded_size);
      assert!(batch.encoded_size <= Batch::MAX_SIZE);
      // The `Batch` should still be able to be serialized
      assert_eq!(
        Batch::deserialize_reader(&mut borsh::to_vec(&batch).unwrap().as_slice()).unwrap(),
        batch
      );

      let mut signature = [0; 64];
      OsRng.fill_bytes(&mut signature);
      let signature = Signature(signature);

      let signed_batch = SignedBatch { batch: batch.clone(), signature };
      assert_eq!(
        SignedBatch::deserialize_reader(&mut borsh::to_vec(&signed_batch).unwrap().as_slice())
          .unwrap(),
        signed_batch
      );

      #[cfg(feature = "scale")]
      {
        use scale::{Encode as _, DecodeAll as _};
        assert_eq!(signed_batch.encode(), borsh::to_vec(&signed_batch).unwrap());
        assert_eq!(
          SignedBatch::decode_all(&mut signed_batch.encode().as_slice()).unwrap(),
          signed_batch
        );
      }
    }

    /*
      The above loop was supposed to terminate when the next instruction would push the `Batch`
      over the size limit. We now check that was the case, and the size limit is enforced upon
      deserialization.
    */
    assert!(
      (borsh::to_vec(&batch).unwrap().len() + borsh::to_vec(&instruction).unwrap().len()) >
        Batch::MAX_SIZE
    );
    // Directly access `instructions` (which isn't `pub`) to push this
    batch.instructions.push(instruction);
    // This should error as the `Batch` is now over the size limit
    Batch::deserialize_reader(&mut borsh::to_vec(&batch).unwrap().as_slice()).unwrap_err();
  }
}
