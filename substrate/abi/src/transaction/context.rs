use core::num::NonZero;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{BlockHash, address::SeraiAddress, balance::Balance, crypto::Signature};

/// Part of the context used to sign with, from the protocol.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ImplicitContext {
  /// The hash of the blockchain's genesis block.
  pub genesis_block_hash: BlockHash,
  /// The ID of the current protocol.
  pub protocol_id: [u8; 32],
}

/// Part of the context used to sign with, specified within the transaction itself.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ExplicitContext {
  /// The historic block this transaction builds upon.
  ///
  /// This transaction can not be included in a blockchain which does not include this block.
  pub historic_block: BlockHash,

  /// The UNIX time this transaction must be included by (and expires after).
  ///
  /// This transaction can not be included in a block whose time is equal or greater to this value.
  pub include_by: Option<NonZero<u64>>,

  /// The signer.
  pub signer: SeraiAddress,

  /// The signer's nonce.
  pub nonce: u32,

  /// The fee paid to the network for inclusion.
  ///
  /// This fee is paid regardless of the success of any of the calls.
  pub fee: Balance,
}

/// A signature, with context.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ContextualizedSignature {
  /// The explicit context.
  pub explicit_context: ExplicitContext,
  /// The signature.
  pub signature: Signature,
}

#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
#[test]
fn serialize() {
  use alloc::vec::Vec;
  use rand_core::{RngCore as _, OsRng};
  use serai_primitives::{coin::Coin, balance::Amount, crypto::RistrettoSignature};

  for _ in 0 .. 100 {
    let mut genesis_block_hash = [0; 32];
    OsRng.fill_bytes(&mut genesis_block_hash);
    let genesis_block_hash = BlockHash(genesis_block_hash);

    let mut protocol_id = [0; 32];
    OsRng.fill_bytes(&mut protocol_id);

    let context = ImplicitContext { genesis_block_hash, protocol_id };

    assert_eq!(
      ImplicitContext::deserialize_reader(&mut borsh::to_vec(&context).unwrap().as_slice())
        .unwrap(),
      context
    );
  }

  for _ in 0 .. 100 {
    let mut historic_block = [0; 32];
    OsRng.fill_bytes(&mut historic_block);
    let historic_block = BlockHash(historic_block);

    let include_by = ((OsRng.next_u64() & 1) == 1).then(|| {
      loop {
        if let Some(include_by) = NonZero::new(OsRng.next_u64()) {
          break include_by;
        }
      }
    });

    let mut signer = [0; 32];
    OsRng.fill_bytes(&mut signer);
    let signer = SeraiAddress(signer);

    let nonce = OsRng.next_u64() as u32;

    let fee = {
      let coin = {
        let coins = Coin::all().collect::<Vec<_>>();
        coins[(OsRng.next_u64() as usize) % coins.len()]
      };
      let amount = Amount(OsRng.next_u64());
      Balance { coin, amount }
    };

    let context = ExplicitContext { historic_block, include_by, signer, nonce, fee };
    assert_eq!(
      ExplicitContext::deserialize_reader(&mut borsh::to_vec(&context).unwrap().as_slice())
        .unwrap(),
      context
    );

    let mut signature = [0; 64];
    OsRng.fill_bytes(&mut signature);
    let signature = Signature::Ristretto(RistrettoSignature(signature));

    let signature = ContextualizedSignature { explicit_context: context, signature };
    assert_eq!(
      ContextualizedSignature::deserialize_reader(
        &mut borsh::to_vec(&signature).unwrap().as_slice()
      )
      .unwrap(),
      signature
    );
  }
}
