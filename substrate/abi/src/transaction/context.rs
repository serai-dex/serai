use core::num::NonZero;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{BlockHash, address::SeraiAddress, balance::Amount, crypto::Signature};

/// Part of the context used to sign with, from the protocol.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ImplicitContext {
  /// The genesis hash of the blockchain.
  pub genesis: BlockHash,
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

  /// The fee, in SRI, paid to the network for inclusion.
  ///
  /// This fee is paid regardless of the success of any of the calls.
  pub fee: Amount,
}

/// A signature, with context.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ContextualizedSignature {
  /// The explicit context.
  pub(super) explicit_context: ExplicitContext,
  /// The signature.
  pub(super) signature: Signature,
}

#[test]
fn serialize() {
  use rand_core::{RngCore as _, OsRng};

  for _ in 0 .. 100 {
    let mut genesis = [0; 32];
    OsRng.fill_bytes(&mut genesis);
    let genesis = BlockHash(genesis);

    let mut protocol_id = [0; 32];
    OsRng.fill_bytes(&mut protocol_id);

    let context = ImplicitContext { genesis, protocol_id };

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

    let include_by = ((OsRng.next_u64() & 1) == 1).then(|| loop {
      if let Some(include_by) = NonZero::new(OsRng.next_u64()) {
        break include_by;
      }
    });

    let mut signer = [0; 32];
    OsRng.fill_bytes(&mut signer);
    let signer = SeraiAddress(signer);

    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let nonce = OsRng.next_u64() as u32;

    let fee = Amount(OsRng.next_u64());

    let context = ExplicitContext { historic_block, include_by, signer, nonce, fee };
    assert_eq!(
      ExplicitContext::deserialize_reader(&mut borsh::to_vec(&context).unwrap().as_slice())
        .unwrap(),
      context
    );

    let mut signature = [0; 64];
    OsRng.fill_bytes(&mut signature);
    let signature = Signature(signature);

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
